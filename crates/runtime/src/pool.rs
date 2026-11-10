//! Concurrency-safe wrapper around `mirage_router::CircuitPool`.
//!
//! The router's `CircuitPool` is an I/O-free state machine - it
//! mutates `&mut self` and is not thread-safe by itself. Phase 2
//! wiring requires shared access from multiple async tasks (the
//! SOCKS5 ingress, the periodic-tick task, the circuit-build
//! completion handlers). [`SharedCircuitPool`] wraps the pool in
//! a `tokio::sync::Mutex` and adds a `tokio::sync::Notify` so
//! tasks blocked on `PoolFull` wake up when capacity frees.
//!
//! # Closures
//!
//! - **[RT-C1]**: pool acquire is now atomic across tasks.
//!   Multiple concurrent `acquire(class)` calls serialize through
//!   the mutex; the cold-start storm de-dup invariant holds.
//! - **[RT-M8]**: [`SharedCircuitPool::acquire_with_wait`]
//!   provides soft backpressure - instead of failing immediately
//!   on `PoolFull`, it waits for a notification (release / build
//!   failure / tick eviction) up to a deadline before giving up.

use mirage_router::pool::AcquireOutcome;
use mirage_router::{CircuitPool, Class, PoolAction, PoolError, PoolPolicy};
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify};

/// Concurrency-safe `CircuitPool` wrapper.
///
/// Cheap to clone - internally an `Arc` of the locked pool and
/// the notifier. All operations are async; lock holding times are
/// the same as the underlying state machine's (`O(N_classes)` at
/// worst for `tick`, O(1) for everything else).
pub struct SharedCircuitPool<Id: Copy + Eq + Hash + Debug + Send + 'static> {
    inner: Arc<Mutex<CircuitPool<Id>>>,
    /// Wakes tasks blocked in [`Self::acquire_with_wait`] when the
    /// pool's state changes in a way that might unblock them
    /// (release, `record_build_failure`, tick removing entries).
    notify: Arc<Notify>,
}

impl<Id: Copy + Eq + Hash + Debug + Send + 'static> std::fmt::Debug for SharedCircuitPool<Id> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // CircuitPool itself doesn't impl Debug (its internal
        // HashMap of HopKeys-derived state is sensitive). Surface
        // diagnostics-only fields.
        f.debug_struct("SharedCircuitPool")
            .field("inner", &"<locked CircuitPool>")
            .field("waiters_pending", &"<Notify, count not exposed by tokio>")
            .finish()
    }
}

impl<Id: Copy + Eq + Hash + Debug + Send + 'static> Clone for SharedCircuitPool<Id> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            notify: Arc::clone(&self.notify),
        }
    }
}

impl<Id: Copy + Eq + Hash + Debug + Send + 'static> SharedCircuitPool<Id> {
    /// Construct from a [`PoolPolicy`]. Validates the policy
    /// up-front (closes [RT-M4] at the wrapper layer too) so a
    /// bad policy is caught at construction.
    pub fn new(policy: PoolPolicy) -> Result<Self, mirage_router::PolicyError> {
        policy.validate()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(CircuitPool::new(policy))),
            notify: Arc::new(Notify::new()),
        })
    }

    /// Construct from an existing [`CircuitPool`]. Useful for
    /// tests that want to set a custom jitter picker before
    /// wrapping.
    pub fn from_pool(pool: CircuitPool<Id>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(pool)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Acquire a circuit for a stream of `class`. Concurrency-safe
    /// equivalent of [`CircuitPool::acquire`].
    pub async fn acquire(&self, class: Class) -> Result<AcquireOutcome<Id>, PoolError> {
        let mut g = self.inner.lock().await;
        g.acquire(class, Instant::now())
    }

    /// Acquire honouring stream-isolation. Same behaviour as
    /// [`CircuitPool::acquire_for_domain`] but concurrency-safe.
    pub async fn acquire_for_domain(
        &self,
        class: Class,
        domain: &str,
        identity_salt: &[u8; 16],
    ) -> Result<AcquireOutcome<Id>, PoolError> {
        let mut g = self.inner.lock().await;
        g.acquire_for_domain(class, domain, identity_salt, Instant::now())
    }

    /// **Soft-backpressure acquire (closes [RT-M8]).**
    ///
    /// Calls [`Self::acquire`] in a loop, waiting on the pool's
    /// notifier between attempts when the result is `PoolFull`.
    /// Returns as soon as any non-`PoolFull` result is produced,
    /// or when `deadline` elapses.
    ///
    /// Use this from SOCKS5 ingress code where blocking briefly
    /// is preferable to surfacing `PoolFull` to the application.
    /// Use plain [`Self::acquire`] from tick / sweep code where
    /// fail-fast is correct.
    pub async fn acquire_with_wait(
        &self,
        class: Class,
        deadline: Duration,
    ) -> Result<AcquireOutcome<Id>, PoolError> {
        let start = tokio::time::Instant::now();
        loop {
            // Register for notifications BEFORE the acquire
            // attempt - otherwise a race could miss a notify that
            // fired between our PoolFull return and the await.
            //
            // RT R3-#6: creating the `Notified` future does NOT register
            // interest - it only registers when first polled. The wakers use
            // `notify_waiters()`, which wakes only already-registered waiters
            // and stores no permit, so a notify firing during `acquire().await`
            // below would be missed and this call could block until `deadline`
            // despite a slot having freed. `enable()` polls the future once now,
            // registering interest before the acquire attempt (and consuming any
            // already-pending notification).
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            // First attempt.
            match self.acquire(class).await {
                Err(PoolError::PoolFull(_)) => {}
                other => return other,
            }
            let elapsed = start.elapsed();
            if elapsed >= deadline {
                return Err(PoolError::PoolFull(class));
            }
            let remaining = deadline - elapsed;
            // Wait for either a notify or the deadline.
            let _ = tokio::time::timeout(remaining, &mut notified).await;
            // Loop and retry. If timeout fired without a notify,
            // the next iteration's elapsed check returns PoolFull.
        }
    }

    /// Record a successful circuit build. Wakes waiters because
    /// even though `record_built` doesn't free a *slot*, a
    /// freshly-Healthy entry may unblock new acquires the waiter
    /// would have piggybacked on as `Pending`.
    pub async fn record_built(&self, id: Id, class: Class) -> Result<u32, PoolError> {
        let result = {
            let mut g = self.inner.lock().await;
            g.record_built(id, class, Instant::now())
        };
        self.notify.notify_waiters();
        result
    }

    /// Record a circuit-build failure. Wakes waiters: the failed
    /// Building slot is removed, freeing the per-class pending-
    /// build budget for retries.
    pub async fn record_build_failure(&self, class: Class) -> Result<(), PoolError> {
        let result = {
            let mut g = self.inner.lock().await;
            g.record_build_failure(class)
        };
        self.notify.notify_waiters();
        result
    }

    /// Stream finished; decrement count. Wakes waiters because a
    /// circuit at `max_streams` capacity may have just dropped
    /// below it.
    pub async fn release(&self, id: Id) -> Result<(), PoolError> {
        let result = {
            let mut g = self.inner.lock().await;
            g.release(id)
        };
        self.notify.notify_waiters();
        result
    }

    /// Mark a circuit as failed. Wakes waiters because the next
    /// `tick` will retire this entry, freeing class capacity.
    pub async fn record_failure(&self, id: Id) -> Result<(), PoolError> {
        let result = {
            let mut g = self.inner.lock().await;
            g.record_failure(id)
        };
        self.notify.notify_waiters();
        result
    }

    /// Periodic sweep. Concurrency-safe equivalent of
    /// [`CircuitPool::tick`]. Wakes waiters after the sweep
    /// because retired entries free class capacity.
    pub async fn tick(&self) -> Vec<PoolAction<Id>> {
        let actions = {
            let mut g = self.inner.lock().await;
            g.tick(Instant::now())
        };
        // Only notify if the tick produced a state change that
        // could unblock waiters - checking exhaustively here is
        // expensive, so notify unconditionally; spurious wakes
        // re-check via acquire and re-block.
        if !actions.is_empty() {
            self.notify.notify_waiters();
        }
        actions
    }

    /// Healthy entry count for diagnostics.
    pub async fn healthy_count(&self, class: Class) -> u32 {
        let g = self.inner.lock().await;
        g.healthy_count(class)
    }

    /// Pending-build count for diagnostics.
    pub async fn pending_count(&self, class: Class) -> u32 {
        let g = self.inner.lock().await;
        g.pending_count(class)
    }

    /// Total entry count for diagnostics.
    pub async fn total_count(&self, class: Class) -> u32 {
        let g = self.inner.lock().await;
        g.total_count(class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_router::pool::zero_jitter;
    use mirage_router::PoolPolicy;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn pool() -> SharedCircuitPool<u64> {
        let mut p = CircuitPool::<u64>::new(PoolPolicy::default());
        p.set_jitter_picker(zero_jitter);
        SharedCircuitPool::from_pool(p)
    }

    #[tokio::test]
    async fn acquire_works_through_wrapper() {
        let p = pool();
        let outcome = p.acquire(Class::Interactive).await.unwrap();
        assert!(matches!(outcome, AcquireOutcome::BuildFirst { .. }));
        p.record_built(1u64, Class::Interactive).await.unwrap();
        let outcome = p.acquire(Class::Interactive).await.unwrap();
        assert!(matches!(outcome, AcquireOutcome::Ready { id: 1 }));
    }

    #[tokio::test]
    async fn concurrent_acquires_serialize_correctly() {
        // RT-C1 closure: 10 concurrent acquires for the same class
        // de-dup correctly through the mutex. Pre-fix this would
        // race past the "find Building entry" check and create
        // multiple Buildings.
        let p = pool();
        let mut handles = vec![];
        for _ in 0..10 {
            let p = p.clone();
            handles.push(tokio::spawn(
                async move { p.acquire(Class::Interactive).await },
            ));
        }
        let mut build_first = 0;
        let mut pending = 0;
        for h in handles {
            match h.await.unwrap().unwrap() {
                AcquireOutcome::BuildFirst { .. } => build_first += 1,
                AcquireOutcome::Pending => pending += 1,
                AcquireOutcome::Ready { .. } => panic!("no circuit yet"),
            }
        }
        assert_eq!(
            build_first, 1,
            "exactly one BuildFirst across concurrent tasks"
        );
        assert_eq!(pending, 9);
        // Pool's pending count agrees.
        assert_eq!(p.pending_count(Class::Interactive).await, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn acquire_with_wait_blocks_until_release() {
        // Configure a tiny pool so we can hit PoolFull deterministically.
        let mut policy = PoolPolicy::default();
        policy.max_per_class.set(Class::Interactive, 1);
        policy.max_pending_builds_per_class = 1;
        let mut raw = CircuitPool::<u64>::new(policy);
        raw.set_jitter_picker(zero_jitter);
        let p = SharedCircuitPool::from_pool(raw);

        // Saturate Interactive: build 1 circuit and fill its
        // max_streams.
        p.acquire(Class::Interactive).await.unwrap();
        p.record_built(1u64, Class::Interactive).await.unwrap();
        let max_streams = Class::Interactive.default_profile().max_streams;
        // Originating stream activated; fill the rest.
        for _ in 1..max_streams {
            assert!(matches!(
                p.acquire(Class::Interactive).await.unwrap(),
                AcquireOutcome::Ready { id: 1 }
            ));
        }
        // Now PoolFull: cap=1, no other Building entries, circuit
        // 1 at max_streams.
        assert!(matches!(
            p.acquire(Class::Interactive).await,
            Err(PoolError::PoolFull(_))
        ));

        // Spawn a waiter that should unblock when we release.
        let p_waiter = p.clone();
        let waiter = tokio::spawn(async move {
            p_waiter
                .acquire_with_wait(Class::Interactive, Duration::from_secs(60))
                .await
        });
        // Yield so the waiter gets to run and registers on Notify.
        tokio::task::yield_now().await;
        // Release a slot - notify fires, waiter retries, succeeds.
        p.release(1u64).await.unwrap();

        // Auto-advance reaches the waiter.
        let result = waiter.await.unwrap().unwrap();
        assert!(matches!(result, AcquireOutcome::Ready { id: 1 }));
    }

    #[tokio::test(start_paused = true)]
    async fn acquire_with_wait_respects_deadline() {
        // Same saturated-pool setup. A waiter with a short
        // deadline gives up cleanly with PoolFull.
        let mut policy = PoolPolicy::default();
        policy.max_per_class.set(Class::Interactive, 1);
        policy.max_pending_builds_per_class = 1;
        let mut raw = CircuitPool::<u64>::new(policy);
        raw.set_jitter_picker(zero_jitter);
        let p = SharedCircuitPool::from_pool(raw);

        p.acquire(Class::Interactive).await.unwrap();
        p.record_built(1u64, Class::Interactive).await.unwrap();
        let max_streams = Class::Interactive.default_profile().max_streams;
        for _ in 1..max_streams {
            p.acquire(Class::Interactive).await.unwrap();
        }
        let err = p
            .acquire_with_wait(Class::Interactive, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(matches!(err, PoolError::PoolFull(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn release_wakes_multiple_waiters() {
        // Two waiters; one release unblocks the next-in-line
        // (the other re-blocks on PoolFull until another release).
        let mut policy = PoolPolicy::default();
        policy.max_per_class.set(Class::Interactive, 1);
        policy.max_pending_builds_per_class = 1;
        let mut raw = CircuitPool::<u64>::new(policy);
        raw.set_jitter_picker(zero_jitter);
        let p = SharedCircuitPool::from_pool(raw);

        p.acquire(Class::Interactive).await.unwrap();
        p.record_built(1u64, Class::Interactive).await.unwrap();
        let max_streams = Class::Interactive.default_profile().max_streams;
        for _ in 1..max_streams {
            p.acquire(Class::Interactive).await.unwrap();
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];
        for _ in 0..2 {
            let p = p.clone();
            let counter = Arc::clone(&counter);
            handles.push(tokio::spawn(async move {
                let r = p
                    .acquire_with_wait(Class::Interactive, Duration::from_secs(60))
                    .await;
                counter.fetch_add(1, Ordering::SeqCst);
                r
            }));
        }
        tokio::task::yield_now().await;
        // First release: one waiter succeeds, one re-blocks.
        p.release(1u64).await.unwrap();
        // Yield until the waker propagates; with start_paused this
        // is essentially deterministic.
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "exactly one waiter should have completed after first release"
        );
        // Second release: the other waiter completes.
        p.release(1u64).await.unwrap();
        let mut results = vec![];
        for h in handles {
            results.push(h.await.unwrap());
        }
        assert!(results.iter().all(std::result::Result::is_ok));
    }

    #[tokio::test]
    async fn invalid_policy_rejected_at_construction() {
        // RT-M4 reaffirmed at the wrapper layer.
        let mut policy = PoolPolicy::default();
        policy.max_per_class.set(Class::Interactive, 0);
        let err = SharedCircuitPool::<u64>::new(policy).unwrap_err();
        // ClassDeadlock for Interactive.
        assert!(matches!(
            err,
            mirage_router::PolicyError::ClassDeadlock(Class::Interactive)
        ));
    }

    #[tokio::test]
    async fn shared_pool_clones_share_state() {
        let p = pool();
        let p2 = p.clone();
        // Acquire on p; observe on p2.
        p.acquire(Class::Interactive).await.unwrap();
        assert_eq!(p2.pending_count(Class::Interactive).await, 1);
    }
}
