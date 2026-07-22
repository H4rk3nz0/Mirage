//! Outbound bridge-to-bridge link cache (Phase 2H).
//!
//! `NextHopPool` keys `SessionStream`s by
//! `(next_hop_static_pk, transport_name)` and shares them across
//! many circuits - one outbound link per bridge pair, even when
//! 1000 circuits flow through it. Reduces handshake load on the
//! next-hop bridge and avoids per-circuit transport-layer state.
//!
//! Phase 2H ships only the **cache key + entry struct** plus a
//! Mutex-wrapped `HashMap`. Actual link establishment (Mirage
//! handshake to the next bridge) is Phase 2I - the daemon's
//! integration layer wires it in.

use std::collections::HashMap;
use std::sync::Arc;

/// Key into the next-hop pool. Two circuits with the same
/// `(next_hop_pk, transport_name)` reuse the same outbound link.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NextHopKey {
    /// Next hop's static x25519 public key.
    pub next_hop_pk: [u8; 32],
    /// Transport name used to reach the next hop (e.g.,
    /// `"reality-v2"`, `"obfs-tcp"`). Distinct transports get
    /// distinct entries even for the same `next_hop_pk` - the
    /// daemon may rotate transports on per-circuit policy.
    pub transport_name: &'static str,
}

/// Cached outbound link to a next-hop bridge. The opaque payload
/// `T` is the runtime-side handle (typically a
/// `tokio::sync::Mutex<SessionStream<DuplexStream>>` wrapped in
/// an `Arc`). Phase 2H ships the cache shape; Phase 2I plugs in
/// the concrete handle type.
pub struct NextHopEntry<T> {
    /// Shared handle to the link.
    pub link: Arc<T>,
    /// Per-link circuit count. When this drops to 0 the entry MAY
    /// be evicted by `garbage_collect`.
    pub refcount: u32,
}

impl<T> std::fmt::Debug for NextHopEntry<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NextHopEntry")
            .field("refcount", &self.refcount)
            .finish()
    }
}

/// Pool of outbound bridge-to-bridge links.
pub struct NextHopPool<T> {
    inner: tokio::sync::Mutex<HashMap<NextHopKey, NextHopEntry<T>>>,
}

impl<T> Default for NextHopPool<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> NextHopPool<T> {
    /// New empty pool.
    pub fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Look up an existing entry. Increments refcount on hit.
    /// Returns `None` if no entry exists - caller dials a fresh
    /// link and inserts via [`Self::insert`].
    pub async fn acquire(&self, key: &NextHopKey) -> Option<Arc<T>> {
        let mut g = self.inner.lock().await;
        if let Some(entry) = g.get_mut(key) {
            entry.refcount = entry.refcount.saturating_add(1);
            Some(entry.link.clone())
        } else {
            None
        }
    }

    /// Insert a freshly-dialed link. Subsequent acquires for the
    /// same key return this link with refcount incremented.
    /// Refcount starts at 1 (the inserting caller holds one
    /// reference).
    ///
    /// **Note** [RT-H15]: prefer [`Self::acquire_or_insert`] for
    /// the dial path - `acquire().await -> None -> dial -> insert()`
    /// has a race window where two concurrent callers can both
    /// dial fresh links for the same key. `insert` here remains
    /// for tests and for callers that have an out-of-band
    /// guarantee against the race.
    pub async fn insert(&self, key: NextHopKey, link: Arc<T>) {
        let mut g = self.inner.lock().await;
        g.insert(key, NextHopEntry { link, refcount: 1 });
    }

    /// Acquire an existing entry or, if none exists, dial a fresh
    /// link via `dialer` and insert it - atomically. Closes
    /// [RT-H15]: `acquire().await -> None -> dial -> insert().await`
    /// has a TOCTOU window where two concurrent callers both
    /// dial. This method holds the pool lock across the dial, so
    /// only one caller's dialer runs per key.
    ///
    /// Trade-off: holding the lock during `dialer.await` means
    /// other callers acquiring DIFFERENT keys are also blocked
    /// for that dial's duration. For Phase 2H this is acceptable
    /// (dials are seconds-scale, traffic is sparse); a refactor
    /// to per-key locks lands when the daemon hits real bridge-
    /// to-bridge load.
    pub async fn acquire_or_insert<F, Fut, E>(
        &self,
        key: NextHopKey,
        dialer: F,
    ) -> Result<Arc<T>, E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Arc<T>, E>>,
    {
        let mut g = self.inner.lock().await;
        if let Some(entry) = g.get_mut(&key) {
            entry.refcount = entry.refcount.saturating_add(1);
            return Ok(entry.link.clone());
        }
        // Dial under the lock - see trade-off above.
        let link = dialer().await?;
        g.insert(
            key,
            NextHopEntry {
                link: link.clone(),
                refcount: 1,
            },
        );
        Ok(link)
    }

    /// Decrement the refcount on an entry. Returns `true` if the
    /// caller should drop the link (refcount reached 0). The
    /// entry is removed from the pool on transition to 0; the
    /// last `Arc<T>` reference falls out of scope as the caller
    /// drops their copy, closing the underlying transport.
    pub async fn release(&self, key: &NextHopKey) -> bool {
        let mut g = self.inner.lock().await;
        if let Some(entry) = g.get_mut(key) {
            entry.refcount = entry.refcount.saturating_sub(1);
            if entry.refcount == 0 {
                g.remove(key);
                return true;
            }
        }
        false
    }

    /// Number of distinct next-hop links cached. Diagnostics.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// True iff the pool holds no entries.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    /// Sweep entries with refcount 0. Defence-in-depth - the
    /// `release` path already removes them, but a bug elsewhere
    /// could leave a zombie. Returns the number reaped.
    pub async fn garbage_collect(&self) -> usize {
        let mut g = self.inner.lock().await;
        let before = g.len();
        g.retain(|_, e| e.refcount > 0);
        before - g.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: u8) -> NextHopKey {
        NextHopKey {
            next_hop_pk: [tag; 32],
            transport_name: "reality-v2",
        }
    }

    #[tokio::test]
    async fn empty_pool_acquire_returns_none() {
        let pool: NextHopPool<()> = NextHopPool::new();
        assert!(pool.acquire(&key(1)).await.is_none());
        assert_eq!(pool.len().await, 0);
    }

    #[tokio::test]
    async fn insert_then_acquire_returns_same_link() {
        let pool: NextHopPool<u32> = NextHopPool::new();
        let link = Arc::new(42u32);
        pool.insert(key(1), link.clone()).await;
        let acquired = pool.acquire(&key(1)).await.expect("insert visible");
        assert_eq!(*acquired, 42);
        // Refcount is now 2 (insert = 1, acquire = +1).
        assert_eq!(pool.len().await, 1);
    }

    #[tokio::test]
    async fn release_decrements_refcount_and_removes_at_zero() {
        let pool: NextHopPool<u32> = NextHopPool::new();
        pool.insert(key(1), Arc::new(7u32)).await;
        // refcount = 1 from insert; release transitions to 0
        // and reports `true` to signal the caller can drop.
        assert!(pool.release(&key(1)).await);
        assert_eq!(pool.len().await, 0);
    }

    #[tokio::test]
    async fn release_returns_true_on_zero_transition() {
        let pool: NextHopPool<u32> = NextHopPool::new();
        pool.insert(key(1), Arc::new(7u32)).await;
        // insert sets refcount=1.
        let removed = pool.release(&key(1)).await;
        assert!(removed);
        assert_eq!(pool.len().await, 0);
    }

    #[tokio::test]
    async fn distinct_keys_distinct_entries() {
        let pool: NextHopPool<u32> = NextHopPool::new();
        pool.insert(key(1), Arc::new(1u32)).await;
        pool.insert(key(2), Arc::new(2u32)).await;
        assert_eq!(pool.len().await, 2);
        assert_eq!(*pool.acquire(&key(1)).await.unwrap(), 1);
        assert_eq!(*pool.acquire(&key(2)).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn refcount_isolates_concurrent_circuits() {
        let pool: NextHopPool<u32> = NextHopPool::new();
        pool.insert(key(1), Arc::new(7u32)).await;
        // Two circuits acquire - refcount ends at 3 (insert + 2).
        let _a = pool.acquire(&key(1)).await.unwrap();
        let _b = pool.acquire(&key(1)).await.unwrap();
        // Three releases -> 0 -> removed.
        assert!(!pool.release(&key(1)).await); // 3 -> 2
        assert!(!pool.release(&key(1)).await); // 2 -> 1
        assert!(pool.release(&key(1)).await); // 1 -> 0, removed
        assert_eq!(pool.len().await, 0);
    }

    #[tokio::test]
    async fn acquire_or_insert_dials_when_empty() {
        // RT-H15: atomic acquire-or-insert dials on miss.
        let pool: NextHopPool<u32> = NextHopPool::new();
        let dialed = std::sync::atomic::AtomicUsize::new(0);
        let link = pool
            .acquire_or_insert::<_, _, std::convert::Infallible>(key(1), || async {
                dialed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(Arc::new(42u32))
            })
            .await
            .unwrap();
        assert_eq!(*link, 42);
        assert_eq!(dialed.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(pool.len().await, 1);
    }

    #[tokio::test]
    async fn acquire_or_insert_skips_dial_on_hit() {
        let pool: NextHopPool<u32> = NextHopPool::new();
        pool.insert(key(1), Arc::new(7u32)).await;
        let dialed = std::sync::atomic::AtomicUsize::new(0);
        let link = pool
            .acquire_or_insert::<_, _, std::convert::Infallible>(key(1), || async {
                dialed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(Arc::new(99u32))
            })
            .await
            .unwrap();
        assert_eq!(*link, 7); // existing link, not 99
        assert_eq!(
            dialed.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "dialer must not run on cache hit"
        );
    }

    #[tokio::test]
    async fn garbage_collect_is_noop_on_healthy_pool() {
        let pool: NextHopPool<u32> = NextHopPool::new();
        pool.insert(key(1), Arc::new(1u32)).await;
        pool.insert(key(2), Arc::new(2u32)).await;
        let reaped = pool.garbage_collect().await;
        assert_eq!(reaped, 0);
        assert_eq!(pool.len().await, 2);
    }
}
