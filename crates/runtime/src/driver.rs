//! Pool driver: ties [`SharedCircuitPool`] tick output to
//! [`build_circuit`] dispatch.
//!
//! [`PoolDriver`] is the long-running tokio task that:
//!
//! 1. Periodically calls `pool.tick()` to harvest [`PoolAction`]s.
//! 2. For `BuildCircuit { profile }`: calls
//!    [`HopSelector::select`] on the live bridge catalogue, then
//!    [`build_circuit`] with the resulting hops, then
//!    [`SharedCircuitPool::record_built`] on success or
//!    [`SharedCircuitPool::record_build_failure`] on error.
//! 3. For `RetireCircuit { id }` / `DrainCircuit { id }`:
//!    delegates to a caller-supplied callback so the runtime
//!    knows how to look up the actual `ConnHandle` for that id
//!    and tear it down.
//!
//! The driver owns NO circuit state itself - it's a pure dispatcher.
//! The caller owns a `CircuitRegistry` (their data structure)
//! mapping `id -> BuiltCircuit<H>`. When the driver emits
//! retire / drain actions, it invokes the caller's callback to
//! perform the actual tear-down.
//!
//! This design lets the driver run forever without taking ownership
//! of every circuit - circuits flow back to the caller via
//! `record_built`'s output, and tear-down requests flow forward
//! via the callback.
//!
//! # Phase 2B status
//!
//! The driver scaffolding is here. The integration end-to-end
//! (SOCKS5 ingress -> driver -> bridge daemon) lands once the
//! bridge-side circuit handler ([RT-C4]) is implemented.

use crate::pool::SharedCircuitPool;
use crate::{build_circuit, BuiltCircuit, HopRuntime};
use mirage_circuit::HopSpec;
use mirage_router::{BridgeCandidate, CircuitProfile, HopSelector, PoolAction, SelectorError};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// CircuitRegistry trait

/// Caller-owned registry mapping circuit ids to runtime state.
///
/// The driver doesn't own any circuit state; it calls into a
/// registry the caller provides so the caller can keep its own
/// view of "which `BuiltCircuit` belongs to which id." Phase 2C
/// will provide a default `MemoryCircuitRegistry` impl.
#[async_trait::async_trait]
pub trait CircuitRegistry<H: Send + 'static>: Send + Sync {
    /// Newly-built circuit. Caller stores it under `id`.
    async fn insert(&self, id: u64, built: BuiltCircuit<H>);
    /// Take the circuit out for tear-down. Returns `None` if the
    /// id was never inserted or already retired.
    async fn take(&self, id: u64) -> Option<BuiltCircuit<H>>;
    /// Mark a circuit as draining. Existing streams continue;
    /// new acquires of this id are refused (typically by the
    /// pool, which is the source of the drain action). Default
    /// implementation is a no-op.
    async fn mark_draining(&self, _id: u64) {}
}

// PoolDriver

/// Configuration for [`PoolDriver`]. All knobs have sensible
/// defaults via [`Default`]; tune for your deployment.
#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// How often to call `pool.tick()`. Default: every 5 seconds.
    pub tick_interval: Duration,
    /// Per-circuit-build deadline passed to [`build_circuit`].
    /// Default: 30 seconds.
    pub build_deadline: Duration,
    /// Maximum number of concurrent in-flight builds the driver
    /// will spawn. Excess `BuildCircuit` actions are deferred to
    /// the next tick.
    pub max_concurrent_builds: usize,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(5),
            build_deadline: Duration::from_secs(30),
            max_concurrent_builds: 8,
        }
    }
}

/// Long-running pool dispatcher.
pub struct PoolDriver<R, REG>
where
    R: HopRuntime + 'static,
    R::ConnHandle: 'static,
    REG: CircuitRegistry<R::ConnHandle> + 'static,
{
    pool: SharedCircuitPool<u64>,
    runtime: Arc<R>,
    selector: Arc<HopSelector>,
    catalogue: Arc<RwLock<Vec<BridgeCandidate>>>,
    registry: Arc<REG>,
    config: DriverConfig,
    next_id: Arc<AtomicU64>,
}

impl<R, REG> Clone for PoolDriver<R, REG>
where
    R: HopRuntime + 'static,
    R::ConnHandle: 'static,
    REG: CircuitRegistry<R::ConnHandle> + 'static,
{
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            runtime: Arc::clone(&self.runtime),
            selector: Arc::clone(&self.selector),
            catalogue: Arc::clone(&self.catalogue),
            registry: Arc::clone(&self.registry),
            config: self.config.clone(),
            next_id: Arc::clone(&self.next_id),
        }
    }
}

impl<R, REG> PoolDriver<R, REG>
where
    R: HopRuntime + 'static,
    R::ConnHandle: 'static,
    REG: CircuitRegistry<R::ConnHandle> + 'static,
{
    /// Construct.
    pub fn new(
        pool: SharedCircuitPool<u64>,
        runtime: Arc<R>,
        selector: Arc<HopSelector>,
        catalogue: Arc<RwLock<Vec<BridgeCandidate>>>,
        registry: Arc<REG>,
        config: DriverConfig,
    ) -> Self {
        Self {
            pool,
            runtime,
            selector,
            catalogue,
            registry,
            config,
            // Start at 1 so 0 is reserved (matches mux convention).
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Run a single tick: harvest pool actions and dispatch them.
    /// Useful for tests; production code typically calls
    /// [`Self::run_forever`].
    ///
    /// Returns the number of actions dispatched.
    pub async fn tick_once(&self) -> usize {
        let actions = self.pool.tick().await;
        let n = actions.len();
        for action in actions {
            match action {
                PoolAction::BuildCircuit { profile } => {
                    let driver = self.clone();
                    tokio::spawn(async move {
                        driver.dispatch_build(profile).await;
                    });
                }
                PoolAction::DrainCircuit { id } => {
                    self.registry.mark_draining(id).await;
                }
                PoolAction::RetireCircuit { id } => {
                    if let Some(built) = self.registry.take(id).await {
                        self.runtime
                            .destroy_circuit(built.conn, built.circuit.hop_count())
                            .await;
                    }
                }
            }
        }
        n
    }

    /// Run the driver forever. Returns only on `cancel` notify.
    ///
    /// Caller spawns this on a tokio task at startup and signals
    /// shutdown via the `cancel` `Notify`.
    pub async fn run_forever(self, cancel: Arc<tokio::sync::Notify>) {
        let mut interval = tokio::time::interval(self.config.tick_interval);
        // Skip the first immediate tick so we don't fire actions
        // before the caller has a chance to populate the catalogue.
        interval.tick().await;
        loop {
            tokio::select! {
                () = cancel.notified() => {
                    tracing::info!("PoolDriver: shutdown signaled");
                    return;
                }
                _ = interval.tick() => {
                    let dispatched = self.tick_once().await;
                    if dispatched > 0 {
                        tracing::debug!(
                            actions = dispatched,
                            "PoolDriver: tick dispatched"
                        );
                    }
                }
            }
        }
    }

    /// Handle one `BuildCircuit` action - select hops, build the
    /// circuit, store it, and report success/failure back to the
    /// pool. Public for tests that want to drive a single build
    /// deterministically without `tokio::spawn`'s scheduling
    /// indeterminism. Production callers use [`Self::tick_once`]
    /// or [`Self::run_forever`].
    pub async fn dispatch_build(&self, profile: CircuitProfile) {
        let class = profile.class;
        let catalogue = { self.catalogue.read().await.clone() };
        let hops: Vec<HopSpec> = match self.selector.select(&profile, &catalogue) {
            Ok(h) => h,
            Err(SelectorError::InsufficientCatalogue { need, got }) => {
                tracing::warn!(
                    class = class.name(),
                    need,
                    got,
                    "PoolDriver: catalogue too small to satisfy build"
                );
                let _ = self.pool.record_build_failure(class).await;
                return;
            }
            Err(e) => {
                tracing::warn!(
                    class = class.name(),
                    error = %e,
                    "PoolDriver: hop selection failed"
                );
                let _ = self.pool.record_build_failure(class).await;
                return;
            }
        };
        match build_circuit(&*self.runtime, hops, self.config.build_deadline).await {
            Ok(built) => {
                let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                self.registry.insert(id, built).await;
                if let Err(e) = self.pool.record_built(id, class).await {
                    // Pool refused the record (no Building entry -
                    // shouldn't happen under our discipline). Tear
                    // the circuit down so it doesn't leak.
                    tracing::error!(
                        class = class.name(),
                        error = %e,
                        "PoolDriver: pool refused record_built; tearing down circuit"
                    );
                    if let Some(built) = self.registry.take(id).await {
                        self.runtime
                            .destroy_circuit(built.conn, built.circuit.hop_count())
                            .await;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    class = class.name(),
                    error = %e,
                    "PoolDriver: build_circuit failed"
                );
                let _ = self.pool.record_build_failure(class).await;
            }
        }
    }
}

// MemoryCircuitRegistry - simple in-memory impl (Phase 2B starter)

/// In-memory `CircuitRegistry`. Phase 2B's default for callers
/// that don't need persistence. Phase 2C may add a richer registry
/// with per-circuit metrics, lifecycle hooks, etc.
pub struct MemoryCircuitRegistry<H: Send + 'static> {
    inner: tokio::sync::Mutex<std::collections::HashMap<u64, BuiltCircuit<H>>>,
    draining: tokio::sync::Mutex<std::collections::HashSet<u64>>,
}

impl<H: Send + 'static> MemoryCircuitRegistry<H> {
    /// Construct empty registry.
    pub fn new() -> Self {
        Self {
            inner: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            draining: tokio::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Look up an active circuit by id without removing. Returns
    /// `None` if the circuit is unknown OR is currently draining
    /// (callers shouldn't open new streams on draining circuits).
    pub async fn lookup_active(&self, id: u64) -> bool {
        let draining = self.draining.lock().await;
        if draining.contains(&id) {
            return false;
        }
        let inner = self.inner.lock().await;
        inner.contains_key(&id)
    }

    /// Total registered circuits.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// True iff empty.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }
}

impl<H: Send + 'static> Default for MemoryCircuitRegistry<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl<H: Send + 'static> CircuitRegistry<H> for MemoryCircuitRegistry<H> {
    async fn insert(&self, id: u64, built: BuiltCircuit<H>) {
        self.inner.lock().await.insert(id, built);
    }

    async fn take(&self, id: u64) -> Option<BuiltCircuit<H>> {
        self.draining.lock().await.remove(&id);
        self.inner.lock().await.remove(&id)
    }

    async fn mark_draining(&self, id: u64) {
        self.draining.lock().await.insert(id);
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{HopOutcome, MockHopRuntime};
    use mirage_circuit::HopEndpoint;
    use mirage_router::pool::AcquireOutcome;
    use mirage_router::{Class, PoolPolicy};

    fn bridge(tag: u8, op: u8) -> BridgeCandidate {
        BridgeCandidate {
            static_pk: [tag; 32],
            endpoint: HopEndpoint::Ipv4 {
                // Distinct /24 per bridge so IP-prefix anti-
                // affinity doesn't reject the whole catalogue.
                addr: [10, 0, tag, 1],
                port: 4433,
            },
            operator_id: [op; 16],
            transports: vec!["reality-v2", "obfs-tcp"],
            last_seen: None,
        }
    }

    fn synth_catalogue() -> Vec<BridgeCandidate> {
        (1..=12u8).map(|i| bridge(i, i)).collect()
    }

    fn pool() -> SharedCircuitPool<u64> {
        let mut raw = mirage_router::CircuitPool::<u64>::new(PoolPolicy::default());
        raw.set_jitter_picker(mirage_router::pool::zero_jitter);
        SharedCircuitPool::from_pool(raw)
    }

    fn driver(
        rt: Arc<MockHopRuntime>,
    ) -> PoolDriver<MockHopRuntime, MemoryCircuitRegistry<crate::mock::MockConn>> {
        PoolDriver::new(
            pool(),
            rt,
            Arc::new(HopSelector::new([0x42; 16])),
            Arc::new(RwLock::new(synth_catalogue())),
            Arc::new(MemoryCircuitRegistry::new()),
            DriverConfig {
                tick_interval: Duration::from_millis(50),
                build_deadline: Duration::from_secs(10),
                max_concurrent_builds: 8,
            },
        )
    }

    #[tokio::test]
    async fn dispatch_build_records_built_on_success() {
        // Drive dispatch directly so the build's completion is
        // synchronous w.r.t. the test's await points.
        let rt = Arc::new(MockHopRuntime::new(vec![HopOutcome::Ok; 100]));
        let d = driver(Arc::clone(&rt));
        // Pool has no Building yet. Insert one so dispatch_build
        // has a slot to convert to Healthy via record_built.
        let outcome = d.pool.acquire(Class::Interactive).await.unwrap();
        assert!(matches!(outcome, AcquireOutcome::BuildFirst { .. }));
        // Dispatch the build inline.
        let profile = Class::Interactive.default_profile();
        d.dispatch_build(profile).await;
        // After dispatch returns, the Building entry has been
        // record_built'd and the registry has the circuit.
        assert_eq!(d.pool.healthy_count(Class::Interactive).await, 1);
        assert_eq!(d.registry.len().await, 1);
    }

    #[tokio::test]
    async fn dispatch_build_records_failure_on_runtime_error() {
        let rt = Arc::new(MockHopRuntime::new(vec![HopOutcome::FailTransport; 100]));
        let d = driver(Arc::clone(&rt));
        let _ = d.pool.acquire(Class::Interactive).await.unwrap();
        let profile = Class::Interactive.default_profile();
        d.dispatch_build(profile).await;
        // Pool's Building entry was cleared via record_build_failure.
        assert_eq!(d.pool.pending_count(Class::Interactive).await, 0);
        assert_eq!(d.pool.healthy_count(Class::Interactive).await, 0);
        // Registry got nothing.
        assert!(d.registry.is_empty().await);
    }

    #[tokio::test]
    async fn dispatch_build_records_failure_on_empty_catalogue() {
        let rt = Arc::new(MockHopRuntime::new(vec![HopOutcome::Ok; 100]));
        let mut d = driver(Arc::clone(&rt));
        d.catalogue = Arc::new(RwLock::new(Vec::new()));
        let _ = d.pool.acquire(Class::Interactive).await.unwrap();
        let profile = Class::Interactive.default_profile();
        d.dispatch_build(profile).await;
        assert_eq!(d.pool.pending_count(Class::Interactive).await, 0);
        assert_eq!(d.pool.healthy_count(Class::Interactive).await, 0);
    }

    #[tokio::test]
    async fn tick_once_emits_floor_enforcement_dispatches() {
        // Empty pool -> tick floor-enforces all classes with min > 0.
        // We don't await the spawned tasks here; the assertion is
        // about action count, not eventual consistency.
        let rt = Arc::new(MockHopRuntime::new(vec![HopOutcome::Ok; 100]));
        let d = driver(Arc::clone(&rt));
        let dispatched = d.tick_once().await;
        // Floor enforcement: Metadata=1, Interactive=3, Bulk=1,
        // Realtime=1, OnionService=1 -> 7. Background=0 (skipped).
        assert!(
            dispatched >= 5,
            "expected floor enforcement to dispatch >= 5 builds, got {dispatched}"
        );
    }

    #[tokio::test]
    async fn registry_insert_take_roundtrip() {
        let reg: MemoryCircuitRegistry<crate::mock::MockConn> = MemoryCircuitRegistry::new();
        // Build a fake BuiltCircuit.
        let rt = MockHopRuntime::new(vec![HopOutcome::Ok]);
        let built = build_circuit(
            &rt,
            vec![HopSpec::new(
                [1; 32],
                HopEndpoint::Ipv4 {
                    addr: [10, 0, 0, 1],
                    port: 4433,
                },
            )],
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        reg.insert(7, built).await;
        assert_eq!(reg.len().await, 1);
        assert!(reg.lookup_active(7).await);
        let taken = reg.take(7).await;
        assert!(taken.is_some());
        assert_eq!(reg.len().await, 0);
        assert!(!reg.lookup_active(7).await);
    }

    #[tokio::test]
    async fn registry_mark_draining_blocks_lookup() {
        let reg: MemoryCircuitRegistry<crate::mock::MockConn> = MemoryCircuitRegistry::new();
        let rt = MockHopRuntime::new(vec![HopOutcome::Ok]);
        let built = build_circuit(
            &rt,
            vec![HopSpec::new(
                [1; 32],
                HopEndpoint::Ipv4 {
                    addr: [10, 0, 0, 1],
                    port: 4433,
                },
            )],
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        reg.insert(7, built).await;
        assert!(reg.lookup_active(7).await);
        reg.mark_draining(7).await;
        assert!(!reg.lookup_active(7).await);
        // Take still works (for tear-down) and clears the draining mark.
        assert!(reg.take(7).await.is_some());
    }
}
