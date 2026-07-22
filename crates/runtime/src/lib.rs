//! Async runtime wrappers for Mirage's I/O-free state machines.
//!
//! The state-machine crates (`mirage-circuit`, `mirage-mux`,
//! `mirage-router`, `mirage-migration`) are pure logic by design -
//! they emit "actions" the runtime must execute. This crate is the
//! runtime: it provides async traits for the I/O each action
//! requires, and async drivers that loop the state machines.
//!
//! # What's in this crate (Phase 2A)
//!
//! - [`HopRuntime`] - async trait the [`build_circuit`] driver
//!   depends on. Implementations dial transport-layer connections,
//!   run per-hop Mirage handshakes, and send / receive cells.
//!   Phase 2A ships the trait + a [`MockHopRuntime`] for testing.
//!   Phase 2B will add a real implementation backed by
//!   `mirage-session::connect` + `mirage-transport::race`.
//! - [`build_circuit`] - async driver that consumes a
//!   `Vec<HopSpec>` and a `HopRuntime`, drives `CircuitBuilder`
//!   to `Ready`, and returns a [`mirage_circuit::Circuit`].
//!   Applies a global deadline + per-hop sub-deadlines, calls
//!   `abort` on the builder on any failure, and invokes
//!   [`HopRuntime::destroy_circuit`] for the partial circuit so
//!   no hops leak. Closes [RT-C2] at the runtime layer.
//!
//! # What's NOT in this crate yet
//!
//! - The Mutex / actor wrapping for `CircuitPool` ([RT-C1])
//!   - Phase 2B.
//! - The bridge-side circuit handler ([RT-C4]) - Phase 2C.
//! - Real I/O `HopRuntime` impl backed by transport + session -
//!   Phase 2B.
//!
//! # Property
//!
//! > **Builder leak invariant:** A `build_circuit` invocation
//! > that returns `Err` MUST have called
//! > [`HopRuntime::destroy_circuit`] before returning, with the
//! > correct hop count to tear down. Tests verify this with the
//! > [`MockHopRuntime`] that records destroy calls.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cell_io;
pub mod driver;
pub mod multi_entry;
pub mod pool;
pub mod transport_runtime;

pub use cell_io::{read_cell, write_cell, CellIoError};
pub use driver::{CircuitRegistry, DriverConfig, MemoryCircuitRegistry, PoolDriver};
pub use multi_entry::{MultiEntryConfig, MultiEntryError, MultiEntryPool};
pub use pool::SharedCircuitPool;
pub use transport_runtime::{
    build_extend_cell, build_extend_finish_cell, parse_extended_cell, OneShotTokens,
    SingleTransportHopRuntime, TokenSupplier, TransportConn,
};

use async_trait::async_trait;
use mirage_circuit::{BuildStep, BuilderError, Circuit, CircuitBuilder, HopKeys, HopSpec};
use std::time::Duration;
use thiserror::Error;
// tokio::time::Instant uses tokio's clock (which respects
// `tokio::time::pause` in tests). std::time::Instant doesn't,
// which would make `start_paused = true` tests unable to fire
// global-timeout assertions deterministically. Phase 2A uses
// tokio::time::Instant internally; the public API still exposes
// std::time::Duration which is clock-agnostic.
use tokio::time::Instant;

// RuntimeError

/// Errors returned by [`build_circuit`] and the [`HopRuntime`]
/// trait.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Underlying state-machine error from
    /// [`mirage_circuit::CircuitBuilder`].
    #[error("builder: {0}")]
    Builder(#[from] BuilderError),
    /// The transport-level dial of hop 0 failed (connect refused,
    /// TLS error, Reality probe rejected, etc.). Caller's
    /// `HopRuntime::dial_hop0` translated the runtime-specific
    /// error into this variant.
    #[error("transport dial failed at hop 0")]
    TransportDial,
    /// A per-hop session handshake failed (Noise rejection,
    /// ML-KEM decapsulation failure, capability-token refused).
    #[error("hop handshake failed at hop {hop_idx}")]
    HopHandshake {
        /// Hop where the handshake failed.
        hop_idx: usize,
    },
    /// EXTEND/EXTENDED cell exchange failed at the cell-protocol
    /// layer (truncated cell, bad command byte, wrong `circ_id`).
    #[error("extend cell exchange failed at hop {hop_idx}")]
    ExtendExchange {
        /// Hop being extended to when the failure occurred.
        hop_idx: usize,
    },
    /// Per-hop sub-deadline elapsed.
    #[error("per-hop deadline elapsed at hop {hop_idx}")]
    HopTimeout {
        /// Hop where the deadline was hit.
        hop_idx: usize,
    },
    /// Global build deadline elapsed.
    #[error("global build deadline elapsed after {hops_built} hops")]
    GlobalTimeout {
        /// How many hops were successfully built before the
        /// deadline expired.
        hops_built: usize,
    },
    /// Free-form runtime-specific error. Use sparingly - prefer a
    /// typed variant where possible.
    #[error("runtime: {0}")]
    Other(String),
}

// HopRuntime trait

/// Async trait the circuit builder driver depends on. Implementations
/// own the transport-layer connection to hop 0 and drive cell I/O
/// for EXTEND/EXTENDED.
///
/// # Lifecycle
///
/// 1. [`dial_hop0`](Self::dial_hop0) is called once per
///    `build_circuit` invocation. Returns the connection handle
///    + hop-0 keys.
/// 2. [`extend_hop`](Self::extend_hop) is called `N - 1` times
///    where `N` is the desired hop count. Each call sends an
///    EXTEND cell through the existing onion and reads back the
///    EXTENDED reply.
/// 3. [`destroy_circuit`](Self::destroy_circuit) is called
///    exactly once - either after `Ready` (cleanup on caller's
///    explicit close) or after a build failure. Best-effort:
///    failures during teardown are logged, not propagated.
#[async_trait]
pub trait HopRuntime: Send + Sync {
    /// Per-connection runtime state. Holds the underlying
    /// `mirage_session::SessionStream` for the link to hop 0,
    /// or whatever the runtime needs.
    ///
    /// `Send + 'static` only - not `Sync`. The conn is owned by
    /// a single in-flight `build_circuit` invocation; sharing
    /// across tasks is via `Arc<Mutex<...>>` in higher layers
    /// (`MemoryCircuitRegistry` wraps the whole `BuiltCircuit`
    /// in a `Mutex`). Forcing `Sync` would prevent `SessionStream`
    /// (whose inner `DuplexStream = Pin<Box<dyn AsyncReadWrite +
    /// Send>>` is `Send` but not `Sync`) from satisfying the
    /// bound.
    type ConnHandle: Send + 'static;

    /// Dial the first hop directly via the transport layer and
    /// run the per-hop Mirage handshake. Returns the connection
    /// handle (for subsequent EXTEND cells) and the hop's
    /// [`HopKeys`] for the circuit's onion layer.
    ///
    /// MUST honour `deadline` - the implementation wraps its
    /// internal I/O in `tokio::time::timeout(deadline, ...)`.
    async fn dial_hop0(
        &self,
        spec: &HopSpec,
        deadline: Duration,
    ) -> Result<(Self::ConnHandle, HopKeys), RuntimeError>;

    /// Extend the existing partial circuit by one hop. The
    /// implementation:
    ///
    /// 1. Constructs an `ExtendBody` (next_hop_pk = `spec.static_pk`,
    ///    endpoint = `spec.endpoint`, hs_msg1 = output of a fresh
    ///    `HandshakeInitiator` for the new hop).
    /// 2. Wraps the EXTEND cell in `circuit_so_far` (onion-seal).
    /// 3. Writes it through `conn`, reads the EXTENDED reply,
    ///    onion-peels via `circuit_so_far.relay_open`.
    /// 4. Finishes the per-hop handshake.
    /// 5. Returns the new hop's `HopKeys`.
    ///
    /// MUST honour `deadline`.
    async fn extend_hop(
        &self,
        conn: &Self::ConnHandle,
        circuit_so_far: &Circuit,
        new_hop_spec: &HopSpec,
        deadline: Duration,
    ) -> Result<HopKeys, RuntimeError>;

    /// Tear down the partial or complete circuit. The runtime
    /// sends `CMD_DESTROY` cells for `hops_built` hops (best
    /// effort - destroy is fire-and-forget) and closes the
    /// underlying connection.
    ///
    /// Called by [`build_circuit`] on every error path so no
    /// hops leak. Idempotent - implementations MUST tolerate
    /// being called multiple times (though the driver only calls
    /// it once).
    async fn destroy_circuit(&self, conn: Self::ConnHandle, hops_built: usize);
}

// BuiltCircuit

/// A successfully-built circuit + the connection handle it rides
/// on. The caller MUST keep `conn` alive for as long as the
/// circuit is in use; dropping `conn` closes the underlying
/// transport, breaking the circuit.
///
/// Pre-fix [`build_circuit`] returned just `Circuit` and let
/// `conn` drop on success - silently breaking the circuit. The
/// runtime caller now owns both halves explicitly.
pub struct BuiltCircuit<H> {
    /// Onion key material + state machine.
    pub circuit: Circuit,
    /// Per-circuit connection handle to hop 0. Must be passed to
    /// [`HopRuntime::destroy_circuit`] when the caller is done.
    pub conn: H,
}

impl<H> std::fmt::Debug for BuiltCircuit<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltCircuit")
            .field("hop_count", &self.circuit.hop_count())
            .field("conn", &"<runtime handle>")
            .finish()
    }
}

// build_circuit driver

/// Async driver that consumes a `Vec<HopSpec>` and a `HopRuntime`,
/// builds the circuit hop-by-hop, and returns the completed
/// `Circuit`.
///
/// Applies:
///
/// - `total_deadline` - global cap. Build aborts with
///   `GlobalTimeout` if the loop exceeds it.
/// - `total_deadline / N` - per-hop sub-deadline. Each `dial_hop0`
///   / `extend_hop` call wraps in this budget; one slow hop
///   doesn't consume the global budget. Closes [RT-H7].
///
/// On any failure (state-machine, transport, handshake, timeout),
/// the driver:
///
/// 1. Calls `builder.abort` so the builder's tear-down list is
///    correctly populated.
/// 2. Calls `runtime.destroy_circuit` with the count of
///    successfully-built hops. This emits `CMD_DESTROY` for each
///    and closes the underlying connection.
/// 3. Returns the typed error.
///
/// Closes [RT-C2] at the driver layer: the only way to leak hops
/// is for the implementation of `destroy_circuit` to itself fail
/// silently, which is the runtime's responsibility to log.
pub async fn build_circuit<R: HopRuntime>(
    runtime: &R,
    hops: Vec<HopSpec>,
    total_deadline: Duration,
) -> Result<BuiltCircuit<R::ConnHandle>, RuntimeError> {
    let mut builder = CircuitBuilder::new(hops)?;
    let n = builder.target_hop_count();
    // Per-hop sub-deadline. If `total_deadline` doesn't divide
    // evenly we accept the rounded-down quotient; the global
    // deadline check below catches the remainder.
    //
    // `n` is bounded by `MAX_CIRCUIT_HOPS` (= 6) at construction,
    // so the cast to u32 is exact in practice. Use try_into for
    // explicit-conversion clarity (closes [RT-N3]) - the cast
    // never lossy under normal use.
    let n_u32: u32 = u32::try_from(n.max(1)).unwrap_or(u32::MAX);
    let per_hop_deadline = total_deadline / n_u32;
    let start = Instant::now();
    let mut conn: Option<R::ConnHandle> = None;

    // Track hops_built outside the builder so we can read it after
    // `into_circuit` consumes the builder on success. Every break
    // path writes this before exiting the loop; the `0` placeholder
    // is unreachable in practice.
    #[allow(unused_assignments)]
    let mut hops_built_at_exit: usize = 0;
    let outcome: Result<Circuit, RuntimeError> = loop {
        // Global deadline check before each step.
        let elapsed = start.elapsed();
        if elapsed >= total_deadline {
            hops_built_at_exit = builder.hop_count();
            let _ = builder.abort(BuilderError::Timeout);
            break Err(RuntimeError::GlobalTimeout {
                hops_built: hops_built_at_exit,
            });
        }
        // Per-hop budget = min(per_hop_slice, remaining_global).
        let remaining_global = total_deadline.saturating_sub(elapsed);
        let step_dl = per_hop_deadline.min(remaining_global);

        match builder.next_step() {
            BuildStep::Ready => {
                hops_built_at_exit = builder.hop_count();
                break builder.into_circuit().map_err(RuntimeError::Builder);
            }
            BuildStep::Failed { error, .. } => {
                hops_built_at_exit = builder.hop_count();
                break Err(RuntimeError::Builder(error));
            }
            BuildStep::DialHop0 { spec } => match runtime.dial_hop0(&spec, step_dl).await {
                Ok((c, keys)) => {
                    conn = Some(c);
                    if let Err(e) = builder.record_hop_built(0, keys) {
                        hops_built_at_exit = builder.hop_count();
                        break Err(RuntimeError::Builder(e));
                    }
                }
                Err(e) => {
                    hops_built_at_exit = builder.hop_count();
                    let _ = builder.record_hop_failure(0, BuilderError::TransportDialFailed);
                    break Err(e);
                }
            },
            BuildStep::Extend { hop_idx, spec, .. } => {
                let conn_ref = conn.as_ref().ok_or_else(|| {
                    RuntimeError::Other(
                        "extend without hop-0 connection - invariant violated".into(),
                    )
                })?;
                let circuit_view = builder.circuit().clone();
                match runtime
                    .extend_hop(conn_ref, &circuit_view, &spec, step_dl)
                    .await
                {
                    Ok(keys) => {
                        if let Err(e) = builder.record_hop_built(hop_idx, keys) {
                            hops_built_at_exit = builder.hop_count();
                            break Err(RuntimeError::Builder(e));
                        }
                    }
                    Err(e) => {
                        hops_built_at_exit = builder.hop_count();
                        let _ =
                            builder.record_hop_failure(hop_idx, BuilderError::HopHandshakeFailed);
                        break Err(e);
                    }
                }
            }
        }
    };

    // Cleanup on error: tear down whatever was built so no hops
    // leak. On success the conn handle is returned to the caller
    // packaged inside `BuiltCircuit` - the caller is now
    // responsible for tear-down via [`HopRuntime::destroy_circuit`].
    match outcome {
        Ok(circuit) => {
            let conn = conn.expect("Ready outcome implies hop 0 dial succeeded");
            Ok(BuiltCircuit { circuit, conn })
        }
        Err(e) => {
            if let Some(c) = conn {
                runtime.destroy_circuit(c, hops_built_at_exit).await;
            }
            Err(e)
        }
    }
}

// MockHopRuntime - for tests + the eventual integration test layer

/// Mock [`HopRuntime`] implementation for tests. Records every
/// call; lets tests inject success / failure outcomes per hop.
///
/// The mock does NO real I/O - it deterministically returns
/// `HopKeys` derived from `spec.static_pk` (matching the synthetic
/// keys used in `mirage-router`'s integration test) and tracks
/// what the driver did.
pub mod mock {
    use super::{async_trait, Circuit, Duration, HopKeys, HopRuntime, HopSpec, RuntimeError};
    use mirage_circuit::derive_hop_keys;
    use std::sync::Mutex;

    /// Outcome to return for a specific hop in the mock.
    ///
    /// `Fail` carries a static-tag error rather than a full
    /// `RuntimeError` so the enum can be cheaply re-emitted
    /// across the mock's borrow boundary.
    #[derive(Debug, Clone, Copy)]
    pub enum HopOutcome {
        /// Succeed and produce keys.
        Ok,
        /// Fail with [`RuntimeError::TransportDial`].
        FailTransport,
        /// Fail with [`RuntimeError::HopHandshake`].
        FailHandshake,
        /// Fail with [`RuntimeError::ExtendExchange`].
        FailExtend,
        /// Sleep for `Duration` then succeed. Tests use this with
        /// `tokio::time::pause` to exercise per-hop timeouts.
        SleepThenOk(Duration),
    }

    /// Records the driver's calls.
    #[derive(Debug, Default)]
    pub struct MockCalls {
        /// `hop_idx`, deadline pairs in call order (hop 0 first,
        /// then hop 1, etc.).
        pub dial_or_extend: Vec<(usize, Duration)>,
        /// `Hops_built` when `destroy_circuit` was called. `None` if
        /// destroy was not called.
        pub destroy: Option<usize>,
    }

    /// Mock connection handle - opaque marker.
    #[derive(Debug)]
    pub struct MockConn {
        // Some unique id so destroy can recognize it.
        _id: u64,
    }

    /// Mock runtime. Construct with [`MockHopRuntime::new`] passing
    /// per-hop outcomes; the driver's behaviour is then deterministic.
    pub struct MockHopRuntime {
        outcomes: Vec<HopOutcome>,
        pub(crate) calls: Mutex<MockCalls>,
    }

    impl MockHopRuntime {
        /// Construct with per-hop outcomes (index 0 = hop 0, etc.).
        pub fn new(outcomes: Vec<HopOutcome>) -> Self {
            Self {
                outcomes,
                calls: Mutex::new(MockCalls::default()),
            }
        }

        /// Snapshot the calls log for assertions.
        pub fn calls(&self) -> MockCalls {
            let g = self.calls.lock().expect("mock mutex");
            MockCalls {
                dial_or_extend: g.dial_or_extend.clone(),
                destroy: g.destroy,
            }
        }
    }

    fn synth_keys(spec: &HopSpec, hop_idx: usize) -> HopKeys {
        let mut i2r = [0u8; 32];
        i2r.copy_from_slice(&spec.static_pk);
        i2r[0] ^= hop_idx as u8;
        let mut r2i = i2r;
        r2i[31] ^= 0xAA;
        derive_hop_keys(&i2r, &r2i)
    }

    fn record_call(rt: &MockHopRuntime, hop_idx: usize, deadline: Duration) {
        rt.calls
            .lock()
            .expect("mock mutex")
            .dial_or_extend
            .push((hop_idx, deadline));
    }

    async fn outcome_to_result(
        outcome: HopOutcome,
        spec: &HopSpec,
        hop_idx: usize,
    ) -> Result<HopKeys, RuntimeError> {
        match outcome {
            HopOutcome::Ok => Ok(synth_keys(spec, hop_idx)),
            HopOutcome::FailTransport => Err(RuntimeError::TransportDial),
            HopOutcome::FailHandshake => Err(RuntimeError::HopHandshake { hop_idx }),
            HopOutcome::FailExtend => Err(RuntimeError::ExtendExchange { hop_idx }),
            HopOutcome::SleepThenOk(d) => {
                tokio::time::sleep(d).await;
                Ok(synth_keys(spec, hop_idx))
            }
        }
    }

    #[async_trait]
    impl HopRuntime for MockHopRuntime {
        type ConnHandle = MockConn;

        async fn dial_hop0(
            &self,
            spec: &HopSpec,
            deadline: Duration,
        ) -> Result<(Self::ConnHandle, HopKeys), RuntimeError> {
            record_call(self, 0, deadline);
            let outcome = self
                .outcomes
                .first()
                .copied()
                .ok_or_else(|| RuntimeError::Other("mock: no outcome for hop 0".into()))?;
            let keys = outcome_to_result(outcome, spec, 0).await?;
            Ok((MockConn { _id: 0 }, keys))
        }

        async fn extend_hop(
            &self,
            _conn: &Self::ConnHandle,
            _circuit_so_far: &Circuit,
            new_hop_spec: &HopSpec,
            deadline: Duration,
        ) -> Result<HopKeys, RuntimeError> {
            let hop_idx = self.calls.lock().expect("mock mutex").dial_or_extend.len();
            record_call(self, hop_idx, deadline);
            let outcome = self
                .outcomes
                .get(hop_idx)
                .copied()
                .ok_or_else(|| RuntimeError::Other("mock: no outcome for hop".into()))?;
            outcome_to_result(outcome, new_hop_spec, hop_idx).await
        }

        async fn destroy_circuit(&self, _conn: Self::ConnHandle, hops_built: usize) {
            self.calls.lock().expect("mock mutex").destroy = Some(hops_built);
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::mock::*;
    use super::*;
    use mirage_circuit::HopEndpoint;

    fn ipv4_spec(tag: u8) -> HopSpec {
        HopSpec {
            static_pk: [tag; 32],
            endpoint: HopEndpoint::Ipv4 {
                addr: [10, 0, 0, tag],
                port: 4433,
            },
        }
    }

    #[tokio::test]
    async fn happy_path_three_hops() {
        let rt = MockHopRuntime::new(vec![HopOutcome::Ok, HopOutcome::Ok, HopOutcome::Ok]);
        let built = build_circuit(
            &rt,
            vec![ipv4_spec(1), ipv4_spec(2), ipv4_spec(3)],
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        assert_eq!(built.circuit.hop_count(), 3);
        let calls = rt.calls();
        assert_eq!(calls.dial_or_extend.len(), 3);
        // Per-hop deadline = 30s / 3 = 10s.
        for (_, dl) in &calls.dial_or_extend {
            assert_eq!(*dl, Duration::from_secs(10));
        }
        // No destroy on success.
        assert_eq!(calls.destroy, None);
    }

    #[tokio::test]
    async fn dial_hop0_failure_no_hops_built() {
        let rt = MockHopRuntime::new(vec![HopOutcome::FailTransport, HopOutcome::Ok]);
        let err = build_circuit(
            &rt,
            vec![ipv4_spec(1), ipv4_spec(2)],
            Duration::from_secs(30),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RuntimeError::TransportDial));
        // Driver did NOT proceed to hop 1.
        let calls = rt.calls();
        assert_eq!(calls.dial_or_extend.len(), 1);
        // No destroy because no conn was acquired.
        assert_eq!(calls.destroy, None);
    }

    #[tokio::test]
    async fn extend_failure_destroys_partial_circuit() {
        // Hop 0 dial OK; hop 1 extend FAILS. Driver MUST call
        // destroy_circuit with hops_built = 1.
        let rt = MockHopRuntime::new(vec![
            HopOutcome::Ok,
            HopOutcome::FailHandshake,
            HopOutcome::Ok,
        ]);
        let err = build_circuit(
            &rt,
            vec![ipv4_spec(1), ipv4_spec(2), ipv4_spec(3)],
            Duration::from_secs(30),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RuntimeError::HopHandshake { hop_idx: 1 }));
        let calls = rt.calls();
        // Two attempts: hop 0 (dial) + hop 1 (extend).
        assert_eq!(calls.dial_or_extend.len(), 2);
        // Destroy called with 1 hop built (hop 0 succeeded, hop 1 didn't).
        assert_eq!(
            calls.destroy,
            Some(1),
            "RT-C2: failed extend MUST tear down partial circuit"
        );
    }

    #[tokio::test]
    async fn extend_failure_at_last_hop_destroys_n_minus_1() {
        // 3-hop build; last hop fails. Driver tears down the 2
        // built hops.
        let rt = MockHopRuntime::new(vec![HopOutcome::Ok, HopOutcome::Ok, HopOutcome::FailExtend]);
        let err = build_circuit(
            &rt,
            vec![ipv4_spec(1), ipv4_spec(2), ipv4_spec(3)],
            Duration::from_secs(30),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RuntimeError::ExtendExchange { hop_idx: 2 }));
        assert_eq!(rt.calls().destroy, Some(2));
    }

    #[tokio::test(start_paused = true)]
    async fn per_hop_deadline_applied() {
        // Total 30s -> per-hop 10s. The mock records the deadline
        // each call receives.
        let rt = MockHopRuntime::new(vec![HopOutcome::Ok; 3]);
        build_circuit(
            &rt,
            vec![ipv4_spec(1), ipv4_spec(2), ipv4_spec(3)],
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        let calls = rt.calls();
        for (_, dl) in &calls.dial_or_extend {
            // Deadline must be at most 10s (30 / 3) and decreasing
            // as elapsed time grows. With paused time and instant
            // mock returns, all see 10s.
            assert!(*dl <= Duration::from_secs(10));
            assert!(*dl >= Duration::from_secs(9));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn global_timeout_aborts_build_and_destroys() {
        // Each hop sleeps 5 seconds; total budget 12 seconds.
        // Hop 0 finishes at t=5; hop 1 starts but its own sub-
        // deadline (12/3 = 4s, but capped at remaining 7s) fits.
        // hop 1 finishes at t=10. Hop 2 starts; remaining 2s
        // shorter than its per-hop budget. The mock is happy to
        // sleep 5s; tokio::time::timeout fires inside the mock's
        // sleep at the per-hop deadline. We should see a Timeout-
        // like error - but the mock doesn't check deadlines
        // internally, so the SleepThenOk completes. We use a
        // shorter mock and verify the GLOBAL timeout fires.
        //
        // Configure: per-hop sleep 1s; global budget 1.5s; 3 hops.
        // Hop 0 completes at t=1. Hop 1 starts; would complete at
        // t=2 but global budget is exceeded at t=1.5 -> on the
        // next loop iteration (after hop 1 completes at t=2), the
        // builder's elapsed >= total_deadline check fires.
        let rt = MockHopRuntime::new(vec![
            HopOutcome::SleepThenOk(Duration::from_secs(1)),
            HopOutcome::SleepThenOk(Duration::from_secs(1)),
            HopOutcome::SleepThenOk(Duration::from_secs(1)),
        ]);
        let err = build_circuit(
            &rt,
            vec![ipv4_spec(1), ipv4_spec(2), ipv4_spec(3)],
            Duration::from_millis(1500),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, RuntimeError::GlobalTimeout { .. }));
        // Destroy was called for whatever was built before the
        // timeout (>= 1 hop).
        let destroy = rt.calls().destroy;
        assert!(destroy.is_some());
        assert!(destroy.unwrap() >= 1);
    }

    #[tokio::test]
    async fn empty_hops_returns_builder_error() {
        let rt = MockHopRuntime::new(vec![]);
        let err = build_circuit(&rt, vec![], Duration::from_secs(30))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            RuntimeError::Builder(BuilderError::EmptyHops)
        ));
        // No I/O attempted.
        assert!(rt.calls().dial_or_extend.is_empty());
        assert!(rt.calls().destroy.is_none());
    }

    #[tokio::test]
    async fn one_hop_circuit_works() {
        let rt = MockHopRuntime::new(vec![HopOutcome::Ok]);
        let built = build_circuit(&rt, vec![ipv4_spec(1)], Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(built.circuit.hop_count(), 1);
        // Only dial_hop0 - no extends.
        assert_eq!(rt.calls().dial_or_extend.len(), 1);
    }

    #[tokio::test]
    async fn three_hop_max_circuit_works() {
        // Mirage caps circuits at 3 hops. Anonymity beyond this
        // comes from concurrent entries (multi-entry cohort),
        // not deeper chains.
        let rt = MockHopRuntime::new(vec![HopOutcome::Ok; 3]);
        let built = build_circuit(
            &rt,
            (1..=3u8).map(ipv4_spec).collect(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        assert_eq!(built.circuit.hop_count(), 3);
        // Per-hop = 60 / 3 = 20s.
        for (_, dl) in &rt.calls().dial_or_extend {
            assert_eq!(*dl, Duration::from_secs(20));
        }
    }

    #[tokio::test]
    async fn ready_circuit_can_seal_relay_traffic() {
        let rt = MockHopRuntime::new(vec![HopOutcome::Ok; 3]);
        let mut built = build_circuit(
            &rt,
            vec![ipv4_spec(1), ipv4_spec(2), ipv4_spec(3)],
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        let pt = b"Phase 2A async wrapper produced a real Circuit";
        let ct = built.circuit.relay_seal(pt).unwrap();
        assert!(!ct.is_empty());
        assert_ne!(ct, pt);
    }

    #[tokio::test]
    async fn happy_path_returns_conn_handle() {
        // Bug-fix verification: pre-fix the conn handle dropped
        // silently at the end of build_circuit, breaking the
        // circuit. Post-fix the caller receives BuiltCircuit
        // with both pieces.
        let rt = MockHopRuntime::new(vec![HopOutcome::Ok; 3]);
        let built = build_circuit(
            &rt,
            vec![ipv4_spec(1), ipv4_spec(2), ipv4_spec(3)],
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        // The conn is something the caller now owns + can pass to
        // destroy_circuit later. Mock conn is just a marker.
        let _conn: MockConn = built.conn;
        // No destroy call yet on success - that's the caller's
        // responsibility now.
        assert_eq!(rt.calls().destroy, None);
    }
}
