//! Client-side circuit-construction orchestrator.
//!
//! Turns a list of `HopSpec` entries into a sequence of concrete
//! protocol actions the runtime executes (dial hop 0, send EXTEND
//! to hop 1, etc.). The state machine itself is **I/O-free** -
//! same discipline as `mirage-mux::state`,
//! `mirage-migration::state`, `mirage-circuit::split_exit`, and
//! `mirage-router::pool`.
//!
//! Strict per-hop progression: at any moment the builder has at
//! most one outstanding action; the runtime MUST complete (or
//! fail) hop K before the builder will emit the action for hop K+1.
//!
//! # Flow
//!
//! ```text
//!   Caller                                    CircuitBuilder
//!   ------                                    --------------
//!   new(hops=[H0, H1, H2])                  -> Idle (count=0)
//!   next_step()                             <- DialHop0 { spec: H0 }
//!   // dial endpoint, run Mirage handshake
//!   record_hop_built(0, keys_h0)            -> hop_count=1
//!   next_step()                             <- Extend { hop_idx: 1, spec: H1 }
//!   // build EXTEND body, send through, peel EXTENDED, finish handshake
//!   record_hop_built(1, keys_h1)            -> hop_count=2
//!   next_step()                             <- Extend { hop_idx: 2, spec: H2 }
//!   record_hop_built(2, keys_h2)            -> hop_count=3
//!   next_step()                             <- Ready
//!   into_circuit()                          -> Circuit
//! ```
//!
//! # Failure
//!
//! Any `record_hop_failure` transitions to `Failed{hop_idx}`.
//! `next_step()` returns `BuildStep::Failed{...}` thereafter, and
//! all subsequent `record_*` calls return `Err(AlreadyFailed)`. The
//! caller MUST tear down hops `[0..hop_idx)` (which were built
//! successfully) by sending `CMD_DESTROY` cells.

use crate::circuit::{Circuit, MAX_CIRCUIT_HOPS, MIN_CIRCUIT_HOPS};
use crate::extend::HopEndpoint;
use crate::keys::HopKeys;
use std::borrow::Cow;
use thiserror::Error;

// HopSpec

/// One hop's specification in a circuit build request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopSpec {
    /// Static x25519 public key of this hop. The runtime's
    /// per-hop Mirage handshake authenticates against this key.
    pub static_pk: [u8; 32],
    /// Network endpoint where the hop is reachable.
    ///
    /// - For `H0` (the first hop): the runtime dials this directly
    ///   via the transport layer.
    /// - For `H_{K>0}`: this is what the runtime puts in the
    ///   `endpoint` field of the [`crate::extend::ExtendBody`] so
    ///   the previous hop knows where to dial.
    pub endpoint: HopEndpoint,
}

impl HopSpec {
    /// Construct a new hop specification.
    pub fn new(static_pk: [u8; 32], endpoint: HopEndpoint) -> Self {
        Self {
            static_pk,
            endpoint,
        }
    }
}

// Errors

/// Errors produced by [`CircuitBuilder`] operations.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BuilderError {
    /// Builder constructed with zero hops.
    #[error("hop list is empty")]
    EmptyHops,
    /// Builder constructed with more than [`MAX_CIRCUIT_HOPS`].
    #[error("too many hops: {0} > {MAX_CIRCUIT_HOPS}")]
    TooManyHops(usize),
    /// `record_*` was called for the wrong hop index. The builder
    /// enforces strict per-hop progression - caller must complete
    /// hop K before reporting hop K+1.
    #[error("out-of-order record: expected hop {expected}, got {got}")]
    OutOfOrderRecord {
        /// Hop the builder was waiting for.
        expected: usize,
        /// Hop the caller reported.
        got: usize,
    },
    /// `record_*` was called after the builder already transitioned
    /// to `Failed`. Caller MUST tear down the partially-built
    /// circuit and start over.
    #[error("builder already failed; tear down and restart")]
    AlreadyFailed,
    /// `record_*` was called after the builder reached `Ready`.
    /// Caller should call [`CircuitBuilder::into_circuit`] instead.
    #[error("builder already complete; extract via into_circuit()")]
    AlreadyComplete,
    /// Runtime reported the per-hop session handshake refused or
    /// timed out.
    #[error("hop handshake failed")]
    HopHandshakeFailed,
    /// Runtime reported the transport-level dial / TLS / Reality
    /// step failed.
    #[error("transport dial failed")]
    TransportDialFailed,
    /// Upper-layer deadline elapsed during the build.
    #[error("circuit build timed out")]
    Timeout,
    /// Free-form runtime-specific cause. `Cow` so callers can pass
    /// either a `&'static str` literal (zero-allocation, cheap to
    /// clone) or an owned `String` with runtime-specific context.
    /// Closes [RT-L3]: the previous `&'static str`-only form lost
    /// runtime context like the underlying error message.
    #[error("builder: {0}")]
    Other(Cow<'static, str>),
}

// BuildStep

/// One step the runtime executes. Returned from
/// [`CircuitBuilder::next_step`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildStep {
    /// Establish a transport-level connection to the hop-0
    /// endpoint and run the per-hop Mirage handshake. On success
    /// derive [`HopKeys`] via [`crate::derive_hop_keys`] and call
    /// [`CircuitBuilder::record_hop_built`] with `hop_idx = 0`.
    DialHop0 {
        /// Hop-0 specification.
        spec: HopSpec,
    },
    /// Construct an [`crate::extend::ExtendBody`] for `hop_idx`,
    /// onion-seal it through the circuit so far, send it to hop 0,
    /// and wait for the EXTENDED response. Finish the per-hop
    /// handshake and call [`CircuitBuilder::record_hop_built`].
    Extend {
        /// Index of the hop being extended to.
        hop_idx: usize,
        /// Specification of the hop being extended to.
        spec: HopSpec,
        /// How many hops are currently established. Equal to
        /// `hop_idx` under strict progression - included so the
        /// runtime doesn't track it independently.
        prev_hop_count: usize,
    },
    /// All hops built; circuit is ready. Call
    /// [`CircuitBuilder::into_circuit`].
    Ready,
    /// Build failed at `hop_idx`. The caller MUST tear down hops
    /// `[0..hop_idx)` by sending `CMD_DESTROY` cells, then discard
    /// the builder.
    Failed {
        /// Hop where the failure was reported.
        hop_idx: usize,
        /// Failure reason.
        error: BuilderError,
    },
}

// Internal state

#[derive(Debug, Clone, PartialEq, Eq)]
enum BuilderState {
    /// `hop_count` hops built (0..=N); waiting for the caller to
    /// invoke `next_step` for the next one.
    Pending,
    /// All N hops built.
    Ready,
    /// Failed at `hop_idx`; the circuit holds hops `[0..hop_idx)`.
    Failed { hop_idx: usize, error: BuilderError },
}

// CircuitBuilder

/// I/O-free orchestrator for client-side circuit construction.
#[derive(Debug)]
pub struct CircuitBuilder {
    hops: Vec<HopSpec>,
    circuit: Circuit,
    state: BuilderState,
}

impl CircuitBuilder {
    /// Construct a builder with the given hop specifications.
    /// `hops.len()` MUST be in `[MIN_CIRCUIT_HOPS, MAX_CIRCUIT_HOPS]`.
    pub fn new(hops: Vec<HopSpec>) -> Result<Self, BuilderError> {
        if hops.is_empty() || hops.len() < MIN_CIRCUIT_HOPS {
            return Err(BuilderError::EmptyHops);
        }
        if hops.len() > MAX_CIRCUIT_HOPS {
            return Err(BuilderError::TooManyHops(hops.len()));
        }
        Ok(Self {
            hops,
            circuit: Circuit::new(),
            state: BuilderState::Pending,
        })
    }

    /// Number of hops built so far.
    pub fn hop_count(&self) -> usize {
        self.circuit.hop_count()
    }

    /// Total number of hops requested.
    pub fn target_hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Hop specifications. Useful for tear-down enumeration after a
    /// failure (caller maps `[0..failed_at)` to the hops that need
    /// `CMD_DESTROY`).
    pub fn hops(&self) -> &[HopSpec] {
        &self.hops
    }

    /// Borrow the partial (or complete) circuit.
    pub fn circuit(&self) -> &Circuit {
        &self.circuit
    }

    /// Builder is complete - all hops built, `Ready` returned by
    /// `next_step`. Caller can [`Self::into_circuit`].
    pub fn is_ready(&self) -> bool {
        matches!(self.state, BuilderState::Ready)
    }

    /// Builder transitioned to `Failed`. Caller MUST tear down
    /// any successfully-built hops and discard.
    pub fn is_failed(&self) -> bool {
        matches!(self.state, BuilderState::Failed { .. })
    }

    /// Inspect the next protocol action. Idempotent - callers MAY
    /// invoke this multiple times; the same step is returned until
    /// the matching `record_*` call updates state.
    pub fn next_step(&self) -> BuildStep {
        match &self.state {
            BuilderState::Failed { hop_idx, error } => BuildStep::Failed {
                hop_idx: *hop_idx,
                error: error.clone(),
            },
            BuilderState::Ready => BuildStep::Ready,
            BuilderState::Pending => {
                let next = self.circuit.hop_count();
                debug_assert!(
                    next < self.hops.len(),
                    "Pending with all hops built: should be Ready"
                );
                let spec = self.hops[next].clone();
                if next == 0 {
                    BuildStep::DialHop0 { spec }
                } else {
                    BuildStep::Extend {
                        hop_idx: next,
                        spec,
                        prev_hop_count: next,
                    }
                }
            }
        }
    }

    /// Runtime reports successful completion of hop `hop_idx`.
    /// `keys` is the [`HopKeys`] derived from that hop's per-hop
    /// session handshake (see [`crate::derive_hop_keys`]).
    pub fn record_hop_built(&mut self, hop_idx: usize, keys: HopKeys) -> Result<(), BuilderError> {
        match &self.state {
            BuilderState::Failed { .. } => return Err(BuilderError::AlreadyFailed),
            BuilderState::Ready => return Err(BuilderError::AlreadyComplete),
            BuilderState::Pending => {}
        }
        let expected = self.circuit.hop_count();
        if hop_idx != expected {
            return Err(BuilderError::OutOfOrderRecord {
                expected,
                got: hop_idx,
            });
        }
        // Extend the underlying circuit. extend() rejects past
        // MAX_CIRCUIT_HOPS, but we already enforced the cap at
        // construction so this should not fire under normal use.
        self.circuit
            .extend(keys)
            .map_err(|_| BuilderError::Other(Cow::Borrowed("circuit extend rejected")))?;
        if self.circuit.hop_count() == self.hops.len() {
            self.state = BuilderState::Ready;
        }
        Ok(())
    }

    /// Runtime reports failure of hop `hop_idx`. State machine
    /// transitions to `Failed`.
    pub fn record_hop_failure(
        &mut self,
        hop_idx: usize,
        error: BuilderError,
    ) -> Result<(), BuilderError> {
        match &self.state {
            BuilderState::Failed { .. } => return Err(BuilderError::AlreadyFailed),
            BuilderState::Ready => return Err(BuilderError::AlreadyComplete),
            BuilderState::Pending => {}
        }
        let expected = self.circuit.hop_count();
        if hop_idx != expected {
            return Err(BuilderError::OutOfOrderRecord {
                expected,
                got: hop_idx,
            });
        }
        self.state = BuilderState::Failed { hop_idx, error };
        Ok(())
    }

    /// Consume the builder and return the completed [`Circuit`].
    /// Returns an error if the builder is not yet `Ready` or has
    /// already `Failed`.
    ///
    /// Implementation note: takes `mut self` and uses `mem::take`
    /// rather than direct move because `CircuitBuilder` implements
    /// `Drop` (for the [RT-C2] leak-warning hook), which prevents
    /// partial-move out of fields. The leftover empty `Circuit` in
    /// `self.circuit` after take is dropped silently by Drop's
    /// `hop_count == 0` check.
    pub fn into_circuit(mut self) -> Result<Circuit, BuilderError> {
        match &self.state {
            BuilderState::Ready => Ok(std::mem::take(&mut self.circuit)),
            BuilderState::Failed { error, .. } => Err(error.clone()),
            BuilderState::Pending => {
                Err(BuilderError::Other(Cow::Borrowed("builder still pending")))
            }
        }
    }

    /// Hops that were successfully built and need teardown after a
    /// failure. Returns `&[]` unless the builder is `Failed`. The
    /// returned slice's indexes are the indexes the runtime should
    /// send `CMD_DESTROY` for.
    pub fn hops_to_tear_down(&self) -> &[HopSpec] {
        match &self.state {
            BuilderState::Failed { hop_idx, .. } => &self.hops[..*hop_idx],
            _ => &[],
        }
    }

    /// Explicitly abort an in-progress build. Transitions a
    /// `Pending` builder to `Failed` so the tear-down list is
    /// correctly populated for the runtime to act on. Calling
    /// `abort` on an already-`Failed` or `Ready` builder is a
    /// no-op (returns Ok) - abort is idempotent.
    ///
    /// The runtime SHOULD call `abort` before dropping a builder
    /// that hasn't reached `Ready`. Phase 2 wrapping code wraps
    /// builders in a struct whose `Drop` impl calls `abort` +
    /// schedules tear-down work.
    pub fn abort(&mut self, reason: BuilderError) -> Result<(), BuilderError> {
        let hop_idx = self.circuit.hop_count();
        match &self.state {
            BuilderState::Failed { .. } | BuilderState::Ready => Ok(()),
            BuilderState::Pending => {
                self.state = BuilderState::Failed {
                    hop_idx,
                    error: reason,
                };
                Ok(())
            }
        }
    }
}

/// On drop, log a warning if the builder is being torn down with
/// hops still built and the caller forgot to call [`abort`] or
/// observe `Ready`. This does NOT emit `CMD_DESTROY` cells -
/// emission requires async I/O which Drop can't perform - but it
/// surfaces a developer error loudly enough that the integration
/// layer's leak gets caught in CI / staging.
///
/// (The full close of [RT-C2] requires the Phase 2 async wrapper
/// to hold both the runtime handle and the builder, with a Drop
/// that spawns the tear-down task. This Drop is the builder-level
/// half of that work.)
impl Drop for CircuitBuilder {
    fn drop(&mut self) {
        let hops_built = self.circuit.hop_count();
        let in_clean_terminal = matches!(
            self.state,
            BuilderState::Ready | BuilderState::Failed { .. }
        );
        if !in_clean_terminal && hops_built > 0 {
            tracing::warn!(
                hops_leaked = hops_built,
                target_hops = self.hops.len(),
                "CircuitBuilder dropped while Pending with hops built; \
                 call abort() before drop so the runtime can emit CMD_DESTROY. \
                 This is a developer bug - hops will leak until idle timeout."
            );
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::derive_hop_keys;

    fn ipv4_spec(tag: u8) -> HopSpec {
        HopSpec {
            static_pk: [tag; 32],
            endpoint: HopEndpoint::Ipv4 {
                addr: [10, 0, 0, tag],
                port: 4433,
            },
        }
    }

    fn fake_keys(tag: u8) -> HopKeys {
        let i2r = [tag; 32];
        let r2i = [tag.wrapping_add(0x10); 32];
        derive_hop_keys(&i2r, &r2i)
    }

    // --- Construction ---

    #[test]
    fn empty_hops_rejected() {
        let err = CircuitBuilder::new(Vec::new()).unwrap_err();
        assert_eq!(err, BuilderError::EmptyHops);
    }

    #[test]
    fn over_max_hops_rejected() {
        let hops: Vec<HopSpec> = (1..=(MAX_CIRCUIT_HOPS as u8 + 1)).map(ipv4_spec).collect();
        let err = CircuitBuilder::new(hops).unwrap_err();
        assert!(matches!(err, BuilderError::TooManyHops(_)));
    }

    #[test]
    fn one_hop_ok() {
        let b = CircuitBuilder::new(vec![ipv4_spec(1)]).unwrap();
        assert_eq!(b.target_hop_count(), 1);
        assert_eq!(b.hop_count(), 0);
        assert!(!b.is_ready());
        assert!(!b.is_failed());
    }

    // --- Linear progression (1..=6 hops) ---

    fn drive_to_ready(n: usize) -> CircuitBuilder {
        let hops: Vec<HopSpec> = (1..=n as u8).map(ipv4_spec).collect();
        let mut b = CircuitBuilder::new(hops).unwrap();
        for k in 0..n {
            // Advance by inspecting next_step then recording.
            let step = b.next_step();
            if k == 0 {
                assert!(matches!(step, BuildStep::DialHop0 { .. }));
            } else {
                match step {
                    BuildStep::Extend {
                        hop_idx,
                        prev_hop_count,
                        ..
                    } => {
                        assert_eq!(hop_idx, k);
                        assert_eq!(prev_hop_count, k);
                    }
                    _ => panic!("expected Extend at hop {k}, got {step:?}"),
                }
            }
            b.record_hop_built(k, fake_keys(k as u8 + 1)).unwrap();
            assert_eq!(b.hop_count(), k + 1);
        }
        assert!(matches!(b.next_step(), BuildStep::Ready));
        assert!(b.is_ready());
        b
    }

    #[test]
    fn linear_progression_one_hop() {
        let b = drive_to_ready(1);
        let circuit = b.into_circuit().unwrap();
        assert_eq!(circuit.hop_count(), 1);
        assert!(circuit.is_ready());
    }

    #[test]
    fn linear_progression_three_hops() {
        let b = drive_to_ready(3);
        let circuit = b.into_circuit().unwrap();
        assert_eq!(circuit.hop_count(), 3);
    }

    #[test]
    fn linear_progression_max_hops() {
        let b = drive_to_ready(MAX_CIRCUIT_HOPS);
        let circuit = b.into_circuit().unwrap();
        assert_eq!(circuit.hop_count(), MAX_CIRCUIT_HOPS);
    }

    // --- Out-of-order rejection ---

    #[test]
    fn out_of_order_record_built_rejected() {
        let mut b = CircuitBuilder::new(vec![ipv4_spec(1), ipv4_spec(2), ipv4_spec(3)]).unwrap();
        // Try to record hop 2 first.
        let err = b.record_hop_built(2, fake_keys(2)).unwrap_err();
        assert_eq!(
            err,
            BuilderError::OutOfOrderRecord {
                expected: 0,
                got: 2
            }
        );
        // Hop 0 still works.
        b.record_hop_built(0, fake_keys(1)).unwrap();
        // Now skip hop 1 and try hop 2 again.
        let err = b.record_hop_built(2, fake_keys(2)).unwrap_err();
        assert_eq!(
            err,
            BuilderError::OutOfOrderRecord {
                expected: 1,
                got: 2
            }
        );
    }

    #[test]
    fn out_of_order_record_failure_rejected() {
        let mut b = CircuitBuilder::new(vec![ipv4_spec(1), ipv4_spec(2)]).unwrap();
        let err = b
            .record_hop_failure(1, BuilderError::HopHandshakeFailed)
            .unwrap_err();
        assert_eq!(
            err,
            BuilderError::OutOfOrderRecord {
                expected: 0,
                got: 1
            }
        );
    }

    // --- Failure path ---

    #[test]
    fn failure_at_hop0_blocks_subsequent_records() {
        let mut b = CircuitBuilder::new(vec![ipv4_spec(1), ipv4_spec(2)]).unwrap();
        b.record_hop_failure(0, BuilderError::TransportDialFailed)
            .unwrap();
        assert!(b.is_failed());
        // Subsequent record returns AlreadyFailed.
        let err = b.record_hop_built(0, fake_keys(1)).unwrap_err();
        assert_eq!(err, BuilderError::AlreadyFailed);
        // next_step is sticky.
        match b.next_step() {
            BuildStep::Failed { hop_idx, error } => {
                assert_eq!(hop_idx, 0);
                assert_eq!(error, BuilderError::TransportDialFailed);
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn failure_at_intermediate_hop_preserves_built_hops() {
        let mut b = CircuitBuilder::new(vec![ipv4_spec(1), ipv4_spec(2), ipv4_spec(3)]).unwrap();
        b.record_hop_built(0, fake_keys(1)).unwrap();
        b.record_hop_built(1, fake_keys(2)).unwrap();
        // Hop 2 fails.
        b.record_hop_failure(2, BuilderError::HopHandshakeFailed)
            .unwrap();
        assert!(b.is_failed());
        // The two completed hops are present in the partial circuit
        // (so the caller can find them for teardown).
        assert_eq!(b.circuit().hop_count(), 2);
        // Tear-down list correctly identifies hops 0 and 1.
        let to_destroy = b.hops_to_tear_down();
        assert_eq!(to_destroy.len(), 2);
        assert_eq!(to_destroy[0].static_pk, [1u8; 32]);
        assert_eq!(to_destroy[1].static_pk, [2u8; 32]);
    }

    #[test]
    fn into_circuit_on_failed_returns_error() {
        let mut b = CircuitBuilder::new(vec![ipv4_spec(1)]).unwrap();
        b.record_hop_failure(0, BuilderError::Timeout).unwrap();
        let err = b.into_circuit().unwrap_err();
        assert_eq!(err, BuilderError::Timeout);
    }

    #[test]
    fn into_circuit_on_pending_returns_error() {
        let b = CircuitBuilder::new(vec![ipv4_spec(1), ipv4_spec(2)]).unwrap();
        let err = b.into_circuit().unwrap_err();
        assert!(matches!(err, BuilderError::Other(_)));
    }

    // --- Idempotence + completion-state guards ---

    #[test]
    fn next_step_idempotent_in_pending_state() {
        let b = CircuitBuilder::new(vec![ipv4_spec(1), ipv4_spec(2)]).unwrap();
        let first = b.next_step();
        let second = b.next_step();
        assert_eq!(first, second);
        assert!(matches!(first, BuildStep::DialHop0 { .. }));
    }

    #[test]
    fn next_step_idempotent_in_ready_state() {
        let b = drive_to_ready(2);
        assert!(matches!(b.next_step(), BuildStep::Ready));
        assert!(matches!(b.next_step(), BuildStep::Ready));
    }

    #[test]
    fn next_step_idempotent_in_failed_state() {
        let mut b = CircuitBuilder::new(vec![ipv4_spec(1)]).unwrap();
        b.record_hop_failure(0, BuilderError::Timeout).unwrap();
        let first = b.next_step();
        let second = b.next_step();
        assert_eq!(first, second);
    }

    #[test]
    fn record_after_ready_returns_already_complete() {
        let mut b = CircuitBuilder::new(vec![ipv4_spec(1)]).unwrap();
        b.record_hop_built(0, fake_keys(1)).unwrap();
        assert!(b.is_ready());
        let err = b.record_hop_built(0, fake_keys(1)).unwrap_err();
        assert_eq!(err, BuilderError::AlreadyComplete);
    }

    // --- Builder produces a Circuit usable for relay traffic ---

    #[test]
    fn ready_circuit_can_seal_relay_traffic() {
        // After a successful 3-hop build, the underlying Circuit
        // accepts relay_seal - no extra wiring required. This is
        // the point of the orchestrator: it produces a Circuit
        // ready for the existing v0.1u onion machinery.
        let b = drive_to_ready(3);
        assert!(b.circuit().is_ready());
        let mut circuit = b.into_circuit().unwrap();
        assert_eq!(circuit.hop_count(), 3);
        let payload = b"relay payload after build".to_vec();
        let ct = circuit.relay_seal(&payload).unwrap();
        // Ciphertext is non-empty and not the plaintext.
        assert!(!ct.is_empty());
        assert_ne!(ct, payload);
    }

    // --- Tear-down enumeration ---

    #[test]
    fn tear_down_list_empty_in_pending() {
        let b = CircuitBuilder::new(vec![ipv4_spec(1), ipv4_spec(2)]).unwrap();
        assert!(b.hops_to_tear_down().is_empty());
    }

    #[test]
    fn tear_down_list_empty_in_ready() {
        let b = drive_to_ready(2);
        assert!(b.hops_to_tear_down().is_empty());
    }

    #[test]
    fn tear_down_list_includes_all_built_hops_when_failed() {
        // Mirage caps circuits at 3 hops. Build 2 hops, fail the
        // 3rd, assert the 2 built hops are in the tear-down list.
        let mut b = CircuitBuilder::new(vec![ipv4_spec(1), ipv4_spec(2), ipv4_spec(3)]).unwrap();
        b.record_hop_built(0, fake_keys(1)).unwrap();
        b.record_hop_built(1, fake_keys(2)).unwrap();
        b.record_hop_failure(2, BuilderError::HopHandshakeFailed)
            .unwrap();
        let to_destroy = b.hops_to_tear_down();
        assert_eq!(to_destroy.len(), 2);
        for (i, hop) in to_destroy.iter().enumerate() {
            assert_eq!(hop.static_pk, [(i + 1) as u8; 32]);
        }
    }

    // --- BuildStep correctness ---

    #[test]
    fn first_step_is_dial_hop0() {
        let b = CircuitBuilder::new(vec![ipv4_spec(1), ipv4_spec(2)]).unwrap();
        match b.next_step() {
            BuildStep::DialHop0 { spec } => {
                assert_eq!(spec.static_pk, [1u8; 32]);
            }
            other => panic!("expected DialHop0, got {other:?}"),
        }
    }

    #[test]
    fn second_step_is_extend_to_hop1() {
        let mut b = CircuitBuilder::new(vec![ipv4_spec(1), ipv4_spec(2)]).unwrap();
        b.record_hop_built(0, fake_keys(1)).unwrap();
        match b.next_step() {
            BuildStep::Extend {
                hop_idx,
                spec,
                prev_hop_count,
            } => {
                assert_eq!(hop_idx, 1);
                assert_eq!(prev_hop_count, 1);
                assert_eq!(spec.static_pk, [2u8; 32]);
            }
            other => panic!("expected Extend, got {other:?}"),
        }
    }

    // --- abort() semantics (RT-C2 closure) ---

    #[test]
    fn abort_transitions_pending_to_failed() {
        let mut b = CircuitBuilder::new(vec![ipv4_spec(1), ipv4_spec(2), ipv4_spec(3)]).unwrap();
        b.record_hop_built(0, fake_keys(1)).unwrap();
        b.record_hop_built(1, fake_keys(2)).unwrap();
        // 2 hops built; abort.
        b.abort(BuilderError::Timeout).unwrap();
        assert!(b.is_failed());
        // Tear-down list reflects the 2 built hops.
        let to_destroy = b.hops_to_tear_down();
        assert_eq!(to_destroy.len(), 2);
    }

    #[test]
    fn abort_is_idempotent() {
        let mut b = CircuitBuilder::new(vec![ipv4_spec(1), ipv4_spec(2)]).unwrap();
        b.record_hop_built(0, fake_keys(1)).unwrap();
        b.abort(BuilderError::Timeout).unwrap();
        // Second abort is a no-op (returns Ok).
        b.abort(BuilderError::HopHandshakeFailed).unwrap();
        // First abort's reason is preserved.
        match b.next_step() {
            BuildStep::Failed { error, .. } => assert_eq!(error, BuilderError::Timeout),
            _ => panic!("expected Failed"),
        }
    }

    #[test]
    fn abort_on_ready_is_noop() {
        let mut b = drive_to_ready(2);
        b.abort(BuilderError::Timeout).unwrap();
        // Builder remains Ready; into_circuit still works.
        assert!(b.is_ready());
        let _ = b.into_circuit().unwrap();
    }

    #[test]
    fn abort_records_correct_hop_idx_for_tear_down() {
        // abort() is called when zero hops are built (e.g., dial of
        // hop 0 timed out). hops_to_tear_down should be empty.
        let mut b = CircuitBuilder::new(vec![ipv4_spec(1), ipv4_spec(2)]).unwrap();
        b.abort(BuilderError::TransportDialFailed).unwrap();
        assert_eq!(b.hops_to_tear_down().len(), 0);
        assert!(b.is_failed());
    }

    #[test]
    fn one_hop_ready_immediately_after_record() {
        let mut b = CircuitBuilder::new(vec![ipv4_spec(7)]).unwrap();
        // First step is DialHop0.
        match b.next_step() {
            BuildStep::DialHop0 { .. } => {}
            other => panic!("expected DialHop0, got {other:?}"),
        }
        b.record_hop_built(0, fake_keys(7)).unwrap();
        // Single-hop builder transitions directly to Ready.
        assert!(b.is_ready());
        assert!(matches!(b.next_step(), BuildStep::Ready));
    }
}
