//! Circuit pool: I/O-free state machine.
//!
//! [`CircuitPool`] tracks pre-built hot circuits per class and emits
//! [`PoolAction`]s the runtime executes. The pool itself does no
//! I/O - same discipline as `mirage-mux::state`,
//! `mirage-migration::state`, and `mirage-circuit::split_exit`.
//!
//! # Lifecycle
//!
//! ```text
//!  acquire(class) --no entry--> BuildFirst(profile)         + inserts a Building entry
//!                  --existing--> Ready(id)                  + increments stream count
//!  record_built(id, profile) --> entry transitions to Healthy
//!  record_build_failure(...)--> pending count decremented; no entry created
//!  release(id)            -----> stream count decremented
//!  tick(now)              -----> Vec<PoolAction>:
//!                                  - BuildCircuit{profile}  for under-floor classes
//!                                  - DrainCircuit{id}       for max_age soft-cap
//!                                  - RetireCircuit{id}      for past-idle Draining + failed
//! ```

use crate::class::Class;
use crate::policy::PoolPolicy;
use crate::profile::CircuitProfile;
use mirage_crypto::blake3;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Per-entry lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// Caller has been told to build this circuit; not yet ready
    /// for stream assignment.
    Building,
    /// Circuit is alive and accepts streams up to `max_streams`.
    Healthy,
    /// `max_age` reached; no new streams accepted, existing ones
    /// continue. Entry will be retired after `idle_ttl` past the
    /// transition.
    Draining,
    /// Build failed or the runtime reported a fatal error. Marked
    /// for retirement on the next sweep.
    Failed,
}

/// One pool slot.
#[derive(Debug)]
pub struct PoolEntry<Id> {
    /// Caller-assigned circuit identifier. The pool is generic over
    /// this type - the runtime can use whatever handle scheme it
    /// prefers (e.g., the circuit's `circ_id` from
    /// `mirage-circuit`).
    pub id: Option<Id>,
    /// Profile this entry was built (or is being built) with.
    pub profile: CircuitProfile,
    /// Current lifecycle state.
    pub state: EntryState,
    /// When the entry was created (Building) or transitioned to
    /// its current state (after that). The pool uses this for
    /// idle-TTL and max-age sweeps.
    pub state_entered: Instant,
    /// When the underlying circuit was first observed Healthy.
    /// `None` for entries still Building or Failed without ever
    /// becoming Healthy.
    pub built_at: Option<Instant>,
    /// Number of streams currently using this circuit. Only valid
    /// after the entry transitions to Healthy.
    pub streams: u32,
    /// Streams that arrived while the entry was Building and are
    /// queued waiting for the build to complete. On `record_built`
    /// these are converted to active streams atomically. Pre-fix
    /// the pool dropped this signal, producing an off-by-one
    /// stream count for every initial build.
    pub pending_streams: u32,
    /// Per-entry effective `max_age` after applying jitter. Stored
    /// so subsequent ticks don't re-roll the jitter and produce
    /// inconsistent decisions across calls.
    pub effective_max_age: Duration,
}

/// Action the runtime must execute. Returned from
/// [`CircuitPool::acquire`] (single action) and
/// [`CircuitPool::tick`] (multiple actions).
#[derive(Debug, Clone)]
pub enum PoolAction<Id> {
    /// Build a new circuit with `profile`. On success the runtime
    /// MUST call [`CircuitPool::record_built`]; on failure
    /// [`CircuitPool::record_build_failure`].
    BuildCircuit {
        /// Profile to build the circuit with.
        profile: CircuitProfile,
    },
    /// Tear down the circuit identified by `id`. The runtime sends
    /// `CMD_DESTROY` cells and frees state. Pool has already
    /// removed the entry by the time this action is emitted.
    RetireCircuit {
        /// Circuit handle.
        id: Id,
    },
    /// Transition the circuit to draining: refuse new streams on
    /// it, but let existing ones complete. Pool has already
    /// updated its internal state.
    DrainCircuit {
        /// Circuit handle.
        id: Id,
    },
}

/// Outcome of [`CircuitPool::acquire`].
#[derive(Debug, Clone)]
pub enum AcquireOutcome<Id> {
    /// Use this circuit for the new stream. Caller MUST eventually
    /// call [`CircuitPool::release`] when the stream finishes.
    Ready {
        /// Circuit handle.
        id: Id,
    },
    /// A circuit build for this class is already in flight; the
    /// pool has reserved a stream slot on the in-flight build.
    /// Caller MUST queue the originating stream locally and start
    /// using the circuit when [`CircuitPool::record_built`] fires
    /// for this class. Caller does NOT initiate a redundant
    /// build - the pool already counted this stream against an
    /// existing Building entry's capacity.
    Pending,
    /// No build for this class is in flight and the pool has none
    /// hot. Caller MUST build a circuit with `profile` and call
    /// [`CircuitPool::record_built`] when ready. The pool has
    /// already inserted a Building entry tracking this acquire's
    /// stream as pending.
    BuildFirst {
        /// Profile the runtime should build with.
        profile: CircuitProfile,
    },
}

/// Errors produced by pool operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PoolError {
    /// `record_built`/`record_build_failure` referenced an entry
    /// the pool isn't expecting.
    #[error("no Building entry for class {0:?}")]
    NoPendingBuild(Class),
    /// `release` referenced an unknown id.
    #[error("unknown circuit id")]
    UnknownId,
    /// `acquire` would exceed `max_per_class` AND no Building
    /// entry of this class exists. Caller can either widen the cap
    /// or fail the stream upstream.
    #[error("class {0:?} pool full and at pending-build cap")]
    PoolFull(Class),
}

/// Generic circuit pool.
///
/// `Id` is the runtime's circuit-handle type: must be `Copy + Eq +
/// Hash + Debug`. Typically `u64` or a newtype around the
/// `mirage-circuit` `circ_id`.
pub struct CircuitPool<Id: Copy + Eq + Hash + Debug> {
    by_class: HashMap<Class, Vec<PoolEntry<Id>>>,
    /// Reverse lookup: id -> class. Lets [`release`] /
    /// [`record_built`] find the entry without scanning every class.
    id_index: HashMap<Id, Class>,
    /// Counter used to vary jitter across entries deterministically
    /// in unit tests (and reasonably in production). Each new
    /// entry's jitter is `(jitter_seq * golden_ratio) mod refresh_jitter`,
    /// which approximates uniform distribution without an RNG dep.
    /// Production callers MAY swap in a CSPRNG-backed picker via
    /// [`CircuitPool::set_jitter_picker`].
    jitter_seq: u64,
    /// Jitter picker - produces a `Duration` in `[0, refresh_jitter)`.
    /// Default is the deterministic golden-ratio mixer; tests pin
    /// this to zero for reproducibility.
    jitter_picker: fn(seq: u64, max: Duration) -> Duration,
    policy: PoolPolicy,
}

impl<Id: Copy + Eq + Hash + Debug> CircuitPool<Id> {
    /// Construct an empty pool with the given policy.
    ///
    /// Uses [`csprng_jitter`] as the default jitter picker
    /// (closes [RT-M1]). Tests that want reproducible timing
    /// should call [`Self::set_jitter_picker`] with
    /// [`zero_jitter`] or [`deterministic_jitter`].
    pub fn new(policy: PoolPolicy) -> Self {
        Self {
            by_class: HashMap::new(),
            id_index: HashMap::new(),
            jitter_seq: 0,
            jitter_picker: csprng_jitter,
            policy,
        }
    }

    /// Override the jitter picker. Tests pin this to
    /// [`zero_jitter`] so timing assertions are exact.
    pub fn set_jitter_picker(&mut self, picker: fn(seq: u64, max: Duration) -> Duration) {
        self.jitter_picker = picker;
    }

    /// Acquire a circuit for a stream of `class`.
    ///
    /// Source ranking:
    ///
    /// 1. Healthy entry with stream capacity -> `Ready{id}` and
    ///    increment that entry's stream count.
    /// 2. Building entry with pending capacity -> reserve a slot on
    ///    it (increment `pending_streams`) and return `Pending`.
    ///    Caller waits for `record_built` to fire.
    /// 3. No Building entry yet -> insert a new Building entry,
    ///    return `BuildFirst{profile}` so caller initiates the
    ///    build.
    ///
    /// Step 2 is the de-duplication that prevents the cold-start
    /// build storm: 100 streams arriving on app launch produce 1
    /// `BuildFirst` and 99 `Pending`s, not 100 builds.
    pub fn acquire(&mut self, class: Class, now: Instant) -> Result<AcquireOutcome<Id>, PoolError> {
        // 1. Healthy with capacity.
        if let Some(entries) = self.by_class.get_mut(&class) {
            for entry in entries.iter_mut() {
                if entry.state == EntryState::Healthy && entry.streams < entry.profile.max_streams {
                    entry.streams += 1;
                    if let Some(id) = entry.id {
                        return Ok(AcquireOutcome::Ready { id });
                    }
                }
            }
        }
        // 2. Building entry with pending capacity -> piggyback.
        if let Some(entries) = self.by_class.get_mut(&class) {
            for entry in entries.iter_mut() {
                if entry.state == EntryState::Building
                    && entry.pending_streams < entry.profile.max_streams
                {
                    entry.pending_streams += 1;
                    return Ok(AcquireOutcome::Pending);
                }
            }
        }
        // 3. Need to insert a new Building entry. Check caps.
        let (total, pending) = self.counts(class);
        if total >= self.policy.max_for(class) {
            return Err(PoolError::PoolFull(class));
        }
        if pending >= self.policy.max_pending_builds_per_class {
            return Err(PoolError::PoolFull(class));
        }
        let profile = class.default_profile();
        self.insert_building(class, profile.clone(), now, 1);
        Ok(AcquireOutcome::BuildFirst { profile })
    }

    /// Caller's circuit-build attempt succeeded. `id` is the
    /// runtime's handle for the new circuit.
    ///
    /// Returns the number of pending streams that were waiting on
    /// this build and are now active on the new circuit. The
    /// runtime SHOULD use this to release exactly that many
    /// queued streams onto `id`.
    pub fn record_built(&mut self, id: Id, class: Class, now: Instant) -> Result<u32, PoolError> {
        let entries = self
            .by_class
            .get_mut(&class)
            .ok_or(PoolError::NoPendingBuild(class))?;
        let entry = entries
            .iter_mut()
            .find(|e| e.state == EntryState::Building && e.id.is_none())
            .ok_or(PoolError::NoPendingBuild(class))?;
        entry.id = Some(id);
        entry.state = EntryState::Healthy;
        entry.state_entered = now;
        entry.built_at = Some(now);
        // Convert the pending-stream reservation into active
        // streams atomically. Pre-fix this transition was missed
        // and the originating stream wasn't counted.
        entry.streams = entry.pending_streams;
        let activated = entry.pending_streams;
        entry.pending_streams = 0;
        self.id_index.insert(id, class);
        Ok(activated)
    }

    /// Caller's circuit-build attempt failed. Removes the
    /// pending-build slot so the pool stops counting it as
    /// in-flight.
    pub fn record_build_failure(&mut self, class: Class) -> Result<(), PoolError> {
        let entries = self
            .by_class
            .get_mut(&class)
            .ok_or(PoolError::NoPendingBuild(class))?;
        let pos = entries
            .iter()
            .position(|e| e.state == EntryState::Building && e.id.is_none())
            .ok_or(PoolError::NoPendingBuild(class))?;
        entries.swap_remove(pos);
        Ok(())
    }

    /// Acquire a circuit for a stream of `class` going to `domain`,
    /// honouring stream-isolation. Same-domain streams of the same
    /// class deterministically prefer the same healthy circuit so
    /// the destination doesn't see two different exit IPs from the
    /// same user within seconds.
    ///
    /// Algorithm:
    ///
    /// 1. Compute a BLAKE3-keyed slot hash from
    ///    `(identity_salt, class, domain)`. Salt is per-client and
    ///    rotated per-session (so cross-session linkability is
    ///    prevented while in-session correlation is mitigated).
    /// 2. If healthy entries exist for `class`, pick the one at
    ///    `hash % healthy_count`. If it has stream capacity, return
    ///    it.
    /// 3. Otherwise fall through to the standard [`Self::acquire`]
    ///    path (which may `BuildFirst` / Pending / fail). This is the
    ///    "acceptable degradation" path - when the
    ///    isolation-preferred circuit is at capacity, we'd rather
    ///    serve the stream on a different circuit than block.
    ///
    /// Pool mutations (rotation / failure) MAY re-index healthy
    /// entries, in which case a domain's slot moves. This means
    /// isolation is best-effort across pool churn - within a
    /// stable pool, identical inputs reliably produce the same
    /// circuit pick.
    pub fn acquire_for_domain(
        &mut self,
        class: Class,
        domain: &str,
        identity_salt: &[u8; 16],
        now: Instant,
    ) -> Result<AcquireOutcome<Id>, PoolError> {
        if let Some(entries) = self.by_class.get_mut(&class) {
            let healthy_indices: Vec<usize> = entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.state == EntryState::Healthy)
                .map(|(i, _)| i)
                .collect();
            if !healthy_indices.is_empty() {
                let slot_hash = compute_isolation_hash(identity_salt, class, domain);
                let slot = (slot_hash as usize) % healthy_indices.len();
                let chosen_idx = healthy_indices[slot];
                let entry = &mut entries[chosen_idx];
                if entry.streams < entry.profile.max_streams {
                    entry.streams += 1;
                    if let Some(id) = entry.id {
                        return Ok(AcquireOutcome::Ready { id });
                    }
                }
                // Slot's circuit is at capacity. Fall through.
            }
        }
        self.acquire(class, now)
    }

    /// Stream finished on `id`; decrement the circuit's stream
    /// counter. Idempotent at zero - won't underflow.
    pub fn release(&mut self, id: Id) -> Result<(), PoolError> {
        let class = *self.id_index.get(&id).ok_or(PoolError::UnknownId)?;
        let entries = self.by_class.get_mut(&class).ok_or(PoolError::UnknownId)?;
        let entry = entries
            .iter_mut()
            .find(|e| e.id == Some(id))
            .ok_or(PoolError::UnknownId)?;
        entry.streams = entry.streams.saturating_sub(1);
        Ok(())
    }

    /// Mark a circuit as failed at the runtime level (transport
    /// error, peer reset, etc.). Pool transitions it to `Failed`
    /// so the next [`tick`] retires it.
    pub fn record_failure(&mut self, id: Id) -> Result<(), PoolError> {
        let class = *self.id_index.get(&id).ok_or(PoolError::UnknownId)?;
        let entries = self.by_class.get_mut(&class).ok_or(PoolError::UnknownId)?;
        let entry = entries
            .iter_mut()
            .find(|e| e.id == Some(id))
            .ok_or(PoolError::UnknownId)?;
        entry.state = EntryState::Failed;
        Ok(())
    }

    /// Periodic sweep: emits actions the runtime must apply.
    /// Idempotent - safe to call as often as the runtime wants.
    ///
    /// Three phases:
    ///
    /// 1. **Drain** - Healthy entries past `effective_max_age`
    ///    transition to Draining; `DrainCircuit` action emitted.
    /// 2. **Retire** - Draining entries with no streams past
    ///    `idle_ttl`, plus all Failed entries, are removed;
    ///    `RetireCircuit` action emitted.
    /// 3. **Floor** - for every class, if healthy count is below
    ///    its `min_pool_size`, emit `BuildCircuit` actions up to
    ///    the per-class cap and pending-build cap. Phase 3 runs
    ///    AFTER phases 1+2 so freshly-drained entries don't count
    ///    toward the healthy total.
    pub fn tick(&mut self, now: Instant) -> Vec<PoolAction<Id>> {
        let mut actions = Vec::new();

        // Phase 1+2: collect drain/retire candidates.
        let mut to_drain: Vec<(Class, Id)> = Vec::new();
        let mut to_retire: Vec<(Class, Id)> = Vec::new();
        let mut classes_with_idless_failed: Vec<Class> = Vec::new();

        for (&class, entries) in &self.by_class {
            for entry in entries {
                match entry.state {
                    EntryState::Healthy => {
                        if let (Some(built_at), Some(id)) = (entry.built_at, entry.id) {
                            if now.saturating_duration_since(built_at) >= entry.effective_max_age {
                                to_drain.push((class, id));
                            }
                        }
                    }
                    EntryState::Draining => {
                        if entry.streams == 0
                            && now.saturating_duration_since(entry.state_entered)
                                >= entry.profile.idle_ttl
                        {
                            if let Some(id) = entry.id {
                                to_retire.push((class, id));
                            }
                        }
                    }
                    EntryState::Failed => {
                        if let Some(id) = entry.id {
                            to_retire.push((class, id));
                        } else {
                            classes_with_idless_failed.push(class);
                        }
                    }
                    EntryState::Building => {}
                }
            }
        }

        for (class, id) in to_drain {
            self.transition_to_draining(class, id, now);
            actions.push(PoolAction::DrainCircuit { id });
        }
        for (class, id) in to_retire {
            self.remove_entry(class, id);
            actions.push(PoolAction::RetireCircuit { id });
        }
        // Failed-without-id: build never succeeded, no external
        // teardown required; just drop the slot.
        classes_with_idless_failed.sort_by_key(|c| c.name());
        classes_with_idless_failed.dedup();
        for class in classes_with_idless_failed {
            if let Some(entries) = self.by_class.get_mut(&class) {
                entries.retain(|e| !(e.state == EntryState::Failed && e.id.is_none()));
            }
        }

        // Phase 3: floor enforcement across ALL classes - including
        // ones that don't yet have any entries (fresh pool, etc.).
        // Pre-fix tick iterated `self.by_class` only, so a fresh
        // pool produced zero floor-enforcement actions.
        //
        // `need` accounts for in-flight builds (`pending`) so the
        // floor isn't satisfied twice: an existing Building entry
        // counts as "potential healthy" for floor purposes.
        for &class in Class::all() {
            let profile = class.default_profile();
            if profile.min_pool_size == 0 {
                continue;
            }
            let healthy = self.healthy_count(class);
            let total = self.total_count(class);
            let pending = self.pending_count(class);
            let cap = self.policy.max_for(class);
            let pending_cap = self.policy.max_pending_builds_per_class;
            let to_request = profile
                .min_pool_size
                .saturating_sub(healthy.saturating_add(pending))
                .min(cap.saturating_sub(total))
                .min(pending_cap.saturating_sub(pending));
            for _ in 0..to_request {
                self.insert_building(class, profile.clone(), now, 0);
                actions.push(PoolAction::BuildCircuit {
                    profile: profile.clone(),
                });
            }
        }

        actions
    }

    /// Look up the class of a known circuit. Diagnostics-only.
    pub fn class_of(&self, id: Id) -> Option<Class> {
        self.id_index.get(&id).copied()
    }

    /// Number of healthy entries for `class`.
    pub fn healthy_count(&self, class: Class) -> u32 {
        self.by_class.get(&class).map_or(0, |v| {
            v.iter().filter(|e| e.state == EntryState::Healthy).count() as u32
        })
    }

    /// Number of in-flight builds for `class`.
    pub fn pending_count(&self, class: Class) -> u32 {
        self.by_class.get(&class).map_or(0, |v| {
            v.iter().filter(|e| e.state == EntryState::Building).count() as u32
        })
    }

    /// Total entries (any state) for `class`.
    pub fn total_count(&self, class: Class) -> u32 {
        self.by_class.get(&class).map_or(0, |v| v.len() as u32)
    }

    /// Snapshot of an entry by id. Diagnostics-only.
    pub fn entry_state(&self, id: Id) -> Option<EntryState> {
        let class = *self.id_index.get(&id)?;
        self.by_class
            .get(&class)?
            .iter()
            .find(|e| e.id == Some(id))
            .map(|e| e.state)
    }

    /// Stream count on circuit `id`. Diagnostics-only.
    pub fn stream_count(&self, id: Id) -> Option<u32> {
        let class = *self.id_index.get(&id)?;
        self.by_class
            .get(&class)?
            .iter()
            .find(|e| e.id == Some(id))
            .map(|e| e.streams)
    }

    // --- Internal helpers ---

    fn counts(&self, class: Class) -> (u32, u32) {
        let entries = self.by_class.get(&class);
        let total = entries.map_or(0, |v| v.len() as u32);
        let pending = entries.map_or(0, |v| {
            v.iter().filter(|e| e.state == EntryState::Building).count() as u32
        });
        (total, pending)
    }

    fn insert_building(
        &mut self,
        class: Class,
        profile: CircuitProfile,
        now: Instant,
        pending_streams: u32,
    ) {
        self.jitter_seq = self.jitter_seq.wrapping_add(1);
        let jitter = (self.jitter_picker)(self.jitter_seq, self.policy.refresh_jitter);
        let effective_max_age = profile.max_age.saturating_add(jitter);
        let entry = PoolEntry {
            id: None,
            profile,
            state: EntryState::Building,
            state_entered: now,
            built_at: None,
            streams: 0,
            pending_streams,
            effective_max_age,
        };
        self.by_class.entry(class).or_default().push(entry);
    }

    fn transition_to_draining(&mut self, class: Class, id: Id, now: Instant) {
        if let Some(entries) = self.by_class.get_mut(&class) {
            if let Some(entry) = entries.iter_mut().find(|e| e.id == Some(id)) {
                entry.state = EntryState::Draining;
                entry.state_entered = now;
            }
        }
    }

    fn remove_entry(&mut self, class: Class, id: Id) {
        if let Some(entries) = self.by_class.get_mut(&class) {
            entries.retain(|e| e.id != Some(id));
        }
        self.id_index.remove(&id);
    }
}

// Jitter pickers

/// **Default jitter picker** - CSPRNG-backed via `getrandom`.
///
/// Produces a uniform value in `[0, max)` per call. Closes
/// [RT-M1]: pre-fix the default was [`deterministic_jitter`] which
/// a network-side observer doing fine-grained timing analysis
/// could in principle reverse-engineer. CSPRNG forecloses that.
///
/// On RNG failure (vanishingly rare; only on a misconfigured
/// container without `/dev/urandom`) falls back to
/// [`deterministic_jitter`] rather than panic.
pub fn csprng_jitter(seq: u64, max: Duration) -> Duration {
    if max.is_zero() {
        return Duration::ZERO;
    }
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return deterministic_jitter(seq, max);
    }
    let raw = u64::from_be_bytes(bytes);
    let max_micros = max.as_micros() as u64;
    if max_micros == 0 {
        return Duration::ZERO;
    }
    Duration::from_micros(raw % max_micros)
}

/// Deterministic jitter picker: golden-ratio mixer.
///
/// Produces approximately uniform values in `[0, max)` without an
/// RNG dep. **Not the default** - see [`csprng_jitter`]. Useful
/// for reproducible test runs and as a fallback when the OS RNG
/// is unavailable.
pub fn deterministic_jitter(seq: u64, max: Duration) -> Duration {
    if max.is_zero() {
        return Duration::ZERO;
    }
    // Golden ratio in u64 fixed-point: 0.6180339887... * 2^64.
    const PHI_FIX: u64 = 0x9E37_79B9_7F4A_7C15;
    let mix = seq.wrapping_mul(PHI_FIX);
    let max_micros = max.as_micros() as u64;
    if max_micros == 0 {
        return Duration::ZERO;
    }
    Duration::from_micros(mix % max_micros)
}

/// Zero-jitter picker. Tests use this to make timing assertions
/// exact; production code should not.
pub fn zero_jitter(_seq: u64, _max: Duration) -> Duration {
    Duration::ZERO
}

/// BLAKE3-keyed isolation hash used by [`CircuitPool::acquire_for_domain`]
/// to pick a stable slot for `(class, domain)` pairs. The salt
/// keys the hash so a network-side observer doesn't learn anything
/// about the user's destination patterns from the resulting slot.
fn compute_isolation_hash(salt: &[u8; 16], class: Class, domain: &str) -> u64 {
    let mut k = [0u8; 32];
    k[..16].copy_from_slice(salt);
    let mut h = blake3::Hasher::new_keyed(&k);
    h.update(class.name().as_bytes());
    h.update(domain.as_bytes());
    let out = *h.finalize().as_bytes();
    u64::from_be_bytes([
        out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> CircuitPool<u64> {
        let mut p = CircuitPool::<u64>::new(PoolPolicy::default());
        p.set_jitter_picker(zero_jitter);
        p
    }

    #[test]
    fn empty_pool_acquire_returns_build_first() {
        let mut p = pool();
        let now = Instant::now();
        let outcome = p.acquire(Class::Interactive, now).unwrap();
        match outcome {
            AcquireOutcome::BuildFirst { profile } => {
                assert_eq!(profile.class, Class::Interactive);
                assert_eq!(profile.hop_count, 3);
            }
            _ => panic!("expected BuildFirst"),
        }
        // Pool tracks the in-flight build.
        assert_eq!(p.pending_count(Class::Interactive), 1);
        assert_eq!(p.healthy_count(Class::Interactive), 0);
    }

    #[test]
    fn record_built_makes_circuit_acquirable() {
        let mut p = pool();
        let now = Instant::now();
        let _ = p.acquire(Class::Interactive, now).unwrap();
        // The originating stream that triggered the build is
        // pending until record_built activates it.
        let activated = p.record_built(42u64, Class::Interactive, now).unwrap();
        assert_eq!(activated, 1, "originating stream should be activated");
        assert_eq!(p.stream_count(42).unwrap(), 1);
        // A fresh acquire after the build returns Ready.
        let outcome = p.acquire(Class::Interactive, now).unwrap();
        match outcome {
            AcquireOutcome::Ready { id } => assert_eq!(id, 42),
            _ => panic!("expected Ready"),
        }
        assert_eq!(p.healthy_count(Class::Interactive), 1);
        assert_eq!(p.stream_count(42).unwrap(), 2);
    }

    #[test]
    fn release_decrements_stream_count() {
        let mut p = pool();
        let now = Instant::now();
        // Acquire #1: BuildFirst, pending_streams=1.
        let _ = p.acquire(Class::Interactive, now).unwrap();
        // record_built activates the originating stream -> streams=1.
        let activated = p.record_built(42u64, Class::Interactive, now).unwrap();
        assert_eq!(activated, 1);
        assert_eq!(p.stream_count(42).unwrap(), 1);
        // Two more acquires hit the Healthy path -> streams=2, 3.
        let _ = p.acquire(Class::Interactive, now).unwrap();
        let _ = p.acquire(Class::Interactive, now).unwrap();
        assert_eq!(p.stream_count(42).unwrap(), 3);
        p.release(42).unwrap();
        assert_eq!(p.stream_count(42).unwrap(), 2);
    }

    #[test]
    fn release_unknown_id_errors() {
        let mut p = pool();
        let err = p.release(999).unwrap_err();
        assert_eq!(err, PoolError::UnknownId);
    }

    #[test]
    fn record_build_failure_clears_pending_slot() {
        let mut p = pool();
        let now = Instant::now();
        let _ = p.acquire(Class::Interactive, now).unwrap();
        assert_eq!(p.pending_count(Class::Interactive), 1);
        p.record_build_failure(Class::Interactive).unwrap();
        assert_eq!(p.pending_count(Class::Interactive), 0);
    }

    #[test]
    fn second_acquire_during_build_returns_pending() {
        // The cold-start de-dup: subsequent acquires for a class
        // that already has a Building entry get reservations on
        // that same Building entry rather than triggering more
        // builds. Critical for "100 streams arrive on app launch
        // -> 1 build, not 100."
        let mut p = pool();
        let now = Instant::now();
        let first = p.acquire(Class::Interactive, now).unwrap();
        assert!(matches!(first, AcquireOutcome::BuildFirst { .. }));
        for _ in 0..5 {
            let outcome = p.acquire(Class::Interactive, now).unwrap();
            assert!(
                matches!(outcome, AcquireOutcome::Pending),
                "expected Pending, got {outcome:?}"
            );
        }
        // Only ONE Building entry exists, with 6 pending streams
        // (1 originating + 5 piggybacked).
        assert_eq!(p.pending_count(Class::Interactive), 1);
        // record_built activates all 6.
        let activated = p.record_built(42u64, Class::Interactive, now).unwrap();
        assert_eq!(activated, 6);
        assert_eq!(p.stream_count(42).unwrap(), 6);
    }

    #[test]
    fn pending_build_cap_blocks_further_acquires() {
        // Acquire returns Pending (piggyback) up to max_streams of
        // the existing Building entry. Then we need a SECOND
        // Building entry, which is bounded by max_pending_builds_per_class.
        let policy = PoolPolicy {
            max_pending_builds_per_class: 1,
            ..PoolPolicy::default()
        };
        let mut p = CircuitPool::<u64>::new(policy);
        p.set_jitter_picker(zero_jitter);
        let now = Instant::now();
        // First acquire creates the only allowed Building entry.
        let first = p.acquire(Class::Interactive, now).unwrap();
        assert!(matches!(first, AcquireOutcome::BuildFirst { .. }));
        // Fill the Building entry's pending capacity (max_streams = 64).
        let max_streams = Class::Interactive.default_profile().max_streams;
        for _ in 1..max_streams {
            assert!(matches!(
                p.acquire(Class::Interactive, now).unwrap(),
                AcquireOutcome::Pending
            ));
        }
        // Now the Building entry is at capacity AND we're at the
        // pending-build cap -> next acquire fails.
        let err = p.acquire(Class::Interactive, now).unwrap_err();
        assert_eq!(err, PoolError::PoolFull(Class::Interactive));
    }

    #[test]
    fn max_per_class_cap_enforced() {
        // max_per_class = 2 -> only 2 entries (Healthy or Building)
        // can coexist for Interactive. After 2 are built and
        // saturated, no new acquire succeeds.
        let mut policy = PoolPolicy::default();
        policy.max_per_class.set(Class::Interactive, 2);
        policy.max_pending_builds_per_class = 4;
        let mut p = CircuitPool::<u64>::new(policy);
        p.set_jitter_picker(zero_jitter);
        let now = Instant::now();
        // Build 1: BuildFirst, pending_streams=1.
        let _ = p.acquire(Class::Interactive, now).unwrap();
        p.record_built(1u64, Class::Interactive, now).unwrap();
        // Build 2: needs a SECOND Building entry. Acquire #2 will
        // first try to piggyback on circuit 1 (Healthy with
        // capacity), so it returns Ready{1} not BuildFirst. To
        // force a 2nd Building, fill circuit 1 first.
        let profile = Class::Interactive.default_profile();
        for _ in 0..(profile.max_streams - 1) {
            // Already have streams=1 from the originating; fill
            // up to max_streams.
            assert!(matches!(
                p.acquire(Class::Interactive, now).unwrap(),
                AcquireOutcome::Ready { id: 1 }
            ));
        }
        // Now circuit 1 is full -> next acquire creates Building 2.
        let outcome = p.acquire(Class::Interactive, now).unwrap();
        assert!(matches!(outcome, AcquireOutcome::BuildFirst { .. }));
        p.record_built(2u64, Class::Interactive, now).unwrap();
        // Saturate circuit 2.
        for _ in 1..profile.max_streams {
            assert!(matches!(
                p.acquire(Class::Interactive, now).unwrap(),
                AcquireOutcome::Ready { id: 2 }
            ));
        }
        // Both circuits full, total = cap (2). Next acquire fails.
        let err = p.acquire(Class::Interactive, now).unwrap_err();
        assert_eq!(err, PoolError::PoolFull(Class::Interactive));
    }

    #[test]
    fn tick_drains_aged_circuits() {
        let mut p = pool();
        let t0 = Instant::now();
        let _ = p.acquire(Class::Interactive, t0).unwrap();
        p.record_built(1u64, Class::Interactive, t0).unwrap();
        // Far past max_age (60 min for Interactive) + zero jitter.
        let later = t0 + Duration::from_secs(70 * 60);
        let actions = p.tick(later);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, PoolAction::DrainCircuit { id: 1 })),
            "expected DrainCircuit, got {actions:?}"
        );
        assert_eq!(
            p.entry_state(1),
            Some(EntryState::Draining),
            "circuit should be Draining after tick"
        );
    }

    #[test]
    fn tick_retires_drained_idle_circuits() {
        let mut p = pool();
        let t0 = Instant::now();
        let _ = p.acquire(Class::Interactive, t0).unwrap();
        p.record_built(1u64, Class::Interactive, t0).unwrap();
        // Originating stream finished before the drain window.
        // Required so the Draining entry can reach streams=0 by
        // the time the idle_ttl elapses.
        p.release(1).unwrap();
        // Force into Draining via tick + max_age.
        let drain_at = t0 + Duration::from_secs(70 * 60);
        let _ = p.tick(drain_at);
        // No streams active; idle_ttl elapses -> retire.
        let retire_at = drain_at + Duration::from_secs(11 * 60);
        let actions = p.tick(retire_at);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, PoolAction::RetireCircuit { id: 1 })),
            "expected RetireCircuit, got {actions:?}"
        );
        // Entry is gone.
        assert_eq!(p.entry_state(1), None);
        assert_eq!(p.class_of(1), None);
    }

    #[test]
    fn tick_emits_build_actions_for_under_floor_classes() {
        // Interactive's min_pool_size is 3. Empty pool + tick ->
        // 3 BuildCircuit actions.
        let mut p = pool();
        let actions = p.tick(Instant::now());
        let interactive_builds = actions
            .iter()
            .filter(|a| {
                matches!(
                    a,
                    PoolAction::BuildCircuit { profile }
                        if profile.class == Class::Interactive
                )
            })
            .count();
        assert_eq!(interactive_builds, 3);
        assert_eq!(p.pending_count(Class::Interactive), 3);
    }

    #[test]
    fn tick_respects_per_class_cap_when_filling_floor() {
        // Cap Interactive at 1; floor wants 3. Tick should only
        // request 1 build, not 3.
        let mut policy = PoolPolicy::default();
        policy.max_per_class.set(Class::Interactive, 1);
        let mut p = CircuitPool::<u64>::new(policy);
        p.set_jitter_picker(zero_jitter);
        let actions = p.tick(Instant::now());
        let interactive_builds = actions
            .iter()
            .filter(|a| {
                matches!(
                    a,
                    PoolAction::BuildCircuit { profile }
                        if profile.class == Class::Interactive
                )
            })
            .count();
        assert_eq!(interactive_builds, 1);
    }

    #[test]
    fn failure_recorded_then_swept_on_tick() {
        let mut p = pool();
        let t0 = Instant::now();
        let _ = p.acquire(Class::Interactive, t0).unwrap();
        p.record_built(1u64, Class::Interactive, t0).unwrap();
        p.record_failure(1).unwrap();
        let actions = p.tick(t0 + Duration::from_secs(1));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, PoolAction::RetireCircuit { id: 1 })),
            "failed circuit should be retired"
        );
        assert_eq!(p.entry_state(1), None);
    }

    #[test]
    fn record_built_without_pending_errors() {
        let mut p = pool();
        let err = p
            .record_built(99, Class::Interactive, Instant::now())
            .unwrap_err();
        assert_eq!(err, PoolError::NoPendingBuild(Class::Interactive));
    }

    #[test]
    fn record_build_failure_without_pending_errors() {
        let mut p = pool();
        let err = p.record_build_failure(Class::Interactive).unwrap_err();
        assert_eq!(err, PoolError::NoPendingBuild(Class::Interactive));
    }

    #[test]
    fn csprng_jitter_stays_within_bounds() {
        // RT-M1 closure: production default is CSPRNG-backed.
        // Same bounds + same zero-handling as the deterministic
        // version; tested independently because the logic is
        // separate.
        let max = Duration::from_secs(60);
        for seq in 0u64..100 {
            let j = csprng_jitter(seq, max);
            assert!(j < max);
        }
        assert_eq!(csprng_jitter(0, Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn deterministic_jitter_stays_within_bounds() {
        // Sanity check the deterministic jitter picker produces
        // values strictly less than `max`.
        let max = Duration::from_secs(60);
        for seq in 0u64..1000 {
            let j = deterministic_jitter(seq, max);
            assert!(j < max, "jitter {j:?} >= max {max:?} for seq {seq}");
        }
    }

    #[test]
    fn jitter_with_zero_max_is_zero() {
        assert_eq!(deterministic_jitter(123, Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn realtime_class_isolation_from_other_classes() {
        // Acquire Realtime -> builds Realtime profile, does NOT
        // affect Interactive pool counts.
        let mut p = pool();
        let _ = p.acquire(Class::Realtime, Instant::now()).unwrap();
        assert_eq!(p.pending_count(Class::Realtime), 1);
        assert_eq!(p.pending_count(Class::Interactive), 0);
    }

    #[test]
    fn realtime_acquire_returns_realtime_profile() {
        let mut p = pool();
        let outcome = p.acquire(Class::Realtime, Instant::now()).unwrap();
        match outcome {
            AcquireOutcome::BuildFirst { profile } => {
                assert_eq!(profile.class, Class::Realtime);
                assert_eq!(profile.hop_count, 2);
                assert!(profile.is_anonymity_downgrade());
                assert!(!profile.transport_bias.allow_fallback);
            }
            _ => panic!("expected BuildFirst"),
        }
    }

    #[test]
    fn cold_start_storm_dedups_to_one_build() {
        // The motivating UX scenario: 100 streams arrive at app
        // launch. Pre-design, this would have meant 100 concurrent
        // circuit handshakes - load amplification + several seconds
        // of latency for every stream. The Pending de-dup is what
        // makes the router actually usable: 100 streams -> 1 build,
        // and once the build completes, all 100 are released onto
        // it (up to max_streams).
        let mut p = pool();
        let now = Instant::now();
        let max_streams = Class::Interactive.default_profile().max_streams;
        // 100 simultaneous arriving streams.
        let mut build_first_count = 0;
        let mut pending_count = 0;
        for _ in 0..100 {
            match p.acquire(Class::Interactive, now).unwrap() {
                AcquireOutcome::BuildFirst { .. } => build_first_count += 1,
                AcquireOutcome::Pending => pending_count += 1,
                AcquireOutcome::Ready { .. } => panic!("no circuit yet, can't be Ready"),
            }
        }
        // First acquire kicks off ONE build; the other 63 piggyback
        // on that Building entry up to its max_streams; then a
        // SECOND BuildFirst kicks off when the first is at capacity.
        // Pattern: 1 + 63 (Pending) + 1 + 35 (Pending) = 100.
        assert!(
            build_first_count <= 2,
            "expected at most 2 BuildFirsts for 100 streams, got {build_first_count}"
        );
        // The first {max_streams} streams should be associated with
        // the first Building entry.
        assert!(pending_count >= max_streams - 1);
        // Build completion releases all the queued streams at once.
        let activated = p.record_built(7u64, Class::Interactive, now).unwrap();
        assert_eq!(
            activated, max_streams,
            "first Building entry should fill to max_streams"
        );
        assert_eq!(p.stream_count(7).unwrap(), max_streams);
    }

    #[test]
    fn ux_scenario_realtime_and_interactive_dont_share_pool() {
        // The core UX promise: opening a video call doesn't
        // disturb your web-browsing pool, and vice versa. This is
        // table-stakes for "actually usable" - a YouTube video
        // shouldn't tie up the same circuit your shell session is
        // on.
        let mut p = pool();
        let now = Instant::now();
        // Web browser opens 5 streams, all Interactive.
        for _ in 0..5 {
            let _ = p.acquire(Class::Interactive, now).unwrap();
        }
        p.record_built(1u64, Class::Interactive, now).unwrap();
        assert_eq!(p.healthy_count(Class::Interactive), 1);
        assert_eq!(p.healthy_count(Class::Realtime), 0);
        // User starts a video call. Realtime acquire goes to its
        // own pool, doesn't disturb the Interactive circuit.
        let outcome = p.acquire(Class::Realtime, now).unwrap();
        match outcome {
            AcquireOutcome::BuildFirst { profile } => {
                assert_eq!(profile.class, Class::Realtime);
                assert_eq!(profile.hop_count, 2, "realtime must be 2-hop");
                assert!(
                    profile.is_anonymity_downgrade(),
                    "realtime is an explicit downgrade"
                );
            }
            other => panic!("expected BuildFirst, got {other:?}"),
        }
        // Realtime build completes on its own circuit.
        p.record_built(99u64, Class::Realtime, now).unwrap();
        // Both pools healthy, completely isolated.
        assert_eq!(p.healthy_count(Class::Interactive), 1);
        assert_eq!(p.healthy_count(Class::Realtime), 1);
        assert_eq!(p.class_of(1), Some(Class::Interactive));
        assert_eq!(p.class_of(99), Some(Class::Realtime));
    }

    // --- Stream isolation (acquire_for_domain) ---

    /// Build `n` healthy Bulk circuits with streams=0. Bulk's
    /// `max_streams=8` so each Building entry needs 8 acquires before
    /// the pool agrees to start a second one. After this helper
    /// returns, the pool has `n` healthy circuits (ids 1..=n).
    fn build_n_healthy_bulk(p: &mut CircuitPool<u64>, n: u64) {
        let now = Instant::now();
        let max_streams = Class::Bulk.default_profile().max_streams as u64;
        // Saturate `n` Building entries - `acquire` reuses an
        // existing Building until it hits max_streams, then creates
        // a new Building.
        for _ in 0..(n * max_streams) {
            let outcome = p.acquire(Class::Bulk, now).unwrap();
            assert!(
                matches!(
                    outcome,
                    AcquireOutcome::BuildFirst { .. } | AcquireOutcome::Pending
                ),
                "unexpected outcome during pool warm-up: {outcome:?}"
            );
        }
        for id in 1u64..=n {
            p.record_built(id, Class::Bulk, now).unwrap();
        }
        // Release all streams so circuits start empty.
        for id in 1u64..=n {
            for _ in 0..max_streams {
                p.release(id).unwrap();
            }
        }
        assert_eq!(p.healthy_count(Class::Bulk), n as u32);
    }

    #[test]
    fn same_domain_picks_same_circuit() {
        // Stream-isolation invariant: two streams to the same
        // destination domain reuse the same circuit (within a
        // stable pool). This prevents the destination from seeing
        // two different exit IPs from "you" within seconds.
        let mut p = pool();
        let now = Instant::now();
        let salt = [0x42u8; 16];
        build_n_healthy_bulk(&mut p, 4);

        // Two streams to the same domain -> same circuit.
        let a = p
            .acquire_for_domain(Class::Bulk, "example.com", &salt, now)
            .unwrap();
        let b = p
            .acquire_for_domain(Class::Bulk, "example.com", &salt, now)
            .unwrap();
        match (a, b) {
            (AcquireOutcome::Ready { id: id_a }, AcquireOutcome::Ready { id: id_b }) => {
                assert_eq!(id_a, id_b, "same domain should map to same circuit");
            }
            other => panic!("expected Ready+Ready, got {other:?}"),
        }
    }

    #[test]
    fn different_domains_spread_across_pool() {
        // Stream-isolation also implies: distinct destinations
        // SPREAD across the pool when multiple healthy circuits
        // exist. This defeats colluding-destinations correlation
        // by shared exit IP.
        let mut p = pool();
        let now = Instant::now();
        let salt = [0x42u8; 16];
        build_n_healthy_bulk(&mut p, 4);

        // 100 distinct domains -> over the pool. With a uniform
        // hash all 4 circuits should be hit.
        let mut hit_circuits = std::collections::HashSet::new();
        for i in 0..100 {
            let domain = format!("example{i}.com");
            let outcome = p
                .acquire_for_domain(Class::Bulk, &domain, &salt, now)
                .unwrap();
            if let AcquireOutcome::Ready { id } = outcome {
                hit_circuits.insert(id);
                // Release so circuits don't fill up.
                p.release(id).unwrap();
            }
        }
        assert!(
            hit_circuits.len() >= 3,
            "expected >= 3 of 4 circuits to be hit by 100 distinct domains, got {}",
            hit_circuits.len()
        );
    }

    #[test]
    fn isolation_falls_through_when_slot_circuit_full() {
        // When the slot-picked circuit is at max_streams capacity,
        // acquire_for_domain falls through to standard acquire so
        // the stream isn't blocked. Documented degradation path.
        let mut policy = PoolPolicy::default();
        policy.max_per_class.set(Class::Interactive, 4);
        let mut p = CircuitPool::<u64>::new(policy);
        p.set_jitter_picker(zero_jitter);
        let now = Instant::now();
        let salt = [0x42u8; 16];

        // 1 healthy circuit only; saturate it to its max_streams.
        p.acquire(Class::Interactive, now).unwrap();
        p.record_built(1u64, Class::Interactive, now).unwrap();
        let max_streams = Class::Interactive.default_profile().max_streams;
        // record_built activated 1 stream; fill the rest.
        for _ in 1..max_streams {
            p.acquire(Class::Interactive, now).unwrap();
        }
        // Now circuit 1 is at capacity. acquire_for_domain should
        // fall through to standard acquire - which creates a NEW
        // Building entry (BuildFirst).
        let outcome = p
            .acquire_for_domain(Class::Interactive, "example.com", &salt, now)
            .unwrap();
        assert!(matches!(outcome, AcquireOutcome::BuildFirst { .. }));
    }

    #[test]
    fn isolation_with_no_healthy_falls_through_to_build() {
        // Empty pool + acquire_for_domain -> just BuildFirst.
        let mut p = pool();
        let salt = [0x42u8; 16];
        let outcome = p
            .acquire_for_domain(Class::Interactive, "example.com", &salt, Instant::now())
            .unwrap();
        assert!(matches!(outcome, AcquireOutcome::BuildFirst { .. }));
    }

    #[test]
    fn isolation_hash_is_salt_dependent() {
        let h1 = compute_isolation_hash(&[0x01u8; 16], Class::Interactive, "example.com");
        let h2 = compute_isolation_hash(&[0x02u8; 16], Class::Interactive, "example.com");
        assert_ne!(
            h1, h2,
            "salt rotation should change isolation hash for the same domain"
        );
    }

    #[test]
    fn isolation_hash_is_class_dependent() {
        // Same domain in different classes -> different hashes ->
        // different slot. Streams of different classes never
        // share circuits anyway (distinct pools), but this
        // guarantees a Realtime stream and an Interactive stream
        // to the same destination don't accidentally co-locate via
        // any future cross-class sharing logic.
        let salt = [0x42u8; 16];
        let h_int = compute_isolation_hash(&salt, Class::Interactive, "example.com");
        let h_bulk = compute_isolation_hash(&salt, Class::Bulk, "example.com");
        assert_ne!(h_int, h_bulk);
    }

    #[test]
    fn class_of_known_id_returns_class() {
        let mut p = pool();
        let now = Instant::now();
        let _ = p.acquire(Class::Bulk, now).unwrap();
        p.record_built(7u64, Class::Bulk, now).unwrap();
        assert_eq!(p.class_of(7), Some(Class::Bulk));
        assert_eq!(p.class_of(999), None);
    }
}
