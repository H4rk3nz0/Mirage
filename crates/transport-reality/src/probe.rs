//! REALITY-v2 auth probe: construct + verify the 32-byte `session_id` payload.
//!
//! This module is pure crypto - no TLS parsing, no I/O. It produces and
//! verifies the 32-byte probe blob; callers are responsible for placing
//! it in a TLS ClientHello `session_id` field (client) and extracting it
//! from an incoming ClientHello (bridge).
//!
//! # Wire format (spec §4, 32 bytes total)
//!
//! ```text
//! offset  size  field
//! ------  ----  -----
//! 0       12    nonce         - client-chosen random
//! 12      4     timestamp     - u32 BE Unix seconds, XOR-masked on the wire with
//!                               a keystream derived from the ECDH `shared` secret
//!                               (red-team round 2), so a passive observer sees
//!                               random bytes, not a monotonic clock. The bridge
//!                               unmasks it; the tag covers the PLAINTEXT value.
//! 16      16    tag           - BLAKE3-keyed truncated MAC
//! ```
//!
//! # Epoch-ratcheted anti-enumeration (§4.2)
//!
//! The MAC's auth key is derived from the X25519 ECDH of the client's ephemeral
//! key against the **bridge's static key**. That static key's PUBLIC half rides
//! in the signed [`Announcement`](mirage_discovery::wire::Announcement) that is
//! broadcast on public discovery channels (Nostr, DNS-TXT, CT). A censor who
//! scrapes one announcement therefore learns everything needed to forge a valid
//! probe and CONFIRM, via active probing, that a suspected IP is a Mirage bridge.
//! This is permanent, since the static key never rotates, and mirrors REALITY's
//! structural short-ID weakness.
//!
//! To close it, [`build_probe`]/[`verify_probe`] additionally bind a **per-epoch
//! probe secret** into the auth key. The secret is derived from a per-bridge
//! `probe_root` that is delivered only in the **authenticated invite** (never in
//! the public announcement) and re-derived by the bridge from its static secret.
//! Any client that can actually authenticate already holds an invite, so no
//! legitimate reach is lost; a censor with only the announcement cannot forge.
//! The epoch index is `timestamp / PROBE_EPOCH_SECONDS`, read from the probe's
//! own timestamp on both sides, so rotation adds **zero wire bytes** and needs
//! no negotiation.
//!
//! HONEST NAMING: the security benefit today is **invite-gating** - a secret
//! (`probe_root`) that is present in the invite and absent from the public
//! announcement - NOT ratcheting or forward secrecy. The per-epoch derivation is
//! deterministic from a *static, long-lived* root, so an invite holder can
//! compute every epoch's secret; the "epoch" rotation buys no security on its own
//! today. It is forward-looking scaffolding: it lets a future revision push fresh
//! per-epoch secrets over the authenticated cohort-refresh channel (so the client
//! never holds the root), which is what would make it genuinely forward-secure /
//! ratcheting (RESIDUAL 2 below). Read "epoch-ratcheted" as "epoch-indexed,
//! invite-gated" until that lands.
//!
//! An all-zero `probe_root` ([`PROBE_ROOT_DISABLED`]) disables the binding and
//! yields a byte-identical legacy probe, so unprovisioned bridges and
//! pre-extension clients interoperate unchanged. A provisioned bridge accepts
//! legacy probes during rollover (`accept_legacy`, default on) and closes the
//! hole once operators set it off - which is safe ONLY when every client that
//! reaches the bridge holds its invite (and hence its root).
//!
//! RESIDUAL 1 (cohort): a bridge discovered through the cohort service is reached
//! WITHOUT a per-bridge invite (the client holds an operator token but no root
//! for that bridge), so it sends a legacy probe. Such a bridge MUST keep
//! `accept_legacy` on, or it rejects legitimate cohort clients. A follow-up will
//! carry each bridge's root in the (confidential) cohort response so cohort
//! bridges can close the hole too.
//!
//! RESIDUAL 2 (compromised client): today the `probe_root` is long-lived
//! (invite-delivered), so a *compromised client* - which can reveal the bridge
//! merely by connecting - can also forge probes until re-invited. A future
//! revision pushes fresh per-epoch secrets over the authenticated cohort-refresh
//! channel so the client never holds the root, bounding even that case to a
//! single epoch. The wire format and this API are already epoch-indexed for that
//! drop-in.

use mirage_crypto::blake3;
use mirage_crypto::subtle::ConstantTimeEq;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_crypto::zeroize::Zeroizing;

use crate::error::RealityError;
use crate::replay::ReplayProbeSet;

// Spec constants (§9)

/// Spec §4: total `session_id` length.
pub const SESSION_ID_LEN: usize = 32;

/// Spec §4: nonce prefix length (bytes 0..12).
pub const NONCE_LEN: usize = 12;

/// Spec §4: MAC tag length (bytes 16..32).
pub const TAG_LEN: usize = 16;

/// Spec §9: timestamp acceptance window around current time.
pub const TIMESTAMP_WINDOW_SECONDS: u64 = 60;

/// BLAKE3 label for the auth key derivation step.
const AUTH_KEY_LABEL: &[u8] = b"mirage-reality-auth-key-v1";

/// BLAKE3 label for the per-epoch probe-secret derivation step.
const PROBE_EPOCH_LABEL: &[u8] = b"mirage-reality-probe-epoch-v1";

/// BLAKE3 label for deriving a bridge's probe root from its X25519 static secret.
const PROBE_ROOT_LABEL: &[u8] = b"mirage-reality-probe-root-v1";

/// Epoch length (seconds) for probe-secret rotation. One UTC day, so the
/// bridge and client agree on the epoch index directly from the probe's own
/// timestamp with no negotiation and a boundary-skew window (a few seconds
/// around midnight UTC) that is negligible next to the 24h epoch. See
/// [`probe_epoch`].
pub const PROBE_EPOCH_SECONDS: u64 = 86_400;

/// The all-zero [`ClientProbeInputs::probe_root`] / [`BridgeProbeInputs::probe_root`]
/// sentinel meaning "epoch binding disabled". A probe built or verified with a
/// disabled root is **byte-identical** to the pre-epoch-binding (legacy) probe,
/// so an unprovisioned bridge and an old client interoperate unchanged. See the
/// module docs on the enumeration threat this closes.
pub const PROBE_ROOT_DISABLED: [u8; 32] = [0u8; 32];

/// Derive a bridge's per-bridge probe root from its X25519 static secret.
///
/// Both the invite-mint (which holds the static secret at keygen time) and the
/// bridge daemon (which loads it at startup) call this, so they agree on the
/// root with no extra provisioning or config. The result is a secret: it is
/// secret **iff** the X25519 static secret is, and the static PUBLIC key that
/// rides in the announcement does NOT reveal it (BLAKE3-keyed is one-way from
/// the key). The mint embeds the result in the invite
/// (`INVITE_EXT_REALITY_PROBE_ROOT`); the bridge passes it as
/// [`BridgeProbeInputs::probe_root`].
///
/// The returned root is a long-lived per-bridge secret. Callers store it
/// alongside co-located material of equal sensitivity - the invite's other
/// secrets (bootstrap tokens, salt, the sibling `obfs_secret`) or, on the
/// bridge, the static secret it is derived from and which sits in plaintext in
/// the same process - so it is not separately `Zeroizing` there. The
/// security-critical *transient* derivative (the per-epoch secret in
/// `derive_epoch_probe_secret`) IS `Zeroizing`; wrap any extra transient copies
/// you make.
#[must_use]
pub fn derive_probe_root(bridge_x25519_sk: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(bridge_x25519_sk);
    h.update(PROBE_ROOT_LABEL);
    *h.finalize().as_bytes()
}

/// Compute the probe epoch index for a Unix timestamp (seconds).
///
/// Both sides derive the SAME index because the bridge reads it from the
/// probe's embedded timestamp (not its own wall clock) - see [`verify_probe`].
#[must_use]
pub fn probe_epoch(unix_secs: u64) -> u64 {
    unix_secs / PROBE_EPOCH_SECONDS
}

/// Derive the per-epoch probe secret from a per-bridge probe root.
///
/// Returns `None` when `probe_root` is the all-zero [`PROBE_ROOT_DISABLED`]
/// sentinel; callers treat `None` as "no epoch binding" and fall back to the
/// legacy auth-key derivation, which keeps the wire bytes identical to a
/// pre-epoch-binding probe.
///
/// The root is a per-bridge secret that rides in the authenticated invite
/// (NOT the public announcement that carries `bridge_x25519_pk`), so a censor
/// who scrapes announcements learns the pubkey but not the root and therefore
/// cannot forge a probe. Rotating per epoch bounds the damage of a leaked
/// root to a single epoch once the client population moves to freshly-pushed
/// per-epoch secrets (see the roadmap note in the module docs).
fn derive_epoch_probe_secret(probe_root: &[u8; 32], epoch: u64) -> Option<Zeroizing<[u8; 32]>> {
    if probe_root == &PROBE_ROOT_DISABLED {
        return None;
    }
    let mut h = blake3::Hasher::new_keyed(probe_root);
    h.update(PROBE_EPOCH_LABEL);
    h.update(&epoch.to_be_bytes());
    Some(Zeroizing::new(*h.finalize().as_bytes()))
}

// Probe payload structure

/// Deserialized view of the 32-byte `session_id` payload.
///
/// Construction by the client happens via [`build_probe`]. Bridge-side
/// verification happens via [`verify_probe`]; callers do not construct
/// this struct directly on the bridge side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// 12-byte client-chosen nonce (replay key).
    pub nonce: [u8; NONCE_LEN],
    /// Unix timestamp (seconds) at which client built the probe.
    pub timestamp: u32,
    /// Truncated MAC over (nonce || timestamp || CH_random || eph_pk).
    pub tag: [u8; TAG_LEN],
}

impl Probe {
    /// Encode to the fixed 32-byte wire form.
    pub fn encode(&self) -> [u8; SESSION_ID_LEN] {
        let mut out = [0u8; SESSION_ID_LEN];
        out[0..NONCE_LEN].copy_from_slice(&self.nonce);
        out[NONCE_LEN..NONCE_LEN + 4].copy_from_slice(&self.timestamp.to_be_bytes());
        out[NONCE_LEN + 4..].copy_from_slice(&self.tag);
        out
    }

    /// Parse the 32-byte wire form. Returns an error if length is wrong.
    pub fn decode(bytes: &[u8]) -> Result<Self, RealityError> {
        if bytes.len() != SESSION_ID_LEN {
            return Err(RealityError::SessionIdLen);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[0..NONCE_LEN]);
        let ts_bytes: [u8; 4] = bytes[NONCE_LEN..NONCE_LEN + 4].try_into().unwrap();
        let timestamp = u32::from_be_bytes(ts_bytes);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&bytes[NONCE_LEN + 4..]);
        Ok(Self {
            nonce,
            timestamp,
            tag,
        })
    }
}

// Client-side: construct a probe

/// Inputs the client collects before calling [`build_probe`].
///
/// # Client-side obligations
///
/// Every field marked "fresh per probe" below MUST be drawn fresh for
/// each TLS connection the client opens. The MAC binds these fields
/// into the probe tag, which prevents a **network forger** from
/// constructing a valid probe - but it does NOT prevent the **client
/// itself** from weakening unlinkability by reusing any of them.
///
/// Concrete risks of reuse:
///
/// - **`ch_random` reuse across connections.** A passive observer sees
///   `ClientHello.random` in the clear. Two ClientHellos with identical
///   random fields (e.g. to two different bridges) immediately link
///   those flows to the same client, even though everything else is
///   encrypted. Mirrors the stock-browser behavior of fresh random per
///   connection - any deviation is a distinguisher.
/// - **`eph_sk` reuse.** The 32-byte ephemeral public key rides in the
///   ClientHello `key_share` extension and is similarly visible. Reuse
///   produces the same linkability problem AND loses forward secrecy
///   for every session it keyed.
/// - **`nonce` reuse with the same timestamp.** Hits the bridge's
///   replay set on the second probe and falls through to cover -
///   correct behavior from the bridge's side, but from the client's
///   side the second connection appears to fail for no visible reason.
///
/// The protocol library cannot enforce freshness (the client supplies
/// the values), so the contract is documented here. Any client
/// implementation MUST:
///
///   1. Generate `ch_random` from a CSPRNG fresh per `ClientHello`.
///   2. Generate `eph_sk` fresh per connection.
///   3. Generate `nonce` fresh per probe.
///
pub struct ClientProbeInputs<'a> {
    /// Client's X25519 ephemeral secret. **MUST be fresh per connection.**
    /// Reusing this across connections both leaks a linkable identifier
    /// in ClientHello `key_share` and breaks forward secrecy.
    pub eph_sk: &'a StaticSecret,
    /// Bridge's X25519 static public key, learned via discovery.
    pub bridge_static_pk: &'a [u8; 32],
    /// The 32-byte `ClientHello.random` field this probe will ride with.
    /// **MUST be drawn fresh from a CSPRNG per `ClientHello`.** Reuse
    /// across connections produces a passive linkage signal; see
    /// struct-level docs.
    pub ch_random: &'a [u8; 32],
    /// 12-byte nonce. **MUST be fresh per probe** from the OS CSPRNG.
    /// Uniqueness within `TIMESTAMP_WINDOW_SECONDS` is enforced bridge-
    /// side by the replay-probe set; repeating a nonce produces a silent
    /// cover-service fallback.
    pub nonce: [u8; NONCE_LEN],
    /// Current Unix time at the client (seconds).
    pub now_unix: u32,
    /// Per-bridge probe root, learned from the authenticated invite
    /// (`INVITE_EXT_REALITY_PROBE_ROOT`). The client derives the current
    /// per-epoch probe secret from `(probe_root, probe_epoch(now_unix))` and
    /// binds it into the MAC, so a censor who scraped only the public
    /// announcement (which carries `bridge_x25519_pk`) cannot forge the probe.
    ///
    /// Pass [`PROBE_ROOT_DISABLED`] (all-zero) when the invite predates this
    /// extension; the resulting probe is byte-identical to a legacy probe.
    pub probe_root: &'a [u8; 32],
}

/// Build a 32-byte REALITY-v2 auth probe.
///
/// Rejects an all-zero X25519 shared secret (peer supplied a bogus pubkey);
/// returns [`RealityError::ZeroPoint`] in that case.
pub fn build_probe(inputs: &ClientProbeInputs<'_>) -> Result<Probe, RealityError> {
    // X25519 ECDH. Wrap the shared secret in Zeroizing so it erases on scope exit.
    let bridge_pk = PublicKey::from(*inputs.bridge_static_pk);
    let shared = Zeroizing::new(inputs.eph_sk.diffie_hellman(&bridge_pk));
    let shared_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(shared.to_bytes());
    if shared_bytes.iter().all(|&b| b == 0) {
        return Err(RealityError::ZeroPoint);
    }

    // Client's own ephemeral public key (bound into the MAC).
    let eph_pk: [u8; 32] = PublicKey::from(inputs.eph_sk).to_bytes();

    // Per-epoch probe secret (None when the invite carried no root). The epoch
    // index comes from `now_unix`; the bridge recomputes the SAME index from the
    // probe's embedded timestamp, so no epoch id rides on the wire.
    let epoch = probe_epoch(u64::from(inputs.now_unix));
    let epoch_secret = derive_epoch_probe_secret(inputs.probe_root, epoch);

    // Derive auth_key = BLAKE3-keyed(shared, label [|| epoch_secret]).
    let auth_key = derive_auth_key(&shared_bytes, epoch_secret.as_deref());

    // Compute tag.
    let tag = compute_tag(
        &auth_key,
        &inputs.nonce,
        inputs.now_unix,
        inputs.ch_random,
        &eph_pk,
    );

    // Red-team round 2: XOR-mask the timestamp with a shared-secret keystream so
    // the session_id carries NO plaintext wall-clock. A real TLS session_id is 32
    // random bytes; a monotonic timestamp in bytes [12..16] was a zero-false-
    // positive passive distinguisher. The tag is still computed over the PLAINTEXT
    // timestamp above; only the on-wire copy is masked, and the bridge (which
    // derives the same `shared`) unmasks it in `verify_probe`.
    Ok(Probe {
        nonce: inputs.nonce,
        timestamp: inputs.now_unix ^ probe_ts_mask(&shared_bytes, &inputs.nonce),
        tag,
    })
}

/// Keystream (4 bytes as a `u32`) that masks the probe timestamp on the wire.
/// Derived from the X25519 ECDH `shared` secret - which a passive observer cannot
/// compute without a private key - and the probe nonce, so client and bridge
/// derive it identically while an observer sees uniformly-random bytes where a
/// wall-clock value used to sit. Timestamp-independent (unlike the epoch secret),
/// so there is no chicken-and-egg on the bridge side.
fn probe_ts_mask(shared: &[u8; 32], nonce: &[u8]) -> u32 {
    let mut h = blake3::Hasher::new_keyed(shared);
    h.update(b"mirage-reality-probe-ts-mask-v1");
    h.update(nonce);
    let d = h.finalize();
    let b = d.as_bytes();
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

// Bridge-side: verify a probe

/// Inputs the bridge collects before calling [`verify_probe`].
pub struct BridgeProbeInputs<'a> {
    /// Bridge's X25519 static secret.
    pub bridge_static_sk: &'a StaticSecret,
    /// Client's X25519 ephemeral public key, extracted from ClientHello `key_share`.
    pub client_eph_pk: &'a [u8; 32],
    /// The incoming `ClientHello.random` field.
    pub ch_random: &'a [u8; 32],
    /// Current Unix time at the bridge (seconds).
    pub now_unix: u32,
    /// Probe bytes extracted from ClientHello `session_id`.
    pub wire_probe: [u8; SESSION_ID_LEN],
    /// Per-bridge probe root, derived at bridge startup from the bridge's
    /// X25519 static secret (`KDF(bridge_static_sk, "...probe-root...")`) - the
    /// SAME value the invite-mint embeds in the invite. The bridge derives the
    /// per-epoch probe secret from `(probe_root, probe_epoch(probe.timestamp))`.
    ///
    /// Pass [`PROBE_ROOT_DISABLED`] to run without epoch binding (legacy
    /// behaviour); verification then accepts only legacy probes.
    pub probe_root: &'a [u8; 32],
    /// When epoch binding is active (non-disabled root) and this is `true`, the
    /// bridge ALSO accepts a legacy (unbound) probe - the seamless-rollover
    /// default while the client population still holds pre-extension invites.
    /// Operators set this `false` post-rollout to close the pubkey-only
    /// enumeration hole (a legacy probe is forgeable from the announcement
    /// alone). Ignored when the root is disabled (all probes are legacy then).
    pub accept_legacy: bool,
    /// Bridge-local replay-probe set; mutable because successful verification
    /// inserts the `(nonce, timestamp)` pair.
    pub replay_set: &'a mut ReplayProbeSet,
}

/// Verify an incoming auth probe. Returns `Ok(())` on success and records
/// the `(nonce, timestamp)` in the replay set; returns a specific
/// [`RealityError`] variant on failure.
///
/// The bridge MUST fall through to cover-service forwarding on ANY error;
/// it MUST NOT emit different wire behavior to the peer based on the
/// specific error variant.
pub fn verify_probe(inputs: &mut BridgeProbeInputs<'_>) -> Result<(), RealityError> {
    // 1. Parse the wire probe.
    let probe = Probe::decode(&inputs.wire_probe)?;

    // 2. X25519 ECDH (always performed). Done FIRST because the on-wire timestamp
    //    is masked with a keystream derived from `shared` (red-team round 2), so
    //    it must be recovered before the freshness / epoch / tag steps below.
    let client_pk = PublicKey::from(*inputs.client_eph_pk);
    let shared = Zeroizing::new(inputs.bridge_static_sk.diffie_hellman(&client_pk));
    let shared_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(shared.to_bytes());
    let zero_point = shared_bytes.iter().all(|&b| b == 0);

    // Recover the real timestamp by unmasking (constant work; XOR + one BLAKE3).
    let real_ts = probe.timestamp ^ probe_ts_mask(&shared_bytes, &probe.nonce);

    // 3. Freshness. `abs(now - real_ts) <= TIMESTAMP_WINDOW_SECONDS`.
    //    Use absolute-difference via saturating arithmetic to avoid
    //    i64 subtraction surprises.
    //
    //    TIMING: do NOT early-return on a stale timestamp. A stale probe
    //    that skipped the X25519 ECDH + tag derivation would return
    //    measurably faster than a fresh-but-bad-tag probe, giving an active
    //    prober a timing oracle that says "this server runs a timestamp-
    //    windowed auth check" (a Mirage tell) even though the outer accept
    //    masks it with a parallel cover-connect. Instead record staleness
    //    and still perform the full cryptographic work below, returning the
    //    error only after constant work.
    let now = inputs.now_unix as u64;
    let ts = real_ts as u64;
    let skew = now.max(ts) - now.min(ts);
    let stale = skew > TIMESTAMP_WINDOW_SECONDS;

    // 4. Derive auth_key(s) and recompute tag(s) (always performed).
    //
    //    The epoch index is read from the PROBE's embedded timestamp, not the
    //    bridge's clock, so client and bridge agree on it with no negotiation
    //    (§probe_epoch). When the root is disabled, `epoch_secret` is None and
    //    the bound tag equals the legacy tag - the two branches collapse.
    //
    //    TIMING: both the epoch-bound and the legacy tag are ALWAYS computed and
    //    ALWAYS constant-time-compared, regardless of `probe_root`, `accept_legacy`,
    //    or which (if either) matches. The accept decision below branches only on
    //    PUBLIC configuration (root-disabled? legacy-accepted?), never on secret
    //    material, so an active prober gains no timing oracle for "does this
    //    server enforce epoch-bound probes".
    let epoch = probe_epoch(u64::from(real_ts));
    let epoch_secret = derive_epoch_probe_secret(inputs.probe_root, epoch);
    let epoch_binding_active = epoch_secret.is_some();

    let auth_key_bound = derive_auth_key(&shared_bytes, epoch_secret.as_deref());
    let expected_bound = compute_tag(
        &auth_key_bound,
        &probe.nonce,
        real_ts,
        inputs.ch_random,
        inputs.client_eph_pk,
    );
    let bound_ok = probe.tag.ct_eq(&expected_bound).unwrap_u8() == 1;

    let auth_key_legacy = derive_auth_key(&shared_bytes, None);
    let expected_legacy = compute_tag(
        &auth_key_legacy,
        &probe.nonce,
        real_ts,
        inputs.ch_random,
        inputs.client_eph_pk,
    );
    let legacy_ok = probe.tag.ct_eq(&expected_legacy).unwrap_u8() == 1;

    // 5. Accept decision (branches only on public config).
    let tag_ok = if epoch_binding_active {
        bound_ok || (inputs.accept_legacy && legacy_ok)
    } else {
        // Root disabled: bound == legacy, so either flag is equivalent.
        legacy_ok
    };

    // Decide AFTER the constant cryptographic work. All failure paths map to
    // cover-service fallback at the caller, so the specific variant is for
    // operator metrics only and is never reflected differently on the wire.
    if zero_point {
        return Err(RealityError::ZeroPoint);
    }
    if stale {
        return Err(RealityError::TimestampStale);
    }
    if !tag_ok {
        return Err(RealityError::TagMismatch);
    }

    // 6. Replay check + insertion. On full set, treat as "auth fail" so
    //    the probing client is forwarded to cover - never return an
    //    error that implies "I rejected you specifically."
    let retention = (real_ts as u64).saturating_add(TIMESTAMP_WINDOW_SECONDS * 2);
    if !inputs
        .replay_set
        .check_and_insert(&probe.nonce, real_ts, retention, now)
    {
        // Distinguish "seen" from "capacity" for operator metrics; either
        // way the caller maps both to `Auth` -> cover-service fallback.
        return Err(if inputs.replay_set.was_recently_full() {
            RealityError::ReplaySetFull
        } else {
            RealityError::Replay
        });
    }

    Ok(())
}

// Internal helpers

fn derive_auth_key(shared: &[u8; 32], epoch_secret: Option<&[u8; 32]>) -> Zeroizing<[u8; 32]> {
    // BLAKE3-keyed(shared, label [|| epoch_secret]). BLAKE3-keyed is a PRF
    // equivalent to HMAC under the same key-management discipline (spec §4.1).
    //
    // When `epoch_secret` is `Some`, the per-epoch probe secret is folded into
    // the PRF *message*: forging the auth key then requires BOTH the ECDH shared
    // secret (i.e. the bridge's PUBLIC key, in the announcement) AND the
    // 32-byte-entropy epoch secret (in the authenticated invite, NOT the
    // announcement). An adversary who scrapes announcements has the pubkey but
    // not the epoch secret, so it cannot compute this key. When `None`, the
    // output is byte-identical to the pre-epoch-binding derivation, preserving
    // wire compatibility with legacy clients/bridges.
    let mut h = blake3::Hasher::new_keyed(shared);
    h.update(AUTH_KEY_LABEL);
    if let Some(es) = epoch_secret {
        h.update(es);
    }
    Zeroizing::new(*h.finalize().as_bytes())
}

fn compute_tag(
    auth_key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    timestamp: u32,
    ch_random: &[u8; 32],
    eph_pk: &[u8; 32],
) -> [u8; TAG_LEN] {
    // tag = BLAKE3-keyed(auth_key, nonce || timestamp || CH_random || eph_pk)[0..16]
    let mut h = blake3::Hasher::new_keyed(auth_key);
    h.update(nonce);
    h.update(&timestamp.to_be_bytes());
    h.update(ch_random);
    h.update(eph_pk);
    let full = h.finalize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full.as_bytes()[..TAG_LEN]);
    tag
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).unwrap();
        s
    }

    fn fresh_bridge_keypair() -> (StaticSecret, [u8; 32]) {
        let sk = StaticSecret::from(rand_seed());
        let pk: [u8; 32] = PublicKey::from(&sk).to_bytes();
        (sk, pk)
    }

    fn fresh_client_eph() -> (StaticSecret, [u8; 32]) {
        let sk = StaticSecret::from(rand_seed());
        let pk: [u8; 32] = PublicKey::from(&sk).to_bytes();
        (sk, pk)
    }

    // ---- happy path ----

    #[test]
    fn probe_roundtrip() {
        let (bridge_sk, bridge_pk) = fresh_bridge_keypair();
        let (client_sk, client_pk) = fresh_client_eph();
        let ch_random = [0xAAu8; 32];
        let nonce = rand_seed()[..NONCE_LEN].try_into().unwrap();
        let now: u32 = 1_700_000_000;

        let probe = build_probe(&ClientProbeInputs {
            eph_sk: &client_sk,
            bridge_static_pk: &bridge_pk,
            ch_random: &ch_random,
            nonce,
            now_unix: now,
            probe_root: &PROBE_ROOT_DISABLED,
        })
        .unwrap();

        let mut rs = ReplayProbeSet::new(64);
        let wire = probe.encode();
        verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: now,
            wire_probe: wire,
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        })
        .expect("valid probe verifies");
    }

    // ---- negative: tamper detection ----

    /// Test setup tuple: bridge keys, client keys, CH random, probe nonce, and built probe.
    type SetupOut = (
        StaticSecret,    // bridge_sk
        [u8; 32],        // bridge_pk
        StaticSecret,    // client_sk
        [u8; 32],        // client_pk
        [u8; 32],        // ch_random
        [u8; NONCE_LEN], // nonce
        Probe,           // probe
    );

    fn setup(now: u32) -> SetupOut {
        let (bridge_sk, bridge_pk) = fresh_bridge_keypair();
        let (client_sk, client_pk) = fresh_client_eph();
        let ch_random = [0xAAu8; 32];
        let nonce: [u8; NONCE_LEN] = rand_seed()[..NONCE_LEN].try_into().unwrap();
        let probe = build_probe(&ClientProbeInputs {
            eph_sk: &client_sk,
            bridge_static_pk: &bridge_pk,
            ch_random: &ch_random,
            nonce,
            now_unix: now,
            probe_root: &PROBE_ROOT_DISABLED,
        })
        .unwrap();
        (
            bridge_sk, bridge_pk, client_sk, client_pk, ch_random, nonce, probe,
        )
    }

    #[test]
    fn wire_timestamp_is_masked_not_plaintext() {
        // Red-team round 2: the on-wire session_id must NOT carry the plaintext
        // Unix timestamp (a monotonic value in bytes [12..16] was a zero-FP
        // passive tell). Build with a known time and confirm the wire bytes are
        // masked, yet the bridge recovers the real value.
        let now = 1_700_000_000u32;
        let (bridge_sk, _bpk, _csk, client_pk, ch_random, _nonce, probe) = setup(now);
        let wire = probe.encode();
        let wire_ts = u32::from_be_bytes([wire[12], wire[13], wire[14], wire[15]]);
        assert_ne!(
            wire_ts, now,
            "the on-wire timestamp must be masked, not the plaintext clock"
        );
        // The bridge (which derives the same ECDH secret) still verifies it,
        // proving the mask round-trips.
        let mut rs = ReplayProbeSet::new(64);
        let res = verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: now,
            wire_probe: wire,
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        });
        assert_eq!(res, Ok(()), "masked-timestamp probe must still verify");
    }

    #[test]
    fn verify_rejects_tampered_tag() {
        let (bridge_sk, _bridge_pk, _client_sk, client_pk, ch_random, _nonce, mut probe) =
            setup(1_700_000_000);
        probe.tag[0] ^= 0x01;
        let mut rs = ReplayProbeSet::new(64);
        let res = verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: 1_700_000_000,
            wire_probe: probe.encode(),
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        });
        assert_eq!(res, Err(RealityError::TagMismatch));
    }

    #[test]
    fn verify_rejects_tampered_nonce() {
        let (bridge_sk, _bridge_pk, _client_sk, client_pk, ch_random, _nonce, mut probe) =
            setup(1_700_000_000);
        probe.nonce[0] ^= 0x01;
        let mut rs = ReplayProbeSet::new(64);
        let res = verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: 1_700_000_000,
            wire_probe: probe.encode(),
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        });
        assert!(res.is_err(), "a tampered/wrong-key probe must be rejected (variant is metrics-only: mask corrupts the recovered timestamp to stale)");
    }

    #[test]
    fn verify_rejects_wrong_ch_random() {
        let (bridge_sk, _bridge_pk, _client_sk, client_pk, _ch_random, _nonce, probe) =
            setup(1_700_000_000);
        let wrong_random = [0xBBu8; 32];
        let mut rs = ReplayProbeSet::new(64);
        let res = verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &wrong_random,
            now_unix: 1_700_000_000,
            wire_probe: probe.encode(),
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        });
        assert_eq!(res, Err(RealityError::TagMismatch));
    }

    #[test]
    fn verify_rejects_wrong_eph_pk() {
        let (bridge_sk, _bridge_pk, _client_sk, _client_pk, ch_random, _nonce, probe) =
            setup(1_700_000_000);
        let wrong_eph = [0xCCu8; 32];
        let mut rs = ReplayProbeSet::new(64);
        let res = verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &wrong_eph,
            ch_random: &ch_random,
            now_unix: 1_700_000_000,
            wire_probe: probe.encode(),
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        });
        // Wrong eph_pk produces wrong shared secret -> wrong auth_key -> wrong tag.
        assert!(res.is_err(), "a tampered/wrong-key probe must be rejected (variant is metrics-only: mask corrupts the recovered timestamp to stale)");
    }

    #[test]
    fn verify_rejects_wrong_bridge_sk() {
        let (_bridge_sk, _bridge_pk, _client_sk, client_pk, ch_random, _nonce, probe) =
            setup(1_700_000_000);
        let (other_bridge_sk, _) = fresh_bridge_keypair();
        let mut rs = ReplayProbeSet::new(64);
        let res = verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &other_bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: 1_700_000_000,
            wire_probe: probe.encode(),
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        });
        // Wrong bridge sk -> wrong shared -> wrong auth_key -> wrong tag.
        assert!(res.is_err(), "a tampered/wrong-key probe must be rejected (variant is metrics-only: mask corrupts the recovered timestamp to stale)");
    }

    // ---- negative: timestamp window ----

    #[test]
    fn verify_rejects_stale_timestamp() {
        let (bridge_sk, _bridge_pk, _client_sk, client_pk, ch_random, _nonce, probe) =
            setup(1_700_000_000);
        let mut rs = ReplayProbeSet::new(64);
        let too_new = 1_700_000_000u32 + (TIMESTAMP_WINDOW_SECONDS as u32) + 1;
        let res = verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: too_new,
            wire_probe: probe.encode(),
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        });
        assert_eq!(res, Err(RealityError::TimestampStale));
    }

    #[test]
    fn verify_rejects_future_timestamp_out_of_window() {
        let (bridge_sk, _bridge_pk, _client_sk, client_pk, ch_random, _nonce, probe) =
            setup(1_700_000_000);
        let mut rs = ReplayProbeSet::new(64);
        let too_old = 1_700_000_000u32 - (TIMESTAMP_WINDOW_SECONDS as u32) - 1;
        let res = verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: too_old,
            wire_probe: probe.encode(),
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        });
        assert_eq!(res, Err(RealityError::TimestampStale));
    }

    #[test]
    fn verify_accepts_at_window_edge() {
        let (bridge_sk, _bridge_pk, _client_sk, client_pk, ch_random, _nonce, probe) =
            setup(1_700_000_000);
        let mut rs = ReplayProbeSet::new(64);
        // Exactly at the window boundary - MUST accept (inclusive).
        let boundary = 1_700_000_000u32 + TIMESTAMP_WINDOW_SECONDS as u32;
        verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: boundary,
            wire_probe: probe.encode(),
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        })
        .expect("window-edge probe must verify");
    }

    // ---- negative: replay ----

    #[test]
    fn verify_rejects_replay() {
        let (bridge_sk, _bridge_pk, _client_sk, client_pk, ch_random, _nonce, probe) =
            setup(1_700_000_000);
        let mut rs = ReplayProbeSet::new(64);
        verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: 1_700_000_000,
            wire_probe: probe.encode(),
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        })
        .unwrap();
        // Second use of the same (nonce, timestamp) MUST fail.
        let res = verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: 1_700_000_000,
            wire_probe: probe.encode(),
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        });
        assert_eq!(res, Err(RealityError::Replay));
    }

    // ---- wire format ----

    #[test]
    fn probe_encode_decode_roundtrip() {
        let p = Probe {
            nonce: [0x11u8; NONCE_LEN],
            timestamp: 1_700_000_000,
            tag: [0x22u8; TAG_LEN],
        };
        let encoded = p.encode();
        assert_eq!(encoded.len(), SESSION_ID_LEN);
        let decoded = Probe::decode(&encoded).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(
            Probe::decode(&[0u8; SESSION_ID_LEN - 1]),
            Err(RealityError::SessionIdLen)
        );
        assert_eq!(
            Probe::decode(&[0u8; SESSION_ID_LEN + 1]),
            Err(RealityError::SessionIdLen)
        );
    }

    // ---- cross-probe isolation ----

    #[test]
    fn different_clients_produce_different_tags() {
        let (_, bridge_pk) = fresh_bridge_keypair();
        let (client_a_sk, _) = fresh_client_eph();
        let (client_b_sk, _) = fresh_client_eph();
        let ch_random = [0xAAu8; 32];
        let nonce = rand_seed()[..NONCE_LEN].try_into().unwrap();
        let now = 1_700_000_000u32;

        let pa = build_probe(&ClientProbeInputs {
            eph_sk: &client_a_sk,
            bridge_static_pk: &bridge_pk,
            ch_random: &ch_random,
            nonce,
            now_unix: now,
            probe_root: &PROBE_ROOT_DISABLED,
        })
        .unwrap();
        let pb = build_probe(&ClientProbeInputs {
            eph_sk: &client_b_sk,
            bridge_static_pk: &bridge_pk,
            ch_random: &ch_random,
            nonce,
            now_unix: now,
            probe_root: &PROBE_ROOT_DISABLED,
        })
        .unwrap();
        assert_ne!(pa.tag, pb.tag);
    }

    #[test]
    fn same_probe_different_random_produces_different_tag() {
        let (_, bridge_pk) = fresh_bridge_keypair();
        let (client_sk, _) = fresh_client_eph();
        let nonce = rand_seed()[..NONCE_LEN].try_into().unwrap();
        let now = 1_700_000_000u32;
        let p1 = build_probe(&ClientProbeInputs {
            eph_sk: &client_sk,
            bridge_static_pk: &bridge_pk,
            ch_random: &[0xAAu8; 32],
            nonce,
            now_unix: now,
            probe_root: &PROBE_ROOT_DISABLED,
        })
        .unwrap();
        let p2 = build_probe(&ClientProbeInputs {
            eph_sk: &client_sk,
            bridge_static_pk: &bridge_pk,
            ch_random: &[0xBBu8; 32],
            nonce,
            now_unix: now,
            probe_root: &PROBE_ROOT_DISABLED,
        })
        .unwrap();
        assert_ne!(p1.tag, p2.tag);
    }

    // ---- epoch-ratcheted anti-enumeration binding ----

    const R1: [u8; 32] = [0x11u8; 32];
    const R2: [u8; 32] = [0x22u8; 32];
    /// A fixed, in-window time far from any epoch boundary.
    const T: u32 = 1_700_000_000;

    /// Full build+verify with explicit roots/flags/clocks. Client and bridge
    /// share a freshly generated keypair (consistent ECDH) within the call.
    fn build_and_verify(
        client_root: &[u8; 32],
        bridge_root: &[u8; 32],
        accept_legacy: bool,
        client_now: u32,
        bridge_now: u32,
    ) -> Result<(), RealityError> {
        let (bridge_sk, bridge_pk) = fresh_bridge_keypair();
        let (client_sk, client_pk) = fresh_client_eph();
        let ch_random = [0x5Au8; 32];
        let nonce: [u8; NONCE_LEN] = rand_seed()[..NONCE_LEN].try_into().unwrap();
        let probe = build_probe(&ClientProbeInputs {
            eph_sk: &client_sk,
            bridge_static_pk: &bridge_pk,
            ch_random: &ch_random,
            nonce,
            now_unix: client_now,
            probe_root: client_root,
        })
        .unwrap();
        let mut rs = ReplayProbeSet::new(64);
        verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: bridge_now,
            wire_probe: probe.encode(),
            probe_root: bridge_root,
            accept_legacy,
            replay_set: &mut rs,
        })
    }

    #[test]
    fn probe_epoch_boundaries() {
        assert_eq!(probe_epoch(0), 0);
        assert_eq!(probe_epoch(PROBE_EPOCH_SECONDS - 1), 0);
        assert_eq!(probe_epoch(PROBE_EPOCH_SECONDS), 1);
        assert_eq!(probe_epoch(PROBE_EPOCH_SECONDS * 2 + 5), 2);
    }

    #[test]
    fn epoch_secret_rotates_and_is_root_bound() {
        let s_e0 = derive_epoch_probe_secret(&R1, 0).expect("root enabled");
        let s_e1 = derive_epoch_probe_secret(&R1, 1).expect("root enabled");
        assert_ne!(*s_e0, *s_e1, "different epochs -> different secrets");
        let s2_e0 = derive_epoch_probe_secret(&R2, 0).expect("root enabled");
        assert_ne!(*s_e0, *s2_e0, "different roots -> different secrets");
        assert!(
            derive_epoch_probe_secret(&PROBE_ROOT_DISABLED, 0).is_none(),
            "disabled (all-zero) root -> None"
        );
    }

    #[test]
    fn epoch_bound_roundtrip_strict() {
        build_and_verify(&R1, &R1, false, T, T).expect("matching root, strict, verifies");
    }

    #[test]
    fn epoch_bound_roundtrip_dual() {
        build_and_verify(&R1, &R1, true, T, T).expect("matching root, dual, verifies");
    }

    #[test]
    fn strict_bridge_rejects_legacy_probe() {
        // THE anti-enumeration property. A censor who scraped the public
        // announcement holds the bridge pubkey and can build a *legacy* probe
        // (disabled root), but NOT the invite-only root. A strict bridge
        // (accept_legacy = false) MUST reject it -> pubkey-only enumeration
        // is closed.
        assert_eq!(
            build_and_verify(&PROBE_ROOT_DISABLED, &R1, false, T, T),
            Err(RealityError::TagMismatch)
        );
    }

    #[test]
    fn dual_bridge_accepts_legacy_probe() {
        // Rollover compatibility: during migration a provisioned (root R1)
        // bridge still accepts a legacy probe so pre-extension clients keep
        // working. This is the seamless default.
        build_and_verify(&PROBE_ROOT_DISABLED, &R1, true, T, T)
            .expect("dual bridge accepts legacy probe during rollover");
    }

    #[test]
    fn strict_bridge_rejects_wrong_root() {
        // Client used root R1; bridge holds R2. Bound tag mismatches and the
        // probe isn't legacy -> reject even before considering accept_legacy.
        assert_eq!(
            build_and_verify(&R1, &R2, false, T, T),
            Err(RealityError::TagMismatch)
        );
    }

    #[test]
    fn dual_bridge_rejects_wrong_nonlegacy_root() {
        // A bound probe under R1 against a bridge holding R2: neither the
        // bound(R2) tag nor the legacy tag matches, so dual mode still rejects.
        assert_eq!(
            build_and_verify(&R1, &R2, true, T, T),
            Err(RealityError::TagMismatch)
        );
    }

    #[test]
    fn old_bridge_rejects_bound_probe() {
        // A bound probe (client has a root) reaching a bridge with the root
        // disabled does not verify: the epoch secret was folded in on the
        // client but not on the bridge. Documents the (non-occurring: invites
        // are minted with the bridge) new-client/old-bridge quadrant.
        assert_eq!(
            build_and_verify(&R1, &PROBE_ROOT_DISABLED, true, T, T),
            Err(RealityError::TagMismatch)
        );
    }

    #[test]
    fn disabled_root_both_sides_verifies() {
        // Legacy <-> legacy interop (the pre-extension world), both flag values.
        build_and_verify(&PROBE_ROOT_DISABLED, &PROBE_ROOT_DISABLED, false, T, T)
            .expect("legacy<->legacy verifies (strict)");
        build_and_verify(&PROBE_ROOT_DISABLED, &PROBE_ROOT_DISABLED, true, T, T)
            .expect("legacy<->legacy verifies (dual)");
    }

    #[test]
    fn bridge_uses_probe_timestamp_epoch_not_its_own_clock() {
        // Probe built 1s before an epoch boundary (epoch e); the bridge's clock
        // has crossed into epoch e+1 but is within the 60s freshness window. The
        // bridge MUST derive the epoch from the probe's OWN timestamp (epoch e),
        // otherwise the bound tag would mismatch across the midnight boundary.
        let client_now = (PROBE_EPOCH_SECONDS as u32) * 20 - 1;
        let bridge_now = client_now + 2;
        assert_ne!(
            probe_epoch(u64::from(client_now)),
            probe_epoch(u64::from(bridge_now)),
            "test precondition: the two clocks straddle an epoch boundary"
        );
        build_and_verify(&R1, &R1, false, client_now, bridge_now).expect(
            "bridge derives epoch from the probe timestamp, so it verifies across the boundary",
        );
    }
}
