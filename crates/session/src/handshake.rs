//! Noise-XX + ML-KEM-768 + capability-token handshake state machine.
//!
//! Two state machines: [`HandshakeInitiator`] (client side) and
//! [`HandshakeResponder`] (bridge side). Both consume and produce fixed-size
//! wire messages. Message 3 carries a 136-byte [`CapabilityToken`] payload
//! inside Noise's AEAD; the responder verifies (bridge-pinning, signature,
//! expiry, replay) before transitioning to transport mode.

use mirage_crypto::hybrid_kem::{
    generate_keypair as mlkem_generate, MlKemDk, MlKemEk, MLKEM_CT_BYTES, MLKEM_EK_BYTES,
    MLKEM_SS_BYTES,
};
use mirage_crypto::zeroize::Zeroizing;
use mirage_discovery::replay::{ReplaySet, SyncReplaySet};
use mirage_discovery::token::CapabilityToken;
use mirage_discovery::token_fs::FsCapabilityToken;
use snow::HandshakeState;

use crate::error::SessionError;
use crate::wire::{
    Message1, Message2, Message3, FS_TOKEN_PAYLOAD_LEN, NOISE_MSG_1_LEN, NOISE_MSG_2_LEN,
    NOISE_MSG_3_LEN_NO_TOKEN, NOISE_MSG_3_LEN_WITH_FS_TOKEN, NOISE_MSG_3_LEN_WITH_TOKEN,
    TOKEN_PAYLOAD_LEN,
};

/// Noise handshake pattern used by Mirage v0.1 (spec §2).
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

/// Clock-skew grace window applied to token `expires_at` checks (seconds).
pub const TOKEN_GRACE_SECONDS: u64 = 60;

// SessionKeys - material produced by a completed handshake

/// Material produced by a completed handshake.
///
/// `session_binding` is a public transcript hash and is not secret.
/// `mlkem_ss` IS secret; callers MUST zeroize it via [`SessionKeys::zeroize_ss`]
/// if not immediately handed off to a consumer (such as [`crate::SessionFramer`])
/// that zeroizes its own local copy. The struct does NOT implement `Drop`
/// because we rely on partial-move semantics (`let transport = keys.transport`)
/// in consumers; Rust forbids partial-move on `Drop`-implementing types.
///
/// `transport` owns snow's internal keys; snow does not currently zeroize
/// on drop (tracked as an upstream concern).
pub struct SessionKeys {
    /// Session binding (spec §3.5): BLAKE3 of Noise transcript + ML-KEM bytes.
    /// Identical on both sides. Public transcript hash; not secret.
    pub session_binding: [u8; 32],
    /// Noise transport state for post-handshake AEAD frames.
    pub transport: snow::TransportState,
    /// ML-KEM-768 shared secret. Identical on both sides. **Callers MUST
    /// zeroize** (via `zeroize_ss` or consumer handoff) before dropping.
    pub mlkem_ss: [u8; MLKEM_SS_BYTES],
}

impl SessionKeys {
    /// Zero out `mlkem_ss`. Call this if the `SessionKeys` won't be passed
    /// into a consumer that zeroizes its own local copy.
    pub fn zeroize_ss(&mut self) {
        use mirage_crypto::zeroize::Zeroize;
        self.mlkem_ss.zeroize();
    }
}

// Explicit, non-derived `Debug` that refuses to print secret material.
//
// `#[derive(Debug)]` on `SessionKeys` would print `mlkem_ss` byte-by-byte
// the first time a caller drops the struct into a `tracing::error!` or
// `dbg!`. Under the "lives at stake" threat model we'd then have the
// shared secret in an operator's journald, sentry trace, or container
// logger - and from there in backups, sidecar shippers, and whoever else
// reads logs. The `zeroize` discipline in memory is worthless if we hand
// the bytes to syslog first.
//
// We show:
// - `session_binding` (BLAKE3 of the transcript; public by spec §3.5),
// - a hex prefix of that binding for grep-ability in logs,
// - `mlkem_ss` length only, with the value elided,
// - `transport` as `<redacted>` (snow keeps raw keys inside it).
//
// If a future change adds a secret field, this impl must be updated in
// the same PR - that is the point of not deriving.
impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let sb_hex: String = self
            .session_binding
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        f.debug_struct("SessionKeys")
            .field("session_binding_prefix", &format_args!("{sb_hex}..."))
            .field(
                "mlkem_ss",
                &format_args!("<redacted: {} bytes>", MLKEM_SS_BYTES),
            )
            .field(
                "transport",
                &format_args!("<redacted: snow::TransportState>"),
            )
            .finish()
    }
}

// Session-binding derivation (spec §3.5)

fn derive_session_binding(
    wire_version: u16,
    noise_h: &[u8; 32],
    mlkem_ek: &[u8; MLKEM_EK_BYTES],
    mlkem_ct: &[u8; MLKEM_CT_BYTES],
    mlkem_ss: &[u8; MLKEM_SS_BYTES],
) -> [u8; 32] {
    let mut hasher = mirage_crypto::blake3::Hasher::new();
    hasher.update(b"mirage-session-binding-v1");
    hasher.update(&wire_version.to_be_bytes());
    hasher.update(noise_h);
    hasher.update(mlkem_ek);
    hasher.update(mlkem_ct);
    hasher.update(mlkem_ss);
    *hasher.finalize().as_bytes()
}

fn noise_h_32(noise: &HandshakeState) -> Result<[u8; 32], SessionError> {
    let slice = noise.get_handshake_hash();
    // Why: snow's Noise_XX_25519_ChaChaPoly_SHA256 hash is always 32 bytes.
    // A regression that returned a different length (or shorter) would
    // silently zero-pad, producing a transcript binding that misses
    // entropy. Hard-fail rather than silently degrade.
    if slice.len() != 32 {
        return Err(SessionError::Wire(
            "noise transcript hash unexpected length",
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

fn build_noise_base() -> Result<snow::Builder<'static>, SessionError> {
    Ok(snow::Builder::new(NOISE_PATTERN.parse().map_err(|_| {
        SessionError::Wire("invalid noise pattern")
    })?))
}

/// Verify a presented token as a bridge-issued refresh token under
/// `refresh_pk`. Used as the last-resort fallback in
/// [`HandshakeResponder::read_message_3`] after both current- and
/// previous-operator paths have been tried.
fn verify_refresh_path(
    token: &CapabilityToken,
    refresh_pk: &[u8; 32],
) -> Result<AcceptedTokenKind, SessionError> {
    use mirage_crypto::ed25519_dalek::{Signature, VerifyingKey};
    use mirage_discovery::refresh::REFRESH_SIGN_DOMAIN;
    use mirage_discovery::token::TOKEN_SIGNED_PREFIX_LEN;
    let vk = VerifyingKey::from_bytes(refresh_pk)
        .map_err(|_| SessionError::TokenVerification("refresh issuer pk invalid"))?;
    let mut prefix = Vec::with_capacity(REFRESH_SIGN_DOMAIN.len() + TOKEN_SIGNED_PREFIX_LEN);
    prefix.extend_from_slice(REFRESH_SIGN_DOMAIN);
    token.encode_signed_prefix(&mut prefix);
    let sig = Signature::from_bytes(&token.signature);
    vk.verify_strict(&prefix, &sig)
        .map_err(|_| SessionError::TokenVerification("signature verification failed"))?;
    Ok(AcceptedTokenKind::Refresh)
}

// TokenVerifier - per-bridge verification context passed into read_message_3

/// Which kind of token was accepted by the responder, for caller
/// state correlation and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptedTokenKind {
    /// Operator-signed bootstrap or cohort-distributed token (spec §6.1 Tier-1).
    Bootstrap,
    /// Bridge-self-signed session refresh token (see
    /// `mirage_discovery::refresh`). Issued by this bridge in a
    /// previous session and presented here for re-authentication.
    Refresh,
}

/// Replay-set backend used by [`TokenVerifier`].
///
/// Two flavours:
/// - [`Owned`] - a borrowed `&mut ReplaySet` for tests and single-
///   threaded bridge configurations. The verifier holds the mutable
///   borrow for its lifetime.
/// - [`Shared`] - a borrowed `&SyncReplaySet` for the production
///   bridge path. The lock is acquired briefly inside
///   [`SyncReplaySet::check_and_insert`] and released immediately;
///   concurrent handshakes never serialize behind one async-mutex
///   guard held across the full Noise exchange.
///
/// Audit fix (CRITICAL-Trust-1): the prior bridge configuration held
/// a `tokio::sync::Mutex<ReplaySet>` lock for the entire handshake
/// (handshake_timeout = 10 s default), making one slow attacker a
/// global onboarding-rate cap.
///
/// [`Owned`]: ReplayBackend::Owned
/// [`Shared`]: ReplayBackend::Shared
pub enum ReplayBackend<'a> {
    /// Mutably-borrowed in-process replay set.
    Owned(&'a mut ReplaySet),
    /// Shared, internally-locked replay set.
    Shared(&'a SyncReplaySet),
}

impl ReplayBackend<'_> {
    fn check_and_insert(&mut self, token_id: &[u8; 32], expires_at: u64, now_unix: u64) -> bool {
        match self {
            ReplayBackend::Owned(rs) => rs.check_and_insert(token_id, expires_at, now_unix),
            ReplayBackend::Shared(rs) => rs.check_and_insert(token_id, expires_at, now_unix),
        }
    }
}

/// Context a bridge passes into [`HandshakeResponder::read_message_3`] to
/// verify the initiator-presented capability token.
pub struct TokenVerifier<'a> {
    /// Bridge-local replay set backend; MUST persist across handshakes.
    pub replay_set: ReplayBackend<'a>,
    /// Current Unix time used for expiry checks.
    pub now_unix: u64,
    /// Grace seconds added to token `expires_at` to absorb clock skew.
    pub grace_seconds: u64,
    /// After a successful verification, the `token_id` that was
    /// accepted. Caller reads this to correlate per-token state
    /// (e.g. cohort-service rationing). `None` if the last verify
    /// failed or this is the no-token path.
    pub last_accepted_token_id: Option<[u8; 32]>,
    /// Kind of token last accepted. Mirrors
    /// [`Self::last_accepted_token_id`]'s lifecycle.
    pub last_accepted_kind: Option<AcceptedTokenKind>,
    /// Optional bridge-self-signed-refresh-token acceptance path.
    ///
    /// When `Some(bridge_pk)`, the verifier will fall through to
    /// refresh-token verification (see
    /// `mirage_discovery::refresh::SessionRefreshToken`) if the
    /// operator-signature path rejects the presented token. This
    /// lets long-lived clients re-use a previously-issued refresh
    /// token in place of a single-use bootstrap token.
    ///
    /// `None` (default) means "operator-signed tokens only" - the
    /// v0.1 conformant baseline.
    pub accept_refresh_signed_by: Option<[u8; 32]>,
    /// Optional previous-operator pubkey accepted during a
    /// rotation overlap window (v0.1i).
    ///
    /// When `Some(prev_pk)`, a token that fails signature
    /// verification under the primary `operator_pk` is given one
    /// more chance against this key. Covers graceful mother-key
    /// rotation: during the overlap, both the old and new invite
    /// sets work at the bridge. Removed after the overlap ends.
    ///
    /// Verified BEFORE the refresh-token fallback so a valid
    /// old-operator token is recognised as
    /// [`AcceptedTokenKind::Bootstrap`] rather than
    /// [`AcceptedTokenKind::Refresh`].
    pub accept_prev_operator_pk: Option<[u8; 32]>,
}

impl<'a> TokenVerifier<'a> {
    /// Construct a verifier with the default [`TOKEN_GRACE_SECONDS`] grace.
    /// The replay set is passed by mutable borrow - the verifier holds
    /// the borrow for its lifetime. Single-threaded; suitable for tests.
    pub fn new(replay_set: &'a mut ReplaySet, now_unix: u64) -> Self {
        Self {
            replay_set: ReplayBackend::Owned(replay_set),
            now_unix,
            grace_seconds: TOKEN_GRACE_SECONDS,
            last_accepted_token_id: None,
            last_accepted_kind: None,
            accept_refresh_signed_by: None,
            accept_prev_operator_pk: None,
        }
    }

    /// Construct a verifier backed by a shared, internally-locked
    /// replay set. The verifier holds only a shared borrow; the
    /// internal `std::sync::Mutex` is acquired briefly during the
    /// `check_and_insert` step and never across `.await` points.
    /// Use this in the production bridge path so concurrent
    /// handshakes don't serialize behind one async-mutex guard.
    pub fn new_shared(replay_set: &'a SyncReplaySet, now_unix: u64) -> Self {
        Self {
            replay_set: ReplayBackend::Shared(replay_set),
            now_unix,
            grace_seconds: TOKEN_GRACE_SECONDS,
            last_accepted_token_id: None,
            last_accepted_kind: None,
            accept_refresh_signed_by: None,
            accept_prev_operator_pk: None,
        }
    }

    /// Enable the refresh-token acceptance fallback. When set, a
    /// presented token that doesn't verify under the operator key
    /// is given a second chance against `bridge_pk` using the
    /// `mirage-refresh-v1` domain-separated signing prefix.
    pub fn with_refresh_issuer(mut self, bridge_pk: &[u8; 32]) -> Self {
        self.accept_refresh_signed_by = Some(*bridge_pk);
        self
    }

    /// Enable the previous-operator acceptance fallback for a
    /// rotation overlap window. `prev_pk` is the operator's
    /// PREVIOUS long-term Ed25519 pubkey; tokens signed by it are
    /// still accepted (subject to expiry + replay checks) until
    /// the operator removes this from the bridge config.
    pub fn with_prev_operator(mut self, prev_pk: &[u8; 32]) -> Self {
        self.accept_prev_operator_pk = Some(*prev_pk);
        self
    }
}

// Initiator

#[derive(Debug, PartialEq, Eq)]
enum InitiatorState {
    Fresh,
    AwaitMessage2,
    Complete,
}

/// Client-side handshake state machine.
///
/// Call sequence: [`HandshakeInitiator::new`] -> [`HandshakeInitiator::write_message_1`] ->
/// [`HandshakeInitiator::read_message_2`] -> [`HandshakeInitiator::write_message_3`].
///
/// **Does not implement `Debug`** (I12). It holds `Option<Zeroizing<[u8; 32]>>`
/// with the ML-KEM shared secret, and `Zeroizing<T>` deliberately has no
/// `Debug` impl - the compiler will reject any future `#[derive(Debug)]`.
/// If you find yourself wanting to log a handshake state, log the
/// `SessionKeys` produced by `write_message_3` instead, which has a
/// redacted manual `Debug` impl.
pub struct HandshakeInitiator {
    noise: HandshakeState,
    mlkem_dk: MlKemDk,
    mlkem_ek_bytes: [u8; MLKEM_EK_BYTES],
    mlkem_ct_bytes: Option<[u8; MLKEM_CT_BYTES]>,
    /// Secret. `Zeroizing<[u8; 32]>` zeroes on drop even if the initiator
    /// is dropped mid-state (e.g., via panic or error path).
    mlkem_ss: Option<Zeroizing<[u8; MLKEM_SS_BYTES]>>,
    wire_version: u16,
    state: InitiatorState,
    expected_remote_static: [u8; 32],
    /// Encoded 136-byte token presented in msg 3. `None` for test-only
    /// state-machine exercises (produces a 67-byte msg 3); a conformant
    /// client always sets this. Wrapped in `Zeroizing` because the token
    /// binds to a specific bridge and leaking it post-use could help a
    /// forensic attacker cross-reference clients.
    ///
    /// Length is either [`TOKEN_PAYLOAD_LEN`] (legacy operator-signed token)
    /// or [`FS_TOKEN_PAYLOAD_LEN`] (forward-secure epoch-subkey token); the
    /// responder dispatches on the decrypted payload length.
    token_bytes: Option<Zeroizing<Vec<u8>>>,
}

impl HandshakeInitiator {
    /// Construct a new conformant initiator. The token is included in
    /// message 3's Noise payload and verified by the responder.
    pub fn new(
        local_static_sk: &[u8; 32],
        remote_static_pk: &[u8; 32],
        token: &CapabilityToken,
    ) -> Result<Self, SessionError> {
        let mut me = Self::new_common(local_static_sk, remote_static_pk)?;
        me.token_bytes = Some(Zeroizing::new(token.encode().to_vec()));
        Ok(me)
    }

    /// Construct a conformant initiator presenting a **forward-secure**
    /// capability token ([`FsCapabilityToken`]). The token embeds its inline
    /// epoch-subkey cert; the responder verifies the root->subkey->token chain
    /// against the pinned operator (root) key. Emits the 315-byte
    /// FS-token-bearing form of message 3.
    pub fn new_fs(
        local_static_sk: &[u8; 32],
        remote_static_pk: &[u8; 32],
        token: &FsCapabilityToken,
    ) -> Result<Self, SessionError> {
        let mut me = Self::new_common(local_static_sk, remote_static_pk)?;
        me.token_bytes = Some(Zeroizing::new(token.encode().to_vec()));
        Ok(me)
    }

    /// **DANGER: test-only.** Constructs an initiator that emits the 67-byte
    /// no-token form of message 3. Used by state-machine smoke tests and
    /// fuzz harnesses; gated behind `#[cfg(test)]` or the
    /// `danger-no-token` cargo feature. The crate refuses to compile in
    /// release profile if that feature is set - see `lib.rs` compile_error.
    ///
    /// The `_danger_` prefix is load-bearing: every call site is grep-able
    /// and code review can reject any production path that ends up here.
    #[cfg(any(test, feature = "danger-no-token"))]
    pub fn _danger_new_without_token(
        local_static_sk: &[u8; 32],
        remote_static_pk: &[u8; 32],
    ) -> Result<Self, SessionError> {
        Self::new_common(local_static_sk, remote_static_pk)
    }

    /// Create an initiator for a **circuit-hop handshake** inside an already
    /// authenticated Mirage session.
    ///
    /// A circuit CREATE/CREATED exchange is a second Noise XX run purely for
    /// per-hop key derivation. The transport session already authenticated the
    /// client via `CapabilityToken`, so no token is needed here - the
    /// responder uses `write_message_2_for_circuit_hop` (which likewise skips
    /// token verification). This constructor is the production-safe entry
    /// point for that path.
    pub fn new_for_circuit_hop(
        local_static_sk: &[u8; 32],
        remote_static_pk: &[u8; 32],
    ) -> Result<Self, SessionError> {
        Self::new_common(local_static_sk, remote_static_pk)
    }

    fn new_common(
        local_static_sk: &[u8; 32],
        remote_static_pk: &[u8; 32],
    ) -> Result<Self, SessionError> {
        let noise = build_noise_base()?
            .local_private_key(local_static_sk)
            .remote_public_key(remote_static_pk)
            .build_initiator()?;
        let (ek, dk) = mlkem_generate();
        Ok(Self {
            noise,
            mlkem_dk: dk,
            mlkem_ek_bytes: ek.to_bytes(),
            mlkem_ct_bytes: None,
            mlkem_ss: None,
            wire_version: mirage_spec::WIRE_VERSION,
            state: InitiatorState::Fresh,
            expected_remote_static: *remote_static_pk,
            token_bytes: None,
        })
    }

    /// Produce message 1 to send on the wire.
    pub fn write_message_1(&mut self) -> Result<Vec<u8>, SessionError> {
        if self.state != InitiatorState::Fresh {
            return Err(SessionError::State("write_message_1: wrong state"));
        }
        // I24: carry mlkem_ek as the Noise message-1 PAYLOAD so it is folded
        // into the Noise transcript hash. Message 1 is unkeyed, so the payload
        // rides in cleartext (no AEAD tag) - but any substitution diverges the
        // peers' transcripts and breaks message-2 authentication, aborting the
        // handshake early rather than at the first outer-layer frame. The
        // resulting on-wire bytes (`e || mlkem_ek`) are identical to the prior
        // separately-appended layout.
        let mut snow_out = vec![0u8; NOISE_MSG_1_LEN + 16];
        let n = self
            .noise
            .write_message(&self.mlkem_ek_bytes, &mut snow_out)?;
        if n != NOISE_MSG_1_LEN {
            return Err(SessionError::State("noise msg 1: unexpected length"));
        }
        let mut noise_msg_1 = [0u8; NOISE_MSG_1_LEN];
        noise_msg_1.copy_from_slice(&snow_out[..NOISE_MSG_1_LEN]);

        let msg = Message1 {
            wire_version: self.wire_version,
            noise_msg_1,
        };
        self.state = InitiatorState::AwaitMessage2;
        Ok(msg.encode())
    }

    /// Consume message 2 from the responder.
    pub fn read_message_2(&mut self, wire: &[u8]) -> Result<(), SessionError> {
        if self.state != InitiatorState::AwaitMessage2 {
            return Err(SessionError::State("read_message_2: wrong state"));
        }
        let msg = Message2::decode(wire)?;
        if msg.wire_version != self.wire_version {
            return Err(SessionError::VersionMismatch {
                peer: msg.wire_version,
                min: mirage_spec::WIRE_VERSION,
                max: mirage_spec::WIRE_VERSION,
            });
        }
        // I24: mlkem_ct is the AEAD-encrypted Noise message-2 PAYLOAD. Reading
        // it back through Noise both authenticates it (a tampered ct fails this
        // `read_message` outright, aborting the handshake) and binds it into the
        // transcript. Buffer is sized to the whole Noise message and zeroes on
        // drop.
        let mut payload_out = Zeroizing::new([0u8; NOISE_MSG_2_LEN]);
        let payload_len = self
            .noise
            .read_message(&msg.noise_msg_2, payload_out.as_mut())?;
        if payload_len != MLKEM_CT_BYTES {
            return Err(SessionError::Wire("message 2: unexpected mlkem_ct length"));
        }

        // Bridge-identity check: the responder static carried inside
        // Noise-XX's `s` token MUST match what we pre-set. snow does not
        // enforce this for XX.
        let got_rs = self
            .noise
            .get_remote_static()
            .ok_or(SessionError::State("no remote static after msg 2"))?;
        use mirage_crypto::subtle::ConstantTimeEq;
        if got_rs.ct_eq(&self.expected_remote_static).unwrap_u8() == 0 {
            return Err(SessionError::Noise(snow::Error::Decrypt));
        }

        let mut mlkem_ct = [0u8; MLKEM_CT_BYTES];
        mlkem_ct.copy_from_slice(&payload_out[..MLKEM_CT_BYTES]);
        let ss = self.mlkem_dk.decapsulate(&mlkem_ct);
        self.mlkem_ct_bytes = Some(mlkem_ct);
        self.mlkem_ss = Some(Zeroizing::new(ss));
        Ok(())
    }

    /// Extract circuit-level hop key material immediately after
    /// `read_message_2` and before `write_message_3`.
    ///
    /// Returns `(mlkem_ss, circuit_binding)` where `circuit_binding`
    /// uses `noise_h` at the post-msg2 point - matching the responder's
    /// `write_message_2_for_circuit_hop`. Both sides therefore derive
    /// identical per-hop circuit keys without including msg3 in the
    /// transcript.
    ///
    /// Errors if called before `read_message_2` (mlkem_ss not yet set)
    /// or after `write_message_3` (noise state destroyed).
    ///
    /// Used by `SingleTransportHopRuntime::extend_hop` in Phase 2G+
    /// so circuit HopKeys are stable before msg3 is sent.
    pub fn circuit_hop_binding(&self) -> Result<([u8; MLKEM_SS_BYTES], [u8; 32]), SessionError> {
        let mlkem_ss: &[u8; MLKEM_SS_BYTES] = self.mlkem_ss.as_deref().ok_or(
            SessionError::State("circuit_hop_binding: call after read_message_2"),
        )?;
        let mlkem_ct = self.mlkem_ct_bytes.ok_or(SessionError::State(
            "circuit_hop_binding: mlkem_ct missing (call after read_message_2)",
        ))?;
        // After read_message_2, noise_h includes msg1+msg2 - same point
        // as the responder after write_message_2.
        let noise_h = noise_h_32(&self.noise)?;
        let circuit_binding = derive_session_binding(
            self.wire_version,
            &noise_h,
            &self.mlkem_ek_bytes,
            &mlkem_ct,
            mlkem_ss,
        );
        Ok((*mlkem_ss, circuit_binding))
    }

    /// Produce message 3 and complete the handshake.
    pub fn write_message_3(mut self) -> Result<(Vec<u8>, SessionKeys), SessionError> {
        if self.state != InitiatorState::AwaitMessage2 {
            return Err(SessionError::State("write_message_3: wrong state"));
        }

        // Payload is the token if present (136-byte legacy or 248-byte FS),
        // else empty (test-only). The expected Noise length follows the token
        // size; anything else means the Noise layer surprised us.
        let (payload_slice, expected_noise_len): (&[u8], usize) = match &self.token_bytes {
            Some(bytes) if bytes.len() == FS_TOKEN_PAYLOAD_LEN => {
                (&bytes[..], NOISE_MSG_3_LEN_WITH_FS_TOKEN)
            }
            Some(bytes) => (&bytes[..], NOISE_MSG_3_LEN_WITH_TOKEN),
            None => (&[][..], NOISE_MSG_3_LEN_NO_TOKEN),
        };

        // Output buffer generously sized for any form (FS is the largest).
        // Zero on drop - it holds Noise ciphertext (already encrypted) but
        // defense-in-depth.
        let mut snow_out = Zeroizing::new(vec![0u8; 256 + FS_TOKEN_PAYLOAD_LEN]);
        let n = self.noise.write_message(payload_slice, &mut snow_out)?;
        if n != expected_noise_len {
            return Err(SessionError::State("noise msg 3: unexpected length"));
        }

        let wire = Message3 {
            noise_msg_3: snow_out[..n].to_vec(),
        }
        .encode();

        let noise_h = noise_h_32(&self.noise)?;
        // Keep K_pq inside its Zeroizing wrapper so this local wipes on drop -
        // do NOT deref-copy it into a bare `[u8; 32]`, which would leave an
        // un-zeroized copy on the stack. The `SessionKeys.mlkem_ss` field built
        // below is the caller-managed copy (wiped by SessionFramer::from_session_keys
        // -> zeroize_ss).
        let mlkem_ss = self
            .mlkem_ss
            .take()
            .ok_or(SessionError::State("mlkem_ss missing at msg 3"))?;
        let mlkem_ct_bytes = self
            .mlkem_ct_bytes
            .ok_or(SessionError::State("mlkem_ct missing at msg 3"))?;

        let session_binding = derive_session_binding(
            self.wire_version,
            &noise_h,
            &self.mlkem_ek_bytes,
            &mlkem_ct_bytes,
            &mlkem_ss,
        );
        let transport = self.noise.into_transport_mode()?;
        self.state = InitiatorState::Complete;

        Ok((
            wire,
            SessionKeys {
                session_binding,
                transport,
                mlkem_ss: *mlkem_ss,
            },
        ))
    }
}

// Responder

#[derive(Debug, PartialEq, Eq)]
enum ResponderState {
    AwaitMessage1,
    AwaitMessage3,
    Complete,
}

/// Post-msg2 circuit-hop material produced by
/// [`HandshakeResponder::write_message_2_for_circuit_hop`]:
/// `(hs_msg2, mlkem_ss, circuit_binding)`.
type CircuitHopMaterial = (Vec<u8>, [u8; MLKEM_SS_BYTES], [u8; 32]);

/// Bridge-side handshake state machine.
///
/// Call sequence: [`HandshakeResponder::new`] -> [`HandshakeResponder::read_message_1`] ->
/// [`HandshakeResponder::write_message_2`] -> [`HandshakeResponder::read_message_3`].
///
/// **Does not implement `Debug`.** See [`HandshakeInitiator`] for the
/// rationale - same invariant applies here.
pub struct HandshakeResponder {
    noise: HandshakeState,
    peer_mlkem_ek: Option<[u8; MLKEM_EK_BYTES]>,
    mlkem_ct_bytes: Option<[u8; MLKEM_CT_BYTES]>,
    /// Secret. Zeroizes on drop (including panic paths).
    mlkem_ss: Option<Zeroizing<[u8; MLKEM_SS_BYTES]>>,
    wire_version: u16,
    state: ResponderState,
    /// Bridge's own Ed25519 identity - tokens must name this key.
    local_ed25519_pk: [u8; 32],
    /// Operator verifying key - used to validate token signatures.
    operator_pk: [u8; 32],
    /// `true` for conformant bridges: msg 3 MUST be the 203-byte token form.
    /// `false` for test-only mode: msg 3 MUST be the 67-byte no-token form.
    require_token: bool,
}

impl HandshakeResponder {
    /// Construct a new conformant responder.
    ///
    /// - `local_x25519_sk`: bridge's X25519 static secret (for Noise).
    /// - `local_ed25519_pk`: bridge's long-term Ed25519 identity (clients'
    ///   capability tokens MUST name this key).
    /// - `operator_pk`: operator's Ed25519 verifying key - source of truth
    ///   for which tokens are valid.
    ///
    /// **Closes [RT-CN-2]**: production responders ALWAYS require
    /// the 203-byte token-bearing msg_3. Accepting the 67-byte
    /// no-token form would let a passive observer detect bridges
    /// that were misconfigured (or running in test mode), giving
    /// a deployment-maturity oracle to a censor. The
    /// `require_token = true` default + the
    /// `compile_error!(danger-no-token + release)` gate in
    /// [`crate::lib.rs`] together guarantee no production binary
    /// can ship with the no-token mode enabled - a release-mode
    /// `cargo build` with the feature would fail at compile
    /// time, not silently link.
    pub fn new(
        local_x25519_sk: &[u8; 32],
        local_ed25519_pk: &[u8; 32],
        operator_pk: &[u8; 32],
    ) -> Result<Self, SessionError> {
        let noise = build_noise_base()?
            .local_private_key(local_x25519_sk)
            .build_responder()?;
        Ok(Self {
            noise,
            peer_mlkem_ek: None,
            mlkem_ct_bytes: None,
            mlkem_ss: None,
            wire_version: mirage_spec::WIRE_VERSION,
            state: ResponderState::AwaitMessage1,
            local_ed25519_pk: *local_ed25519_pk,
            operator_pk: *operator_pk,
            require_token: true,
        })
    }

    /// **DANGER: test-only.** Constructs a responder that accepts ONLY the
    /// 67-byte no-token msg 3 form and rejects the 203-byte token-bearing
    /// form (so test/prod confusion produces a loud failure, not a silent
    /// bypass). Gated behind `#[cfg(test)]` or the `danger-no-token`
    /// cargo feature; `lib.rs` emits `compile_error!` if the feature is
    /// enabled in a release profile.
    ///
    /// The `_danger_` prefix is load-bearing: every call site is grep-able
    /// and code review can reject any production path that ends up here.
    #[cfg(any(test, feature = "danger-no-token"))]
    pub fn _danger_new_without_token_verification(
        local_x25519_sk: &[u8; 32],
    ) -> Result<Self, SessionError> {
        let mut me = Self::new(local_x25519_sk, &[0u8; 32], &[0u8; 32])?;
        me.require_token = false;
        Ok(me)
    }

    /// Consume message 1 from the initiator.
    pub fn read_message_1(&mut self, wire: &[u8]) -> Result<(), SessionError> {
        if self.state != ResponderState::AwaitMessage1 {
            return Err(SessionError::State("read_message_1: wrong state"));
        }
        let msg = Message1::decode(wire)?;
        if msg.wire_version != self.wire_version {
            return Err(SessionError::VersionMismatch {
                peer: msg.wire_version,
                min: mirage_spec::WIRE_VERSION,
                max: mirage_spec::WIRE_VERSION,
            });
        }
        // I24: mlkem_ek is the Noise message-1 PAYLOAD. Reading it back through
        // Noise mixes it into our transcript hash (matching the initiator's
        // binding); a substituted ek diverges the transcripts and breaks
        // message-2 authentication at the peer. Message 1 is unkeyed, so there
        // is no inline tag to verify here - the binding surfaces one round
        // later. Buffer is sized to the whole Noise message and zeroes on drop.
        let mut payload_out = Zeroizing::new([0u8; NOISE_MSG_1_LEN]);
        let payload_len = self
            .noise
            .read_message(&msg.noise_msg_1, payload_out.as_mut())?;
        if payload_len != MLKEM_EK_BYTES {
            return Err(SessionError::Wire("message 1: unexpected mlkem_ek length"));
        }
        let mut ek = [0u8; MLKEM_EK_BYTES];
        ek.copy_from_slice(&payload_out[..MLKEM_EK_BYTES]);
        self.peer_mlkem_ek = Some(ek);
        self.state = ResponderState::AwaitMessage3;
        Ok(())
    }

    /// Produce message 2 to send back.
    pub fn write_message_2(&mut self) -> Result<Vec<u8>, SessionError> {
        if self.state != ResponderState::AwaitMessage3 {
            return Err(SessionError::State("write_message_2: wrong state"));
        }
        // I24: encapsulate against the initiator's ek FIRST so mlkem_ct can be
        // carried as the message-2 Noise PAYLOAD (AEAD-encrypted + transcript-
        // bound), instead of appended outside the AEAD.
        let peer_ek_bytes = self
            .peer_mlkem_ek
            .ok_or(SessionError::State("peer mlkem_ek missing at msg 2"))?;
        let peer_ek = MlKemEk::from_bytes(&peer_ek_bytes).map_err(SessionError::MlKem)?;
        let (ct, ss) = peer_ek.encapsulate();
        self.mlkem_ct_bytes = Some(ct);
        self.mlkem_ss = Some(Zeroizing::new(ss));

        let mut snow_out = vec![0u8; NOISE_MSG_2_LEN + 16];
        let n = self.noise.write_message(&ct, &mut snow_out)?;
        if n != NOISE_MSG_2_LEN {
            return Err(SessionError::State("noise msg 2: unexpected length"));
        }
        let mut noise_msg_2 = [0u8; NOISE_MSG_2_LEN];
        noise_msg_2.copy_from_slice(&snow_out[..NOISE_MSG_2_LEN]);

        Ok(Message2 {
            wire_version: self.wire_version,
            noise_msg_2,
        }
        .encode())
    }

    /// Like `write_message_2` but ALSO returns the circuit-level hop
    /// key material derived from `noise_h` at the post-msg2 point.
    ///
    /// Returns `(hs_msg2, mlkem_ss, circuit_binding)` where
    /// `circuit_binding` is the same `derive_session_binding` formula
    /// applied to `noise_h_after_msg2`. This matches
    /// `HandshakeInitiator::circuit_hop_binding` computed on the
    /// initiator side after `read_message_2`, so both parties derive
    /// identical per-hop circuit keys without waiting for msg3.
    ///
    /// The responder remains in `AwaitMessage3` state after this call;
    /// `read_message_3` can still be called later for token verification.
    ///
    /// Used by `mirage_bridge::circuit_executor` in `perform_handshake`
    /// (Phase 2H).
    pub fn write_message_2_for_circuit_hop(&mut self) -> Result<CircuitHopMaterial, SessionError> {
        let hs_msg2 = self.write_message_2()?;
        // After write_message_2, noise_h includes msg1+msg2.
        let noise_h = noise_h_32(&self.noise)?;
        let mlkem_ss: [u8; MLKEM_SS_BYTES] = *self.mlkem_ss.as_deref().ok_or(
            SessionError::State("mlkem_ss missing after msg2 circuit path"),
        )?;
        let mlkem_ek = self.peer_mlkem_ek.ok_or(SessionError::State(
            "mlkem_ek missing after msg2 circuit path",
        ))?;
        let mlkem_ct = self.mlkem_ct_bytes.ok_or(SessionError::State(
            "mlkem_ct missing after msg2 circuit path",
        ))?;
        let circuit_binding =
            derive_session_binding(self.wire_version, &noise_h, &mlkem_ek, &mlkem_ct, &mlkem_ss);
        Ok((hs_msg2, mlkem_ss, circuit_binding))
    }

    /// Consume message 3 and complete the handshake.
    ///
    /// Verifies the embedded capability token against the bridge's identity
    /// and the operator's verifying key, checks expiry and replay set.
    pub fn read_message_3(
        mut self,
        wire: &[u8],
        verifier: &mut TokenVerifier<'_>,
    ) -> Result<SessionKeys, SessionError> {
        if self.state != ResponderState::AwaitMessage3 {
            return Err(SessionError::State("read_message_3: wrong state"));
        }

        let msg = Message3::decode(wire)?;

        // Mode enforcement (R21): the responder configured as conformant MUST
        // see a token-bearing msg 3 (either the 203-byte legacy form or the
        // 315-byte forward-secure form); a test-only responder MUST see the
        // 67-byte no-token form. A prod bridge that accepted the short form
        // would bypass token verification silently - a hole, closed here.
        let noise_len = msg.noise_msg_3.len();
        let is_legacy = noise_len == NOISE_MSG_3_LEN_WITH_TOKEN;
        let is_fs = noise_len == NOISE_MSG_3_LEN_WITH_FS_TOKEN;
        let is_conformant = is_legacy || is_fs;
        if self.require_token && !is_conformant {
            return Err(SessionError::TokenVerification(
                "token required but not presented",
            ));
        }
        if !self.require_token && is_conformant {
            return Err(SessionError::Wire(
                "test-only responder received token-bearing msg 3",
            ));
        }

        // Decrypt through the Noise state machine (spec §11.3 step 1).
        // Buffer zeros on drop - it briefly holds the decrypted token. Sized
        // for the largest (forward-secure) token form.
        let mut payload_out = Zeroizing::new([0u8; 256 + FS_TOKEN_PAYLOAD_LEN]);
        let payload_len = self
            .noise
            .read_message(&msg.noise_msg_3, payload_out.as_mut())?;

        if is_legacy {
            // Spec §11.3 steps 2-7.
            if payload_len != TOKEN_PAYLOAD_LEN {
                return Err(SessionError::TokenVerification("payload length mismatch"));
            }
            let token = CapabilityToken::decode(&payload_out[..TOKEN_PAYLOAD_LEN])
                .map_err(|_| SessionError::TokenVerification("token decode failed"))?;

            // R22: verify signature BEFORE pin check so rejection time
            // is dominated by the constant-cost Ed25519 verify. Otherwise
            // "wrong bridge" (cheap memcmp) is distinguishable by timing
            // from "bad signature" (expensive Ed25519 verify).
            //
            // Multi-path verification (v0.1i):
            //
            // Path A - operator-signed bootstrap / cohort token. The
            // token's signature covers `token_id || bridge_pk ||
            // expires_at` verbatim and MUST verify under the
            // operator's long-term signing key.
            //
            // Path A' - PREVIOUS operator key, during a mother-key
            // rotation overlap window. Same signing-prefix shape as
            // Path A. Accepted only when the bridge is configured
            // with `accept_prev_operator_pk`. This lets invites
            // minted before rotation keep working until the
            // operator explicitly removes the previous key.
            //
            // Path B - bridge-self-signed refresh token. Only
            // attempted when the caller configured
            // `accept_refresh_signed_by`. Signature covers the SAME
            // token prefix but domain-separated with
            // `mirage-refresh-v1\0` (see
            // `mirage_discovery::refresh::REFRESH_SIGN_DOMAIN`), so
            // a refresh-path success cannot be cross-presented as a
            // bootstrap-path success.
            //
            // Evaluate EVERY configured path unconditionally so the NUMBER of
            // Ed25519 verifications is a function of the bridge's static config
            // (which paths are enabled), never of the presented token's type.
            // Short-circuiting on the first match (the previous code, despite a
            // comment claiming constant-time) let an attacker holding a valid
            // token learn from response latency whether it was operator-,
            // prev-operator-, or refresh-signed - a confirmed red-team finding.
            // verify_refresh_path is pure, so the extra verify has no side
            // effect beyond the intended fixed cost.
            let ok_operator = token.verify_signature(&self.operator_pk).is_ok();
            let ok_prev = verifier
                .accept_prev_operator_pk
                .map(|prev_pk| token.verify_signature(&prev_pk).is_ok())
                .unwrap_or(false);
            let refresh_kind = verifier
                .accept_refresh_signed_by
                .and_then(|refresh_pk| verify_refresh_path(&token, &refresh_pk).ok());
            let token_kind = if ok_operator || ok_prev {
                AcceptedTokenKind::Bootstrap
            } else if let Some(kind) = refresh_kind {
                kind
            } else {
                return Err(SessionError::TokenVerification(
                    "signature verification failed",
                ));
            };
            if !token.is_for_bridge(&self.local_ed25519_pk) {
                return Err(SessionError::TokenVerification("token not for this bridge"));
            }
            if token.is_expired(verifier.now_unix, verifier.grace_seconds) {
                return Err(SessionError::TokenVerification("token expired"));
            }
            // R23: saturating_add against u64::MAX overflow.
            let retention = token.expires_at.saturating_add(verifier.grace_seconds);
            if !verifier
                .replay_set
                .check_and_insert(&token.token_id, retention, verifier.now_unix)
            {
                return Err(SessionError::TokenVerification(
                    "token replayed or capacity",
                ));
            }
            // Stash for caller. Correlates per-token state (e.g.
            // cohort rationing) without exposing the full token.
            verifier.last_accepted_token_id = Some(token.token_id);
            verifier.last_accepted_kind = Some(token_kind);
        } else if is_fs {
            // Forward-secure token: verify the root -> epoch-subkey -> token
            // certificate chain (spec §11.4). The bridge's pinned operator key
            // is the offline ROOT; a compromise of the online issuer that
            // signed this token cannot forge tokens for a *retired* epoch,
            // because that subkey's secret is destroyed and the root is offline.
            if payload_len != FS_TOKEN_PAYLOAD_LEN {
                return Err(SessionError::TokenVerification(
                    "fs payload length mismatch",
                ));
            }
            let token = FsCapabilityToken::decode(&payload_out[..FS_TOKEN_PAYLOAD_LEN])
                .map_err(|_| SessionError::TokenVerification("fs token decode failed"))?;

            // Accept a chain rooted at the operator key, or (during a rotation
            // overlap) the previous operator key. Evaluate BOTH configured root
            // paths unconditionally, mirroring the legacy path's constant-time
            // discipline: for a validly-signed token exactly one chain does two
            // Ed25519 verifies and the other does one, so the total cost is
            // independent of WHICH root certified the subkey - closing the same
            // provenance-by-timing oracle R22 closed for legacy tokens.
            let ok_root = token
                .verify_chain(&self.operator_pk, verifier.now_unix, verifier.grace_seconds)
                .is_ok();
            let ok_prev = verifier
                .accept_prev_operator_pk
                .map(|prev_pk| {
                    token
                        .verify_chain(&prev_pk, verifier.now_unix, verifier.grace_seconds)
                        .is_ok()
                })
                .unwrap_or(false);
            if !(ok_root || ok_prev) {
                return Err(SessionError::TokenVerification(
                    "fs chain verification failed",
                ));
            }
            if !token.is_for_bridge(&self.local_ed25519_pk) {
                return Err(SessionError::TokenVerification("token not for this bridge"));
            }
            if token.is_expired(verifier.now_unix, verifier.grace_seconds) {
                return Err(SessionError::TokenVerification("token expired"));
            }
            let retention = token.expires_at.saturating_add(verifier.grace_seconds);
            if !verifier
                .replay_set
                .check_and_insert(&token.token_id, retention, verifier.now_unix)
            {
                return Err(SessionError::TokenVerification(
                    "token replayed or capacity",
                ));
            }
            verifier.last_accepted_token_id = Some(token.token_id);
            // FS tokens are operator-root-signed, i.e. bootstrap-family.
            verifier.last_accepted_kind = Some(AcceptedTokenKind::Bootstrap);
        }
        // Else: test-only no-token form; skip verification.
        // `last_accepted_token_id` stays as whatever the caller
        // passed in - they should reset it to None between sessions.

        let noise_h = noise_h_32(&self.noise)?;
        let mlkem_ek_bytes = self
            .peer_mlkem_ek
            .ok_or(SessionError::State("peer_mlkem_ek missing at msg 3"))?;
        let mlkem_ct_bytes = self
            .mlkem_ct_bytes
            .ok_or(SessionError::State("mlkem_ct missing at msg 3"))?;
        let mlkem_ss: [u8; MLKEM_SS_BYTES] = *self
            .mlkem_ss
            .take()
            .ok_or(SessionError::State("mlkem_ss missing at msg 3"))?;

        let session_binding = derive_session_binding(
            self.wire_version,
            &noise_h,
            &mlkem_ek_bytes,
            &mlkem_ct_bytes,
            &mlkem_ss,
        );
        let transport = self.noise.into_transport_mode()?;
        self.state = ResponderState::Complete;

        Ok(SessionKeys {
            session_binding,
            transport,
            mlkem_ss,
        })
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{MSG_1_LEN, MSG_2_LEN, MSG_3_LEN_NO_TOKEN, MSG_3_LEN_WITH_TOKEN};
    use mirage_crypto::ed25519_dalek::SigningKey;
    use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
    use mirage_discovery::replay::ReplaySet;
    use mirage_discovery::token::{sign_token, CapabilityToken};

    // ---- helpers ----

    fn rand_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).unwrap();
        s
    }

    fn gen_x25519_keypair() -> ([u8; 32], [u8; 32]) {
        let sk = StaticSecret::from(rand_seed());
        let pk = PublicKey::from(&sk);
        (sk.to_bytes(), *pk.as_bytes())
    }

    fn gen_ed25519_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&rand_seed());
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// Issue a token for the given bridge identity, valid for 24 hours.
    fn issue_token(
        bridge_ed25519_pk: [u8; 32],
        op_sk: &SigningKey,
        token_id: [u8; 32],
        now_unix: u64,
    ) -> CapabilityToken {
        sign_token(token_id, bridge_ed25519_pk, now_unix + 86_400, op_sk)
    }

    struct Party {
        init_x_sk: [u8; 32],
        bridge_x_sk: [u8; 32],
        bridge_x_pk: [u8; 32],
        bridge_ed_pk: [u8; 32],
        op_sk: SigningKey,
        op_pk: [u8; 32],
    }

    fn fresh_party() -> Party {
        let (init_x_sk, _) = gen_x25519_keypair();
        let (bridge_x_sk, bridge_x_pk) = gen_x25519_keypair();
        let (_bridge_id_sk, bridge_ed_pk) = gen_ed25519_keypair();
        let (op_sk, op_pk) = gen_ed25519_keypair();
        Party {
            init_x_sk,
            bridge_x_sk,
            bridge_x_pk,
            bridge_ed_pk,
            op_sk,
            op_pk,
        }
    }

    fn run_handshake(
        p: &Party,
        token: &CapabilityToken,
        verifier: &mut TokenVerifier<'_>,
    ) -> Result<(SessionKeys, SessionKeys), SessionError> {
        let mut initiator = HandshakeInitiator::new(&p.init_x_sk, &p.bridge_x_pk, token)?;
        let mut responder = HandshakeResponder::new(&p.bridge_x_sk, &p.bridge_ed_pk, &p.op_pk)?;

        let m1 = initiator.write_message_1()?;
        assert_eq!(m1.len(), MSG_1_LEN);
        responder.read_message_1(&m1)?;

        let m2 = responder.write_message_2()?;
        assert_eq!(m2.len(), MSG_2_LEN);
        initiator.read_message_2(&m2)?;

        let (m3, ik) = initiator.write_message_3()?;
        assert_eq!(m3.len(), MSG_3_LEN_WITH_TOKEN);
        let rk = responder.read_message_3(&m3, verifier)?;
        Ok((ik, rk))
    }

    // ---- forward-secure token handshake ----

    fn run_fs_handshake(
        p: &Party,
        token: &FsCapabilityToken,
        verifier: &mut TokenVerifier<'_>,
    ) -> Result<(SessionKeys, SessionKeys), SessionError> {
        use crate::wire::MSG_3_LEN_WITH_FS_TOKEN;
        let mut initiator = HandshakeInitiator::new_fs(&p.init_x_sk, &p.bridge_x_pk, token)?;
        let mut responder = HandshakeResponder::new(&p.bridge_x_sk, &p.bridge_ed_pk, &p.op_pk)?;

        let m1 = initiator.write_message_1()?;
        responder.read_message_1(&m1)?;
        let m2 = responder.write_message_2()?;
        initiator.read_message_2(&m2)?;
        let (m3, ik) = initiator.write_message_3()?;
        assert_eq!(m3.len(), MSG_3_LEN_WITH_FS_TOKEN, "FS msg 3 is 315 bytes");
        let rk = responder.read_message_3(&m3, verifier)?;
        Ok((ik, rk))
    }

    #[test]
    fn fs_token_handshake_accepts_and_binds_session() {
        use mirage_discovery::token_fs::EpochSigner;
        let p = fresh_party();
        let now = 1_700_000_000u64;
        // Online epoch signer certified by the operator ROOT (p.op_sk).
        let signer = EpochSigner::generate(&p.op_sk, 1, now + 86_400).unwrap();
        let tok = signer.sign_token([0xA1u8; 32], p.bridge_ed_pk, now + 3600);

        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, now);
        let (ik, rk) = expect_ok(run_fs_handshake(&p, &tok, &mut v), "fs handshake");
        // Both sides derive the same session binding.
        assert_eq!(ik.session_binding, rk.session_binding);
        assert_eq!(v.last_accepted_token_id, Some([0xA1u8; 32]));
        assert_eq!(v.last_accepted_kind, Some(AcceptedTokenKind::Bootstrap));
    }

    #[test]
    fn fs_token_forged_cert_rejected() {
        // An attacker who compromises the online issuer but NOT the root tries
        // to mint a token: they generate their own subkey and self-sign its
        // cert (they lack the root key). The chain must fail at the cert layer.
        use mirage_discovery::token_fs::EpochSigner;
        let p = fresh_party();
        let now = 1_700_000_000u64;
        let (attacker_root, _) = gen_ed25519_keypair(); // NOT p.op_sk
        let signer = EpochSigner::generate(&attacker_root, 1, now + 86_400).unwrap();
        let tok = signer.sign_token([0x66u8; 32], p.bridge_ed_pk, now + 3600);

        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, now);
        assert!(
            run_fs_handshake(&p, &tok, &mut v).is_err(),
            "cert not signed by the pinned root must be rejected"
        );
    }

    #[test]
    fn fs_token_retired_subkey_rejected() {
        // The subkey's cert expired before `now`: forward-security window shut.
        use mirage_discovery::token_fs::EpochSigner;
        let p = fresh_party();
        let now = 1_700_000_000u64;
        // cert_valid_until well in the past (beyond the grace window).
        let signer = EpochSigner::generate(&p.op_sk, 1, now - 10_000).unwrap();
        let tok = signer.sign_token([0x77u8; 32], p.bridge_ed_pk, now + 3600);

        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, now);
        assert!(
            run_fs_handshake(&p, &tok, &mut v).is_err(),
            "retired epoch subkey must be rejected"
        );
    }

    #[test]
    fn fs_token_replay_rejected() {
        use mirage_discovery::token_fs::EpochSigner;
        let p = fresh_party();
        let now = 1_700_000_000u64;
        let signer = EpochSigner::generate(&p.op_sk, 1, now + 86_400).unwrap();
        let tok = signer.sign_token([0x88u8; 32], p.bridge_ed_pk, now + 3600);

        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, now);
        expect_ok(run_fs_handshake(&p, &tok, &mut v), "first use");
        // Same token_id again -> replay set rejects.
        let mut v2 = TokenVerifier::new(&mut rs, now);
        assert!(
            run_fs_handshake(&p, &tok, &mut v2).is_err(),
            "replayed FS token must be rejected (one-time use)"
        );
    }

    #[test]
    fn fs_token_for_wrong_bridge_rejected() {
        use mirage_discovery::token_fs::EpochSigner;
        let p = fresh_party();
        let now = 1_700_000_000u64;
        let signer = EpochSigner::generate(&p.op_sk, 1, now + 86_400).unwrap();
        // Token bound to a DIFFERENT bridge identity.
        let tok = signer.sign_token([0x99u8; 32], [0x00u8; 32], now + 3600);

        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, now);
        assert!(
            run_fs_handshake(&p, &tok, &mut v).is_err(),
            "FS token pinned to another bridge must be rejected"
        );
    }

    #[test]
    fn fs_token_accepted_via_prev_operator_during_rotation() {
        // Root rotated: the token's subkey was certified by the PREVIOUS root.
        // A bridge configured with `with_prev_operator(old_root)` accepts it
        // during the overlap window (mirrors legacy Path A').
        use mirage_discovery::token_fs::EpochSigner;
        let mut p = fresh_party();
        let now = 1_700_000_000u64;
        // The old root that certified the subkey.
        let (old_root, old_root_pk) = gen_ed25519_keypair();
        let signer = EpochSigner::generate(&old_root, 1, now + 86_400).unwrap();
        let tok = signer.sign_token([0xABu8; 32], p.bridge_ed_pk, now + 3600);
        // The bridge now pins a NEW operator root (p.op_pk) but still accepts
        // the previous one during the overlap.
        let (_new_root, new_root_pk) = gen_ed25519_keypair();
        p.op_pk = new_root_pk;

        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, now).with_prev_operator(&old_root_pk);
        expect_ok(
            run_fs_handshake(&p, &tok, &mut v),
            "FS token under prev root during overlap",
        );
    }

    // ---- happy path ----

    fn expect_ok(
        result: Result<(SessionKeys, SessionKeys), SessionError>,
        ctx: &str,
    ) -> (SessionKeys, SessionKeys) {
        match result {
            Ok(pair) => pair,
            Err(e) => panic!("{}: {}", ctx, e),
        }
    }

    #[test]
    fn refresh_token_accepted_via_fallback_path() {
        // A bridge-signed refresh token is presented at handshake
        // time in place of an operator-signed bootstrap token. The
        // verifier's operator-sig path rejects, but the
        // `with_refresh_issuer` fallback accepts. End-to-end proves:
        // (1) the refresh-domain-separated signature verifies,
        // (2) bridge-pin check still holds,
        // (3) the replay set still records the id (single-use).
        use mirage_discovery::refresh::sign_refresh_token;

        let (init_x_sk, _) = gen_x25519_keypair();
        let (bridge_x_sk, bridge_x_pk) = gen_x25519_keypair();
        let (bridge_id_sk, bridge_ed_pk) = gen_ed25519_keypair();
        let (_op_sk, op_pk) = gen_ed25519_keypair();

        // Build a refresh token signed by the bridge's identity
        // key, bound to the bridge's own pubkey, 24h TTL.
        let now = 1_700_000_000u64;
        let refresh = sign_refresh_token([0xAAu8; 32], &bridge_id_sk, now + 86_400);

        // Present it as if it were a CapabilityToken - same 136-byte
        // wire format; the payload shape is identical.
        let as_cap = refresh.inner.clone();
        let mut initiator =
            HandshakeInitiator::new(&init_x_sk, &bridge_x_pk, &as_cap).expect("initiator new");
        let mut responder =
            HandshakeResponder::new(&bridge_x_sk, &bridge_ed_pk, &op_pk).expect("responder new");

        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, now).with_refresh_issuer(&bridge_ed_pk);

        let m1 = initiator.write_message_1().expect("m1");
        responder.read_message_1(&m1).expect("r m1");
        let m2 = responder.write_message_2().expect("m2");
        initiator.read_message_2(&m2).expect("r m2");
        let (m3, _ik) = initiator.write_message_3().expect("m3");
        let _rk = responder
            .read_message_3(&m3, &mut v)
            .expect("refresh token must verify via fallback path");
        assert_eq!(v.last_accepted_kind, Some(AcceptedTokenKind::Refresh));
        assert_eq!(v.last_accepted_token_id, Some([0xAAu8; 32]));
        assert_eq!(rs.len(), 1, "refresh token recorded in replay set");
    }

    #[test]
    fn prev_operator_path_accepts_during_rotation_overlap() {
        // A mother-key rotation has taken place: the bridge is now
        // configured with a new operator_pk as primary and the old
        // one as `accept_prev_operator_pk`. A user presenting an
        // old-invite token (signed by the OLD operator key) must
        // still handshake successfully during the overlap.
        let p = fresh_party();
        // Mint the token with an OPERATOR different from
        // p.op_sk - simulating the rotation: the bridge's primary
        // operator_pk has moved on to a new key, the old one is the
        // one that signed the user's existing invite.
        let old_op_sk = SigningKey::from_bytes(&rand_seed());
        let old_op_pk = old_op_sk.verifying_key().to_bytes();
        let token = issue_token(p.bridge_ed_pk, &old_op_sk, [0xA1u8; 32], 1_700_000_000);

        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000).with_prev_operator(&old_op_pk);

        // Run a full handshake with p's (new) operator pk; token is
        // old-signed; fallback must accept.
        let mut initiator =
            HandshakeInitiator::new(&p.init_x_sk, &p.bridge_x_pk, &token).expect("initiator new");
        let mut responder = HandshakeResponder::new(&p.bridge_x_sk, &p.bridge_ed_pk, &p.op_pk)
            .expect("responder new");
        let m1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&m1).unwrap();
        let m2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&m2).unwrap();
        let (m3, _ik) = initiator.write_message_3().unwrap();
        responder
            .read_message_3(&m3, &mut v)
            .expect("prev-operator token must verify during overlap");
        // Classified as Bootstrap (not Refresh) - callers that
        // track rotation telemetry see a normal invite redemption.
        assert_eq!(v.last_accepted_kind, Some(AcceptedTokenKind::Bootstrap));
    }

    #[test]
    fn prev_operator_token_rejected_when_overlap_over() {
        // Same setup but the bridge has REMOVED
        // `accept_prev_operator_pk` (overlap window ended). The
        // old token must now fail.
        let p = fresh_party();
        let old_op_sk = SigningKey::from_bytes(&rand_seed());
        let token = issue_token(p.bridge_ed_pk, &old_op_sk, [0xA2u8; 32], 1_700_000_000);

        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000); // NO with_prev_operator

        let mut initiator =
            HandshakeInitiator::new(&p.init_x_sk, &p.bridge_x_pk, &token).expect("initiator new");
        let mut responder = HandshakeResponder::new(&p.bridge_x_sk, &p.bridge_ed_pk, &p.op_pk)
            .expect("responder new");
        let m1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&m1).unwrap();
        let m2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&m2).unwrap();
        let (m3, _ik) = initiator.write_message_3().unwrap();
        let err = responder.read_message_3(&m3, &mut v).unwrap_err();
        assert!(
            matches!(err, SessionError::TokenVerification(_)),
            "post-overlap handshake with old-operator token must fail"
        );
    }

    #[test]
    fn refresh_token_rejected_when_fallback_not_enabled() {
        // Same setup as above but without `with_refresh_issuer`.
        // Verifier's operator-sig path is the only one tried, so
        // the bridge-signed token (whose sig doesn't match
        // operator_pk) must be rejected with the standard
        // "signature verification failed" error.
        use mirage_discovery::refresh::sign_refresh_token;

        let (init_x_sk, _) = gen_x25519_keypair();
        let (bridge_x_sk, bridge_x_pk) = gen_x25519_keypair();
        let (bridge_id_sk, bridge_ed_pk) = gen_ed25519_keypair();
        let (_op_sk, op_pk) = gen_ed25519_keypair();
        let now = 1_700_000_000u64;
        let refresh = sign_refresh_token([0xABu8; 32], &bridge_id_sk, now + 86_400);
        let as_cap = refresh.inner.clone();

        let mut initiator =
            HandshakeInitiator::new(&init_x_sk, &bridge_x_pk, &as_cap).expect("initiator new");
        let mut responder =
            HandshakeResponder::new(&bridge_x_sk, &bridge_ed_pk, &op_pk).expect("responder new");
        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, now);

        let m1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&m1).unwrap();
        let m2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&m2).unwrap();
        let (m3, _ik) = initiator.write_message_3().unwrap();
        let err = responder.read_message_3(&m3, &mut v).unwrap_err();
        assert!(
            matches!(err, SessionError::TokenVerification(_)),
            "refresh must not be accepted without explicit fallback"
        );
    }

    #[test]
    fn handshake_with_token_roundtrip() {
        let p = fresh_party();
        let token = issue_token(p.bridge_ed_pk, &p.op_sk, [0x01u8; 32], 1_700_000_000);
        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000);
        let (ik, rk) = expect_ok(run_handshake(&p, &token, &mut v), "handshake");
        assert_eq!(ik.session_binding, rk.session_binding);
        assert_eq!(ik.mlkem_ss, rk.mlkem_ss);
        assert_eq!(rs.len(), 1, "token recorded");
    }

    #[test]
    fn different_sessions_produce_different_bindings() {
        let p = fresh_party();
        let mut rs = ReplaySet::new(16);
        let t1 = issue_token(p.bridge_ed_pk, &p.op_sk, [0x01u8; 32], 1_700_000_000);
        let t2 = issue_token(p.bridge_ed_pk, &p.op_sk, [0x02u8; 32], 1_700_000_000);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000);
        let (ik1, _) = expect_ok(run_handshake(&p, &t1, &mut v), "first handshake");
        let (ik2, _) = expect_ok(run_handshake(&p, &t2, &mut v), "second handshake");
        assert_ne!(ik1.session_binding, ik2.session_binding);
    }

    // ---- negative: token verification failures ----

    fn assert_token_err(
        result: Result<(SessionKeys, SessionKeys), SessionError>,
        expected: &'static str,
    ) {
        match result {
            Err(SessionError::TokenVerification(msg)) if msg == expected => {}
            Ok(_) => panic!("expected TokenVerification({}), got Ok", expected),
            Err(e) => panic!("expected TokenVerification({}), got {}", expected, e),
        }
    }

    #[test]
    fn expired_token_rejected() {
        let p = fresh_party();
        let token = sign_token([0x01u8; 32], p.bridge_ed_pk, 1_000, &p.op_sk);
        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000); // far in the future
        assert_token_err(run_handshake(&p, &token, &mut v), "token expired");
    }

    #[test]
    fn token_for_different_bridge_rejected() {
        let p = fresh_party();
        let (_, other_bridge_ed_pk) = gen_ed25519_keypair();
        let token = issue_token(other_bridge_ed_pk, &p.op_sk, [0x01u8; 32], 1_700_000_000);
        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000);
        assert_token_err(
            run_handshake(&p, &token, &mut v),
            "token not for this bridge",
        );
    }

    #[test]
    fn token_signed_by_wrong_operator_rejected() {
        let p = fresh_party();
        let (impostor_sk, _) = gen_ed25519_keypair();
        let token = issue_token(p.bridge_ed_pk, &impostor_sk, [0x01u8; 32], 1_700_000_000);
        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000);
        assert_token_err(
            run_handshake(&p, &token, &mut v),
            "signature verification failed",
        );
    }

    #[test]
    fn tampered_token_rejected() {
        let p = fresh_party();
        let mut token = issue_token(p.bridge_ed_pk, &p.op_sk, [0x01u8; 32], 1_700_000_000);
        // Flip a byte in expires_at without re-signing.
        token.expires_at += 1;
        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000);
        assert_token_err(
            run_handshake(&p, &token, &mut v),
            "signature verification failed",
        );
    }

    #[test]
    fn replayed_token_rejected_on_second_use() {
        let p = fresh_party();
        let token = issue_token(p.bridge_ed_pk, &p.op_sk, [0x01u8; 32], 1_700_000_000);
        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000);
        // First use: should succeed.
        match run_handshake(&p, &token, &mut v) {
            Ok(_) => {}
            Err(e) => panic!("first use should succeed, got {}", e),
        }
        // Second use with same token_id must be rejected.
        assert_token_err(
            run_handshake(&p, &token, &mut v),
            "token replayed or capacity",
        );
    }

    // ---- negative: wire / crypto-level failures still work ----

    #[test]
    fn wrong_responder_key_fails() {
        let mut p = fresh_party();
        // Swap the bridge's x25519 static with a fresh keypair so initiator
        // expects a different key than responder holds.
        let (wrong_sk, wrong_pk) = gen_x25519_keypair();
        let token = issue_token(p.bridge_ed_pk, &p.op_sk, [0x01u8; 32], 1_700_000_000);
        // Initiator expects wrong_pk, but responder uses p.bridge_x_sk (distinct).
        p.bridge_x_pk = wrong_pk;
        let _ = wrong_sk;
        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000);
        assert!(run_handshake(&p, &token, &mut v).is_err());
    }

    #[test]
    fn state_machine_rejects_out_of_order() {
        let (init_sk, _) = gen_x25519_keypair();
        let (_, resp_pk) = gen_x25519_keypair();
        let (op_sk, _) = gen_ed25519_keypair();
        let token = issue_token([0u8; 32], &op_sk, [0u8; 32], 1);
        let mut initiator = HandshakeInitiator::new(&init_sk, &resp_pk, &token).unwrap();
        assert!(initiator.read_message_2(&[0u8; MSG_2_LEN]).is_err());
    }

    /// I24: mlkem_ek is carried as the message-1 Noise payload, so it is folded
    /// into the transcript hash. An active MITM that substitutes it must abort
    /// the HANDSHAKE, not merely surface as a later first-frame decrypt error.
    ///
    /// Message 1 is unkeyed (cleartext payload, no inline tag), so the responder
    /// still ingests the tampered ek; the tamper then manifests in one of two
    /// handshake-time ways, both asserted here:
    ///   (a) the mangled ek fails ML-KEM `from_bytes` validation when the
    ///       responder tries to encapsulate (`write_message_2` errors), or
    ///   (b) the ek parses, but the responder's transcript now diverges from the
    ///       initiator's, so message 2's `s`/payload AEAD - authenticated under
    ///       the responder's transcript - fails to decrypt at the initiator
    ///       (`read_message_2` errors).
    /// It is impossible for BOTH to succeed, which is exactly the property we
    /// want: no completed session under a substituted ek.
    #[test]
    fn tampered_mlkem_ek_aborts_handshake() {
        let p = fresh_party();
        let token = issue_token(p.bridge_ed_pk, &p.op_sk, [0x01u8; 32], 1_700_000_000);
        let mut initiator = HandshakeInitiator::new(&p.init_x_sk, &p.bridge_x_pk, &token).unwrap();
        let mut responder =
            HandshakeResponder::new(&p.bridge_x_sk, &p.bridge_ed_pk, &p.op_pk).unwrap();

        let mut m1 = initiator.write_message_1().unwrap();
        // Flip a byte well inside the 1184-byte mlkem_ek payload region: after
        // the 5-byte header and the 32-byte `e` token.
        let ek_off = 2 + 1 + 2 + 32 + 100;
        m1[ek_off] ^= 0x01;
        // Message 1 has no AEAD, so the responder parses the tampered payload.
        responder.read_message_1(&m1).unwrap();

        match responder.write_message_2() {
            // (a) responder rejected the mangled ek at encapsulation.
            Err(_) => {}
            // (b) ek parsed; the divergent transcript must break msg-2 auth.
            Ok(m2) => assert!(
                initiator.read_message_2(&m2).is_err(),
                "substituted mlkem_ek must abort the handshake at read_message_2, not a later frame"
            ),
        }
    }

    /// I24: mlkem_ct is carried as the AEAD-encrypted message-2 Noise payload.
    /// Tampering with it on the wire must fail the initiator's `read_message_2`
    /// with a Noise authentication error - a handshake abort, not a later frame.
    #[test]
    fn tampered_mlkem_ct_aborts_handshake() {
        let p = fresh_party();
        let token = issue_token(p.bridge_ed_pk, &p.op_sk, [0x01u8; 32], 1_700_000_000);
        let mut initiator = HandshakeInitiator::new(&p.init_x_sk, &p.bridge_x_pk, &token).unwrap();
        let mut responder =
            HandshakeResponder::new(&p.bridge_x_sk, &p.bridge_ed_pk, &p.op_pk).unwrap();

        let m1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&m1).unwrap();
        let mut m2 = responder.write_message_2().unwrap();
        // Flip a byte deep in the encrypted mlkem_ct payload region of msg 2:
        // header(5) + e(32) + enc-s(48) = 85; the ct payload spans 85..1189.
        m2[600] ^= 0x01;
        let err = initiator
            .read_message_2(&m2)
            .expect_err("tampered mlkem_ct must abort the handshake at read_message_2");
        assert!(
            matches!(err, SessionError::Noise(_)),
            "tampered mlkem_ct must fail the Noise AEAD, got {err:?}"
        );
    }

    // ---- R21/R22/R23 regression tests ----

    /// R21: a conformant bridge MUST refuse a 67-byte msg 3. Otherwise an
    /// attacker can strip the token payload and bypass authorization.
    #[test]
    fn conformant_responder_rejects_no_token_form() {
        let p = fresh_party();
        // Initiator in test-only mode produces a 67-byte msg 3.
        let mut initiator =
            HandshakeInitiator::_danger_new_without_token(&p.init_x_sk, &p.bridge_x_pk).unwrap();
        // Responder in PROD (conformant) mode.
        let mut responder =
            HandshakeResponder::new(&p.bridge_x_sk, &p.bridge_ed_pk, &p.op_pk).unwrap();

        let m1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&m1).unwrap();
        let m2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&m2).unwrap();
        let (m3, _) = initiator.write_message_3().unwrap();
        assert_eq!(m3.len(), MSG_3_LEN_NO_TOKEN);
        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000);
        match responder.read_message_3(&m3, &mut v) {
            Err(SessionError::TokenVerification("token required but not presented")) => {}
            Ok(_) => panic!("conformant responder must reject no-token msg 3"),
            Err(e) => panic!("expected token-required error, got {}", e),
        }
    }

    /// R21 converse: test-only responder refuses token-bearing msg 3 so
    /// test fixtures can't silently drift into prod code paths.
    #[test]
    fn test_only_responder_rejects_token_form() {
        let p = fresh_party();
        let token = issue_token(p.bridge_ed_pk, &p.op_sk, [0x01u8; 32], 1_700_000_000);
        let mut initiator = HandshakeInitiator::new(&p.init_x_sk, &p.bridge_x_pk, &token).unwrap();
        let mut responder =
            HandshakeResponder::_danger_new_without_token_verification(&p.bridge_x_sk).unwrap();

        let m1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&m1).unwrap();
        let m2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&m2).unwrap();
        let (m3, _) = initiator.write_message_3().unwrap();
        assert_eq!(m3.len(), MSG_3_LEN_WITH_TOKEN);
        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000);
        match responder.read_message_3(&m3, &mut v) {
            Err(SessionError::Wire(_)) => {}
            Ok(_) => panic!("test-only responder must reject token-bearing msg 3"),
            Err(e) => panic!("expected wire error, got {}", e),
        }
    }

    /// R23: a token with `expires_at == u64::MAX` and any nonzero grace
    /// must not overflow when computing the replay-set retention.
    #[test]
    fn replay_retention_saturates_at_u64_max() {
        let p = fresh_party();
        let token = sign_token([0x77u8; 32], p.bridge_ed_pk, u64::MAX, &p.op_sk);
        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000);
        // If overflow were to panic, this test would crash. We don't assert
        // the resulting retention value directly - we just assert the
        // handshake completes without panic.
        match run_handshake(&p, &token, &mut v) {
            Ok(_) => {}
            Err(e) => panic!("handshake should succeed at u64::MAX expiry, got {}", e),
        }
    }

    // ---- test-only no-token path still works (state-machine smoke test) ----

    #[test]
    fn handshake_without_token_smoke() {
        let (init_sk, _) = gen_x25519_keypair();
        let (resp_sk, resp_pk) = gen_x25519_keypair();
        let mut initiator =
            HandshakeInitiator::_danger_new_without_token(&init_sk, &resp_pk).unwrap();
        let mut responder =
            HandshakeResponder::_danger_new_without_token_verification(&resp_sk).unwrap();

        let m1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&m1).unwrap();
        let m2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&m2).unwrap();
        let (m3, ik) = initiator.write_message_3().unwrap();
        assert_eq!(m3.len(), MSG_3_LEN_NO_TOKEN);
        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 0);
        let rk = responder.read_message_3(&m3, &mut v).unwrap();
        assert_eq!(ik.session_binding, rk.session_binding);
        assert_eq!(rs.len(), 0, "no-token path MUST NOT touch replay set");
    }

    #[test]
    fn debug_impl_redacts_mlkem_ss() {
        // Run a full handshake so `mlkem_ss` holds real, non-zero bytes,
        // then assert no byte of it appears in the Debug rendering.
        let p = fresh_party();
        let now = 1_700_000_000u64;
        let token_id = [42u8; 32];
        let token = issue_token(p.bridge_ed_pk, &p.op_sk, token_id, now);
        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, now);
        let (ik, _rk) = expect_ok(run_handshake(&p, &token, &mut v), "handshake");

        let rendered = format!("{ik:?}");
        assert!(
            rendered.contains("SessionKeys"),
            "debug must name the type: {rendered}"
        );
        assert!(
            rendered.contains("<redacted"),
            "debug must mark secrets as redacted: {rendered}"
        );
        // Smoking gun: not a single byte of the shared secret should
        // appear in the output, in any casing or separator style.
        let hex_lower: String = ik.mlkem_ss.iter().map(|b| format!("{b:02x}")).collect();
        let hex_upper = hex_lower.to_ascii_uppercase();
        assert!(
            !rendered.contains(&hex_lower) && !rendered.contains(&hex_upper),
            "mlkem_ss leaked into Debug output"
        );
    }
}
