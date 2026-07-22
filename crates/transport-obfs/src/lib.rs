//! `obfs-tcp` transport for Mirage.
//!
//! # Wire format
//!
//! ```text
//!  Client                                  Bridge
//!  ------                                  ------
//!  TCP CONNECT
//!  -------------------------------------->
//!
//!  AUTH                            (64 B fixed)
//!    nonce       (32 B, CSPRNG)
//!    auth_tag    (32 B, BLAKE3-keyed)
//!  -------------------------------------->
//!                                          verify auth_tag
//!                                          (constant-time)
//!                                            down success
//!  Mirage session frames (msg1/2/3, then app)
//!  <------------------------------------->
//! ```
//!
//! Auth tag derivation (audit #9 - two modes):
//!
//! ```text
//!   with invite obfs secret (preferred):
//!     key = BLAKE3-keyed(secret, "mirage-obfs-secret-v1-key" || bridge_static_pk)
//!   legacy / no secret provisioned:
//!     key = BLAKE3-keyed(bridge_static_pk, "mirage-obfs-v1-key")
//!   tag   = BLAKE3-keyed(key, nonce)   // 32 B, either mode
//! ```
//!
//! # Threat model fit
//!
//! - **T1 (signature DPI):** [ok] - wire bytes are uniform random;
//!   no protocol-specific signature.
//! - **T2 (active prober):** [ok WHEN an invite obfs secret is provisioned]
//!   (audit #9) - the knock is then keyed on a per-bridge secret carried only
//!   inside the confidential invite, so a prober who merely scraped the
//!   announcement pubkey can no longer mint a valid tag. Without a secret it
//!   falls back to the legacy pubkey-derived key [FAIL], for which Reality-v2's
//!   session_id-MAC remains the stronger answer.
//! - **T3 (ML on flow shape):** [FAIL] - no traffic shaping at this
//!   layer. Compose with traffic-shaping for partial
//!   coverage.
//!
//! ## Entropy-DPI (fully-encrypted-traffic blocking) - accepted, mitigated by demotion (finding #28)
//!
//! The wire is uniform-random from byte 0 with no protocol cover,
//! and the auth is public-key-derived (T2 FAIL, above). This is an
//! ACCEPTED design point: obfs-tcp is the *lightest* carrier, not
//! the *stealthiest*. Against a censor that blocks high-entropy
//! flows outright (Wu et al., USENIX Security 2023 - the GFW's
//! fully-encrypted-traffic classifier), obfs-tcp is exactly the
//! shape that gets flagged. Mirage does NOT try to disguise that
//! here; instead the client's closed-loop self-adversary
//! (`mirage_transport::self_adversary`, wired in `mirage-client`)
//! grades this carrier's egress with the SAME Wu-2023 heuristic and
//! folds a predictive penalty into per-network transport selection,
//! so the router steers OFF obfs-tcp *before* an entropy-DPI censor
//! blocks it. obfs-tcp then serves networks where raw-ciphertext
//! carriers still pass (and are cheaper/faster), and is demoted
//! where they do not.
//!
//! `obfs-tcp` is therefore the **complementary transport for T1**:
//! when a deployment's primary cover destinations are themselves
//! flagged (Reality is detected by the local DPI's signature pack),
//! obfs gives users a fallback that doesn't carry Reality's
//! cipher/ALPN/cert-verify wire characteristics.
//!
//! # Why no TLS
//!
//! TLS adds wire-shape cover but also a known cipher / handshake /
//! cert exchange that's a fingerprint surface. Plain TCP with a
//! 64-byte handshake-then-random-bytes is, paradoxically, harder to
//! signature on a wire pattern level - the only signal is "high
//! entropy on the wire from byte 0." Censors can flag that, but
//! collateral damage is high (TLS-tunnels, SSH-over-non-22, `BTSync`,
//! etc. all look the same).
//!
//! v0.2 adds a TLS layer on top (`mirage-transport-trojan`); obfs
//! stays as the lighter test-bed.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use mirage_crypto::blake3;
use mirage_crypto::subtle::ConstantTimeEq;
use mirage_discovery::wire::Endpoint;
use mirage_transport::{ClientTransport, DialInputs, DuplexStream, TransportError};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Capability bit for `obfs-tcp` (reserved bit 5). Operators
/// advertise this in their announcement's `transport_caps` to
/// indicate the bridge accepts obfs-tcp.
pub const OBFS_TCP_CAPABILITY_BIT: u32 = 1 << 5;

/// Domain separator for the obfs handshake key derivation.
const OBFS_KEY_LABEL: &[u8] = b"mirage-obfs-v1-key";

/// Domain separator for the secret-keyed obfs handshake key derivation
/// (audit #9). Distinct from [`OBFS_KEY_LABEL`] so the two key-derivation
/// modes can never collide.
const OBFS_SECRET_KEY_LABEL: &[u8] = b"mirage-obfs-secret-v1-key";

/// Total auth bytes on the wire: nonce(32) + tag(32).
///
/// KNOWN RESIDUAL (red-team #6/#9): unlike the WebSocket / meek knocks, the
/// obfs-tcp knock carries no timestamp, so freshness rests solely on the bridge
/// mux's nonce replay-set (bounded TTL + capacity). A knock CAPTURED off the wire
/// (from a legitimate invite-holder's connection) and replayed AFTER the replay
/// entry has expired or been evicted re-confirms the bridge to an active prober.
/// The secret-keyed tag (audit #9) already prevents FORGING a knock without the
/// invite; this residual is confirmation-by-replay only, and is the light-carrier
/// tradeoff obfs-tcp documents throughout. The full fix (a MAC-covered timestamp
/// like the WS frame, widening the auth frame) is a wire-format change deferred
/// as disproportionate to the bounded window; prefer Reality where active-probe
/// resistance is the priority.
pub const OBFS_AUTH_LEN: usize = 64;

/// **Phase 2I redesign - closes [RT-CN-3].**
///
/// Lower bound on the auth-failure jitter window. The original
/// design used a 500-3500 ms tarpit so a probe that submitted 64
/// random bytes did not see an immediate close. The failure mode
/// the redesign addresses: real TCP services typically close
/// immediately on garbage input. A 500 ms+ hold time on every
/// connection that sent something the bridge couldn't auth was
/// itself a Mirage signature - a censor probing N suspected
/// bridges with random tags would see 100% have a 500-3500 ms
/// hold time, while real TCP services close immediately. The
/// distribution itself was the giveaway.
///
/// New design: close fast (matching real-TCP-server behavior on
/// garbage), with a tiny randomized jitter (`[0, JITTER_MAX]`) to
/// obscure auth-tag computation timing. Real servers close in 0-
/// few-ms on garbage; Mirage now lands in the same window.
pub const OBFS_AUTH_FAIL_JITTER_MIN: Duration = Duration::from_millis(0);
/// Upper bound on the post-auth-fail jitter. Tight (50 ms) so the
/// distribution overlaps with real-server behaviors, but non-zero
/// so timing of the auth-tag verification (constant-time but
/// still measurably variable across hosts) is masked.
pub const OBFS_AUTH_FAIL_JITTER_MAX: Duration = Duration::from_millis(50);

// Backwards-compatible aliases for code that still references the
// old constants. New callers should use the JITTER variants.
/// Deprecated alias for [`OBFS_AUTH_FAIL_JITTER_MIN`].
#[deprecated(note = "use OBFS_AUTH_FAIL_JITTER_MIN - closes [RT-CN-3]")]
pub const OBFS_AUTH_FAIL_TARPIT_MIN: Duration = OBFS_AUTH_FAIL_JITTER_MIN;
/// Deprecated alias for [`OBFS_AUTH_FAIL_JITTER_MAX`].
#[deprecated(note = "use OBFS_AUTH_FAIL_JITTER_MAX - closes [RT-CN-3]")]
pub const OBFS_AUTH_FAIL_TARPIT_MAX: Duration = OBFS_AUTH_FAIL_JITTER_MAX;

/// Construct the auth tag for a given bridge-static-pk and nonce, using the
/// legacy PUBLIC-key-derived key. Kept for backward compatibility and for
/// bridges/clients with no provisioned obfs secret. Prefer
/// [`obfs_auth_tag_with_secret`] - keying on the public pk means any prober who
/// scraped the announcement can mint a valid tag (the documented T2 FAIL).
///
/// Public so client + bridge implementations can derive the same
/// value from their respective sides.
pub fn obfs_auth_tag(bridge_static_pk: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    obfs_auth_tag_with_secret(bridge_static_pk, None, nonce)
}

/// Construct the auth tag, keyed on the invite-shared **secret** when one is
/// available (audit #9). Closing the T2 hole: with a secret, only a party who
/// holds an actual invite (not merely the scraped public key) can forge a valid
/// knock, so a pubkey-only active prober is turned away. Falls back to the
/// legacy pubkey-derived key when `obfs_secret` is `None` (bridges/clients that
/// have not provisioned a secret), mirroring `mirage_quic_obfs`'s
/// secret-or-pubkey key resolution. The bridge static pk is always mixed in so a
/// secret shared across bridges still yields per-bridge tags.
pub fn obfs_auth_tag_with_secret(
    bridge_static_pk: &[u8; 32],
    obfs_secret: Option<&[u8; 32]>,
    nonce: &[u8; 32],
) -> [u8; 32] {
    let key_input = match obfs_secret {
        Some(secret) => {
            // Secret-keyed: BLAKE3-keyed(secret, label || bridge_static_pk).
            let mut h = blake3::Hasher::new_keyed(secret);
            h.update(OBFS_SECRET_KEY_LABEL);
            h.update(bridge_static_pk);
            *h.finalize().as_bytes()
        }
        // Legacy: pubkey-derived (T2 FAIL, documented).
        None => blake3_keyed_to_array(bridge_static_pk, OBFS_KEY_LABEL),
    };
    let key = blake3::keyed_hash(&key_input, nonce);
    *key.as_bytes()
}

/// BLAKE3-keyed with a 32-byte key derived from `key_input`.
fn blake3_keyed_to_array(key_input: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key_input);
    hasher.update(label);
    *hasher.finalize().as_bytes()
}

/// Verify an auth tag, constant-time (legacy pubkey-keyed).
pub fn obfs_auth_verify(
    bridge_static_pk: &[u8; 32],
    nonce: &[u8; 32],
    presented_tag: &[u8; 32],
) -> bool {
    obfs_auth_verify_with_secret(bridge_static_pk, None, nonce, presented_tag)
}

/// Verify an auth tag, constant-time, keyed on the invite-shared secret when
/// available (audit #9). A bridge configured with an obfs secret passes
/// `Some(secret)` and thereby REQUIRES a secret-keyed knock - a pubkey-only
/// prober no longer authenticates.
pub fn obfs_auth_verify_with_secret(
    bridge_static_pk: &[u8; 32],
    obfs_secret: Option<&[u8; 32]>,
    nonce: &[u8; 32],
    presented_tag: &[u8; 32],
) -> bool {
    let expected = obfs_auth_tag_with_secret(bridge_static_pk, obfs_secret, nonce);
    expected.ct_eq(presented_tag).unwrap_u8() == 1
}

// ClientTransport impl

/// Client-side `obfs-tcp` transport.
///
/// Stateless; safe to share via `Arc` across tasks. The actual
/// TCP socket lives only inside the returned [`DuplexStream`].
pub struct ObfsClientTransport;

impl ObfsClientTransport {
    /// Construct a new client-side transport. Cheap (zero-sized).
    pub fn new() -> Self {
        Self
    }
}

impl Default for ObfsClientTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ClientTransport for ObfsClientTransport {
    fn name(&self) -> &'static str {
        "obfs-tcp"
    }

    fn capability_bit(&self) -> u32 {
        OBFS_TCP_CAPABILITY_BIT
    }

    async fn dial(&self, inputs: &DialInputs<'_>) -> Result<DuplexStream, TransportError> {
        let socket_addr = endpoint_to_socket_addr(inputs.endpoint)?;
        let mut stream = tokio::time::timeout(inputs.deadline, TcpStream::connect(socket_addr))
            .await
            .map_err(|_| TransportError::Timeout(inputs.deadline))?
            .map_err(TransportError::Io)?;
        // Build the auth message.
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| TransportError::Other("CSPRNG failure".into()))?;
        // #9: key the knock on the invite-shared obfs secret when present, so a
        // pubkey-only prober cannot forge it.
        let tag = obfs_auth_tag_with_secret(inputs.bridge_static_pk, inputs.obfs_secret, &nonce);
        let mut buf = [0u8; OBFS_AUTH_LEN];
        buf[0..32].copy_from_slice(&nonce);
        buf[32..64].copy_from_slice(&tag);
        // Write auth under deadline.
        tokio::time::timeout(inputs.deadline, stream.write_all(&buf))
            .await
            .map_err(|_| TransportError::Timeout(inputs.deadline))?
            .map_err(TransportError::Io)?;
        tokio::time::timeout(inputs.deadline, stream.flush())
            .await
            .map_err(|_| TransportError::Timeout(inputs.deadline))?
            .map_err(TransportError::Io)?;
        Ok(Box::pin(stream))
    }
}

fn endpoint_to_socket_addr(ep: &Endpoint) -> Result<std::net::SocketAddr, TransportError> {
    match ep {
        Endpoint::Ipv4 { addr, port } => Ok(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
            *port,
        )),
        Endpoint::Ipv6 { addr, port } => Ok(std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(*addr)),
            *port,
        )),
        Endpoint::Domain { .. } => Err(TransportError::Other(
            "obfs-tcp does not resolve domains; use IP endpoints".into(),
        )),
        Endpoint::OnionV3 { .. } => Err(TransportError::Other(
            "obfs-tcp does not speak onion; use a Tor SOCKS forwarder".into(),
        )),
    }
}

// Server-side accept helper

/// Read and verify the obfs-tcp auth from `stream`. On success the
/// stream is positioned at byte 65 (just past the auth) and the
/// caller hands it to the session layer's `accept`.
///
/// # Timing-oracle unification (finding #9)
///
/// The auth tag is a deterministic function of the bridge's X25519
/// PUBLIC key (which rides in the public announcement) and a
/// per-connection nonce, so a censor who scraped the announcement
/// can mint a VALID knock for any announced bridge - it is a
/// pre-auth knock, NOT authentication (T2 FAIL, see the module
/// threat model). To stop that censor turning the pass/fail split
/// into a positive Mirage classifier, BOTH the pass path and the
/// fail path now draw the SAME post-read jitter from
/// [`random_tarpit`] (`[OBFS_AUTH_FAIL_JITTER_MIN,
/// OBFS_AUTH_FAIL_JITTER_MAX)`, 0 to ~50 ms). The draw is
/// unconditional and independent of the verify result, so the
/// two branches are drawn from an identical distribution and the
/// close-latency side-channel is removed. This also preserves the
/// [RT-CN-3] fix (the previous 500-3500 ms tarpit was itself a
/// Mirage signature; the sub-50 ms window matches a real TCP
/// server closing on garbage while masking auth-tag-verify timing).
///
/// # Residual (honest)
///
/// Unifying timing does NOT make the tag authentication: because
/// the tag is forgeable from PUBLIC announcement data, a censor
/// can always drive the pass branch, and whether the *caller* then
/// holds the socket open (pass) versus closes it (fail) is still an
/// observable that this function cannot control from here. Fully
/// collapsing that branch needs Option A - binding the knock to an
/// invite-only secret a pubkey scraper does NOT hold (the codebase
/// already carries one: `INVITE_EXT_QUIC_OBFS_SECRET`). That is not
/// plumbable in this function today: neither `mirage_transport::DialInputs`
/// (client dial) nor `mirage_transport_mux::MuxConfig` (bridge verify)
/// carries the obfs secret, so wiring it through is a cross-crate
/// change out of scope here. Recommended follow-up. NOTE: the
/// PRODUCTION bridge path authenticates obfs-tcp in the protocol
/// mux, whose fail branch falls through to cover (`MuxResult::Unknown`)
/// with the peeked bytes intact - no bare close - so it already
/// avoids the close tell; this standalone helper backs the simpler
/// integration/test path and now matches on timing.
///
/// Caller still MUST close the stream after this function
/// returns Err - the jitter only delays the close, it does not
/// perform cover-forwarding.
pub async fn obfs_server_authenticate<S>(
    stream: &mut S,
    bridge_static_pk: &[u8; 32],
    obfs_secret: Option<&[u8; 32]>,
    deadline: Duration,
) -> Result<(), TransportError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = [0u8; OBFS_AUTH_LEN];
    tokio::time::timeout(deadline, stream.read_exact(&mut buf))
        .await
        .map_err(|_| TransportError::Timeout(deadline))?
        .map_err(TransportError::Io)?;
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&buf[0..32]);
    let mut presented = [0u8; 32];
    presented.copy_from_slice(&buf[32..64]);
    // #9: when the bridge has an obfs secret configured, the knock is verified
    // against the secret-keyed tag, so a pubkey-only prober is turned away.
    let ok = obfs_auth_verify_with_secret(bridge_static_pk, obfs_secret, &nonce, &presented);
    // Finding #9: draw the jitter UNCONDITIONALLY, before branching on
    // `ok`, so the pass and fail paths take identically-distributed time.
    // The delay does not depend on the verify result, so there is no
    // close-latency oracle a forged-valid knock could read out.
    tokio::time::sleep(random_tarpit()).await;
    if !ok {
        return Err(TransportError::Auth("obfs auth verify failed"));
    }
    Ok(())
}

/// Draw a post-read jitter from `[OBFS_AUTH_FAIL_JITTER_MIN,
/// OBFS_AUTH_FAIL_JITTER_MAX)`. Drawn on BOTH the pass and the fail
/// path of [`obfs_server_authenticate`] (finding #9) so the two are
/// identically distributed in time; it also masks the
/// constant-time-but-variable auth-tag-verify timing. Closes
/// [RT-CN-3]. CSPRNG failure falls back to the lower bound (0 ms
/// - matches an immediate close).
fn random_tarpit() -> Duration {
    let min = OBFS_AUTH_FAIL_JITTER_MIN.as_millis() as u64;
    let max = OBFS_AUTH_FAIL_JITTER_MAX.as_millis() as u64;
    let span = max.saturating_sub(min);
    if span == 0 {
        return OBFS_AUTH_FAIL_JITTER_MIN;
    }
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return OBFS_AUTH_FAIL_JITTER_MIN;
    }
    let pick = u64::from_be_bytes(bytes) % span;
    Duration::from_millis(min + pick)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tokio::io::duplex;

    #[test]
    fn auth_tag_deterministic() {
        let pk = [0x11u8; 32];
        let n = [0x22u8; 32];
        let t1 = obfs_auth_tag(&pk, &n);
        let t2 = obfs_auth_tag(&pk, &n);
        assert_eq!(t1, t2, "auth tag is deterministic in pk + nonce");
    }

    #[test]
    fn secret_keyed_tag_closes_pubkey_forgery() {
        // Audit #9: with a secret, the tag is NOT derivable from the public key
        // alone - a pubkey-only prober (the T2 attacker) can no longer forge it.
        let pk = [0x11u8; 32];
        let secret = [0x99u8; 32];
        let n = [0x22u8; 32];

        let pubkey_tag = obfs_auth_tag_with_secret(&pk, None, &n);
        let secret_tag = obfs_auth_tag_with_secret(&pk, Some(&secret), &n);
        assert_ne!(
            pubkey_tag, secret_tag,
            "secret-keyed tag must differ from the pubkey-derived one"
        );
        // A verifier that requires the secret rejects the pubkey-only tag (what a
        // scraper could compute) ...
        assert!(!obfs_auth_verify_with_secret(
            &pk,
            Some(&secret),
            &n,
            &pubkey_tag
        ));
        // ... and accepts the genuine secret-keyed tag.
        assert!(obfs_auth_verify_with_secret(
            &pk,
            Some(&secret),
            &n,
            &secret_tag
        ));
        // A different secret does not verify (the secret is load-bearing).
        let other = [0x42u8; 32];
        assert!(!obfs_auth_verify_with_secret(
            &pk,
            Some(&other),
            &n,
            &secret_tag
        ));
        // Deterministic + still per-bridge (pk mixed in).
        assert_eq!(
            secret_tag,
            obfs_auth_tag_with_secret(&pk, Some(&secret), &n)
        );
        let pk2 = [0x33u8; 32];
        assert_ne!(
            secret_tag,
            obfs_auth_tag_with_secret(&pk2, Some(&secret), &n)
        );
    }

    #[test]
    fn different_pk_produces_different_tag() {
        let n = [0x22u8; 32];
        let t1 = obfs_auth_tag(&[0x11u8; 32], &n);
        let t2 = obfs_auth_tag(&[0x12u8; 32], &n);
        assert_ne!(t1, t2);
    }

    #[test]
    fn different_nonce_produces_different_tag() {
        let pk = [0x11u8; 32];
        let t1 = obfs_auth_tag(&pk, &[0x01u8; 32]);
        let t2 = obfs_auth_tag(&pk, &[0x02u8; 32]);
        assert_ne!(t1, t2);
    }

    #[test]
    fn auth_verify_round_trips() {
        let pk = [0x11u8; 32];
        let n = [0x22u8; 32];
        let tag = obfs_auth_tag(&pk, &n);
        assert!(obfs_auth_verify(&pk, &n, &tag));
    }

    #[test]
    fn auth_verify_rejects_wrong_tag() {
        let pk = [0x11u8; 32];
        let n = [0x22u8; 32];
        let mut tag = obfs_auth_tag(&pk, &n);
        tag[0] ^= 0x01;
        assert!(!obfs_auth_verify(&pk, &n, &tag));
    }

    #[test]
    fn auth_verify_rejects_wrong_pk() {
        let n = [0x22u8; 32];
        let tag = obfs_auth_tag(&[0x11u8; 32], &n);
        assert!(!obfs_auth_verify(&[0x12u8; 32], &n, &tag));
    }

    #[tokio::test]
    async fn server_authenticate_accepts_valid_auth() {
        let (mut a, b) = duplex(1024);
        let pk = [0xAAu8; 32];
        // Write valid auth from one side.
        let mut nonce = [0u8; 32];
        for (i, byte) in nonce.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_add(1);
        }
        let tag = obfs_auth_tag(&pk, &nonce);
        let mut handshake = Vec::with_capacity(64);
        handshake.extend_from_slice(&nonce);
        handshake.extend_from_slice(&tag);
        a.write_all(&handshake).await.unwrap();
        a.flush().await.unwrap();
        // Authenticate from the other.
        let mut b = b;
        let r = obfs_server_authenticate(&mut b, &pk, None, Duration::from_secs(1)).await;
        assert!(r.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn server_authenticate_rejects_garbage() {
        // start_paused = true so the auth-fail tarpit's sleep
        // auto-advances and the test still completes instantly.
        let (mut a, b) = duplex(1024);
        let garbage = [0u8; 64];
        a.write_all(&garbage).await.unwrap();
        a.flush().await.unwrap();
        let mut b = b;
        let pk = [0xAAu8; 32];
        let r = obfs_server_authenticate(&mut b, &pk, None, Duration::from_secs(1)).await;
        assert!(matches!(r, Err(TransportError::Auth(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn server_authenticate_rejects_wrong_pk() {
        let (mut a, b) = duplex(1024);
        // Auth signed with one pk; verify with another.
        let signing_pk = [0x11u8; 32];
        let verifying_pk = [0x12u8; 32];
        let mut nonce = [0u8; 32];
        nonce[0] = 1;
        let tag = obfs_auth_tag(&signing_pk, &nonce);
        let mut handshake = Vec::with_capacity(64);
        handshake.extend_from_slice(&nonce);
        handshake.extend_from_slice(&tag);
        a.write_all(&handshake).await.unwrap();
        a.flush().await.unwrap();
        let mut b = b;
        let r = obfs_server_authenticate(&mut b, &verifying_pk, None, Duration::from_secs(1)).await;
        assert!(matches!(r, Err(TransportError::Auth(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn server_authenticate_jitters_on_auth_fail() {
        // RT-CN-3 (Phase 2I redesign): on auth fail, the bridge
        // closes within `[OBFS_AUTH_FAIL_JITTER_MIN,
        // OBFS_AUTH_FAIL_JITTER_MAX)`. Mimics real-TCP-server
        // behavior on garbage (close immediately, with hardware
        // jitter measured in milliseconds). The previous
        // 500-3500 ms tarpit was itself a Mirage signature.
        let (mut a, b) = duplex(1024);
        a.write_all(&[0u8; 64]).await.unwrap();
        a.flush().await.unwrap();
        let mut b = b;
        let pk = [0xAAu8; 32];
        let start = tokio::time::Instant::now();
        let _ = obfs_server_authenticate(&mut b, &pk, None, Duration::from_secs(10)).await;
        let elapsed = start.elapsed();
        // Lower bound is 0 ms - there's no minimum wait; we just
        // verify we stay under the upper bound (no rogue long
        // tarpit).
        assert!(
            elapsed < OBFS_AUTH_FAIL_JITTER_MAX + Duration::from_millis(50),
            "fail-path took too long: {elapsed:?} >= {:?}",
            OBFS_AUTH_FAIL_JITTER_MAX + Duration::from_millis(50)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn server_authenticate_pass_and_fail_have_identical_timing_treatment() {
        // Finding #9 regression: a censor can forge a VALID knock (the tag
        // is derived from the PUBLIC bridge pk), so the pass and fail paths
        // MUST NOT differ in close latency - both draw the SAME post-read
        // jitter. Under paused time, `elapsed()` equals exactly the jitter
        // slept (the pre-written duplex read completes without advancing the
        // virtual clock), so we can read out each call's drawn delay directly.
        let pk = [0xAAu8; 32];
        let mut pass_saw_nonzero = false;
        let mut fail_saw_nonzero = false;
        for _ in 0..128 {
            // PASS: a valid (forgeable-from-pubkey) knock.
            {
                let (mut a, mut b) = duplex(1024);
                let mut nonce = [0u8; 32];
                getrandom::fill(&mut nonce).unwrap();
                let tag = obfs_auth_tag(&pk, &nonce);
                let mut hs = Vec::with_capacity(64);
                hs.extend_from_slice(&nonce);
                hs.extend_from_slice(&tag);
                a.write_all(&hs).await.unwrap();
                a.flush().await.unwrap();
                let start = tokio::time::Instant::now();
                let r = obfs_server_authenticate(&mut b, &pk, None, Duration::from_secs(10)).await;
                let elapsed = start.elapsed();
                assert!(r.is_ok(), "valid knock must authenticate");
                assert!(
                    elapsed < OBFS_AUTH_FAIL_JITTER_MAX,
                    "pass jitter out of range: {elapsed:?}"
                );
                if elapsed > Duration::ZERO {
                    pass_saw_nonzero = true;
                }
            }
            // FAIL: a garbage knock.
            {
                let (mut a, mut b) = duplex(1024);
                a.write_all(&[0u8; 64]).await.unwrap();
                a.flush().await.unwrap();
                let start = tokio::time::Instant::now();
                let r = obfs_server_authenticate(&mut b, &pk, None, Duration::from_secs(10)).await;
                let elapsed = start.elapsed();
                assert!(matches!(r, Err(TransportError::Auth(_))));
                assert!(
                    elapsed < OBFS_AUTH_FAIL_JITTER_MAX,
                    "fail jitter out of range: {elapsed:?}"
                );
                if elapsed > Duration::ZERO {
                    fail_saw_nonzero = true;
                }
            }
        }
        // Before the fix the PASS path returned instantly (never jittered)
        // while FAIL slept - the oracle. Both drawing from the same window
        // means each, over 128 draws of a 50-wide range, is non-zero with
        // overwhelming probability ((1/50)^128 of an all-zero run).
        assert!(
            pass_saw_nonzero,
            "pass path never jittered - close-latency oracle vs fail path"
        );
        assert!(fail_saw_nonzero, "fail path never jittered");
    }

    #[tokio::test]
    async fn server_authenticate_times_out_on_silent_peer() {
        let (_a, b) = duplex(1024); // _a never writes
        let mut b = b;
        let pk = [0xAAu8; 32];
        let r = obfs_server_authenticate(&mut b, &pk, None, Duration::from_millis(20)).await;
        // Either Timeout (we hit the deadline) or Io (BrokenPipe
        // when test harness closes the duplex). Both are ok.
        assert!(r.is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn auth_verify_fuzz_random_bytes_always_rejects(buf in prop::array::uniform32(any::<u8>())) {
            // Random "tag" bytes should virtually never validate
            // against a fixed pk + nonce. (Probability: 2^-256.)
            let pk = [0x11u8; 32];
            let nonce = [0x22u8; 32];
            // Skip the (essentially-impossible) collision case.
            let real_tag = obfs_auth_tag(&pk, &nonce);
            if buf == real_tag {
                return Ok(());
            }
            prop_assert!(!obfs_auth_verify(&pk, &nonce, &buf));
        }
    }
}
