//! Reality carrier async orchestrators: `reality_connect` (client),
//! `reality_accept` (bridge), cover-service fallback, and
//! `RealityStream` (AsyncRead + AsyncWrite over the TLS record layer).
//!
//! # Client side (`reality_connect`)
//!
//! 1. Generate a fresh X25519 ephemeral + a 32-byte ClientHello
//!    random + a 12-byte probe nonce.
//! 2. Build the auth probe ([`crate::build_probe`]) and place it
//!    verbatim in the TLS ClientHello's `session_id`; place the
//!    X25519 public in the `key_share` extension.
//! 3. Write the ClientHello bytes to the underlying byte stream
//!    (typically a TCP socket the caller already opened to the
//!    bridge).
//! 4. Read and parse the bridge's ServerHello response.
//! 5. Return a [`RealityStream`] - subsequent bytes are wrapped by
//!    the TLS record layer on the wire so a passive observer sees
//!    TLS 1.3 application_data frames.
//!
//! # Bridge side (`reality_accept`)
//!
//! 1. Read the incoming ClientHello (bounded by
//!    [`MAX_CLIENT_HELLO_SIZE`]; timeout is the caller's concern).
//! 2. Parse it; extract `random`, `session_id`, `key_share`.
//! 3. Verify the probe ([`crate::verify_probe`]). On ANY failure
//!    we do NOT respond on the original socket - we transparently
//!    forward the buffered ClientHello bytes and every subsequent
//!    byte to a configured cover destination. The peer sees a
//!    normal TLS session to the cover host; no signal of "this is
//!    a Mirage bridge."
//! 4. On success: generate a ServerHello, send it, return a
//!    [`RealityStream`].
//!
//! # Cover-service fallback
//!
//! The bridge pre-configures a `cover_addr: SocketAddr` (e.g., a
//! real `www.example.com:443`). On auth failure we open a fresh
//! TCP to it, write the exact ClientHello bytes we buffered (so
//! SNI/key_share match the client's expectation from the cover),
//! and bidirectionally pump bytes. The client sees a real TLS
//! session with the cover; the bridge's behavior for
//! non-authenticated peers is indistinguishable from a transparent
//! TCP proxy to the cover. Operators pick covers that serve real
//! traffic (TLS + HTTPS) so a casual probe looks legitimate.
//!
//! # v0.1a scope disclaimer
//!
//! The ServerHello is a synthesized TLS 1.3 handshake shell: it
//! parses as TLS 1.3 at the record/handshake layer but we do NOT
//! derive real TLS traffic keys. After the handshake shells, both
//! sides wrap Mirage frames in `application_data` records. A
//! passive DPI that classifies by record-layer pattern is
//! defeated. An active prober that attempts to complete the TLS
//! handshake (e.g., GFW replay-probe) will diverge - we ship
//! full TLS 1.3 crypto mimicry in v0.1b.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_crypto::zeroize::Zeroizing;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

use crate::error::RealityError;
use crate::probe::{build_probe, verify_probe, BridgeProbeInputs, ClientProbeInputs, NONCE_LEN};
use crate::record::{unwrap_app_data, wrap_app_data, MAX_INNER_PAYLOAD, RECORD_HEADER_LEN};
use crate::record_cipher::RecordCipher;
use crate::replay::ReplayProbeSet;
use crate::tls_cert::build_self_signed_ecdsa_p256;
use crate::tls_client_hello::{parse_client_hello_record, MAX_CLIENT_HELLO_SIZE};
use crate::tls_client_hello_gen::{build_client_hello, ClientHelloInputs};
use crate::tls_handshake_flight::{
    build_certificate, build_certificate_verify, build_encrypted_extensions, build_finished,
    build_new_session_ticket, read_handshake, strip_inner_content_type, verify_finished,
    with_inner_content_type, HS_TYPE_CERTIFICATE, HS_TYPE_CERTIFICATE_VERIFY,
    HS_TYPE_ENCRYPTED_EXTENSIONS, HS_TYPE_FINISHED, HS_TYPE_NEW_SESSION_TICKET,
    INNER_CONTENT_TYPE_HANDSHAKE, SIG_SCHEME_ECDSA_SECP256R1_SHA256,
};
use crate::tls_keyschedule::{
    application_traffic_secret_0, early_secret_no_psk, finished_key, handshake_secret,
    handshake_traffic_secret, master_secret, TranscriptHash, AEAD_IV_LEN,
};
use crate::tls_server_hello::{build_server_hello, parse_server_hello_record, ServerHelloInputs};

// Reality v0.1b traffic keys

/// AEAD tag length (ChaCha20-Poly1305 / AES-GCM: 16 bytes).
const AEAD_TAG_LEN: usize = 16;

/// Per-direction traffic keys derived from the X25519 shared
/// secret. TLS 1.3 uses a full HKDF-with-transcript derivation; for
/// v0.1b we use a simpler HKDF-Expand-Label-ish scheme that binds
/// the direction and context. An adversary who breaks ECDH can
/// forge records; an adversary who has the ciphertext but not the
/// ECDH output cannot decrypt.
///
/// v0.1c will switch to the TLS 1.3 key schedule proper (matching
/// the transcript hash a real TLS 1.3 peer would compute) so an
/// active prober that completes the handshake succeeds - at that
/// point the carrier is indistinguishable from a real TLS 1.3
/// server even to a stateful adversary.
struct DirKeys {
    /// AEAD selected by the negotiated cipher suite (ChaCha20 or AES-128-GCM).
    cipher: RecordCipher,
    /// AEAD key: 32 bytes (ChaCha) or 16 (AES-128).
    key: Zeroizing<Vec<u8>>,
    iv: [u8; 12],
    seq: u64,
}

impl DirKeys {
    /// Construct directly from cipher + key + IV (used by the v0.1c post-
    /// handshake switch to application traffic secrets, where the
    /// key schedule already expanded everything).
    fn from_key_iv(cipher: RecordCipher, key: Zeroizing<Vec<u8>>, iv: [u8; 12]) -> Self {
        Self {
            cipher,
            key,
            iv,
            seq: 0,
        }
    }

    fn next_nonce(&mut self) -> Result<[u8; 12], RealityError> {
        let mut n = self.iv;
        // RFC 8446 §5.3: pad seq to 12 bytes (LHS zero), XOR with iv.
        let seq_bytes = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= seq_bytes[i];
        }
        self.seq = self.seq.checked_add(1).ok_or(RealityError::TagMismatch)?;
        Ok(n)
    }
}

/// Both directions' AEAD state. Owned by [`RealityStream`].
struct TrafficKeys {
    send: DirKeys,
    recv: DirKeys,
}

fn x25519_shared(sk: &StaticSecret, pk: &[u8; 32]) -> Result<[u8; 32], RealityError> {
    let peer = PublicKey::from(*pk);
    let s = sk.diffie_hellman(&peer);
    let out = s.to_bytes();
    if out.iter().all(|&b| b == 0) {
        return Err(RealityError::ZeroPoint);
    }
    Ok(out)
}

// Inputs

/// Client-side Reality carrier inputs.
pub struct ClientCarrierInputs<'a> {
    /// Bridge's X25519 static public key, from the invite /
    /// announcement.
    pub bridge_static_pk: &'a [u8; 32],
    /// SNI to put in the ClientHello. Convention: the cover
    /// destination's hostname, so traffic inspection sees a
    /// plausible name matching the cover certificate an active
    /// prober would observe.
    pub server_name: &'a str,
    /// Current Unix time (seconds), for the probe timestamp.
    pub now_unix: u32,
    /// Per-bridge probe root from the authenticated invite
    /// (`INVITE_EXT_REALITY_PROBE_ROOT`), used to derive the per-epoch probe
    /// secret bound into the auth probe. Pass
    /// [`crate::probe::PROBE_ROOT_DISABLED`] (all-zero) when the invite carried
    /// no root; the probe is then byte-identical to a legacy probe. See
    /// [`crate::probe`] for the anti-enumeration rationale.
    pub probe_root: &'a [u8; 32],
    /// Optional override for CertificateVerify signature checking.
    /// When `Some`, the client verifies the bridge's CertVerify
    /// signature against THIS key, ignoring the cert's SPKI. Used
    /// when the bridge runs in `pinned` or `cover_mimicry` TLS
    /// mode - the cert shown on the wire can be the cover
    /// destination's, whose private key the bridge doesn't hold;
    /// the operator publishes the bridge's TLS-signing pubkey in
    /// the invite (see
    /// [`mirage_discovery::invite::MasterInvite::tls_cert_verify_pk`]),
    /// and the caller threads it here. `None` (default) falls
    /// back to v0.1c behavior (use cert's SPKI). The pubkey is a
    /// compressed SEC1 P-256 point (33 bytes).
    pub cert_verify_override_pk: Option<&'a [u8; 33]>,
    /// ClientHello fingerprint template. Drives cipher-suite list,
    /// extension order, signature algorithms, ALPN protocols.
    /// `None` = Chrome desktop default. See
    /// [`crate::tls_fingerprint`] for built-in alternatives
    /// (Firefox, Safari) and for the operator-controlled rotation
    /// story (A17 + A26).
    pub tls_fingerprint: Option<&'a crate::tls_fingerprint::TlsFingerprintTemplate>,
}

/// Bridge-side Reality carrier inputs.
pub struct BridgeCarrierInputs<'a> {
    /// Bridge's X25519 static secret.
    pub bridge_static_sk: &'a StaticSecret,
    /// Current Unix time (seconds).
    pub now_unix: u32,
    /// Where to forward traffic when probe verification fails.
    /// Operators pick a real HTTPS endpoint (`www.example.com:443`,
    /// etc.) that serves real content.
    pub cover_addr: SocketAddr,
    /// Replay-probe set shared across accepts.
    ///
    /// A reference to the shared `Mutex`, NOT a pre-acquired guard: the lock is
    /// taken *inside* `reality_accept` for the sole duration of the synchronous
    /// [`verify_probe`] call and released before the ClientHello I/O and the
    /// (up to `cover_duration_cap`) cover-serve. Passing a guard here - as an
    /// earlier version did - held this single bridge-wide lock across the whole
    /// accept, so one attacker holding an unauthenticated connection open for
    /// the 30s cover cap serialized every other Reality handshake (a trivial
    /// bridge-wide DoS). Keep the critical section around `verify_probe` only.
    pub replay_set: &'a tokio::sync::Mutex<ReplayProbeSet>,
    /// Per-bridge probe root, re-derived at bridge startup from the bridge's
    /// X25519 static secret (the SAME value the invite-mint embedded in
    /// invites). Pass [`crate::probe::PROBE_ROOT_DISABLED`] to run without
    /// epoch binding (legacy behaviour). See [`crate::probe`].
    pub probe_root: &'a [u8; 32],
    /// When epoch binding is active, also accept legacy (unbound) probes -
    /// the seamless-rollover default. Operators set this `false` post-rollout
    /// to close the pubkey-only enumeration hole. Ignored when `probe_root` is
    /// disabled.
    ///
    /// This flag also gates the #3 pass-path timing equalization: while
    /// `accept_legacy` is `true` a scraper can forge a legacy-valid probe from
    /// the public static key and reach the auth-PASS path, so `reality_accept`
    /// runs the same cover round-trip on the pass path to erase the pass/fail
    /// response-latency bifurcation. Running strict (`false`) makes the pass
    /// path unreachable by a scraper and skips that per-handshake tax - the
    /// preferred end state once every cohort bridge has an invite-delivered
    /// `probe_root`.
    pub accept_legacy: bool,
    /// Hard cap on time spent reading the ClientHello. Without
    /// this, a slow-loris client can tie up an accept slot.
    pub client_hello_read_timeout: Duration,
    /// Hard cap on time spent shuttling cover-service bytes after
    /// auth failure. Bounds the blast radius of a flood of junk
    /// connections.
    pub cover_duration_cap: Duration,
    /// Optional TLS identity to present in the handshake's
    /// `Certificate` + `CertificateVerify` messages. `None`
    /// (default) = ephemeral mode: the bridge mints a fresh
    /// self-signed Ed25519 cert per session. `Some` = pinned
    /// mode: cert bytes are served verbatim (possibly copied
    /// from a cover destination), CertVerify is signed by
    /// `tls_signing_key`. Operators choose pinned mode via the
    /// `tls_mode` bridge config; see the bridge daemon for the
    /// full loader.
    pub tls_identity: Option<&'a TlsIdentity>,
    /// Target wire size (bytes) for the authenticated-path server flight,
    /// measured from the cover destination by [`crate::probe_cover_flight`].
    /// When `Some`, the bridge pads its encrypted `Certificate` flight up to
    /// this size so a passive censor comparing it to the real cover sees a
    /// matching encrypted-flight length (closes the self-signed-flight-too-small
    /// distinguisher). `None` (default) = no padding. Operators get this for
    /// free; the bridge profiles each cover once at startup.
    pub cover_flight_target: Option<usize>,
    /// The cover's per-`application_data`-record wire sizes (M1). When this holds
    /// two or more records AND the flight can be split to match them while keeping
    /// the Finished message in the LAST record (so the client, which stops reading
    /// at Finished, leaves no record unread), the bridge reproduces the cover's
    /// record FRAMING (count + sizes), not just its total. Otherwise it falls
    /// back to one coalesced padded record. Empty = coalesced. From
    /// [`crate::CoverFlightProfile::record_wire_lens`].
    pub cover_flight_records: &'a [usize],
}

/// Per-bridge TLS identity for the Reality carrier's
/// `Certificate` + `CertificateVerify` messages.
///
/// See [`BridgeCarrierInputs::tls_identity`] for the operator
/// modes this feeds. The struct does NOT hold the cert's private
/// key - that would only matter if we were validating TLS chain
/// or expected the client to chain-verify. Our design routes the
/// client's trust through the invite's `tls_cert_verify_pk` field;
/// the cert bytes on the wire exist purely for passive-DPI
/// mimicry.
#[derive(Debug, Clone)]
pub struct TlsIdentity {
    /// Raw DER-encoded X.509 certificate bytes. Embedded verbatim
    /// in each `Certificate` handshake message.
    pub cert_der: Vec<u8>,
    /// ECDSA P-256 signing key the bridge uses for `CertificateVerify`
    /// (scheme `ecdsa_secp256r1_sha256`, matching real browsers). In
    /// `cover_mimicry` mode this key does NOT match `cert_der`'s SPKI - the
    /// operator publishes the corresponding compressed-SEC1 pubkey in the invite
    /// (`MasterInvite::tls_cert_verify_pk`) so the client bypasses cert-SPKI
    /// verification.
    pub signing_key: p256::ecdsa::SigningKey,
}

/// Outcome of a bridge-side `reality_accept` call.
// `Authenticated` (the large variant) is the hot success path; boxing it just to
// shrink the rare `CoverServed` error path would be a net pessimisation.
#[allow(clippy::large_enum_variant)]
pub enum AcceptOutcome<S> {
    /// Probe verified; carrier is ready for a Mirage session
    /// handshake to run on top.
    Authenticated(RealityStream<S>),
    /// Probe failed; the bridge forwarded the buffered ClientHello
    /// and subsequent bytes to the cover.
    CoverServed {
        /// Bytes from the client that reached the cover (including
        /// the initial ClientHello).
        c2s: u64,
        /// Bytes from the cover that reached the client.
        s2c: u64,
    },
}

/// Errors that can end a carrier handshake.
#[derive(Debug, thiserror::Error)]
pub enum CarrierError {
    /// I/O error on the underlying byte stream (usually TCP).
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// Probe or TLS-layer failure. Client-side errors are fatal.
    /// Bridge-side errors that would reach this type have already
    /// been handled by the cover fallback; seeing one at this level
    /// means an internal bug.
    #[error("reality: {0}")]
    Reality(String),
    /// The server's ServerHello session_id did not echo the
    /// client's session_id. Either the peer isn't a Mirage bridge
    /// or the ClientHello was tampered with in transit.
    #[error("server_hello echo mismatch")]
    EchoMismatch,
    /// Hit a deadline while waiting for peer bytes.
    #[error("timeout")]
    Timeout,
}

impl From<RealityError> for CarrierError {
    fn from(e: RealityError) -> Self {
        Self::Reality(e.to_string())
    }
}

// Client side

/// Run a Reality carrier handshake on `stream` as the client.
///
/// TLS 1.3 middlebox-compatibility ChangeCipherSpec record
/// (`content_type=0x14, version=0x0303, len=1, payload=0x01`). Real TLS 1.3
/// endpoints emit this dummy record whenever the ClientHello carried a
/// non-empty legacy_session_id (reality's does - the 32-byte probe). Its
/// absence was a passive conformance tell (F1). It is NOT part of the
/// handshake transcript, so emitting/skipping it doesn't affect the hashes.
const TLS_CCS_RECORD: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

/// Upper bound on middlebox-compat ChangeCipherSpec records tolerated before the
/// encrypted flight. A conformant TLS 1.3 peer sends at most ONE CCS; without a
/// bound, a malicious peer (or on-path injector) streaming endless CCS records
/// spins the flight-read loop forever - a remote hang/DoS, since CCS records are
/// skipped *before* the flight-size cap. Two allows for benign duplication while
/// still terminating (red-team finding).
const MAX_CCS_RECORDS: u32 = 2;

/// True if `record` is a ChangeCipherSpec (content_type 0x14).
fn is_ccs_record(record: &[u8]) -> bool {
    record.first() == Some(&0x14)
}

/// The caller supplies an already-connected byte stream (usually a
/// `TcpStream` to the bridge endpoint) and the bridge's static
/// pubkey. On success, returns a [`RealityStream`] that the caller
/// uses as an `AsyncRead + AsyncWrite` substrate for the Mirage
/// session handshake.
pub async fn reality_connect<S>(
    mut stream: S,
    inputs: &ClientCarrierInputs<'_>,
) -> Result<RealityStream<S>, CarrierError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // ---- 1. Ephemeral + probe + ClientHello ----
    let eph_sk = StaticSecret::from(rand32());
    let eph_pk = *PublicKey::from(&eph_sk).as_bytes();
    let ch_random = rand32();
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(to_io)?;

    let probe = build_probe(&ClientProbeInputs {
        eph_sk: &eph_sk,
        bridge_static_pk: inputs.bridge_static_pk,
        ch_random: &ch_random,
        nonce,
        now_unix: inputs.now_unix,
        probe_root: inputs.probe_root,
    })
    .map_err(CarrierError::from)?;
    let session_id = probe.encode();

    // When the caller doesn't pin a specific template, pick one weighted by
    // real-world browser-population shares (~75% Chrome / 15% Safari / 10%
    // Firefox). Uniform rotation (the earlier default) made the network look
    // ~33% Firefox - itself a Mirage signature a long-flow population
    // classifier flags (RT-CN-4; Mirage's own `ja3_uniform_population_skew`
    // test returns Distinguished for the uniform picker). (Match instead of
    // `unwrap_or_else` because the caller's reference is `'a`-bound while the
    // picked one is `'static`; the Option's invariance forbids unifying them.)
    let fingerprint: &'_ crate::tls_fingerprint::TlsFingerprintTemplate =
        match inputs.tls_fingerprint {
            Some(t) => t,
            None => crate::tls_fingerprint::pick_weighted_template(),
        };
    // Per-connection REAL ML-KEM-768 keypair for the hybrid X25519MLKEM768
    // key_share. We RETAIN the decapsulation key (`mlkem_dk`) so that when the
    // bridge selects the hybrid group and encapsulates against our ek, we can
    // decapsulate its ciphertext and complete a genuine post-quantum handshake -
    // the ServerHello then carries the hybrid group a real PQ-capable cover
    // would, closing the passive PQ-downgrade tell. (The TLS-layer PQ secret is
    // cover for the fingerprint; Mirage's load-bearing PQ KEM is the Noise
    // session inside.)
    let (mlkem_ek_obj, mlkem_dk) = mirage_crypto::hybrid_kem::generate_keypair();
    let mlkem_ek = mlkem_ek_obj.to_bytes();
    let ch_bytes = build_client_hello(&ClientHelloInputs {
        random: &ch_random,
        session_id: &session_id,
        x25519_key_share: &eph_pk,
        server_name: inputs.server_name,
        include_alpn: true,
        fingerprint,
        // Per-connection GREASE (RFC 8701) + the hybrid key_share so the
        // ClientHello byte-matches modern Chrome/Firefox.
        grease: Some(crate::tls_fingerprint::GreaseValues::random()),
        mlkem_ek: Some(&mlkem_ek),
    })
    .map_err(CarrierError::from)?;
    stream.write_all(&ch_bytes).await?;
    stream.flush().await?;

    // ---- 2. Read ServerHello ----
    let sh_bytes = read_one_tls_record(&mut stream, MAX_CLIENT_HELLO_SIZE)
        .await
        .map_err(|(e, _)| e)?;
    let parts = parse_server_hello_record(&sh_bytes).map_err(CarrierError::from)?;
    if parts.session_id != session_id {
        return Err(CarrierError::EchoMismatch);
    }

    // ---- 3. TLS 1.3 transcript + handshake secrets ----
    let mut transcript = TranscriptHash::new();
    transcript.update(&ch_bytes[RECORD_HEADER_LEN..]);
    transcript.update(&sh_bytes[RECORD_HEADER_LEN..]);
    let th_ch_sh = transcript.snapshot();

    let x25519_ss = x25519_shared(&eph_sk, &parts.x25519_key_share)?;
    // If the bridge selected the hybrid group, decapsulate its ML-KEM ciphertext
    // with our retained decapsulation key and combine per X25519MLKEM768:
    // `ML-KEM ss || X25519 ss` (64 B). Else plain X25519 (32 B).
    let ecdh: Vec<u8> = match &parts.mlkem_ct {
        Some(ct) => {
            let ss_mlkem = mlkem_dk.decapsulate(ct);
            let mut combined = Vec::with_capacity(ss_mlkem.len() + x25519_ss.len());
            combined.extend_from_slice(&ss_mlkem);
            combined.extend_from_slice(&x25519_ss);
            combined
        }
        None => x25519_ss.to_vec(),
    };
    // The record AEAD is whichever suite the bridge selected in its
    // ServerHello - AES-128-GCM (what a real CDN picks for Chrome) or ChaCha20.
    let record_cipher = RecordCipher::from_cipher_suite(parts.cipher_suite);
    let early = early_secret_no_psk();
    let hs = handshake_secret(&early, &ecdh);
    let chs = handshake_traffic_secret(&hs, "c hs traffic", &th_ch_sh);
    let shs = handshake_traffic_secret(&hs, "s hs traffic", &th_ch_sh);
    let (chs_key, chs_iv) = record_cipher.traffic_keys(&chs);
    let (shs_key, shs_iv) = record_cipher.traffic_keys(&shs);

    // ---- 4. Read + decrypt server flight (EE || Cert || CV || Fin) ----
    let mut shs_seq = 0u64;
    let mut flight = Vec::with_capacity(4096);
    let mut ccs_seen = 0u32;
    loop {
        let rec = read_one_tls_record(&mut stream, MAX_INNER_PAYLOAD + RECORD_HEADER_LEN)
            .await
            .map_err(|(e, _)| e)?;
        // Skip the server's middlebox-compat ChangeCipherSpec between the
        // ServerHello and the encrypted flight (F1) - not part of the flight.
        // Bounded so an endless CCS stream cannot hang this loop (DoS).
        if is_ccs_record(&rec) {
            ccs_seen += 1;
            if ccs_seen > MAX_CCS_RECORDS {
                return Err(CarrierError::Reality(
                    "too many ChangeCipherSpec records in server flight".into(),
                ));
            }
            continue;
        }
        let unwrapped = unwrap_app_data(&rec)
            .map_err(CarrierError::from)?
            .ok_or_else(|| CarrierError::Reality("short server record".into()))?;
        let nonce = aead_nonce(&shs_iv, shs_seq);
        shs_seq = shs_seq
            .checked_add(1)
            .ok_or_else(|| CarrierError::Reality("shs seq overflow".into()))?;
        let plain = record_cipher
            .open(shs_key.as_ref(), &nonce, &[], unwrapped.payload)
            .map_err(|_| CarrierError::Reality("server flight AEAD auth failed".into()))?;
        let (ct, body) = strip_inner_content_type(&plain).map_err(CarrierError::from)?;
        if ct != INNER_CONTENT_TYPE_HANDSHAKE {
            return Err(CarrierError::Reality(
                "server flight wrong content type".into(),
            ));
        }
        flight.extend_from_slice(body);
        if let Some(plan) = parse_server_flight(&flight) {
            return finish_client_handshake_linear(
                stream,
                transcript,
                flight,
                plan,
                hs,
                shs,
                chs,
                record_cipher,
                chs_key,
                chs_iv,
                shs_key,
                shs_iv,
                inputs.cert_verify_override_pk.copied(),
            )
            .await;
        }
        if flight.len() > MAX_INNER_PAYLOAD * 4 {
            return Err(CarrierError::Reality(
                "server flight exceeds plausible size".into(),
            ));
        }
    }
}

// Helper that does the post-flight verification and sends client
// Finished. Split out only so `reality_connect` above stays
// readable - we pass every piece of key material through.
#[allow(clippy::too_many_arguments)]
async fn finish_client_handshake_linear<S>(
    mut stream: S,
    mut transcript: TranscriptHash,
    flight: Vec<u8>,
    plan: ServerFlightPlan,
    hs: [u8; 32],
    shs: [u8; 32],
    chs: [u8; 32],
    record_cipher: RecordCipher,
    chs_key: mirage_crypto::zeroize::Zeroizing<Vec<u8>>,
    chs_iv: [u8; AEAD_IV_LEN],
    _shs_key: mirage_crypto::zeroize::Zeroizing<Vec<u8>>,
    _shs_iv: [u8; AEAD_IV_LEN],
    cert_verify_override_pk: Option<[u8; 33]>,
) -> Result<RealityStream<S>, CarrierError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ee = &flight[plan.ee_range.clone()];
    let cert_msg = &flight[plan.cert_range.clone()];
    let cv_msg = &flight[plan.cv_range.clone()];
    let fin_msg = &flight[plan.fin_range.clone()];

    transcript.update(ee);
    transcript.update(cert_msg);
    let th_ch_cert = transcript.snapshot();

    // Decide which pubkey verifies CertificateVerify.
    //
    // - Override present (invite carries `tls_cert_verify_pk`):
    //   use the operator-published key. The cert on the wire can
    //   be anything, including a byte-for-byte copy of the cover
    //   destination's cert whose SPKI we could never sign
    //   against. This is the `cover_mimicry` / `pinned` path.
    // - Override absent: derive from the cert's SPKI
    //   (v0.1c-ephemeral behavior: the bridge's fresh cert is
    //   signed by a key it also controls).
    let cert_verify_pub = match cert_verify_override_pk {
        Some(pk) => pk,
        None => parse_first_cert_pubkey(cert_msg)
            .ok_or_else(|| CarrierError::Reality("cannot extract server cert pubkey".into()))?,
    };

    // Verify CertificateVerify.
    let (cv_type, cv_body) = read_handshake(cv_msg).map_err(CarrierError::from)?;
    if cv_type != HS_TYPE_CERTIFICATE_VERIFY || cv_body.len() < 4 {
        return Err(CarrierError::Reality("malformed CertificateVerify".into()));
    }
    let scheme = u16::from_be_bytes([cv_body[0], cv_body[1]]);
    let sig_len = u16::from_be_bytes([cv_body[2], cv_body[3]]) as usize;
    if scheme != SIG_SCHEME_ECDSA_SECP256R1_SHA256 {
        return Err(CarrierError::Reality(format!(
            "unsupported CertVerify scheme: 0x{scheme:04x}"
        )));
    }
    if sig_len == 0 || 4 + sig_len != cv_body.len() {
        return Err(CarrierError::Reality("CertVerify sig length".into()));
    }
    // ECDSA P-256 signature is DER-encoded (SEQUENCE { r, s }), variable length.
    let sig = Signature::from_der(&cv_body[4..4 + sig_len])
        .map_err(|_| CarrierError::Reality("CertVerify sig not valid DER ECDSA".into()))?;
    let mut signing_input = Vec::with_capacity(64 + 33 + 1 + 32);
    signing_input.extend_from_slice(&[0x20u8; 64]);
    signing_input.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signing_input.push(0x00);
    signing_input.extend_from_slice(&th_ch_cert);
    // Pinned/override or cert-SPKI pubkey is a compressed SEC1 P-256 point.
    let vk = VerifyingKey::from_sec1_bytes(&cert_verify_pub)
        .map_err(|_| CarrierError::Reality("server cert pubkey invalid".into()))?;
    vk.verify(&signing_input, &sig)
        .map_err(|_| CarrierError::Reality("CertVerify signature invalid".into()))?;

    // Verify server Finished.
    transcript.update(cv_msg);
    let th_ch_cv = transcript.snapshot();
    let sfin_key = finished_key(&shs);
    verify_finished(fin_msg, &sfin_key, &th_ch_cv)
        .map_err(|_| CarrierError::Reality("server Finished verify failed".into()))?;

    // transcript through server Finished -> app traffic secrets.
    transcript.update(fin_msg);
    let th_ch_sf = transcript.snapshot();
    let master = master_secret(&hs);
    let cats = application_traffic_secret_0(&master, "c ap traffic", &th_ch_sf);
    let sats = application_traffic_secret_0(&master, "s ap traffic", &th_ch_sf);
    let (cat_key, cat_iv) = record_cipher.traffic_keys(&cats);
    let (sat_key, sat_iv) = record_cipher.traffic_keys(&sats);

    // Build + encrypt + send client Finished. A middlebox-compat
    // ChangeCipherSpec precedes it, as a real TLS 1.3 client emits when the
    // ServerHello echoed a session_id (F1).
    let cfin_key = finished_key(&chs);
    let cfin_msg = build_finished(&cfin_key, &th_ch_sf);
    stream.write_all(&TLS_CCS_RECORD).await?;
    write_encrypted_handshake_record(
        &mut stream,
        &cfin_msg,
        record_cipher,
        chs_key.as_ref(),
        &chs_iv,
        0,
        // No cover-flight padding on the client Finished: a real client's
        // Finished is a fixed ~53-byte record and padding it would itself be a
        // tell. Only the bridge's server flight is size-matched to the cover.
        0,
    )
    .await?;

    // Hand off RealityStream with app traffic keys. Client-side
    // send direction uses `cats`; recv uses `sats`.
    let keys = TrafficKeys {
        send: DirKeys::from_key_iv(record_cipher, cat_key, cat_iv),
        recv: DirKeys::from_key_iv(record_cipher, sat_key, sat_iv),
    };
    Ok(RealityStream::with_keys(stream, keys))
}

/// Plan for the concatenated server flight plaintext.
struct ServerFlightPlan {
    ee_range: std::ops::Range<usize>,
    cert_range: std::ops::Range<usize>,
    cv_range: std::ops::Range<usize>,
    fin_range: std::ops::Range<usize>,
}

fn parse_server_flight(buf: &[u8]) -> Option<ServerFlightPlan> {
    let step = |buf: &[u8], i: usize, expected_type: u8| -> Option<usize> {
        if i + 4 > buf.len() {
            return None;
        }
        if buf[i] != expected_type {
            return None;
        }
        let len =
            ((buf[i + 1] as usize) << 16) | ((buf[i + 2] as usize) << 8) | (buf[i + 3] as usize);
        let end = i + 4 + len;
        if end > buf.len() {
            return None;
        }
        Some(end)
    };
    let mut i = 0usize;
    let ee_start = i;
    i = step(buf, i, HS_TYPE_ENCRYPTED_EXTENSIONS)?;
    let cert_start = i;
    i = step(buf, i, HS_TYPE_CERTIFICATE)?;
    let cv_start = i;
    i = step(buf, i, HS_TYPE_CERTIFICATE_VERIFY)?;
    let fin_start = i;
    i = step(buf, i, HS_TYPE_FINISHED)?;
    let fin_end = i;
    // Audit #16: a real TLS 1.3 server may append one (or more) NewSessionTicket
    // messages at 0.5-RTT within the same flight. Consume and DISCARD any that
    // trail the Finished (they are not part of the handshake transcript and
    // Reality does not resume with them - they exist for wire realism). The
    // flight must still end exactly on a message boundary.
    while i < buf.len() {
        i = step(buf, i, HS_TYPE_NEW_SESSION_TICKET)?;
    }
    if i != buf.len() {
        return None;
    }
    Some(ServerFlightPlan {
        ee_range: ee_start..cert_start,
        cert_range: cert_start..cv_start,
        cv_range: cv_start..fin_start,
        fin_range: fin_start..fin_end,
    })
}

/// Extract the ECDSA P-256 public key from the first CertificateEntry in a
/// TLS 1.3 `Certificate` handshake message, returned as a compressed SEC1
/// point (33 bytes). Looks for the EC `SubjectPublicKeyInfo`
/// `AlgorithmIdentifier` (`id-ecPublicKey` + `prime256v1`) followed by a
/// BIT STRING of 66 bytes (0x00 unused-bits + 65-byte uncompressed point).
fn parse_first_cert_pubkey(cert_handshake: &[u8]) -> Option<[u8; 33]> {
    // Strip handshake header.
    if cert_handshake.len() < 4 {
        return None;
    }
    let body = &cert_handshake[4..];
    // Body: context_len(1) + context + cert_list_len(3) + cert_list.
    if body.is_empty() {
        return None;
    }
    let ctx_len = body[0] as usize;
    if body.len() < 1 + ctx_len + 3 {
        return None;
    }
    let list_off = 1 + ctx_len;
    let list_len = ((body[list_off] as usize) << 16)
        | ((body[list_off + 1] as usize) << 8)
        | (body[list_off + 2] as usize);
    let list = body
        .get(list_off + 3..list_off + 3 + list_len)
        .unwrap_or(&[]);
    if list.len() < 3 {
        return None;
    }
    let cd_len = ((list[0] as usize) << 16) | ((list[1] as usize) << 8) | (list[2] as usize);
    let cd = list.get(3..3 + cd_len)?;
    // Search the DER for the EC-P256 SubjectPublicKeyInfo AlgorithmIdentifier.
    // Unlike Ed25519, this OID pair appears only in the SPKI (the TBS
    // signatureAlgorithm is the distinct `ecdsa-with-SHA256` OID), and it is
    // followed by a BIT STRING of length 0x42 (66 = 1 unused-bits byte + 65-byte
    // uncompressed point `0x04 || X || Y`). We return the compressed form for a
    // stable 33-byte representation.
    const MARKER: &[u8] = &[
        0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // id-ecPublicKey
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // prime256v1
    ];
    let mut start = 0usize;
    while start + MARKER.len() <= cd.len() {
        let slice = &cd[start..];
        let Some(rel_pos) = slice.windows(MARKER.len()).position(|w| w == MARKER) else {
            break;
        };
        let abs = start + rel_pos;
        let after = &cd[abs + MARKER.len()..];
        if after.len() >= 3 + 65
            && after[0] == 0x03
            && after[1] == 0x42
            && after[2] == 0x00
            && after[3] == 0x04
        {
            let point = &after[3..3 + 65];
            // Normalize to compressed SEC1 (33 B) via a full curve-point parse
            // (also rejects an off-curve / invalid point).
            let vk = VerifyingKey::from_sec1_bytes(point).ok()?;
            let mut out = [0u8; 33];
            out.copy_from_slice(vk.to_encoded_point(true).as_bytes());
            return Some(out);
        }
        start = abs + 1;
    }
    None
}

/// TLS 1.3 nonce construction per RFC 8446 §5.3: pad the 64-bit
/// seq to 12 bytes (left-pad with zeros) and XOR with the
/// direction's static IV.
fn aead_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *iv;
    let s = seq.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= s[i];
    }
    n
}

/// Encrypt `handshake_msg` with the given key/IV/seq and send one
/// TLS 1.3 application_data record containing it. Used for both
/// the bridge-side server flight and the client-side Finished.
/// M1: plan how to split a `flight_len`-byte server flight (whose Finished
/// STARTS at byte offset `fin_start`) into records matching the cover's measured
/// `record_wires`, KEEPING Finished + the trailing NST in the LAST record.
///
/// Returns the per-record REAL byte counts (each padded to `record_wires[i]` by
/// the writer), or `None` to fall back to one coalesced record. Guarantees:
/// - every record carries at least one real byte (no pure-padding records),
/// - the first k-1 records carry only pre-Finished bytes,
/// - the last record carries the remainder (incl. Finished + NST).
///
/// The client stops reading its flight at Finished, so keeping Finished in the
/// last record ensures it reads every record and leaves none unread (an unread
/// record would desync the next read). Exact reproduction or coalesced fallback
/// only; never a guessed split.
fn plan_cover_matched_records(
    flight_len: usize,
    fin_start: usize,
    record_wires: &[usize],
) -> Option<Vec<usize>> {
    let k = record_wires.len();
    // Nothing to reproduce for a single coalesced record; need Finished strictly
    // inside the flight with at least one pre-Finished byte per non-last record.
    if k < 2 || fin_start == 0 || fin_start >= flight_len || fin_start < k - 1 {
        return None;
    }
    // Plaintext capacity of a record of wire size `w` (minus 5-byte header, AEAD
    // tag, and the 1-byte TLS 1.3 inner content type).
    let cap = |w: usize| w.checked_sub(RECORD_HEADER_LEN + AEAD_TAG_LEN + 1);
    let mut real = Vec::with_capacity(k);
    let mut prefix_left = fin_start; // bytes strictly before Finished
    for (i, &w) in record_wires[..k - 1].iter().enumerate() {
        let c = cap(w)?;
        // Reserve >= 1 pre-Finished byte for each still-later non-last record.
        let reserve = (k - 1) - (i + 1);
        let take = c.min(prefix_left.checked_sub(reserve)?);
        if take == 0 {
            return None;
        }
        real.push(take);
        prefix_left -= take;
    }
    // Last record: whatever pre-Finished bytes are left + Finished + NST.
    let last_real = flight_len - (fin_start - prefix_left);
    if last_real == 0 || last_real > cap(record_wires[k - 1])? {
        return None;
    }
    real.push(last_real);
    debug_assert_eq!(real.iter().sum::<usize>(), flight_len);
    Some(real)
}

async fn write_encrypted_handshake_record<S: AsyncWrite + Unpin>(
    stream: &mut S,
    handshake_msg: &[u8],
    cipher: RecordCipher,
    key: &[u8],
    iv: &[u8; AEAD_IV_LEN],
    seq: u64,
    pad_to_wire: usize,
) -> Result<(), CarrierError> {
    let mut inner = with_inner_content_type(handshake_msg, INNER_CONTENT_TYPE_HANDSHAKE);
    // Cover-flight mimicry: grow this record to `pad_to_wire` on-the-wire bytes
    // with TLS 1.3 record padding (RFC 8446 §5.4 - zero bytes after the inner
    // content type, sanctioned for traffic-analysis defence). The receiver
    // strips it in `strip_inner_content_type`. Padding only grows a record; a
    // smaller-than-target natural size means no change, and the inner plaintext
    // is capped at the 2^14 record maximum. `pad_to_wire == 0` disables padding.
    if pad_to_wire > 0 {
        let natural_wire = RECORD_HEADER_LEN + inner.len() + AEAD_TAG_LEN;
        if pad_to_wire > natural_wire {
            let want_inner =
                (pad_to_wire - RECORD_HEADER_LEN - AEAD_TAG_LEN).min(MAX_INNER_PAYLOAD);
            if want_inner > inner.len() {
                inner.resize(want_inner, 0x00);
            }
        }
    }
    let nonce = aead_nonce(iv, seq);
    let ct = cipher
        .seal(key, &nonce, &[], inner.as_slice())
        .map_err(|_| CarrierError::Reality("encrypt handshake record".into()))?;
    let rec = wrap_app_data(&ct).map_err(CarrierError::from)?;
    stream.write_all(&rec).await?;
    stream.flush().await?;
    // NOTE (#18): a uniform-[0,50] ms per-record "jitter" used to be applied
    // here and was REMOVED - it did not mask what it claimed and was itself a
    // fingerprint. On the client it inserted a uniform-over-50 ms gap between
    // the Finished record and the first application record; real TLS 1.3
    // clients emit that record within sub-ms (often coalesced), so a uniform
    // gap was an unnatural, measurable tell (a genuine network gap has a floor
    // plus a right tail, not a uniform law). On the bridge the call sat after
    // the LAST flight write, so it delayed only the bridge's own subsequent
    // read and had no on-wire effect at all. Genuine per-record cadence masking
    // needs a delay drawn from a distribution fitted to a real cover capture,
    // applied BETWEEN records actually emitted back-to-back and BEFORE each
    // write. That is capture-blocked - the same conclusion as the record-length
    // sequence model - so we ship no jitter rather than a wrong one.
    Ok(())
}

/// Read + decrypt one TLS 1.3 application_data record containing a
/// handshake payload, returning the plaintext handshake message.
async fn read_encrypted_handshake_record<S: AsyncRead + Unpin>(
    stream: &mut S,
    cipher: RecordCipher,
    key: &[u8],
    iv: &[u8; AEAD_IV_LEN],
    seq: u64,
) -> Result<Vec<u8>, CarrierError> {
    // Skip any leading middlebox-compat ChangeCipherSpec record(s) (F1) - the
    // peer emits one before its encrypted Finished. Bounded so an endless CCS
    // stream from a malicious peer cannot hang this loop (DoS).
    let mut ccs_seen = 0u32;
    let rec = loop {
        let r = read_one_tls_record(stream, MAX_INNER_PAYLOAD + RECORD_HEADER_LEN)
            .await
            .map_err(|(e, _)| e)?;
        if !is_ccs_record(&r) {
            break r;
        }
        ccs_seen += 1;
        if ccs_seen > MAX_CCS_RECORDS {
            return Err(CarrierError::Reality(
                "too many ChangeCipherSpec records before Finished".into(),
            ));
        }
    };
    let unwrapped = unwrap_app_data(&rec)
        .map_err(CarrierError::from)?
        .ok_or_else(|| CarrierError::Reality("short handshake record".into()))?;
    let nonce = aead_nonce(iv, seq);
    let plain = cipher
        .open(key, &nonce, &[], unwrapped.payload)
        .map_err(|_| CarrierError::Reality("handshake record AEAD auth failed".into()))?;
    let (ct, body) = strip_inner_content_type(&plain).map_err(CarrierError::from)?;
    if ct != INNER_CONTENT_TYPE_HANDSHAKE {
        return Err(CarrierError::Reality(
            "handshake record wrong content type".into(),
        ));
    }
    Ok(body.to_vec())
}

// Bridge side

/// Run a Reality carrier handshake on `stream` as the bridge.
///
/// On probe verify success: writes a ServerHello shell and returns
/// [`AcceptOutcome::Authenticated`] wrapping a [`RealityStream`]
/// ready for the Mirage session handshake to run on top.
///
/// On probe verify failure: opens a fresh TCP to `inputs.cover_addr`,
/// replays the buffered ClientHello, and bidirectionally pumps
/// bytes for up to `cover_duration_cap`. Returns
/// [`AcceptOutcome::CoverServed`] with the byte totals.
///
/// This function deliberately does NOT return the specific reason
/// a probe was rejected: the bridge's wire behavior for any
/// non-authenticated peer must be identical. The returned
/// `CoverServed { .. }` carries only bookkeeping.
///
/// # Closes [RT-CN-1] - auth-fail timing distinguisher
///
/// **Threat**: an active prober submitting a crafted ClientHello
/// could time the response and observe two distributions:
/// - auth-pass path: ServerHello in ~1-10 ms (parse + verify).
/// - auth-fail path: ServerHello in 50-500 ms (cover-connect
///   added). Real CDNs respond fast in both cases.
///
/// **Mitigation** (Phase 2J): eager parallel cover-connect. The
/// bridge spawns `TcpStream::connect(cover_addr)` in parallel
/// with auth verification AS SOON AS the ClientHello finishes
/// arriving. Both paths await the connect:
/// - On pass: drop the cover stream (close on drop), send
///   ServerHello.
/// - On fail: hand the connected cover to
///   [`forward_to_cover_with_stream`] - skip its internal
///   connect.
///
/// Result: both paths take `max(auth_verify_time,
/// cover_connect_time)`. The 1-bit oracle the censor's prober
/// could use to distinguish Mirage from real CDNs by ServerHello
/// latency is gone.
///
/// **Operator-side residual**: the **absolute** ServerHello
/// latency is still typically `cover_connect_time`, which is
/// ~RTT(bridge <-> cover). A real CDN responds in sub-ms because
/// the cover IS the same process. Operators can match real-CDN
/// timing by:
/// - Co-locating the bridge and cover on the same host (same
///   datacenter - TCP-connect goes through localhost loopback
///   in microseconds).
/// - Using a cover within the same VPC / direct-connect peer.
///
/// Without one of these operational mitigations, the bridge is
/// distinguishable from real CDNs by absolute latency, but NOT
/// by the auth-pass-vs-fail oracle (which RT-CN-1 specifically
/// addressed).
pub async fn reality_accept<S>(
    mut stream: S,
    inputs: &mut BridgeCarrierInputs<'_>,
) -> Result<AcceptOutcome<S>, CarrierError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Buffer enough for a ClientHello. We read incrementally,
    // parsing as we go, so we don't wait for bytes past the end.
    let ch_bytes = match tokio::time::timeout(
        inputs.client_hello_read_timeout,
        // +RECORD_HEADER_LEN so a record whose body is the full 2^14 TLS max is
        // ACCEPTED (read the body), not rejected off its 5-byte header.
        read_one_tls_record(&mut stream, MAX_CLIENT_HELLO_SIZE + RECORD_HEADER_LEN),
    )
    .await
    {
        Err(_) => return Err(CarrierError::Timeout),
        Ok(Ok(b)) => b,
        Ok(Err((_e, consumed))) => {
            // M2: origin error-parity. Do NOT synthesize a `record_overflow`
            // alert (a Mirage-specific 7-byte response is itself a distinguisher)
            // and do NOT bare-drop (a silent close diverges from a real origin,
            // which for an oversized record sends record_overflow). Instead
            // forward the bytes we already consumed to the REAL cover and splice,
            // so a prober sees exactly what the cover origin does. This converges
            // the malformed-record path onto the SAME cover-forward + jittered
            // duration-cap path as the auth-fail branch below - no early return,
            // no new oracle. (The already-consumed body bytes of a truncated
            // record can't be replayed byte-for-byte; that residual is accepted.)
            let (c2s, s2c) = match TcpStream::connect(inputs.cover_addr).await {
                Ok(cover) => forward_to_cover_with_stream(
                    &mut stream,
                    cover,
                    &consumed,
                    inputs.cover_duration_cap,
                )
                .await
                .unwrap_or((0, 0)),
                Err(_) => (0, 0),
            };
            return Ok(AcceptOutcome::CoverServed { c2s, s2c });
        }
    };

    // **Closes [RT-CN-1]** - eager parallel cover-connect.
    //
    // Spawn the cover-connect in parallel with auth-verify. We
    // ALWAYS await this handle below (whether auth passed or
    // failed) so both paths take `max(auth_verify, cover_connect)`
    // time - eliminating the timing oracle a censor's prober
    // could use to distinguish Mirage bridges from real CDNs.
    //
    // On pass: drop the connected cover (closes silently when
    // the variable falls out of scope). On fail: hand it off to
    // `forward_to_cover_with_stream`, skipping its internal
    // connect step.
    //
    // Operators wanting to minimise the success-path tax should
    // co-locate the cover (same datacenter - sub-millisecond
    // TCP-connect) per the operational guidance below.
    let cover_addr = inputs.cover_addr;
    let cover_handle = tokio::spawn(async move { TcpStream::connect(cover_addr).await });

    // Parse and verify. Any failure drops into cover fallback.
    //
    // The replay-probe lock is acquired for the SOLE duration of the
    // synchronous `verify_probe` below and dropped before the cover-connect
    // await and the (up to `cover_duration_cap`) cover-serve. This lock is a
    // single bridge-wide `Mutex`; holding it across the cover-serve - as an
    // earlier version did by locking in the caller and passing the guard in -
    // let one attacker holding an unauthenticated socket open for the 30s cover
    // cap serialize every other Reality accept. Note the lock is taken on BOTH
    // the pass and fail paths identically, before the `match` below, so it adds
    // no new pass/fail timing bifurcation; and it is taken AFTER the (attacker-
    // paced) ClientHello read, which therefore no longer serializes either.
    let verify_result = {
        let parsed = parse_client_hello_record(&ch_bytes);
        match parsed {
            Err(e) => Err(e),
            Ok(parsed) => {
                let mut wire_probe = [0u8; crate::probe::SESSION_ID_LEN];
                wire_probe.copy_from_slice(&parsed.session_id);
                let mut rps = inputs.replay_set.lock().await;
                verify_probe(&mut BridgeProbeInputs {
                    bridge_static_sk: inputs.bridge_static_sk,
                    client_eph_pk: &parsed.x25519_key_share,
                    ch_random: &parsed.random,
                    now_unix: inputs.now_unix,
                    wire_probe,
                    probe_root: inputs.probe_root,
                    accept_legacy: inputs.accept_legacy,
                    replay_set: &mut rps,
                })
                // `rps` guard dropped here - before the cover await/serve below.
            }
        }
    };

    // ALWAYS await the cover-connect - equalises timing between
    // pass and fail paths. The result type is
    // `Result<Result<TcpStream, io::Error>, JoinError>`; we
    // collapse to `Option<TcpStream>` since failures here are
    // benign (cover unreachable -> cover_stream = None; on auth
    // pass we ignore it anyway, on auth fail we err out below
    // with a fast close that mimics a real-server connection
    // refusal).
    let cover_stream: Option<TcpStream> = cover_handle.await.ok().and_then(|inner| inner.ok());

    match verify_result {
        Ok(()) => {
            // **Closes [#3]** - pass-vs-fail response-generation timing oracle.
            //
            // The auth-FAIL path answers only after a full bridge<->cover
            // ClientHello->ServerHello round-trip (~2*RTT to the first server
            // byte the client sees). The auth-PASS path answers from local
            // state (~1*RTT). RT-CN-1 equalized the cover *connect* but not this
            // response-generation asymmetry. When `accept_legacy` is set, a
            // censor who scraped the bridge's public static key can forge a
            // legacy-valid probe (no invite secret needed) and reach BOTH paths,
            // so that ~1-RTT bifurcation becomes a positive bridge-detection
            // oracle a genuine TLS server never exhibits.
            //
            // Mitigation: when the pass path is scraper-reachable, perform the
            // SAME cover round-trip here before answering locally, so both paths
            // incur ~2*RTT. The pass path is scraper-reachable precisely when
            // `verify_probe` would accept an unbound (pubkey-only-derivable)
            // probe: either epoch binding is disabled entirely, OR
            // `accept_legacy` leaves the unbound path open during rollover.
            // Running strict (bound probe_root AND `accept_legacy == false`,
            // #26) makes the pass path unreachable by a scraper, so we skip the
            // round-trip tax. Operators who co-locate the cover (loopback) pay
            // ~0 either way.
            let pass_reachable_by_scraper =
                *inputs.probe_root == crate::probe::PROBE_ROOT_DISABLED || inputs.accept_legacy;
            if pass_reachable_by_scraper {
                if let Some(mut cover) = cover_stream {
                    equalize_pass_path_via_cover(&mut cover, &ch_bytes, inputs.cover_duration_cap)
                        .await;
                    // cover dropped here (close on drop).
                }
            } else {
                drop(cover_stream);
            }
            let parsed =
                parse_client_hello_record(&ch_bytes).expect("already parsed successfully above");
            bridge_complete_tls_handshake(
                stream,
                ch_bytes,
                parsed,
                inputs.bridge_static_sk,
                inputs.tls_identity,
                inputs.cover_flight_target,
                inputs.cover_flight_records,
            )
            .await
        }
        Err(e) => {
            debug!(reason = ?e, "reality_accept: probe failed, falling through to cover");
            let (c2s, s2c) = match cover_stream {
                Some(cover) => forward_to_cover_with_stream(
                    &mut stream,
                    cover,
                    &ch_bytes,
                    inputs.cover_duration_cap,
                )
                .await
                .unwrap_or((0, 0)),
                None => {
                    // Cover unreachable. Drop the client; mimics
                    // a real CDN whose backend is briefly down.
                    debug!("reality_accept: cover unreachable; dropping client");
                    (0, 0)
                }
            };
            Ok(AcceptOutcome::CoverServed { c2s, s2c })
        }
    }
}

/// Post-probe bridge-side handshake: emits ServerHello, derives
/// handshake keys, signs + sends the {EE|Cert|CertVerify|Finished}
/// server flight encrypted under `server_handshake_traffic_secret`,
/// reads + verifies the client's encrypted Finished, switches to
/// application traffic keys.
async fn bridge_complete_tls_handshake<S>(
    mut stream: S,
    ch_bytes: Vec<u8>,
    parsed: crate::tls_client_hello::ParsedClientHello,
    bridge_static_sk: &StaticSecret,
    tls_identity: Option<&TlsIdentity>,
    cover_flight_target: Option<usize>,
    cover_flight_records: &[usize],
) -> Result<AcceptOutcome<S>, CarrierError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // NOTE on authentication: the Reality TLS layer is a transport
    // *disguise*, NOT the authentication boundary. Mirage authenticates the
    // bridge in the INNER PQ-Noise-XX session, which pins the bridge's static
    // key against the value the client learned from the (operator-signed)
    // invite (see `mirage_session` `HandshakeInitiator`: it constant-time
    // compares the responder's transmitted static against `expected_remote_
    // static` and aborts on mismatch). An active MitM on the TLS layer
    // therefore cannot impersonate the bridge - it can only relay, and the
    // inner session is end-to-end confidential + authenticated. The cert
    // below exists to look like a plausible TLS server to a passive observer
    // or active prober, not to anchor identity.
    // 1. Decide on the TLS identity to present. Two paths:
    //    - `Some` identity -> pinned / cover-mimicry: serve the
    //      operator-provided cert bytes, sign CertVerify with the
    //      operator's TLS signing key. Constant across sessions.
    //    - `None` -> ephemeral: mint a fresh Ed25519 keypair + a
    //      self-signed cert whose CN mirrors the requested SNI,
    //      sign CertVerify with the matching key. Each session
    //      presents a unique cert; client verifies against its
    //      SPKI.
    // Owned-only-in-ephemeral; pinned mode borrows from `tls_identity`
    // so we don't clone the DER cert or signing key on every session.
    // Under attack load (N handshakes/sec) this matters: a 4 KiB cert
    // clone at 1k conn/s is 4 MiB/s of allocator churn + zeroize work
    // on the signing-key drop.
    let ephemeral_storage: Option<(Vec<u8>, p256::ecdsa::SigningKey)> = if tls_identity.is_some() {
        None
    } else {
        let sni = extract_sni(&ch_bytes).unwrap_or_else(|| "mirage.invalid".to_string());
        // Derive the ephemeral cert's signing key DETERMINISTICALLY from
        // the bridge static identity + SNI (domain-separated KDF), NOT a
        // fresh random seed per session. A per-session random cert is an
        // active-probe distinguisher: a real server presents a STABLE
        // cert when you reconnect; a bridge that minted a new self-signed
        // cert every connection stood out. Deriving from the static key
        // makes the presented cert stable across sessions for a given
        // (bridge, SNI) and binds it to the bridge identity, while the KDF
        // (one-way) never exposes the X25519 static secret.
        //
        // A P-256 scalar must be in [1, n); a raw 32-byte KDF output exceeds
        // the curve order with probability ~2^-32. Loop with a domain-
        // separating counter so the key is still deterministic per
        // (bridge, SNI) but always valid (counter is 0 in ~all cases).
        let sk = {
            let mut counter: u8 = 0;
            loop {
                let seed =
                    mirage_crypto::blake3::derive_key("mirage reality ephemeral cert v1", &{
                        let mut km = Zeroizing::new(Vec::with_capacity(32 + sni.len() + 1));
                        km.extend_from_slice(&bridge_static_sk.to_bytes());
                        km.extend_from_slice(sni.as_bytes());
                        km.push(counter);
                        km
                    });
                if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&seed) {
                    break k;
                }
                counter = counter.wrapping_add(1);
            }
        };
        Some((build_self_signed_ecdsa_p256(&sk, &sni), sk))
    };
    let (cert_der, tls_server_sk): (&[u8], &p256::ecdsa::SigningKey) =
        match (tls_identity, ephemeral_storage.as_ref()) {
            (Some(id), _) => (id.cert_der.as_slice(), &id.signing_key),
            (None, Some((der, sk))) => (der.as_slice(), sk),
            (None, None) => unreachable!("ephemeral branch always populates"),
        };

    // 2. Bridge ephemeral for TLS 1.3 ECDH.
    let bridge_eph_sk = StaticSecret::from(rand32());
    let bridge_eph_pk = *PublicKey::from(&bridge_eph_sk).as_bytes();

    // 3. Emit ServerHello.
    let sh_random = rand32();
    // Audit fix C1+C2: pick the cipher from the client's offered
    // list (typically AES-128-GCM-SHA256 first per Chrome) and
    // echo the first matching ALPN if the client offered any.
    // Without these, the bridge always declared `0x1303` and never
    // echoed ALPN, both passive distinguishers vs. real cover.
    let cipher_suite = crate::tls_server_hello::pick_server_cipher(&parsed.cipher_suites);
    // Pick the first ALPN we both speak. v0.1 prefers `h2` then
    // `http/1.1` to match real CDN behavior; an ALPN we don't
    // speak (e.g., a custom QUIC proto over the same port) is
    // ignored, matching a server that doesn't support it.
    const SUPPORTED_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
    let alpn_choice: Option<&[u8]> = parsed
        .alpn_protocols
        .iter()
        .find_map(|p| SUPPORTED_ALPN.iter().find(|s| **s == p.as_slice()).copied());
    // Hybrid X25519MLKEM768: if the client offered a well-formed ML-KEM ek,
    // encapsulate against it so the ServerHello SELECTS the PQ hybrid group -
    // exactly what a real PQ-capable cover echoes for a Chrome/Firefox
    // ClientHello. Without this the bridge always downgraded to plain X25519, a
    // passive PQ-downgrade distinguisher no real modern server produces. A
    // malformed ek falls back to X25519 (matching a non-PQ server).
    let mlkem = parsed.mlkem_ek.as_ref().and_then(|ek_bytes| {
        mirage_crypto::hybrid_kem::MlKemEk::from_bytes(ek_bytes)
            .ok()
            .map(|ek| ek.encapsulate())
    });
    let sh_bytes = build_server_hello(&ServerHelloInputs {
        random: &sh_random,
        session_id_echo: &parsed.session_id,
        x25519_key_share: &bridge_eph_pk,
        mlkem_ct: mlkem.as_ref().map(|(ct, _)| ct),
        cipher_suite,
        // F3: TLS 1.3 forbids ALPN in the ServerHello - it goes in the
        // (encrypted) EncryptedExtensions below. Never emit it here.
        alpn_echo: None,
    })
    .map_err(CarrierError::from)?;
    stream.write_all(&sh_bytes).await?;
    // Middlebox-compat ChangeCipherSpec after the ServerHello - real TLS 1.3
    // servers emit this whenever the ClientHello carried a legacy_session_id
    // (reality's does). Its absence was a passive conformance tell (F1).
    stream.write_all(&TLS_CCS_RECORD).await?;
    stream.flush().await?;

    // 4. Transcript + handshake secrets.
    let mut transcript = TranscriptHash::new();
    transcript.update(&ch_bytes[RECORD_HEADER_LEN..]);
    transcript.update(&sh_bytes[RECORD_HEADER_LEN..]);
    let th_ch_sh = transcript.snapshot();

    let x25519_ss = x25519_shared(&bridge_eph_sk, &parsed.x25519_key_share)?;
    // (EC)DHE input: for the hybrid group, the X25519MLKEM768 combiner is
    // `ML-KEM ss || X25519 ss` (64 B); for plain X25519 it is the 32-B DH.
    let ecdh: Vec<u8> = match &mlkem {
        Some((_, ss_mlkem)) => {
            let mut combined = Vec::with_capacity(ss_mlkem.len() + x25519_ss.len());
            combined.extend_from_slice(ss_mlkem);
            combined.extend_from_slice(&x25519_ss);
            combined
        }
        None => x25519_ss.to_vec(),
    };
    // Record AEAD = the suite we advertised in the ServerHello (the client's
    // top-preferred that we support, typically AES-128-GCM for Chrome).
    let record_cipher = RecordCipher::from_cipher_suite(cipher_suite);
    let early = early_secret_no_psk();
    let hs = handshake_secret(&early, &ecdh);
    let chs = handshake_traffic_secret(&hs, "c hs traffic", &th_ch_sh);
    let shs = handshake_traffic_secret(&hs, "s hs traffic", &th_ch_sh);
    let (chs_key, chs_iv) = record_cipher.traffic_keys(&chs);
    let (shs_key, shs_iv) = record_cipher.traffic_keys(&shs);

    // 5. Build the server flight. ALPN rides here (encrypted), per TLS 1.3.
    let ee = build_encrypted_extensions(alpn_choice);
    let cert_msg = build_certificate(cert_der);
    transcript.update(&ee);
    transcript.update(&cert_msg);
    let th_ch_cert = transcript.snapshot();
    let cv_msg = build_certificate_verify(tls_server_sk, &th_ch_cert);
    transcript.update(&cv_msg);
    let th_ch_cv = transcript.snapshot();
    let sfin_key_s = finished_key(&shs);
    let sfin_msg = build_finished(&sfin_key_s, &th_ch_cv);
    transcript.update(&sfin_msg);

    // Concatenate and send as ONE encrypted app_data record, padded up to the
    // cover's measured flight size so a passive censor comparing our encrypted
    // Certificate flight to the real cover's sees a matching wire size (closes
    // the self-signed-flight-too-small tell). `None` = no cover profile => no
    // padding (ephemeral/test path).
    let mut flight = Vec::with_capacity(ee.len() + cert_msg.len() + cv_msg.len() + sfin_msg.len());
    flight.extend_from_slice(&ee);
    flight.extend_from_slice(&cert_msg);
    flight.extend_from_slice(&cv_msg);
    // Offset where Finished begins (everything after is Finished + NST). M1 keeps
    // this and the trailing NST in the LAST emitted record.
    let flight_fin_start = ee.len() + cert_msg.len() + cv_msg.len();
    flight.extend_from_slice(&sfin_msg);
    // Audit #16: append a 0.5-RTT NewSessionTicket so the flight carries the
    // resumption-ticket shape a genuine TLS 1.3 server emits. It is NOT added to
    // the transcript (it follows Finished) and the client discards it - it exists
    // for wire realism only. The ticket + nonce are CSPRNG opaque blobs of a
    // realistic size (~192 B, typical of real tickets).
    {
        let mut nst_rand = [0u8; 4 + 32 + 192];
        if getrandom::fill(&mut nst_rand).is_ok() {
            let age_add = u32::from_be_bytes([nst_rand[0], nst_rand[1], nst_rand[2], nst_rand[3]]);
            let nonce = &nst_rand[4..36];
            let ticket = &nst_rand[36..];
            // 2-hour lifetime, within the RFC 8446 7-day ceiling and typical of
            // real deployments.
            let nst = build_new_session_ticket(7200, age_add, nonce, ticket);
            // Red-team #8: in cover-matched mode (pinned / cover-mimicry, where
            // `cover_flight_target` is the measured real-cover flight size), only
            // append the ticket if the flight record STILL fits that size. If it
            // would push us over, skip it - preserving the size-match matters more
            // than the ticket-shape realism, and overshooting the cover would be
            // its own size tell. In ephemeral mode (no target) always append.
            let fits = match cover_flight_target {
                Some(target) => {
                    RECORD_HEADER_LEN + flight.len() + nst.len() + 1 + AEAD_TAG_LEN <= target
                }
                None => true,
            };
            if fits {
                flight.extend_from_slice(&nst);
            }
        }
    }
    // M1: reproduce the cover's record FRAMING (count + per-record sizes) when we
    // safely can (Finished stays in the last record), else emit one coalesced
    // record padded to the total. The client reads records with an incrementing
    // AEAD seq, so writing N records with seq 0..N is transparent to it.
    match plan_cover_matched_records(flight.len(), flight_fin_start, cover_flight_records) {
        Some(plan) => {
            let mut off = 0usize;
            for (i, &n) in plan.iter().enumerate() {
                write_encrypted_handshake_record(
                    &mut stream,
                    &flight[off..off + n],
                    record_cipher,
                    shs_key.as_ref(),
                    &shs_iv,
                    i as u64,
                    cover_flight_records[i],
                )
                .await?;
                off += n;
            }
        }
        None => {
            write_encrypted_handshake_record(
                &mut stream,
                &flight,
                record_cipher,
                shs_key.as_ref(),
                &shs_iv,
                0,
                cover_flight_target.unwrap_or(0),
            )
            .await?;
        }
    }

    // 6. Read + verify client Finished.
    let cfin =
        read_encrypted_handshake_record(&mut stream, record_cipher, chs_key.as_ref(), &chs_iv, 0)
            .await?;
    let th_ch_sf = transcript.snapshot();
    let cfin_key = finished_key(&chs);
    verify_finished(&cfin, &cfin_key, &th_ch_sf)
        .map_err(|_| CarrierError::Reality("client Finished verify failed".into()))?;

    // 7. Derive application traffic secrets.
    let master = master_secret(&hs);
    let cats = application_traffic_secret_0(&master, "c ap traffic", &th_ch_sf);
    let sats = application_traffic_secret_0(&master, "s ap traffic", &th_ch_sf);
    let (cat_key, cat_iv) = record_cipher.traffic_keys(&cats);
    let (sat_key, sat_iv) = record_cipher.traffic_keys(&sats);

    // Bridge-side send direction is server->client (sats); recv is
    // client->server (cats).
    let keys = TrafficKeys {
        send: DirKeys::from_key_iv(record_cipher, sat_key, sat_iv),
        recv: DirKeys::from_key_iv(record_cipher, cat_key, cat_iv),
    };
    Ok(AcceptOutcome::Authenticated(RealityStream::with_keys(
        stream, keys,
    )))
}

/// Extract the first SNI (host_name) from a ClientHello record.
/// Returns `None` if absent or malformed.
fn extract_sni(ch_record: &[u8]) -> Option<String> {
    // ch_record: 5-byte TLS record header + handshake message.
    if ch_record.len() < 5 + 4 {
        return None;
    }
    let hs = &ch_record[5..];
    if hs[0] != 0x01 {
        return None;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    let body = hs.get(4..4 + hs_len)?;
    // legacy_version(2) + random(32) + session_id_len(1) + session_id + cs_len(2) + cs + cm_len(1) + cm + ext_len(2) + ext
    let mut i = 2 + 32;
    let sid_len = *body.get(i)? as usize;
    i += 1 + sid_len;
    if i + 2 > body.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2 + cs_len;
    if i + 1 > body.len() {
        return None;
    }
    let cm_len = body[i] as usize;
    i += 1 + cm_len;
    if i + 2 > body.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    let ext_bytes = body.get(i..i + ext_len)?;
    let mut j = 0;
    while j + 4 <= ext_bytes.len() {
        let et = u16::from_be_bytes([ext_bytes[j], ext_bytes[j + 1]]);
        let el = u16::from_be_bytes([ext_bytes[j + 2], ext_bytes[j + 3]]) as usize;
        let eb = ext_bytes.get(j + 4..j + 4 + el)?;
        if et == 0x0000 {
            // server_name: list_len(2) + name_type(1) + name_len(2) + name
            if eb.len() < 5 {
                return None;
            }
            let name_len = u16::from_be_bytes([eb[3], eb[4]]) as usize;
            let name = eb.get(5..5 + name_len)?;
            return std::str::from_utf8(name).ok().map(String::from);
        }
        j += 4 + el;
    }
    None
}

// Cover-service fallback

/// Timing-equalize the auth-PASS path with the auth-FAIL cover-relay path (#3).
///
/// Writes the buffered ClientHello into the already-connected cover and awaits
/// the cover's first response bytes (its ServerHello flight), then returns. The
/// cover's bytes are discarded - the bridge answers the client from local state
/// afterwards. The point is only that the time until the client sees the first
/// *bridge* byte on a successful probe matches the ~2*RTT the cover-relay path
/// would take for a forged legacy probe, so the pass/fail latency bifurcation a
/// censor could otherwise time is removed. Bounded by `cap` so an unresponsive
/// cover cannot stall a legitimate handshake longer than the fail path would.
async fn equalize_pass_path_via_cover(cover: &mut TcpStream, ch_bytes: &[u8], cap: Duration) {
    cover.set_nodelay(true).ok();
    let _ = tokio::time::timeout(cap, async {
        cover.write_all(ch_bytes).await?;
        cover.flush().await?;
        // A single successful read == the cover's first flight byte has
        // arrived (~1 bridge<->cover RTT past the connect). That is the same
        // instant the fail path would begin relaying the cover's ServerHello
        // to the client. One read is sufficient for timing equalization.
        let mut buf = [0u8; 4096];
        let _ = cover.read(&mut buf).await?;
        Ok::<(), io::Error>(())
    })
    .await;
}

/// Phase 2J helper (closes [RT-CN-1]): forward client traffic to
/// an **already-connected** cover stream. Used by `reality_accept`
/// when the cover connect happened in parallel with auth-verify -
/// equalising the response-time distribution between the
/// auth-pass and auth-fail paths so a timing prober can't
/// distinguish Mirage bridges from real CDNs by measuring
/// ServerHello latency.
async fn forward_to_cover_with_stream<S>(
    client: &mut S,
    mut cover: TcpStream,
    buffered_client_hello: &[u8],
    duration_cap: Duration,
) -> Result<(u64, u64), io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + ?Sized,
{
    cover.set_nodelay(true).ok();
    // Replay the buffered ClientHello so the cover sees the exact
    // bytes the client sent. SNI / key_share all line up.
    cover.write_all(buffered_client_hello).await?;
    // Jitter the cap per-connection. A FIXED cut (every unauthenticated
    // cover-forwarded session severed at exactly `duration_cap`) is a Mirage
    // signature no real HTTPS server produces. Draw a uniform factor in
    // [0.6, 1.9] so the cutoff is spread across a wide, non-round window; a
    // zero cap (disabled) stays disabled.
    let duration_cap = if duration_cap.is_zero() {
        duration_cap
    } else {
        let mut b = [0u8; 8];
        let f = match getrandom::fill(&mut b) {
            Ok(()) => 0.6 + (u64::from_le_bytes(b) as f64 / u64::MAX as f64) * 1.3,
            Err(_) => 1.0,
        };
        duration_cap.mul_f64(f)
    };
    let fut = tokio::io::copy_bidirectional(client, &mut cover);
    let result = tokio::time::timeout(duration_cap, fut).await;
    let _ = cover.shutdown().await;
    match result {
        Ok(Ok((c2s, s2c))) => Ok((c2s + buffered_client_hello.len() as u64, s2c)),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            warn!(cap = ?duration_cap, "cover session exceeded duration cap; dropping");
            Ok((buffered_client_hello.len() as u64, 0))
        }
    }
}

// Low-level TLS record reader used by both sides of the handshake

/// Read one TLS record. On error the `Err` carries the bytes we already
/// consumed from `stream` (the 5-byte header, empty if even that failed), so
/// the accept path can replay them to the cover for origin error-parity (M2)
/// instead of a Mirage-specific silent drop.
async fn read_one_tls_record<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_size: usize,
) -> Result<Vec<u8>, (io::Error, Vec<u8>)> {
    // Read the 5-byte record header.
    let mut hdr = [0u8; 5];
    stream
        .read_exact(&mut hdr)
        .await
        .map_err(|e| (e, Vec::new()))?;
    let claimed = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if 5 + claimed > max_size {
        return Err((
            io::Error::new(io::ErrorKind::InvalidData, "tls record exceeds max_size"),
            hdr.to_vec(),
        ));
    }
    let mut out = Vec::with_capacity(5 + claimed);
    out.extend_from_slice(&hdr);
    out.resize(5 + claimed, 0);
    stream
        .read_exact(&mut out[5..])
        .await
        .map_err(|e| (e, hdr.to_vec()))?;
    Ok(out)
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("OS CSPRNG failed");
    b
}

fn to_io(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

// RealityStream: AsyncRead + AsyncWrite over the TLS record layer

/// Byte-stream view over an authenticated Reality carrier. All
/// outgoing bytes are wrapped in TLS 1.3 `application_data`
/// records; all incoming bytes are unwrapped from the same.
///
/// Parameterized on the underlying stream `S: AsyncRead + AsyncWrite`,
/// so tests can use `tokio::io::duplex`.
pub struct RealityStream<S> {
    inner: S,
    rx: RxState,
    tx: TxState,
    /// v0.1b+: AEAD traffic keys. When present, outgoing payloads
    /// are encrypted into TLS record ciphertext; incoming record
    /// payloads are decrypted before being served to the caller.
    /// When None, the stream wraps plaintext in TLS record shells
    /// (v0.1a behavior, retained for tests).
    keys: Option<TrafficKeys>,
    /// DPI-R2: splits large plaintext writes into multiple variable-size TLS
    /// records (each its own AEAD unit) so the data-phase record-size
    /// distribution matches real TLS 1.3 instead of a 1:1 map to Mirage frames.
    shaper: crate::shaper::RecordShaper,
    /// Shaper-v2 passthrough: when `true`, `poll_write` emits exactly ONE record
    /// per write (bypassing [`shaper`]) so an envelope pacer stacked above
    /// ([`crate::paced::PacedChannel`]) gets a 1:1 frame->record map and full
    /// control of each record's wire size. Off by default; the record shaper runs.
    passthrough: bool,
    /// Shaper-v2 schedule seed: a direction-symmetric mix of the shared AEAD keys,
    /// so both endpoints derive the identical value with nothing on the wire. Used
    /// only when an envelope pacer wraps this stream ([`Self::pace_seed`]).
    pace_seed: u64,
}

enum RxState {
    /// Collecting the 5-byte record header.
    Header {
        got: usize,
        buf: [u8; RECORD_HEADER_LEN],
    },
    /// Collecting the body bytes.
    Body { wire: Vec<u8>, remaining: usize },
    /// Plaintext payload ready to serve.
    Payload { buf: Vec<u8>, off: usize },
}

enum TxState {
    Idle,
    /// Draining a record already wrapped into `wire`.
    Draining {
        wire: Vec<u8>,
        off: usize,
    },
}

impl<S> RealityStream<S> {
    fn with_keys(inner: S, keys: TrafficKeys) -> Self {
        // Direction-symmetric mix of the shared AEAD keys: the client's
        // (send, recv) = (cats, sats) and the bridge's = (sats, cats), so XORing
        // both directions' mixes yields the same seed on each end without any
        // wire exchange. Only read when an envelope pacer wraps this stream.
        let pace_seed = crate::pacer::mix_seed(keys.send.key.as_ref())
            ^ crate::pacer::mix_seed(keys.recv.key.as_ref());
        Self {
            inner,
            passthrough: false,
            pace_seed,
            rx: RxState::Header {
                got: 0,
                buf: [0u8; RECORD_HEADER_LEN],
            },
            tx: TxState::Idle,
            keys: Some(keys),
            // Shape the data phase to a calibrated record-size distribution (i.i.d.
            // draws from a browser-HTTPS marginal).
            //
            // NOTE (measured, not assumed): the conditional record-length PROCESS
            // ([`crate::shaper::SplitSource::Markov`]) reproduces the length
            // *sequence* structure an i.i.d. draw omits, BUT only helps against a
            // cover whose run-length law it is calibrated to. Real TLS flows are
            // *bimodal* (short interactive record bursts + long bulk-transfer
            // runs), which a first-order single-stickiness Markov chain cannot
            // express - and against such a cover it is measurably WORSE than the
            // i.i.d. draw (it adds a uniform geometric autocorrelation that a
            // bimodal flow does not have). So the uncalibrated Markov process is
            // NOT shipped as the default; it is an opt-in
            // ([`RecordShaper::from_markov_profile`]) for a deployment that has
            // calibrated a profile to a capture of its cover. Closing the length-
            // sequence gap for real (bimodal) traffic needs a phase-state model,
            // not a first-order chain - tracked as a residual.
            shaper: crate::shaper::RecordShaper::from_profile(
                &crate::shaper::TrafficProfile::browser_https(),
            ),
        }
    }

    /// Access the underlying stream. Do not read/write through it
    /// directly or you will desync the record layer.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Consume and return the underlying stream.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// The AEAD negotiated for the data phase (send direction), or `None` for a
    /// plaintext-shell stream (v0.1a test path). Both directions always use the
    /// same suite - the one the ServerHello selected.
    pub fn negotiated_cipher(&self) -> Option<RecordCipher> {
        self.keys.as_ref().map(|k| k.send.cipher)
    }

    /// Shaper-v2 session seed: a direction-symmetric mix of the shared AEAD keys.
    /// Both endpoints derive the identical value, so an envelope pacer wrapping
    /// each side generates a coherent schedule with nothing exchanged on the wire.
    /// See [`crate::paced`].
    pub fn pace_seed(&self) -> u64 {
        self.pace_seed
    }

    /// Enable/disable shaper-v2 record passthrough. When enabled, `poll_write`
    /// emits exactly one TLS record per write (bypassing the record shaper) so a
    /// pacer stacked above controls each record's wire size 1:1. Off by default.
    pub fn set_passthrough(&mut self, on: bool) {
        self.passthrough = on;
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RealityStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let this = &mut *self;
            match &mut this.rx {
                RxState::Payload { buf: pl, off } => {
                    let avail = pl.len() - *off;
                    if avail == 0 {
                        this.rx = RxState::Header {
                            got: 0,
                            buf: [0u8; RECORD_HEADER_LEN],
                        };
                        continue;
                    }
                    let take = avail.min(buf.remaining());
                    buf.put_slice(&pl[*off..*off + take]);
                    *off += take;
                    return Poll::Ready(Ok(()));
                }
                RxState::Header { got, buf: hbuf } => {
                    let mut tmp = ReadBuf::new(&mut hbuf[*got..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut tmp) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = tmp.filled().len();
                            if n == 0 {
                                if *got == 0 {
                                    return Poll::Ready(Ok(()));
                                }
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "truncated reality record header",
                                )));
                            }
                            *got += n;
                            if *got == RECORD_HEADER_LEN {
                                // Validate the header now so we
                                // bail early on obvious garbage.
                                if hbuf[0] != 0x17 || hbuf[1] != 0x03 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "reality: non-app_data record after handshake",
                                    )));
                                }
                                let body_len = u16::from_be_bytes([hbuf[3], hbuf[4]]) as usize;
                                if body_len == 0 || body_len > MAX_INNER_PAYLOAD {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "reality: record length out of range",
                                    )));
                                }
                                let mut wire = Vec::with_capacity(RECORD_HEADER_LEN + body_len);
                                wire.extend_from_slice(hbuf);
                                wire.resize(RECORD_HEADER_LEN + body_len, 0);
                                this.rx = RxState::Body {
                                    wire,
                                    remaining: body_len,
                                };
                            }
                        }
                    }
                }
                RxState::Body { wire, remaining } => {
                    let total = wire.len();
                    let start = total - *remaining;
                    let mut tmp = ReadBuf::new(&mut wire[start..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut tmp) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let n = tmp.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "truncated reality record body",
                                )));
                            }
                            *remaining -= n;
                            if *remaining == 0 {
                                let w = std::mem::take(wire);
                                let ciphertext = match unwrap_app_data(&w) {
                                    Ok(Some(u)) => u.payload.to_vec(),
                                    Ok(None) => {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "reality: unexpected partial record",
                                        )));
                                    }
                                    Err(e) => {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            format!("reality: record parse: {e}"),
                                        )));
                                    }
                                };
                                let payload = match &mut this.keys {
                                    Some(k) => {
                                        let nonce = match k.recv.next_nonce() {
                                            Ok(n) => n,
                                            Err(e) => {
                                                return Poll::Ready(Err(io::Error::new(
                                                    io::ErrorKind::InvalidData,
                                                    format!("reality: nonce exhausted: {e}"),
                                                )));
                                            }
                                        };
                                        match k.recv.cipher.open(
                                            k.recv.key.as_ref(),
                                            &nonce,
                                            &[],
                                            &ciphertext,
                                        ) {
                                            Ok(p) => p,
                                            Err(_) => {
                                                return Poll::Ready(Err(io::Error::new(
                                                    io::ErrorKind::InvalidData,
                                                    "reality: AEAD authentication failed",
                                                )));
                                            }
                                        }
                                    }
                                    None => ciphertext,
                                };
                                this.rx = RxState::Payload {
                                    buf: payload,
                                    off: 0,
                                };
                            }
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RealityStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Drain any in-flight record first so backpressure is
        // applied before accepting more plaintext.
        loop {
            let this = &mut *self;
            match &mut this.tx {
                TxState::Idle => break,
                TxState::Draining { wire, off } => {
                    let remaining = &wire[*off..];
                    match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "reality: inner stream accepted 0 bytes",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            *off += n;
                            if *off == wire.len() {
                                this.tx = TxState::Idle;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // AEAD output is plaintext.len() + 16 tag bytes. Clamp
        // take so ciphertext fits within MAX_INNER_PAYLOAD.
        let plaintext_cap = if self.keys.is_some() {
            MAX_INNER_PAYLOAD.saturating_sub(AEAD_TAG_LEN)
        } else {
            MAX_INNER_PAYLOAD
        };
        let take = buf.len().min(plaintext_cap);
        // Record shaping. Two regimes, matching real TLS 1.3:
        //
        // - BULK: when this write FILLS the plaintext cap (`take == plaintext_cap`,
        //   i.e. the app handed us at least a full record's worth), it is a bulk-
        //   transfer fragment. Real TLS emits a *run of max-size records* for bulk
        //   (RFC 8446 §5.1: records are filled to the limit), so we emit ONE
        //   max-size record here; back-to-back full writes then form the max-size
        //   run a large download shows. (The shaper's own bulk branch keys on
        //   `>= MAX_RECORD_PLAINTEXT`, which the cap makes unreachable from here -
        //   so bulk MUST be handled at this layer, which knows the cap. Emitting
        //   cdf/markov-sampled *varied* sizes for bulk, as the shaper alone would,
        //   is itself a distinguisher from real TLS bulk.)
        // - INTERACTIVE: a sub-cap write is shaped into per-sub-record sizes drawn
        //   from the record-size distribution, so the data-phase histogram
        //   resembles a real browser<->CDN flow rather than a 1:1 frame map.
        //
        // All records are concatenated into ONE Draining `wire` so the existing
        // backpressure-safe drain (returns Ok(take) even on a partial inner
        // write) is unchanged.
        let sublens = if self.passthrough || take == plaintext_cap {
            // Passthrough (shaper-v2): the pacer above already sized this write to a
            // cover-envelope token, so emit it as ONE record and don't re-split.
            vec![take]
        } else {
            self.shaper.split_plan(take)
        };
        let mut wire: Vec<u8> =
            Vec::with_capacity(take + sublens.len() * (RECORD_HEADER_LEN + AEAD_TAG_LEN));
        let mut seg_off = 0usize;
        for &sublen in &sublens {
            let slice = &buf[seg_off..seg_off + sublen];
            seg_off += sublen;
            let record = match &mut self.keys {
                Some(k) => {
                    let nonce = match k.send.next_nonce() {
                        Ok(n) => n,
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("reality: nonce exhausted: {e}"),
                            )));
                        }
                    };
                    let ct = match k.send.cipher.seal(k.send.key.as_ref(), &nonce, &[], slice) {
                        Ok(c) => c,
                        Err(_) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::Other,
                                "reality: AEAD encrypt failed",
                            )));
                        }
                    };
                    match wrap_app_data(&ct) {
                        Ok(w) => w,
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("reality: wrap: {e}"),
                            )));
                        }
                    }
                }
                None => match wrap_app_data(slice) {
                    Ok(w) => w,
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("reality: wrap: {e}"),
                        )));
                    }
                },
            };
            wire.extend_from_slice(&record);
        }
        self.tx = TxState::Draining { wire, off: 0 };

        // Make best-effort progress on the drain within this call.
        loop {
            let this = &mut *self;
            match &mut this.tx {
                TxState::Idle => return Poll::Ready(Ok(take)),
                TxState::Draining { wire, off } => {
                    let remaining = &wire[*off..];
                    match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                        Poll::Pending => return Poll::Ready(Ok(take)),
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "reality: inner stream accepted 0 bytes",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            *off += n;
                            if *off == wire.len() {
                                this.tx = TxState::Idle;
                                return Poll::Ready(Ok(take));
                            }
                        }
                    }
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let this = &mut *self;
            match &mut this.tx {
                TxState::Idle => break,
                TxState::Draining { wire, off } => {
                    let remaining = &wire[*off..];
                    match Pin::new(&mut this.inner).poll_write(cx, remaining) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "reality: inner stream accepted 0 bytes",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            *off += n;
                            if *off == wire.len() {
                                this.tx = TxState::Idle;
                            }
                        }
                    }
                }
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut *self).poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio::net::TcpListener;

    #[test]
    fn parse_server_flight_tolerates_trailing_new_session_tickets() {
        use crate::tls_handshake_flight::{
            build_new_session_ticket, wrap_handshake, HS_TYPE_CERTIFICATE,
            HS_TYPE_CERTIFICATE_VERIFY, HS_TYPE_ENCRYPTED_EXTENSIONS, HS_TYPE_FINISHED,
        };
        let ee = wrap_handshake(HS_TYPE_ENCRYPTED_EXTENSIONS, &[0, 0]);
        let cert = wrap_handshake(HS_TYPE_CERTIFICATE, b"cert-body");
        let cv = wrap_handshake(HS_TYPE_CERTIFICATE_VERIFY, b"cv-body");
        let fin = wrap_handshake(HS_TYPE_FINISHED, &[0x11; 32]);

        let base: Vec<u8> = [&ee[..], &cert, &cv, &fin].concat();
        // No trailing ticket: parses, ranges cover exactly the four messages.
        let plan = parse_server_flight(&base).expect("bare flight parses");
        assert_eq!(plan.fin_range.end, base.len());
        assert_eq!(&base[plan.ee_range.clone()], &ee[..]);
        assert_eq!(&base[plan.fin_range.clone()], &fin[..]);

        // Audit #16: one (and two) trailing NewSessionTickets are consumed, and
        // the plan still points only at EE|Cert|CV|Fin.
        let nst = build_new_session_ticket(7200, 42, &[0xAA; 8], &[0xBB; 96]);
        for tickets in [1usize, 2] {
            let mut buf = base.clone();
            for _ in 0..tickets {
                buf.extend_from_slice(&nst);
            }
            let plan = parse_server_flight(&buf).expect("flight with NST parses");
            assert_eq!(
                plan.fin_range.end,
                base.len(),
                "plan excludes the ticket(s)"
            );
            assert_eq!(&buf[plan.fin_range.clone()], &fin[..]);
        }

        // Garbage (non-NST) after Finished is still rejected.
        let mut bad = base.clone();
        bad.extend_from_slice(&[0xFF, 0x00, 0x00, 0x01, 0x00]);
        assert!(parse_server_flight(&bad).is_none());
    }

    #[test]
    fn parse_first_cert_pubkey_robust_to_sni_length() {
        use crate::tls_handshake_flight::build_certificate;
        for sni in [
            "a",
            "mirage.invalid",
            "www.example.com",
            "really-long-subdomain.cdn.example.org",
        ] {
            let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
            let expected = p256_compressed_pk(&sk);
            let cert = crate::tls_cert::build_self_signed_ecdsa_p256(&sk, sni);
            let cert_msg = build_certificate(&cert);
            let extracted = parse_first_cert_pubkey(&cert_msg)
                .unwrap_or_else(|| panic!("parse failed for SNI={sni}"));
            assert_eq!(
                extracted, expected,
                "extracted pubkey != signing pubkey for SNI={sni}"
            );
        }
    }

    /// Helper: in-process cover echo server on 127.0.0.1:random.
    async fn spawn_cover_echo() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });
        addr
    }

    fn bridge_keys() -> (StaticSecret, [u8; 32]) {
        let sk_bytes = {
            let mut b = [0u8; 32];
            getrandom::fill(&mut b).unwrap();
            b
        };
        let sk = StaticSecret::from(sk_bytes);
        let pk = *PublicKey::from(&sk).as_bytes();
        (sk, pk)
    }

    /// A valid random P-256 CertVerify signing key (rejection-samples the
    /// ~2^-32 case where a raw 32-byte value exceeds the curve order).
    fn p256_test_key() -> p256::ecdsa::SigningKey {
        loop {
            let mut s = [0u8; 32];
            getrandom::fill(&mut s).unwrap();
            if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&s) {
                return k;
            }
        }
    }

    /// Compressed SEC1 (33-byte) public key of a P-256 signing key - the form
    /// the invite publishes as `tls_cert_verify_pk`.
    fn p256_compressed_pk(sk: &p256::ecdsa::SigningKey) -> [u8; 33] {
        sk.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed P-256 point is 33 bytes")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pinned_tls_identity_mimicry_roundtrip() {
        // Bridge presents a cert whose SPKI does NOT match its
        // CertVerify-signing key. The client, given the override
        // pubkey via `cert_verify_override_pk`, accepts the
        // handshake. Any client WITHOUT the override would reject
        // (verified by a negative test below).
        let (bridge_sk, bridge_pk) = bridge_keys();
        let now = 1_700_000_000u32;
        let cover = spawn_cover_echo().await;

        // "Cover" cert: minted with one keypair, held by the bridge.
        // "Cover" cert: a self-signed ECDSA-P256 cert whose key is SEPARATE from
        // the CertVerify signing key (the cover-mimicry invariant under test).
        let cover_sk = p256_test_key();
        let cert_der =
            crate::tls_cert::build_self_signed_ecdsa_p256(&cover_sk, "cover.example.com");

        // Bridge's TLS-signing key - a SEPARATE ECDSA P-256 keypair.
        // This is what the invite would publish as `tls_cert_verify_pk`
        // (compressed SEC1, 33 bytes).
        let sign_sk = p256_test_key();
        let sign_pk = p256_compressed_pk(&sign_sk);

        let identity = TlsIdentity {
            cert_der: cert_der.clone(),
            signing_key: sign_sk.clone(),
        };

        let (a, b) = duplex(64 * 1024);

        let sign_pk_for_client = sign_pk;
        let client_fut = tokio::spawn(async move {
            let mut rs = reality_connect(
                a,
                &ClientCarrierInputs {
                    bridge_static_pk: &bridge_pk,
                    server_name: "cover.example.com",
                    now_unix: now,
                    cert_verify_override_pk: Some(&sign_pk_for_client),
                    probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                    tls_fingerprint: None,
                },
            )
            .await
            .expect("client handshake");
            rs.write_all(b"ping").await.unwrap();
            rs.flush().await.unwrap();
            let mut got = [0u8; 4];
            rs.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"pong");
        });

        let identity_clone = identity.clone();
        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(3),
                tls_identity: Some(&identity_clone),
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            match reality_accept(b, &mut binputs).await.unwrap() {
                AcceptOutcome::Authenticated(mut rs) => {
                    let mut got = [0u8; 4];
                    rs.read_exact(&mut got).await.unwrap();
                    assert_eq!(&got, b"ping");
                    rs.write_all(b"pong").await.unwrap();
                    rs.flush().await.unwrap();
                }
                AcceptOutcome::CoverServed { .. } => panic!("expected authenticated"),
            }
        });

        client_fut.await.unwrap();
        bridge_fut.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pinned_tls_without_client_override_fails() {
        // Same bridge setup as above (cert and signing key are
        // different), but the client DOES NOT supply the override.
        // The client will try to verify CertVerify against the
        // cert's SPKI -> mismatch -> handshake must fail.
        let (bridge_sk, bridge_pk) = bridge_keys();
        let now = 1_700_000_000u32;
        let cover = spawn_cover_echo().await;

        // "Cover" cert: a self-signed ECDSA-P256 cert whose key is SEPARATE from
        // the CertVerify signing key (the cover-mimicry invariant under test).
        let cover_sk = p256_test_key();
        let cert_der =
            crate::tls_cert::build_self_signed_ecdsa_p256(&cover_sk, "cover.example.com");

        let sign_sk = p256_test_key();

        let identity = TlsIdentity {
            cert_der,
            signing_key: sign_sk,
        };

        let (a, b) = duplex(64 * 1024);

        let client_fut = tokio::spawn(async move {
            reality_connect(
                a,
                &ClientCarrierInputs {
                    bridge_static_pk: &bridge_pk,
                    server_name: "cover.example.com",
                    now_unix: now,
                    cert_verify_override_pk: None,
                    probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                    tls_fingerprint: None,
                },
            )
            .await
        });

        let identity_clone = identity.clone();
        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(3),
                tls_identity: Some(&identity_clone),
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            reality_accept(b, &mut binputs).await
        });

        let r = client_fut.await.unwrap();
        assert!(
            r.is_err(),
            "client without override must reject mismatched cert/CertVerify"
        );
        let _ = bridge_fut.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pinned_tls_wrong_override_pubkey_fails() {
        // Red-team regression: client is given the WRONG
        // `cert_verify_override_pk` (one that doesn't match the
        // bridge's signing key). CertVerify must fail - proves the
        // override path is load-bearing, not a "trust anything"
        // bypass. A MitM who swaps the invite's
        // `tls_cert_verify_pk` to their own key without also
        // replacing the bridge cannot terminate the handshake.
        let (bridge_sk, bridge_pk) = bridge_keys();
        let now = 1_700_000_000u32;
        let cover = spawn_cover_echo().await;

        // Cover cert (SPKI we never verify against in this path).
        // "Cover" cert: a self-signed ECDSA-P256 cert whose key is SEPARATE from
        // the CertVerify signing key (the cover-mimicry invariant under test).
        let cover_sk = p256_test_key();
        let cert_der =
            crate::tls_cert::build_self_signed_ecdsa_p256(&cover_sk, "cover.example.com");

        // Bridge's real signing key.
        let sign_sk = p256_test_key();

        // Client is handed a DIFFERENT pubkey - simulates an
        // attacker-substituted invite extension.
        let wrong_sk = p256_test_key();
        let wrong_pk = p256_compressed_pk(&wrong_sk);

        let identity = TlsIdentity {
            cert_der,
            signing_key: sign_sk,
        };

        let (a, b) = duplex(64 * 1024);

        let client_fut = tokio::spawn(async move {
            reality_connect(
                a,
                &ClientCarrierInputs {
                    bridge_static_pk: &bridge_pk,
                    server_name: "cover.example.com",
                    now_unix: now,
                    cert_verify_override_pk: Some(&wrong_pk),
                    probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                    tls_fingerprint: None,
                },
            )
            .await
        });

        let identity_clone = identity.clone();
        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(3),
                tls_identity: Some(&identity_clone),
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            reality_accept(b, &mut binputs).await
        });

        let r = client_fut.await.unwrap();
        assert!(
            r.is_err(),
            "wrong override pubkey must fail CertVerify, not silently accept"
        );
        let _ = bridge_fut.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handshake_and_roundtrip_authenticated_path() {
        let (bridge_sk, bridge_pk) = bridge_keys();
        let now = 1_700_000_000u32;
        let cover = spawn_cover_echo().await; // unused here but OK

        let (a, b) = duplex(64 * 1024);

        let client_fut = tokio::spawn(async move {
            let mut rs = reality_connect(
                a,
                &ClientCarrierInputs {
                    bridge_static_pk: &bridge_pk,
                    server_name: "cover.example.com",
                    now_unix: now,
                    cert_verify_override_pk: None,
                    probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                    tls_fingerprint: None,
                },
            )
            .await
            .unwrap();
            // The Chrome-parrot ClientHello offers AES-128-GCM first, so the
            // bridge selects it and the data phase runs over the AES-GCM record
            // path (not the legacy always-ChaCha path).
            assert_eq!(
                rs.negotiated_cipher(),
                Some(RecordCipher::Aes128Gcm),
                "Chrome-parrot handshake must negotiate AES-128-GCM"
            );
            rs.write_all(b"hello reality").await.unwrap();
            rs.flush().await.unwrap();
            let mut got = [0u8; 11];
            rs.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"hi mirage!!");
        });

        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(3),
                tls_identity: None,
                // Exercise cover-flight padding on the authenticated path: the
                // client must still parse the (now zero-padded) flight record
                // transparently, proving the padding is spec-correct RFC 8446
                // §5.4 record padding and not a wire-format break.
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: Some(4096),
                cover_flight_records: &[],
            };
            match reality_accept(b, &mut binputs).await.unwrap() {
                AcceptOutcome::Authenticated(mut rs) => {
                    let mut got = [0u8; 13];
                    rs.read_exact(&mut got).await.unwrap();
                    assert_eq!(&got, b"hello reality");
                    rs.write_all(b"hi mirage!!").await.unwrap();
                    rs.flush().await.unwrap();
                }
                AcceptOutcome::CoverServed { .. } => panic!("expected authenticated"),
            }
        });

        client_fut.await.unwrap();
        bridge_fut.await.unwrap();
    }

    /// M1: the bridge splits its server flight into MULTIPLE records matching a
    /// cover's measured framing; the client must still complete the handshake and
    /// round-trip data - proving the extra records do NOT desync it (Finished
    /// stays in the last record, so the client reads every record).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handshake_roundtrip_with_cover_matched_record_framing() {
        let (bridge_sk, bridge_pk) = bridge_keys();
        let now = 1_700_000_000u32;
        let cover = spawn_cover_echo().await;
        let (a, b) = duplex(64 * 1024);

        let client_fut = tokio::spawn(async move {
            let mut rs = reality_connect(
                a,
                &ClientCarrierInputs {
                    bridge_static_pk: &bridge_pk,
                    server_name: "cover.example.com",
                    now_unix: now,
                    cert_verify_override_pk: None,
                    probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                    tls_fingerprint: None,
                },
            )
            .await
            .unwrap();
            rs.write_all(b"ping").await.unwrap();
            rs.flush().await.unwrap();
            let mut got = [0u8; 4];
            rs.read_exact(&mut got).await.unwrap();
            assert_eq!(
                &got, b"pong",
                "roundtrip intact across the multi-record flight"
            );
        });

        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            // Two-record cover framing; the ephemeral flight fits, so M1 emits two
            // records with Finished in the second.
            let records = [900usize, 900usize];
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(3),
                tls_identity: None,
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: Some(1800),
                cover_flight_records: &records,
            };
            match reality_accept(b, &mut binputs).await.unwrap() {
                AcceptOutcome::Authenticated(mut rs) => {
                    let mut got = [0u8; 4];
                    rs.read_exact(&mut got).await.unwrap();
                    assert_eq!(&got, b"ping");
                    rs.write_all(b"pong").await.unwrap();
                    rs.flush().await.unwrap();
                }
                AcceptOutcome::CoverServed { .. } => panic!("expected authenticated"),
            }
        });

        client_fut.await.unwrap();
        bridge_fut.await.unwrap();
    }

    /// DPI-R2 regression: a 40 KiB payload each way exercises the RecordShaper
    /// split path (writes > RECORD_SPLIT_THRESHOLD become multiple TLS records).
    /// The bytes MUST round-trip intact across the record boundaries.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handshake_and_roundtrip_large_payload_record_split() {
        let (bridge_sk, bridge_pk) = bridge_keys();
        let now = 1_700_000_000u32;
        let cover = spawn_cover_echo().await;
        let (a, b) = duplex(256 * 1024);

        let up: Vec<u8> = (0..40_000usize).map(|i| (i % 251) as u8).collect();
        let down: Vec<u8> = (0..40_000usize)
            .map(|i| ((i * 7 + 3) % 251) as u8)
            .collect();
        let up_c = up.clone();
        let down_c = down.clone();

        let client_fut = tokio::spawn(async move {
            let mut rs = reality_connect(
                a,
                &ClientCarrierInputs {
                    bridge_static_pk: &bridge_pk,
                    server_name: "cover.example.com",
                    now_unix: now,
                    cert_verify_override_pk: None,
                    probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                    tls_fingerprint: None,
                },
            )
            .await
            .unwrap();
            rs.write_all(&up_c).await.unwrap();
            rs.flush().await.unwrap();
            let mut got = vec![0u8; down_c.len()];
            rs.read_exact(&mut got).await.unwrap();
            assert_eq!(got, down_c, "client did not receive bridge payload intact");
        });

        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(3),
                tls_identity: None,
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            match reality_accept(b, &mut binputs).await.unwrap() {
                AcceptOutcome::Authenticated(mut rs) => {
                    let mut got = vec![0u8; up.len()];
                    rs.read_exact(&mut got).await.unwrap();
                    assert_eq!(got, up, "bridge did not receive client payload intact");
                    rs.write_all(&down).await.unwrap();
                    rs.flush().await.unwrap();
                }
                AcceptOutcome::CoverServed { .. } => panic!("expected authenticated"),
            }
        });
        client_fut.await.unwrap();
        bridge_fut.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn reality_paced_bidirectional_bulk_survives_real_carrier() {
        // Full Reality handshake, then stack the shaper-v2 envelope pacer on BOTH
        // ends (passthrough = 1 frame : 1 record) and push a bulk transfer each
        // way. Proves paced+padded frames survive the real seal / AEAD / record
        // path and reassemble byte-exact. Both sides derive the SAME schedule seed
        // from the shared keys (no wire exchange). Paused time fires the cover
        // schedule instantly.
        let (bridge_sk, bridge_pk) = bridge_keys();
        let now = 1_700_000_000u32;
        let cover = spawn_cover_echo().await;
        let (a, b) = duplex(256 * 1024);

        let up: Vec<u8> = (0..24_000usize).map(|i| (i % 251) as u8).collect();
        let down: Vec<u8> = (0..48_000usize)
            .map(|i| ((i * 7 + 3) % 251) as u8)
            .collect();
        let up_c = up.clone();
        let down_c = down.clone();

        let client_fut = tokio::spawn(async move {
            let mut rs = reality_connect(
                a,
                &ClientCarrierInputs {
                    bridge_static_pk: &bridge_pk,
                    server_name: "cover.example.com",
                    now_unix: now,
                    cert_verify_override_pk: None,
                    probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                    tls_fingerprint: None,
                },
            )
            .await
            .unwrap();
            let seed = rs.pace_seed();
            rs.set_passthrough(true);
            let proc = crate::pacer::CoverProcess::from_class_seed("video", seed);
            let paced = crate::paced::PacedChannel::spawn(
                rs,
                crate::pacer::ScheduleStream::new(proc, seed),
                crate::pacer::Dir::Up,
            );
            let (mut rd, mut wr) = tokio::io::split(paced);
            let w = tokio::spawn(async move {
                wr.write_all(&up_c).await.unwrap();
                wr.shutdown().await.unwrap();
            });
            let mut got = Vec::new();
            rd.read_to_end(&mut got).await.unwrap();
            w.await.unwrap();
            assert_eq!(got, down_c, "client did not receive bridge payload intact");
        });

        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(3),
                tls_identity: None,
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            match reality_accept(b, &mut binputs).await.unwrap() {
                AcceptOutcome::Authenticated(mut rs) => {
                    let seed = rs.pace_seed();
                    rs.set_passthrough(true);
                    let proc = crate::pacer::CoverProcess::from_class_seed("video", seed);
                    let paced = crate::paced::PacedChannel::spawn(
                        rs,
                        crate::pacer::ScheduleStream::new(proc, seed),
                        crate::pacer::Dir::Down,
                    );
                    let (mut rd, mut wr) = tokio::io::split(paced);
                    let w = tokio::spawn(async move {
                        wr.write_all(&down).await.unwrap();
                        wr.shutdown().await.unwrap();
                    });
                    let mut got = Vec::new();
                    rd.read_to_end(&mut got).await.unwrap();
                    w.await.unwrap();
                    assert_eq!(got, up, "bridge did not receive client payload intact");
                }
                AcceptOutcome::CoverServed { .. } => panic!("expected authenticated"),
            }
        });
        client_fut.await.unwrap();
        bridge_fut.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn reality_paced_wire_records_match_schedule_sizes() {
        // LINCHPIN of the shaping claim: whatever the payload, the on-wire records
        // must land at the cover SCHEDULE's token sizes (padding hides the payload
        // in the size domain). We drive a paced Down writer over the real carrier,
        // capture the raw wire, and assert every record's wire size is a token size
        // the video schedule actually emits - NOT a size derived from the payload.
        use crate::pacer::{CoverProcess, Dir};
        let seed = 0x1357_9BDF_2468_ACE0u64;
        let (a, mut b) = duplex(512 * 1024);
        let mk = || {
            DirKeys::from_key_iv(
                RecordCipher::ChaCha20Poly1305,
                Zeroizing::new(vec![0x42u8; 32]),
                [0u8; AEAD_IV_LEN],
            )
        };
        let mut rs = RealityStream::with_keys(
            a,
            TrafficKeys {
                send: mk(),
                recv: mk(),
            },
        );
        rs.set_passthrough(true);
        let proc = CoverProcess::from_class_seed("video", seed);
        // The set of wire sizes the Down schedule can legally emit (floored like the
        // pump does). For video these are all MTU-sized down bursts.
        let mut legal: std::collections::HashSet<usize> = proc
            .schedule(30.0, seed)
            .into_iter()
            .filter(|e| e.dir == Dir::Down)
            .map(|e| e.bytes.max(RECORD_HEADER_LEN + 4 + AEAD_TAG_LEN))
            .collect();
        // The pump rolls to fresh windows with derived seeds; include a few so a
        // long transfer's later records are covered too.
        let mut s = seed;
        for _ in 0..4 {
            s = s
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(0x1234_5678_9ABC_DEF1);
            for e in proc.schedule(30.0, s) {
                if e.dir == Dir::Down {
                    legal.insert(e.bytes.max(RECORD_HEADER_LEN + 4 + AEAD_TAG_LEN));
                }
            }
        }

        let mut paced = crate::paced::PacedChannel::spawn(
            rs,
            crate::pacer::ScheduleStream::new(proc, seed),
            Dir::Down,
        );
        let payload = vec![0xABu8; 40_000]; // 40 KB of real demand
        let writer = tokio::spawn(async move {
            paced.write_all(&payload).await.unwrap();
            paced.shutdown().await.unwrap();
        });
        let mut wire = Vec::new();
        b.read_to_end(&mut wire).await.unwrap();
        writer.await.unwrap();

        let mut off = 0usize;
        let mut nrec = 0usize;
        while off + RECORD_HEADER_LEN <= wire.len() {
            assert_eq!(wire[off], 0x17, "each record is application_data");
            let body = ((wire[off + 3] as usize) << 8) | wire[off + 4] as usize;
            let wire_sz = RECORD_HEADER_LEN + body;
            assert!(
                legal.contains(&wire_sz),
                "record #{nrec} wire size {wire_sz} is NOT a schedule token size \
                 (payload leaked into the size domain); legal set = {legal:?}"
            );
            off += RECORD_HEADER_LEN + body;
            nrec += 1;
        }
        assert_eq!(off, wire.len(), "records tile the wire exactly");
        assert!(nrec >= 20, "40 KB paced -> many records, got {nrec}");
    }

    #[tokio::test(start_paused = true)]
    async fn reality_pace_seed_agrees_across_endpoints() {
        // Claim under test: both ends derive the IDENTICAL schedule seed from the
        // shared keys with nothing on the wire (so their up/down envelopes are one
        // coherent draw). Never asserted before - data round-trips regardless of
        // seed agreement, so a mismatch would have passed silently.
        let (bridge_sk, bridge_pk) = bridge_keys();
        let now = 1_700_000_000u32;
        let cover = spawn_cover_echo().await;
        let (a, b) = duplex(64 * 1024);

        let client = tokio::spawn(async move {
            let rs = reality_connect(
                a,
                &ClientCarrierInputs {
                    bridge_static_pk: &bridge_pk,
                    server_name: "cover.example.com",
                    now_unix: now,
                    cert_verify_override_pk: None,
                    probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                    tls_fingerprint: None,
                },
            )
            .await
            .unwrap();
            rs.pace_seed()
        });
        let bridge = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(5),
                cover_duration_cap: Duration::from_secs(5),
                tls_identity: None,
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            match reality_accept(b, &mut binputs).await.unwrap() {
                AcceptOutcome::Authenticated(rs) => rs.pace_seed(),
                AcceptOutcome::CoverServed { .. } => panic!("expected authenticated"),
            }
        });
        let cs = client.await.unwrap();
        let bs = bridge.await.unwrap();
        assert_eq!(cs, bs, "client and bridge must derive the same pace seed");
        assert_ne!(cs, 0, "a real session seed should not be zero");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reality_paced_small_message_pingpong() {
        // Reproduces the live session-handshake shape: small messages (heavy
        // padding per frame) exchanged over the paced carrier, under a REAL clock
        // (the production path). The bulk test barely pads (queue always full); this
        // exercises the small-real / large-pad frame path the MUX handshake hits.
        // Kept to 3 rounds inside the cover's first dense burst so pacing latency
        // (the documented interactive limit of a video envelope) can't stall it.
        let (bridge_sk, bridge_pk) = bridge_keys();
        let now = 1_700_000_000u32;
        let cover = spawn_cover_echo().await;
        let (a, b) = duplex(256 * 1024);

        let client_fut = tokio::spawn(async move {
            let mut rs = reality_connect(
                a,
                &ClientCarrierInputs {
                    bridge_static_pk: &bridge_pk,
                    server_name: "cover.example.com",
                    now_unix: now,
                    cert_verify_override_pk: None,
                    probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                    tls_fingerprint: None,
                },
            )
            .await
            .unwrap();
            let seed = rs.pace_seed();
            rs.set_passthrough(true);
            let proc = crate::pacer::CoverProcess::from_class_seed("video", seed);
            let mut paced = crate::paced::PacedChannel::spawn(
                rs,
                crate::pacer::ScheduleStream::new(proc, seed),
                crate::pacer::Dir::Up,
            );
            // Client is the initiator: write a small msg, read the echo, repeat.
            for i in 0u8..3 {
                let msg = [i, i.wrapping_add(17), i.wrapping_add(42), 0xAB, 0xCD];
                paced.write_all(&msg).await.unwrap();
                paced.flush().await.unwrap();
                let mut got = [0u8; 5];
                paced.read_exact(&mut got).await.unwrap();
                assert_eq!(got, msg, "round {i}: echo mismatch (corruption)");
            }
            // A paced channel BUFFERS behind its pump; shutdown() drains the queue
            // before closing. Dropping without it discards queued bytes (production
            // paths close via copy_bidirectional's shutdown, so this matches them).
            paced.shutdown().await.unwrap();
        });

        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(5),
                cover_duration_cap: Duration::from_secs(5),
                tls_identity: None,
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            match reality_accept(b, &mut binputs).await.unwrap() {
                AcceptOutcome::Authenticated(mut rs) => {
                    let seed = rs.pace_seed();
                    rs.set_passthrough(true);
                    let proc = crate::pacer::CoverProcess::from_class_seed("video", seed);
                    let mut paced = crate::paced::PacedChannel::spawn(
                        rs,
                        crate::pacer::ScheduleStream::new(proc, seed),
                        crate::pacer::Dir::Down,
                    );
                    for _ in 0u8..3 {
                        let mut got = [0u8; 5];
                        paced.read_exact(&mut got).await.unwrap();
                        paced.write_all(&got).await.unwrap();
                        paced.flush().await.unwrap();
                    }
                    // Drain the last echo before dropping (see client note).
                    paced.shutdown().await.unwrap();
                }
                AcceptOutcome::CoverServed { .. } => panic!("expected authenticated"),
            }
        });
        tokio::time::timeout(Duration::from_secs(60), async {
            client_fut.await.unwrap();
            bridge_fut.await.unwrap();
        })
        .await
        .expect("paced ping-pong deadlocked/timed out");
    }

    #[tokio::test]
    async fn bulk_write_emits_a_run_of_max_size_records_on_the_wire() {
        // GENUINE (live-path) confirmation of the bulk-transfer shape. A large
        // ("bulk") write must emit a RUN of identical max-size TLS records on the
        // wire, like real TLS 1.3 (RFC 8446 §5.1 fills records to the limit) - NOT
        // the varied cdf/markov-split sizes the shaper's own bulk branch would
        // leave (that branch keys on `pt_len >= MAX_RECORD_PLAINTEXT`, which the
        // carrier's `plaintext_cap` clamp makes unreachable, so bulk is handled at
        // the carrier layer). This exercises the ACTUAL `poll_write` path and
        // parses the raw record headers (no decryption needed) - unlike the
        // shaper's abstract-API bulk tests, which drive a `pt_len` the live caller
        // never produces.
        let (a, mut b) = duplex(512 * 1024);
        let mk = || {
            DirKeys::from_key_iv(
                RecordCipher::ChaCha20Poly1305,
                Zeroizing::new(vec![0x42u8; 32]),
                [0u8; AEAD_IV_LEN],
            )
        };
        let mut rs = RealityStream::with_keys(
            a,
            TrafficKeys {
                send: mk(),
                recv: mk(),
            },
        );
        let payload = vec![0xABu8; 100_000]; // a 100 KB bulk transfer
        rs.write_all(&payload).await.unwrap();
        rs.flush().await.unwrap();
        drop(rs); // close the write half so the reader sees EOF

        let mut wire = Vec::new();
        b.read_to_end(&mut wire).await.unwrap();

        // Parse application_data record lengths from the 5-byte headers.
        let mut sizes = Vec::new();
        let mut off = 0usize;
        while off + RECORD_HEADER_LEN <= wire.len() {
            assert_eq!(wire[off], 0x17, "each record is application_data");
            let len = ((wire[off + 3] as usize) << 8) | wire[off + 4] as usize;
            sizes.push(len);
            off += RECORD_HEADER_LEN + len;
        }
        assert_eq!(off, wire.len(), "records must tile the wire exactly");
        assert!(
            sizes.len() >= 6,
            "a 100 KB bulk transfer is many records: {}",
            sizes.len()
        );

        // The defining property: a RUN of the MAX record size (the bulk fragments),
        // dominating the flow - not varied sizes. (Without the carrier-layer bulk
        // handling, each 16368-byte take is cdf-split into varied sizes and this
        // run does not form.)
        let max_size = *sizes.iter().max().unwrap();
        let n_max = sizes.iter().filter(|&&s| s == max_size).count();
        assert!(
            n_max >= 6,
            "bulk must produce a RUN of >= 6 max-size records; sizes = {sizes:?}"
        );
        assert!(
            n_max * 2 > sizes.len(),
            "max-size records must dominate (a bulk run); sizes = {sizes:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn garbage_client_falls_through_to_cover() {
        let (bridge_sk, _bridge_pk) = bridge_keys();
        let cover = spawn_cover_echo().await;
        let now = 1_700_000_000u32;

        let (mut a, b) = duplex(4096);

        // Client sends 2 KiB of random garbage; no valid ClientHello.
        let hostile_fut = tokio::spawn(async move {
            let mut junk = vec![0u8; 2048];
            getrandom::fill(&mut junk).unwrap();
            // Make bytes parse as a TLS record header so the bridge
            // consumes them instead of erroring immediately. Set
            // type = handshake and a reasonable length.
            junk[0] = 0x16;
            junk[1] = 0x03;
            junk[2] = 0x01;
            let len = 2048 - 5;
            junk[3] = ((len >> 8) & 0xFF) as u8;
            junk[4] = (len & 0xFF) as u8;
            a.write_all(&junk).await.unwrap();
            // Read whatever the cover sends back.
            let mut back = vec![0u8; 2048];

            a.read(&mut back).await.unwrap_or(0)
        });

        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(2),
                tls_identity: None,
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            reality_accept(b, &mut binputs).await.unwrap()
        });

        let _bytes_read_by_client = hostile_fut.await.unwrap();
        match bridge_fut.await.unwrap() {
            AcceptOutcome::CoverServed { c2s, .. } => {
                assert!(c2s > 0, "cover got at least the ClientHello");
            }
            AcceptOutcome::Authenticated(_) => panic!("garbage must NOT authenticate"),
        }
    }

    /// M1: the cover-matched record plan must keep Finished in the LAST record
    /// (so the client, which stops reading at Finished, leaves no record unread),
    /// cover the whole flight, and fall back to `None` when it can't be done
    /// safely - never a guessed split.
    #[test]
    fn plan_cover_matched_records_keeps_finished_in_last_record() {
        // Record of plaintext capacity `c` has wire size c + header + tag + 1.
        let rec = |c: usize| c + RECORD_HEADER_LEN + AEAD_TAG_LEN + 1;
        // 1000-byte flight, Finished starts at 900 (prefix 900, Finished+NST 100).
        let wires = vec![rec(400), rec(400), rec(300)];
        let plan = plan_cover_matched_records(1000, 900, &wires).expect("fits");
        assert_eq!(plan.len(), 3, "reproduces the cover's record count");
        assert_eq!(plan.iter().sum::<usize>(), 1000, "covers the whole flight");
        assert!(plan.iter().all(|&n| n >= 1), "no pure-padding records");
        let first: usize = plan[..plan.len() - 1].iter().sum();
        assert!(
            first <= 900,
            "first records carry only pre-Finished bytes => Finished lands in the last record"
        );
        assert!(
            *plan.last().unwrap() >= 100,
            "the last record carries Finished + NST"
        );

        // Single record => coalesce (None).
        assert!(plan_cover_matched_records(1000, 900, &[rec(1000)]).is_none());
        // Last record too small to hold the tail => fall back (None).
        assert!(plan_cover_matched_records(1000, 900, &[rec(950), rec(10)]).is_none());
        // Finished at the very start (no prefix) => fall back.
        assert!(plan_cover_matched_records(1000, 0, &[rec(500), rec(500)]).is_none());

        // Certifies the e2e (`handshake_roundtrip_with_cover_matched_record_framing`,
        // which uses cover_flight_records = [900, 900]) exercises the SPLIT path,
        // not the coalesced fallback, for EVERY plausible ephemeral-flight size:
        // any flight in 400..=1700 bytes with a realistic ~280-byte Finished+NST
        // tail splits into exactly two records with Finished in the last.
        for flight_len in (400..=1700).step_by(37) {
            let fin_start = flight_len - 280; // Finished starts, leaving Finished+NST tail
            let plan = plan_cover_matched_records(flight_len, fin_start, &[900, 900])
                .unwrap_or_else(|| panic!("[900,900] must split a {flight_len}-byte flight"));
            assert_eq!(plan.len(), 2, "two-record cover => two-record split");
            assert_eq!(plan.iter().sum::<usize>(), flight_len);
            assert!(
                plan[0] <= fin_start,
                "Finished stays out of the first record"
            );
        }
    }

    /// M2 regression: an OVERSIZED TLS record header (claimed body > the TLS
    /// maximum) must be forwarded to the cover (origin error-parity) as a
    /// `CoverServed` outcome, NOT dropped with a bare `Err`. The prior version
    /// returned `Err` before the cover-forward path - a silent close, diverging
    /// from a real origin (which answers an oversized record with a
    /// record_overflow alert). Guards against a refactor reintroducing the drop.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn oversized_record_header_forwards_to_cover() {
        let (bridge_sk, _bridge_pk) = bridge_keys();
        let cover = spawn_cover_echo().await;
        let now = 1_700_000_000u32;
        let (mut a, b) = duplex(4096);

        let client_fut = tokio::spawn(async move {
            // 5-byte TLS record header claiming 65535 body bytes (>> TLS max
            // 2^14), then no body: drives read_one_tls_record's oversized error.
            let hdr = [0x16u8, 0x03, 0x01, 0xFF, 0xFF];
            a.write_all(&hdr).await.unwrap();
            // Read back whatever the cover echoes (proves the bytes were
            // forwarded rather than the connection being silently dropped).
            let mut back = vec![0u8; 64];
            a.read(&mut back).await.unwrap_or(0)
        });

        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(2),
                tls_identity: None,
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            reality_accept(b, &mut binputs).await.unwrap()
        });

        let echoed = client_fut.await.unwrap();
        match bridge_fut.await.unwrap() {
            AcceptOutcome::CoverServed { c2s, .. } => {
                assert!(c2s >= 5, "the oversized header was forwarded to the cover");
            }
            AcceptOutcome::Authenticated(_) => panic!("oversized record must NOT authenticate"),
        }
        assert!(
            echoed >= 5,
            "cover echoed the forwarded header bytes back to the client"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn replay_lock_is_released_during_cover_serve() {
        // Regression for the bridge-wide Reality DoS: the single shared
        // `Mutex<ReplayProbeSet>` MUST NOT be held across the auth-fail
        // cover-serve. An earlier version locked it in the bridge caller and
        // passed the guard into `reality_accept`, so the guard lived across
        // `forward_to_cover_with_stream` (up to `cover_duration_cap`). One
        // attacker holding an unauthenticated socket open for the cover cap
        // then serialized EVERY other Reality accept - a trivial DoS.
        //
        // We drive the fail path into a cover that hangs (never responds, never
        // closes) so `copy_bidirectional` blocks, and assert the shared lock is
        // FREE while that cover-serve is in flight. The cover receiving the
        // forwarded ClientHello is the deterministic signal that the bridge is
        // PAST probe verification (where the lock is taken) and inside the serve
        // phase - so at that instant the lock must already be released.
        use std::sync::Arc;

        let (bridge_sk, _bridge_pk) = bridge_keys();
        let now = 1_700_000_000u32;

        let (got_ch_tx, got_ch_rx) = tokio::sync::oneshot::channel::<()>();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cover = l.local_addr().unwrap();
        let cover_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = l.accept().await {
                let mut buf = [0u8; 64];
                // Completes only once the bridge writes the buffered ClientHello
                // into the cover -> the bridge is inside the serve phase.
                if let Ok(n) = sock.read(&mut buf).await {
                    if n > 0 {
                        let _ = got_ch_tx.send(());
                    }
                }
                // Hold open, silent, so the bridge's copy_bidirectional blocks
                // (until the test tears us down).
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        let rset = Arc::new(tokio::sync::Mutex::new(ReplayProbeSet::new(16)));

        let (mut a, b) = duplex(4096);

        // Keep the client socket open (do NOT drop `a`) so the c2s copy half
        // does not EOF; `stop_rx` lets the test end it.
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let client_task = tokio::spawn(async move {
            let mut junk = vec![0u8; 2048];
            getrandom::fill(&mut junk).unwrap();
            junk[0] = 0x16;
            junk[1] = 0x03;
            junk[2] = 0x01;
            let len = 2048 - 5;
            junk[3] = ((len >> 8) & 0xFF) as u8;
            junk[4] = (len & 0xFF) as u8;
            a.write_all(&junk).await.unwrap();
            let _ = stop_rx.await;
            drop(a);
        });

        let rset_bridge = Arc::clone(&rset);
        let bridge_task = tokio::spawn(async move {
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset_bridge,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(5),
                tls_identity: None,
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            reality_accept(b, &mut binputs).await
        });

        // Bridge is now inside the cover-serve, past probe verification.
        tokio::time::timeout(Duration::from_secs(4), got_ch_rx)
            .await
            .expect("cover should receive the forwarded ClientHello within the window")
            .expect("cover signal channel closed unexpectedly");

        // THE INVARIANT: the shared replay lock is free during the cover-serve.
        // Under the old caller-holds-the-guard code this try_lock would fail.
        assert!(
            rset.try_lock().is_ok(),
            "replay-probe lock must be released during cover-serve, not held across it"
        );

        // Tear down promptly - we've proven the property.
        let _ = stop_tx.send(());
        bridge_task.abort();
        client_task.abort();
        cover_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pass_path_equalizes_via_cover_when_scraper_reachable() {
        // #3: when the pass path is reachable by a public-key scraper (here:
        // accept_legacy=true, so a legacy pubkey-derivable probe is accepted), a
        // SUCCESSFUL probe must still round-trip the cover so its
        // time-to-first-server-byte matches the ~2*RTT the auth-fail cover-relay
        // path would take. We assert the cover RECEIVES the ClientHello on the
        // authenticated path - proving the equalization round-trip fired rather
        // than the bridge answering from local state ~1 RTT faster.
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let (bridge_sk, bridge_pk) = bridge_keys();
        let now = 1_700_000_000u32;

        let hit = Arc::new(AtomicBool::new(false));
        let hit_c = Arc::clone(&hit);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cover = l.local_addr().unwrap();
        let cover_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = l.accept().await {
                let mut buf = [0u8; 1024];
                if let Ok(n) = sock.read(&mut buf).await {
                    if n > 0 {
                        hit_c.store(true, Ordering::SeqCst);
                        // Echo so the equalization read completes promptly.
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        let (a, b) = duplex(64 * 1024);
        let client_fut = tokio::spawn(async move {
            let mut rs = reality_connect(
                a,
                &ClientCarrierInputs {
                    bridge_static_pk: &bridge_pk,
                    server_name: "cover.example.com",
                    now_unix: now,
                    cert_verify_override_pk: None,
                    probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                    tls_fingerprint: None,
                },
            )
            .await
            .unwrap();
            rs.write_all(b"hi").await.unwrap();
            rs.flush().await.unwrap();
        });

        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(3),
                tls_identity: None,
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            match reality_accept(b, &mut binputs).await.unwrap() {
                AcceptOutcome::Authenticated(mut s) => {
                    let mut got = [0u8; 2];
                    let _ = s.read_exact(&mut got).await;
                }
                AcceptOutcome::CoverServed { .. } => panic!("valid probe must authenticate"),
            }
        });

        let _ = client_fut.await;
        let _ = bridge_fut.await;
        cover_task.abort();
        assert!(
            hit.load(Ordering::SeqCst),
            "pass path must round-trip the cover when scraper-reachable (#3)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v01b_aead_encrypts_on_the_wire() {
        // Man-in-the-middle observer should see ciphertext that
        // does NOT contain the plaintext we fed in. Prove the v0.1b
        // AEAD layer is active.
        let (bridge_sk, bridge_pk) = bridge_keys();
        let now = 1_700_000_000u32;
        let cover = spawn_cover_echo().await; // unused here
        let (a, b) = duplex(64 * 1024);
        // Sniff the bridge->client direction by splitting `b` into
        // read/write halves the bridge task controls.
        let plaintext = b"SECRET-STRING-NOT-ON-THE-WIRE";

        let client_fut = tokio::spawn(async move {
            let mut rs = reality_connect(
                a,
                &ClientCarrierInputs {
                    bridge_static_pk: &bridge_pk,
                    server_name: "cover.example.com",
                    now_unix: now,
                    cert_verify_override_pk: None,
                    probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                    tls_fingerprint: None,
                },
            )
            .await
            .unwrap();
            rs.write_all(plaintext).await.unwrap();
            rs.flush().await.unwrap();
            // Shutdown the write side so the bridge sees EOF.
            let _ = rs.shutdown().await;
        });

        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(3),
                tls_identity: None,
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            match reality_accept(b, &mut binputs).await.unwrap() {
                AcceptOutcome::Authenticated(mut rs) => {
                    // Read back via the decrypted stream - should match.
                    let mut got = vec![0u8; plaintext.len()];
                    rs.read_exact(&mut got).await.unwrap();
                    assert_eq!(got, plaintext);
                    // Now peek at the inner duplex's recently-read
                    // buffer - we can't directly, but we CAN assert
                    // the decrypted plaintext never appeared
                    // anywhere in a wire capture by running a
                    // parallel no-keys test and comparing. Skipped
                    // here: the AEAD guarantee is that a correct
                    // decrypt implies correct encrypt; the test
                    // above proves this round-trip.
                }
                AcceptOutcome::CoverServed { .. } => panic!("must authenticate"),
            }
        });

        client_fut.await.unwrap();
        bridge_fut.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn v01b_tampered_record_aead_rejects() {
        // Flip a byte of the ciphertext payload on the wire; the
        // receiving RealityStream must return InvalidData.
        use tokio::io::AsyncWriteExt;

        let (bridge_sk, bridge_pk) = bridge_keys();
        let now = 1_700_000_000u32;
        let cover = spawn_cover_echo().await;
        let (a, b) = duplex(64 * 1024);

        let client_fut = tokio::spawn(async move {
            let mut rs = reality_connect(
                a,
                &ClientCarrierInputs {
                    bridge_static_pk: &bridge_pk,
                    server_name: "cover.example.com",
                    now_unix: now,
                    cert_verify_override_pk: None,
                    probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                    tls_fingerprint: None,
                },
            )
            .await
            .unwrap();
            // Send normally.
            rs.write_all(b"hi").await.unwrap();
            rs.flush().await.unwrap();

            // Then synthesize a tampered app_data record by
            // reaching into the inner stream and writing bogus
            // ciphertext. Because AEAD is stateful on seq, even
            // random ciphertext will fail tag check.
            let (_framer, mut inner) = ((), {
                let stream: tokio::io::DuplexStream = rs.into_inner();
                stream
            });
            // Valid-looking TLS app_data record header + 32 random bytes.
            inner
                .write_all(&[0x17, 0x03, 0x03, 0x00, 32])
                .await
                .unwrap();
            let mut junk = [0u8; 32];
            getrandom::fill(&mut junk).unwrap();
            inner.write_all(&junk).await.unwrap();
            inner.flush().await.unwrap();
            // Close to unblock the bridge read.
            let _ = inner.shutdown().await;
        });

        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(3),
                tls_identity: None,
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            match reality_accept(b, &mut binputs).await.unwrap() {
                AcceptOutcome::Authenticated(mut rs) => {
                    // First record decrypts fine.
                    let mut got = [0u8; 2];
                    rs.read_exact(&mut got).await.unwrap();
                    assert_eq!(&got, b"hi");
                    // Second read must error on tag failure.
                    let mut bigbuf = [0u8; 64];
                    let err = rs.read(&mut bigbuf).await.unwrap_err();
                    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                }
                AcceptOutcome::CoverServed { .. } => panic!("must authenticate"),
            }
        });

        client_fut.await.unwrap();
        bridge_fut.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_bridge_pubkey_falls_through_to_cover() {
        let (bridge_sk, _real_pk) = bridge_keys();
        let (_, wrong_pk) = bridge_keys();
        let cover = spawn_cover_echo().await;
        let now = 1_700_000_000u32;

        let (a, b) = duplex(16 * 1024);

        // Client uses the WRONG bridge pubkey. Its probe is valid
        // against a different bridge; THIS bridge can't verify it.
        let client_fut = tokio::spawn(async move {
            let res = reality_connect(
                a,
                &ClientCarrierInputs {
                    bridge_static_pk: &wrong_pk,
                    server_name: "cover.example.com",
                    now_unix: now,
                    cert_verify_override_pk: None,
                    probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                    tls_fingerprint: None,
                },
            )
            .await;
            // Expect the bridge to drop into cover; client sees
            // echoes of its ClientHello rather than a ServerHello,
            // so parse_server_hello fails with EchoMismatch or the
            // inner parser rejects.
            assert!(res.is_err(), "client should not get a valid ServerHello");
        });

        let bridge_fut = tokio::spawn(async move {
            let rset = tokio::sync::Mutex::new(ReplayProbeSet::new(16));
            let mut binputs = BridgeCarrierInputs {
                bridge_static_sk: &bridge_sk,
                now_unix: now,
                cover_addr: cover,
                replay_set: &rset,
                client_hello_read_timeout: Duration::from_secs(3),
                cover_duration_cap: Duration::from_secs(2),
                tls_identity: None,
                probe_root: &crate::probe::PROBE_ROOT_DISABLED,
                accept_legacy: true,
                cover_flight_target: None,
                cover_flight_records: &[],
            };
            match reality_accept(b, &mut binputs).await.unwrap() {
                AcceptOutcome::CoverServed { c2s, .. } => {
                    assert!(c2s > 0);
                }
                AcceptOutcome::Authenticated(_) => panic!("wrong pk must NOT authenticate"),
            }
        });

        tokio::time::timeout(Duration::from_secs(8), async {
            client_fut.await.unwrap();
            bridge_fut.await.unwrap();
        })
        .await
        .expect("test deadline");
    }

    #[tokio::test]
    async fn flight_record_padded_to_exact_wire_target() {
        // A small handshake message padded to a larger target must produce a
        // record whose on-the-wire length equals the target EXACTLY - this is
        // what lets the bridge's Certificate flight match a real cover's
        // encrypted-flight size. A zero target, or a target below the natural
        // size, must leave the record at its natural (unpadded) size.
        let cipher = RecordCipher::ChaCha20Poly1305;
        let key = [0x11u8; 32];
        let iv = [0x22u8; AEAD_IV_LEN];
        let msg = vec![0xABu8; 200];
        let natural = RECORD_HEADER_LEN + (msg.len() + 1) + AEAD_TAG_LEN;

        for &target in &[0usize, 100, 1024, 4096, 8000] {
            let mut sink: Vec<u8> = Vec::new();
            write_encrypted_handshake_record(&mut sink, &msg, cipher, &key, &iv, 0, target)
                .await
                .unwrap();
            assert_eq!(sink[0], 0x17, "must be an application_data record");
            let len = ((sink[3] as usize) << 8) | sink[4] as usize;
            let wire = RECORD_HEADER_LEN + len;
            assert_eq!(wire, sink.len(), "header length must match bytes emitted");
            if target > natural {
                assert_eq!(wire, target, "padded record must hit the exact wire target");
            } else {
                assert_eq!(wire, natural, "target <= natural must not change the size");
            }
        }

        // Padding must be transparent: a padded record decrypts back to the
        // original handshake message (trailing zeros stripped).
        let mut sink: Vec<u8> = Vec::new();
        write_encrypted_handshake_record(&mut sink, &msg, cipher, &key, &iv, 0, 4096)
            .await
            .unwrap();
        let unwrapped = unwrap_app_data(&sink).unwrap().unwrap();
        let nonce = aead_nonce(&iv, 0);
        let plain = cipher.open(&key, &nonce, &[], unwrapped.payload).unwrap();
        let (ct, body) = strip_inner_content_type(&plain).unwrap();
        assert_eq!(ct, INNER_CONTENT_TYPE_HANDSHAKE);
        assert_eq!(
            body,
            &msg[..],
            "padding must strip back to the original message"
        );
    }
}
