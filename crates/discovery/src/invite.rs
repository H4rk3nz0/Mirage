//! `MasterInvite` wire format.
//!
//! The invite is the single OOB-distributed bundle that
//! lets a fresh client reach its first bridge:
//!
//! - `operator_ed25519_pk` - trust anchor; the client will accept no
//!   announcement or revocation not signed by this key.
//! - `shared_salt` - secret input to the info-hash / cipher-key
//!   derivation (spec §4). Held in `Zeroizing` in memory.
//! - `issued_at` / `expires_at` - invite validity window.
//! - `channel_hints` - UTF-8 JSON with recommended discovery channels
//!   (usually a list of Nostr relay URLs).
//! - `bootstrap_tokens` - one-shot capability tokens (spec §6.1) a
//!   client presents on its first handshake.
//! - Optional `bootstrap_announcement` (§8.6) - lets a client skip the
//!   discovery-channel query on the very first connection; a discovery
//!   sub is only run once the first tunnel is established.
//!
//! ## Text form
//!
//! Distribution is typically via URL, QR code, or secure messenger.
//! The canonical text form is `base64-url(binary-form)` without padding.
//! A `mirage://` URL prefix is the recommended UX on top of this.
//!
//! ## Threat-model notes
//!
//! - The invite is a **shared secret** (the `shared_salt`) plus a **trust
//!   anchor** (the operator pubkey). Anyone with the invite can decrypt
//!   discovery announcements for that operator; anyone with just the
//!   pubkey cannot. OOB distribution integrity is therefore critical -
//!   a corrupted channel that swaps the operator pubkey routes the user
//!   to an attacker-controlled bridge mesh (A19 in ROADMAP).
//! - `expires_at` enforcement is a client obligation; a client with a
//!   broken clock can silently accept an expired (possibly revoked)
//!   invite. Document this in operator runbooks.
//! - The spec (§3.3) defines rotation: overlapping old+new invites for a
//!   grace window. Implementations MUST accept multiple valid invites
//!   simultaneously so users can migrate without an outage.

use mirage_crypto::zeroize::Zeroizing;
use zeroize::Zeroize;

use crate::error::DiscoveryError;
use crate::token::{CapabilityToken, TOKEN_LEN};
use crate::token_fs::{FsCapabilityToken, FS_TOKEN_LEN};
use crate::wire::{Announcement, ED25519_PK_LEN, MAGIC};

/// Doc-type byte identifying a `MasterInvite` (spec §3.1).
pub const DOC_TYPE_INVITE: u8 = 0x10;

/// Invite wire version byte. Only `0x01` is accepted in v0.1.
pub const INVITE_VERSION_V0_1: u8 = 0x01;

/// Byte length of one bootstrap token on the wire.
///
/// Spec §6.1 v0.1 describes a 64-byte form (32 B token_id + 32 B
/// operator_sig). The implemented session-layer verifier
/// ([`crate::token::TokenVerifier`]) consumes the richer 136-byte
/// `CapabilityToken` form (token_id + bridge_pin + expires_at +
/// 64 B Ed25519 sig). The invite carries that richer form so a
/// freshly-unbundled client can present the token on its first
/// handshake without any conversion step. The spec text is tracked
/// as a minor drift item and will be corrected in the next spec rev.
pub const BOOTSTRAP_TOKEN_LEN: usize = TOKEN_LEN;

// TLV extensions (RFC-style forward-compatible extension block at the
// tail of the invite). Each extension = `[u8 type][u16 len BE][value]`.
// New clients learn new extensions; old clients skip unknown types.

/// Extension type: 33-byte compressed-SEC1 **ECDSA P-256** public key the
/// client uses to verify Reality-carrier `CertificateVerify` signatures
/// (scheme `ecdsa_secp256r1_sha256`, matching real browsers) when the bridge is
/// operating in `pinned` or `cover_mimicry` TLS mode. If absent, the client
/// extracts the CertVerify pubkey from the TLS cert's SPKI (v0.1c default,
/// ephemeral TLS).
pub const INVITE_EXT_TLS_CERT_VERIFY_PK: u8 = 0x01;

/// Extension type: 32-byte per-invite **claim id** for one-time
/// redemption (v0.1e). Clients send this id through the bridge's
/// `_mirage_claim._internal` magic hostname on first connection;
/// the bridge records it as claimed and subsequent claim attempts
/// with the same id at that bridge fail. The bridge may
/// piggyback a batch of session refresh tokens in the response
/// so the client never needs to spend its remaining bootstrap
/// tokens on the same bridge.
///
/// A leaked invite's attack window is narrowed: once the
/// legitimate user has redeemed at a bridge, an attacker cannot
/// re-redeem at that bridge (they'd still be able to consume
/// bootstrap tokens, but the redemption itself signals leak -
/// operators can alert on duplicate-claim attempts).
pub const INVITE_EXT_CLAIM_ID: u8 = 0x02;

/// Extension type: per-epoch port hopping parameters (A35).
///
/// 4-byte body: `[port_base u16 BE][port_range u16 BE]`.
///
/// When present, both bridge and client MUST compute the current-epoch
/// and next-epoch derived ports via [`mirage_discovery::derive::derive_port`]
/// using the invite's `shared_salt`. The client tries the derived-port
/// addresses before falling back to the static `bootstrap_announcement`
/// endpoint. The bridge additionally binds on those derived ports via
/// `derived_port_base` / `derived_port_range` config fields.
///
/// An invite lacking this extension behaves like the v0.1 static-endpoint
/// baseline (old bridges / old clients are unaffected).
pub const INVITE_EXT_PORT_HOP: u8 = 0x05;

/// Extension type: 32-byte secret QUIC-obfuscation key.
///
/// When present, the client derives its hysteria2 / h3 obfs key from this
/// per-bridge random secret instead of the pubkey-derived default, so a censor
/// must possess an actual invite (not merely the scraped bridge pubkey) to
/// de-obfuscate the QUIC traffic. The bridge is configured with the same secret
/// (`quic_obfs_secret_hex`). Absent = pubkey-derived default (backward-compatible).
pub const INVITE_EXT_QUIC_OBFS_SECRET: u8 = 0x06;

/// Extension type: forward-secret rendezvous flag (presence = enabled,
/// zero-length value). When present, the client + operator derive per-epoch
/// discovery keys from the one-way [`crate::ratchet`] chain anchored at the
/// invite's issue epoch, so a party that discards the salt (the operator
/// publisher) cannot recompute PAST rendezvous keys. Absent = baseline
/// direct-from-salt derivation (backward-compatible).
pub const INVITE_EXT_FORWARD_SECRET_RENDEZVOUS: u8 = 0x07;

/// Extension type: inline forward-secure bootstrap token(s).
///
/// Body = `count (u8) || count x 248-byte FsCapabilityToken::encode()`. These
/// are the forward-secure analogue of the fixed-section `bootstrap_tokens`
/// (which carry the 136-byte legacy [`CapabilityToken`]). A client that
/// understands this extension presents an FS token via `HandshakeInitiator::new_fs`;
/// an older client silently skips it (the `_ =>` decode arm) and falls back to
/// the legacy `bootstrap_tokens`, so dual-minted invites are fully backward
/// compatible. FS tokens are carried here - NOT in `bootstrap_tokens` - because
/// that fixed section is `count || Nx136B` with no per-record length and a
/// 248-byte record would corrupt its offset math.
///
/// Note the naming: [`INVITE_EXT_FORWARD_SECRET_RENDEZVOUS`] (0x07) is about the
/// discovery-key ratchet, a *different* forward-secrecy mechanism.
pub const INVITE_EXT_FS_BOOTSTRAP_TOKENS: u8 = 0x08;

/// Extension type: 32-byte Reality anti-probe root secret.
///
/// The Reality carrier's auth probe MACs against the X25519 ECDH of a client
/// ephemeral and the **bridge's static key** - whose PUBLIC half rides in the
/// signed [`Announcement`](crate::wire::Announcement) on public discovery
/// channels. A censor who scrapes one announcement can therefore forge a valid
/// probe and permanently confirm the IP is a Mirage bridge. When present, the
/// client folds a per-epoch secret derived from THIS per-bridge root into the
/// probe MAC, so forging additionally requires the (invite-only) root - closing
/// pubkey-only enumeration. The bridge re-derives the same root from its static
/// secret (`mirage_transport_reality::derive_probe_root`); the invite-mint holds
/// that secret at keygen time and embeds the derived root here. Absent = legacy
/// probe (backward-compatible; the bridge still accepts it while `accept_legacy`
/// is on). Exactly mirrors [`INVITE_EXT_QUIC_OBFS_SECRET`]'s pubkey-vs-invite
/// escalation for the QUIC obfs key.
pub const INVITE_EXT_REALITY_PROBE_ROOT: u8 = 0x09;

/// Extension type: a CDN's ECHConfigList (variable-length raw bytes, e.g. the value
/// from the front's DNS HTTPS record). When present, the client uses ECH (RFC 9180) on
/// the `carrier_tls` handshake, so the real inner SNI is encrypted and a censor sees only
/// the CDN's outer public name. Absent = no ECH (backward-compatible). Bounded by
/// [`MAX_ECH_CONFIG_BYTES`].
pub const INVITE_EXT_ECH_CONFIG: u8 = 0x0a;

/// Sanity cap on the ECHConfigList carried in an invite. Real lists are ~100-300 bytes;
/// this bounds a forged invite's parse/memory while staying well inside a plausible size.
pub const MAX_ECH_CONFIG_BYTES: usize = 1024;

/// Extension type: 32-byte Ed25519 mother-key public key.
/// When present, clients MAY
/// accept rotation announcements (`doc_type = 0x41`) signed by this
/// key as authoritative for replacing the active operator key.
/// Operators store the mother SK offline and use it only for
/// emergency rotation
pub const INVITE_EXT_MOTHER_ED25519_PK: u8 = 0x03;

/// Extension type: 1-byte operator signing policy.
/// When absent, defaults to
/// `SIGNING_POLICY_SINGLE_KEY` for backward compatibility.
/// Values:
///   - `0x00` = single-key (v0.1 baseline; single operator key signs)
///   - `0x01` = mother-pinned (single operator key + mother key
///     pinned for rotation; SHIPPED in v0.1t)
///   - `0x02` = k-of-n threshold (v0.2; not yet implemented; clients
///     receiving this value MUST refuse to use the invite until
///     the v0.2 protocol ships)
pub const INVITE_EXT_SIGNING_POLICY: u8 = 0x04;

/// Signing-policy values (1-byte values stored in
/// `INVITE_EXT_SIGNING_POLICY`).
pub const SIGNING_POLICY_SINGLE_KEY: u8 = 0x00;
/// See [`SIGNING_POLICY_SINGLE_KEY`].
pub const SIGNING_POLICY_MOTHER_PINNED: u8 = 0x01;
/// See [`SIGNING_POLICY_SINGLE_KEY`]. Not yet implemented in v0.1t;
/// reserved for v0.2 threshold-signing protocol.
pub const SIGNING_POLICY_THRESHOLD_KOFN: u8 = 0x02;

/// Maximum total bytes the extension block can occupy. Cap defends
/// against malicious invites whose extension block is sized to
/// exhaust memory during decode. Raised from 4 KiB to 8 KiB when the
/// forward-secure bootstrap-token extension (0x08) landed: a full batch of
/// 16 FS tokens is ~4 KiB on its own and must coexist with the other
/// extensions inside this cap.
pub const MAX_INVITE_EXT_BYTES: usize = 8 * 1024;

/// Hard cap on the number of bootstrap tokens in a single invite.
/// Spec §6.1 fixes the range `0..=16`. Anything beyond is rejected.
pub const MAX_BOOTSTRAP_TOKENS: usize = 16;

/// Hard cap on the `channel_hints` length. Guards against an invite
/// forged to drag a client through megabytes of JSON on parse.
pub const MAX_CHANNEL_HINTS_BYTES: usize = 8 * 1024;

/// Total invite-size ceiling. After the fixed prefix, bootstrap tokens,
/// channel hints, and optional bootstrap announcement, the whole blob
/// stays under this cap. Useful for URL / QR-code sizing decisions.
pub const MAX_INVITE_BYTES: usize =
    8 * 1024 + 1024 + 16 * BOOTSTRAP_TOKEN_LEN + 16 * FS_TOKEN_LEN + 1024;

/// A bootstrap token carried by a [`MasterInvite`]. Thin wrapper over
/// [`CapabilityToken`] for type clarity at the invite boundary.
pub type BootstrapToken = CapabilityToken;

/// A `master_invite`.
///
/// `shared_salt` is secret and carried in `Zeroizing<[u8; 32]>`; dropping
/// the invite zeroes the salt. `operator_ed25519_pk`, timestamps,
/// channel hints, and bootstrap material are public per-invite metadata
/// and held as plain fields.
pub struct MasterInvite {
    /// Operator's long-term Ed25519 identity (spec §3.1).
    pub operator_ed25519_pk: [u8; ED25519_PK_LEN],
    /// Per-invite shared salt. Secret; zeroed on drop.
    pub shared_salt: Zeroizing<[u8; 32]>,
    /// Unix seconds when this invite was issued.
    pub issued_at: u64,
    /// Unix seconds when this invite stops being valid.
    pub expires_at: u64,
    /// UTF-8 JSON with recommended discovery channels (spec §8.3). Kept
    /// as bytes so parsing is the caller's concern; we only enforce
    /// size and UTF-8 at decode.
    pub channel_hints: Vec<u8>,
    /// Bootstrap tokens for first-connection capability presentation.
    pub bootstrap_tokens: Vec<BootstrapToken>,
    /// Optional in-line bootstrap announcement (§8.6). Lets a fresh
    /// client connect without a discovery-channel query.
    pub bootstrap_announcement: Option<Announcement>,
    /// If `Some`, the Ed25519 public key the client uses to verify
    /// the Reality carrier's `CertificateVerify` signature. Used
    /// when the bridge runs in `pinned` or `cover_mimicry` TLS
    /// mode - the real cert's SPKI (cover's pubkey) would not
    /// verify against any key the bridge controls, so we publish
    /// the bridge's TLS signing pubkey in the invite instead.
    ///
    /// `None` (default) means "use the cert's SPKI", which is
    /// correct for `ephemeral` mode where the bridge mints a
    /// fresh cert-and-key pair per session.
    pub tls_cert_verify_pk: Option<[u8; 33]>,
    /// If `Some`, the 32-byte per-invite claim id for one-time
    /// redemption (v0.1e). The client sends this id through the
    /// bridge's `_mirage_claim._internal` magic hostname on first
    /// connection so the bridge can mark the invite as claimed at
    /// that bridge. `None` means "no per-invite redemption" -
    /// bootstrap tokens work as usual with no extra gating.
    pub claim_id: Option<[u8; 32]>,
    /// Optional 32-byte Ed25519 mother key.
    /// When present, the client
    /// considers rotation announcements signed by this key as
    /// authoritative for replacing the active operator key. The
    /// mother key MUST be stored offline; the operator's
    /// long-running publishing host has no need to hold the SK.
    pub mother_ed25519_pk: Option<[u8; 32]>,
    /// Optional signing-policy byte (`SIGNING_POLICY_*`). When
    /// `None` (i.e., the extension was absent on the wire), clients
    /// MUST treat the policy as
    /// [`SIGNING_POLICY_SINGLE_KEY`] for backward compatibility
    /// with v0.1 baseline invites.
    pub signing_policy: Option<u8>,
    /// Optional port-hopping parameters (A35 / `INVITE_EXT_PORT_HOP`).
    ///
    /// When `Some((port_base, port_range))`, both the bridge and client
    /// derive an epoch-rolling port from `shared_salt` and these bounds.
    /// The client tries the current-epoch and next-epoch derived addresses
    /// before falling back to the static bootstrap endpoint.
    pub port_hop: Option<(u16, u16)>,
    /// Optional 32-byte secret QUIC-obfuscation key (`INVITE_EXT_QUIC_OBFS_SECRET`).
    ///
    /// The hysteria2 / h3 transports obfuscate their QUIC datagrams by default
    /// with a key both sides derive from the bridge's *public* key
    /// (`mirage_quic_obfs::default_obfs_key`) - which defeats generic
    /// QUIC-classifying DPI but is NOT secret against an adversary who scrapes
    /// the bridge pubkey from a discovery announcement. When `Some`, the client
    /// instead derives the obfs key from this per-bridge random secret (carried
    /// only inside the confidential invite), raising the bar to "must possess an
    /// actual invite" to de-obfuscate. The bridge is configured with the same
    /// secret (`quic_obfs_secret_hex`). `None` = fall back to the pubkey-derived
    /// default (backward-compatible with pre-0.1 invites).
    pub obfs_secret: Option<[u8; 32]>,
    /// Optional 32-byte Reality anti-probe root (`INVITE_EXT_REALITY_PROBE_ROOT`).
    ///
    /// When `Some`, the Reality carrier binds a per-epoch secret derived from
    /// this root into the auth probe, so a censor who scraped only the public
    /// announcement (which carries `bridge_x25519_pk`) cannot forge a probe. The
    /// bridge re-derives the SAME value from its static secret via
    /// `mirage_transport_reality::derive_probe_root`. `None` = legacy probe
    /// (backward-compatible with pre-extension invites). See
    /// [`INVITE_EXT_REALITY_PROBE_ROOT`].
    pub probe_root: Option<[u8; 32]>,
    /// A CDN's ECHConfigList (`INVITE_EXT_ECH_CONFIG`). When set, the client uses ECH on
    /// the `carrier_tls` (meek/DoH/WS) handshake to encrypt the inner SNI. `None` = no ECH.
    pub ech_config_list: Option<Vec<u8>>,
    /// Forward-secret rendezvous flag (`INVITE_EXT_FORWARD_SECRET_RENDEZVOUS`).
    /// When `true`, the client + operator derive per-epoch discovery keys from
    /// the one-way [`crate::ratchet`] chain anchored at [`Self::issued_at`]'s
    /// epoch (see [`crate::pipeline`]'s `with_forward_secret`), so a party that
    /// discards the salt (the operator publisher) cannot recompute past
    /// rendezvous keys. `false` (default) = baseline direct-from-salt derivation.
    pub forward_secret_rendezvous: bool,
    /// Forward-secure bootstrap tokens (`INVITE_EXT_FS_BOOTSTRAP_TOKENS`).
    ///
    /// The forward-secure analogue of [`Self::bootstrap_tokens`]: each is signed
    /// by an epoch subkey certified by the operator root, so a compromise of the
    /// online issuer cannot forge tokens for a retired epoch. When non-empty a
    /// capable client presents one of these via `HandshakeInitiator::new_fs`
    /// instead of a legacy token. Empty (default) = legacy-only invite, and old
    /// clients ignore this extension entirely (backward compatible). Capped at
    /// [`MAX_BOOTSTRAP_TOKENS`].
    pub fs_bootstrap_tokens: Vec<FsCapabilityToken>,
}

impl MasterInvite {
    /// Construct a new invite. Convenience wrapper around the public
    /// fields that also validates `expires_at > issued_at` and the size
    /// caps before the caller ever tries to encode.
    pub fn new(
        operator_ed25519_pk: [u8; ED25519_PK_LEN],
        shared_salt: [u8; 32],
        issued_at: u64,
        expires_at: u64,
        channel_hints: Vec<u8>,
        bootstrap_tokens: Vec<BootstrapToken>,
        bootstrap_announcement: Option<Announcement>,
    ) -> Result<Self, DiscoveryError> {
        Self::new_with_extensions(
            operator_ed25519_pk,
            shared_salt,
            issued_at,
            expires_at,
            channel_hints,
            bootstrap_tokens,
            bootstrap_announcement,
            None,
            None,
            None,
            None,
            None,
        )
    }

    /// Construct an invite with TLV extensions. `tls_cert_verify_pk`
    /// overrides the cert-SPKI-based CertVerify check when present;
    /// `claim_id` opts the invite into per-user redemption (v0.1e);
    /// `port_hop` enables epoch-rolling port derivation (A35).
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_extensions(
        operator_ed25519_pk: [u8; ED25519_PK_LEN],
        shared_salt: [u8; 32],
        issued_at: u64,
        expires_at: u64,
        channel_hints: Vec<u8>,
        bootstrap_tokens: Vec<BootstrapToken>,
        bootstrap_announcement: Option<Announcement>,
        tls_cert_verify_pk: Option<[u8; 33]>,
        claim_id: Option<[u8; 32]>,
        mother_ed25519_pk: Option<[u8; 32]>,
        signing_policy: Option<u8>,
        port_hop: Option<(u16, u16)>,
    ) -> Result<Self, DiscoveryError> {
        if expires_at <= issued_at {
            return Err(DiscoveryError::Wire("invite: expires_at <= issued_at"));
        }
        if channel_hints.len() > MAX_CHANNEL_HINTS_BYTES {
            return Err(DiscoveryError::Wire("invite: channel_hints exceed cap"));
        }
        if std::str::from_utf8(&channel_hints).is_err() {
            return Err(DiscoveryError::Wire("invite: channel_hints not UTF-8"));
        }
        if bootstrap_tokens.len() > MAX_BOOTSTRAP_TOKENS {
            return Err(DiscoveryError::Wire("invite: too many bootstrap tokens"));
        }
        // Policy consistency: a `mother_ed25519_pk` extension implies
        // policy MUST be `SIGNING_POLICY_MOTHER_PINNED` (or a future
        // policy that subsumes mother-pinning). Catch the inconsistent
        // pair at construction so a misconfigured operator can't ship
        // an invite that nominally pins a mother key but declares
        // single-key policy.
        if let (Some(_), Some(p)) = (mother_ed25519_pk, signing_policy) {
            if p == SIGNING_POLICY_SINGLE_KEY {
                return Err(DiscoveryError::Wire(
                    "invite: mother_pk set with single-key policy",
                ));
            }
        }
        // Reject k-of-n policy in v0.1t (spec scaffold only; no
        // verification path implemented yet).
        if signing_policy == Some(SIGNING_POLICY_THRESHOLD_KOFN) {
            return Err(DiscoveryError::Wire(
                "invite: threshold k-of-n policy is v0.2; refuse to mint",
            ));
        }
        if let Some((base, range)) = port_hop {
            use crate::derive::DERIVED_PORT_MIN;
            if base < DERIVED_PORT_MIN {
                return Err(DiscoveryError::Wire(
                    "invite: port_hop.port_base < 1024 (privileged port)",
                ));
            }
            if range == 0 {
                return Err(DiscoveryError::Wire(
                    "invite: port_hop.port_range must be > 0",
                ));
            }
            if (base as u32) + (range as u32) > 65536 {
                return Err(DiscoveryError::Wire(
                    "invite: port_hop.port_base + port_range overflows u16",
                ));
            }
        }
        Ok(Self {
            operator_ed25519_pk,
            shared_salt: Zeroizing::new(shared_salt),
            issued_at,
            expires_at,
            channel_hints,
            bootstrap_tokens,
            bootstrap_announcement,
            tls_cert_verify_pk,
            claim_id,
            mother_ed25519_pk,
            signing_policy,
            port_hop,
            obfs_secret: None,
            probe_root: None,
            ech_config_list: None,
            forward_secret_rendezvous: false,
            fs_bootstrap_tokens: Vec::new(),
        })
    }

    /// Attach a secret QUIC-obfuscation key (`INVITE_EXT_QUIC_OBFS_SECRET`).
    /// The client will derive its hysteria2 / h3 obfs key from this per-bridge
    /// secret instead of the pubkey-derived default; the bridge must be
    /// configured with the same secret via `quic_obfs_secret_hex`.
    #[must_use]
    pub fn with_obfs_secret(mut self, secret: [u8; 32]) -> Self {
        self.obfs_secret = Some(secret);
        self
    }

    /// Attach a Reality anti-probe root (`INVITE_EXT_REALITY_PROBE_ROOT`).
    /// The client folds a per-epoch secret derived from this root into the
    /// Reality auth probe; the bridge re-derives the same root from its static
    /// secret via `mirage_transport_reality::derive_probe_root`, so operators
    /// provide nothing extra.
    #[must_use]
    pub fn with_probe_root(mut self, root: [u8; 32]) -> Self {
        self.probe_root = Some(root);
        self
    }

    /// Attach a CDN's ECHConfigList (`INVITE_EXT_ECH_CONFIG`) so invited clients use ECH
    /// on the `carrier_tls` handshake. Silently ignored if longer than
    /// [`MAX_ECH_CONFIG_BYTES`] (a real list is far smaller).
    #[must_use]
    pub fn with_ech_config(mut self, ech_config_list: Vec<u8>) -> Self {
        if ech_config_list.len() <= MAX_ECH_CONFIG_BYTES {
            self.ech_config_list = Some(ech_config_list);
        }
        self
    }

    /// Enable forward-secret rendezvous (`INVITE_EXT_FORWARD_SECRET_RENDEZVOUS`).
    /// The client + operator anchor a one-way discovery-key ratchet at this
    /// invite's issue epoch. The operator publisher must run with the matching
    /// `--forward-secret` mode so it discards the salt and gains producer FS.
    #[must_use]
    pub fn with_forward_secret_rendezvous(mut self) -> Self {
        self.forward_secret_rendezvous = true;
        self
    }

    /// Attach forward-secure bootstrap tokens (`INVITE_EXT_FS_BOOTSTRAP_TOKENS`).
    ///
    /// A capable client presents one of these via `HandshakeInitiator::new_fs`;
    /// older clients ignore the extension. Excess beyond [`MAX_BOOTSTRAP_TOKENS`]
    /// is dropped so the invite always round-trips through [`Self::decode`]
    /// (which rejects an over-cap extension).
    #[must_use]
    pub fn with_fs_bootstrap_tokens(mut self, mut toks: Vec<FsCapabilityToken>) -> Self {
        toks.truncate(MAX_BOOTSTRAP_TOKENS);
        self.fs_bootstrap_tokens = toks;
        self
    }

    /// Epoch the forward-secret rendezvous ratchet is anchored at: the invite's
    /// issue epoch. Both the operator publisher and the client use this anchor.
    pub fn fs_anchor_epoch(&self) -> u64 {
        crate::derive::epoch_for_time(self.issued_at)
    }

    /// Effective signing policy (the explicit byte if set, or the
    /// v0.1 default of single-key). Centralises the "missing
    /// extension = single-key" rule for callers.
    pub fn effective_signing_policy(&self) -> u8 {
        self.signing_policy.unwrap_or(SIGNING_POLICY_SINGLE_KEY)
    }

    /// True iff `now_unix` is inside `[issued_at, expires_at)`.
    pub fn is_valid_at(&self, now_unix: u64) -> bool {
        now_unix >= self.issued_at && now_unix < self.expires_at
    }

    /// Serialize to binary wire form (spec §3.1 + §8.6).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.channel_hints.len());
        out.extend_from_slice(&MAGIC);
        out.push(DOC_TYPE_INVITE);
        out.push(INVITE_VERSION_V0_1);
        out.extend_from_slice(&self.operator_ed25519_pk);
        out.extend_from_slice(self.shared_salt.as_ref());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&(self.channel_hints.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.channel_hints);
        out.push(self.bootstrap_tokens.len() as u8);
        for t in &self.bootstrap_tokens {
            out.extend_from_slice(&t.encode());
        }
        match &self.bootstrap_announcement {
            Some(ann) => {
                out.push(1);
                out.extend_from_slice(&ann.encode());
            }
            None => {
                out.push(0);
            }
        }
        // TLV extension block (variable length, optional).
        if let Some(pk) = &self.tls_cert_verify_pk {
            out.push(INVITE_EXT_TLS_CERT_VERIFY_PK);
            out.extend_from_slice(&(33u16).to_be_bytes());
            out.extend_from_slice(pk);
        }
        if let Some(cid) = &self.claim_id {
            out.push(INVITE_EXT_CLAIM_ID);
            out.extend_from_slice(&(32u16).to_be_bytes());
            out.extend_from_slice(cid);
        }
        if let Some(mpk) = &self.mother_ed25519_pk {
            out.push(INVITE_EXT_MOTHER_ED25519_PK);
            out.extend_from_slice(&(32u16).to_be_bytes());
            out.extend_from_slice(mpk);
        }
        if let Some(p) = &self.signing_policy {
            out.push(INVITE_EXT_SIGNING_POLICY);
            out.extend_from_slice(&(1u16).to_be_bytes());
            out.push(*p);
        }
        if let Some((base, range)) = self.port_hop {
            out.push(INVITE_EXT_PORT_HOP);
            out.extend_from_slice(&(4u16).to_be_bytes());
            out.extend_from_slice(&base.to_be_bytes());
            out.extend_from_slice(&range.to_be_bytes());
        }
        if let Some(secret) = &self.obfs_secret {
            out.push(INVITE_EXT_QUIC_OBFS_SECRET);
            out.extend_from_slice(&(32u16).to_be_bytes());
            out.extend_from_slice(secret);
        }
        if let Some(root) = &self.probe_root {
            out.push(INVITE_EXT_REALITY_PROBE_ROOT);
            out.extend_from_slice(&(32u16).to_be_bytes());
            out.extend_from_slice(root);
        }
        if let Some(list) = &self.ech_config_list {
            if list.len() <= MAX_ECH_CONFIG_BYTES {
                out.push(INVITE_EXT_ECH_CONFIG);
                out.extend_from_slice(&(list.len() as u16).to_be_bytes());
                out.extend_from_slice(list);
            }
        }
        if self.forward_secret_rendezvous {
            out.push(INVITE_EXT_FORWARD_SECRET_RENDEZVOUS);
            out.extend_from_slice(&(0u16).to_be_bytes());
        }
        if !self.fs_bootstrap_tokens.is_empty() {
            // Body = count(1) || count x 248-byte FS token. Capped at
            // MAX_BOOTSTRAP_TOKENS by the builder, so count fits in a u8 and the
            // body stays inside MAX_INVITE_EXT_BYTES.
            let count = self.fs_bootstrap_tokens.len().min(MAX_BOOTSTRAP_TOKENS);
            let body_len = 1 + count * FS_TOKEN_LEN;
            out.push(INVITE_EXT_FS_BOOTSTRAP_TOKENS);
            out.extend_from_slice(&(body_len as u16).to_be_bytes());
            out.push(count as u8);
            for t in self.fs_bootstrap_tokens.iter().take(count) {
                out.extend_from_slice(&t.encode());
            }
        }
        out
    }

    /// Parse from binary wire form.
    ///
    /// Does NOT verify the bootstrap announcement's signature - callers
    /// do that via [`Announcement::verify`] against `operator_ed25519_pk`
    /// once they have the parsed invite.
    pub fn decode(buf: &[u8]) -> Result<Self, DiscoveryError> {
        if buf.len() > MAX_INVITE_BYTES {
            return Err(DiscoveryError::Wire("invite: over total-size cap"));
        }
        // Fixed-prefix length: 2(magic) + 1(doc) + 1(ver) + 32(pk) +
        // 32(salt) + 8(issued) + 8(expires) + 2(hints_len) = 86.
        if buf.len() < 86 {
            return Err(DiscoveryError::Wire("invite: too short"));
        }
        if buf[0..2] != MAGIC {
            return Err(DiscoveryError::Wire("invite: bad magic"));
        }
        if buf[2] != DOC_TYPE_INVITE {
            return Err(DiscoveryError::Wire("invite: wrong doc_type"));
        }
        if buf[3] != INVITE_VERSION_V0_1 {
            return Err(DiscoveryError::Wire("invite: unsupported version"));
        }
        let mut operator_ed25519_pk = [0u8; ED25519_PK_LEN];
        operator_ed25519_pk.copy_from_slice(&buf[4..36]);
        let mut shared_salt_raw = [0u8; 32];
        shared_salt_raw.copy_from_slice(&buf[36..68]);
        let issued_at = u64::from_be_bytes(buf[68..76].try_into().unwrap());
        let expires_at = u64::from_be_bytes(buf[76..84].try_into().unwrap());
        if expires_at <= issued_at {
            shared_salt_raw.zeroize();
            return Err(DiscoveryError::Wire("invite: expires_at <= issued_at"));
        }
        let hints_len = u16::from_be_bytes(buf[84..86].try_into().unwrap()) as usize;
        if hints_len > MAX_CHANNEL_HINTS_BYTES {
            shared_salt_raw.zeroize();
            return Err(DiscoveryError::Wire("invite: channel_hints exceed cap"));
        }
        if buf.len() < 86 + hints_len + 1 {
            shared_salt_raw.zeroize();
            return Err(DiscoveryError::Wire(
                "invite: truncated before bootstrap_count",
            ));
        }
        let hints_start = 86usize;
        let hints_end = hints_start + hints_len;
        let channel_hints = buf[hints_start..hints_end].to_vec();
        if std::str::from_utf8(&channel_hints).is_err() {
            shared_salt_raw.zeroize();
            return Err(DiscoveryError::Wire("invite: channel_hints not UTF-8"));
        }
        let bootstrap_count = buf[hints_end] as usize;
        if bootstrap_count > MAX_BOOTSTRAP_TOKENS {
            shared_salt_raw.zeroize();
            return Err(DiscoveryError::Wire("invite: bootstrap_count > 16"));
        }
        let tokens_start = hints_end + 1;
        let tokens_end = tokens_start + bootstrap_count * BOOTSTRAP_TOKEN_LEN;
        if buf.len() < tokens_end + 1 {
            shared_salt_raw.zeroize();
            return Err(DiscoveryError::Wire("invite: truncated bootstrap tokens"));
        }
        let mut bootstrap_tokens = Vec::with_capacity(bootstrap_count);
        for i in 0..bootstrap_count {
            let s = tokens_start + i * BOOTSTRAP_TOKEN_LEN;
            let e = s + BOOTSTRAP_TOKEN_LEN;
            bootstrap_tokens.push(CapabilityToken::decode(&buf[s..e])?);
        }
        let has_bootstrap_announcement = buf[tokens_end];
        let (bootstrap_announcement, ext_start) = match has_bootstrap_announcement {
            0 => (None, tokens_end + 1),
            1 => {
                let ann_start = tokens_end + 1;
                if ann_start >= buf.len() {
                    shared_salt_raw.zeroize();
                    return Err(DiscoveryError::Wire("invite: flag set but no announcement"));
                }
                let (ann, consumed) = match Announcement::decode_prefix(&buf[ann_start..]) {
                    Ok(v) => v,
                    Err(e) => {
                        shared_salt_raw.zeroize();
                        return Err(e);
                    }
                };
                (Some(ann), ann_start + consumed)
            }
            _ => {
                shared_salt_raw.zeroize();
                return Err(DiscoveryError::Wire(
                    "invite: has_bootstrap_announcement not 0/1",
                ));
            }
        };

        // Parse TLV extensions (may be zero-length).
        let ext_bytes = match buf.get(ext_start..) {
            Some(b) => b,
            None => {
                shared_salt_raw.zeroize();
                return Err(DiscoveryError::Wire("invite: truncated extensions"));
            }
        };
        if ext_bytes.len() > MAX_INVITE_EXT_BYTES {
            shared_salt_raw.zeroize();
            return Err(DiscoveryError::Wire("invite: extensions over cap"));
        }
        let mut tls_cert_verify_pk: Option<[u8; 33]> = None;
        let mut claim_id: Option<[u8; 32]> = None;
        let mut mother_ed25519_pk: Option<[u8; 32]> = None;
        let mut signing_policy: Option<u8> = None;
        let mut port_hop: Option<(u16, u16)> = None;
        let mut obfs_secret: Option<[u8; 32]> = None;
        let mut probe_root: Option<[u8; 32]> = None;
        let mut ech_config_list: Option<Vec<u8>> = None;
        let mut forward_secret_rendezvous = false;
        let mut fs_bootstrap_tokens: Vec<FsCapabilityToken> = Vec::new();
        let mut i = 0usize;
        while i < ext_bytes.len() {
            if i + 3 > ext_bytes.len() {
                shared_salt_raw.zeroize();
                return Err(DiscoveryError::Wire("invite: truncated extension header"));
            }
            let ext_type = ext_bytes[i];
            let ext_len = u16::from_be_bytes([ext_bytes[i + 1], ext_bytes[i + 2]]) as usize;
            if i + 3 + ext_len > ext_bytes.len() {
                shared_salt_raw.zeroize();
                return Err(DiscoveryError::Wire("invite: truncated extension body"));
            }
            let val = &ext_bytes[i + 3..i + 3 + ext_len];
            match ext_type {
                INVITE_EXT_TLS_CERT_VERIFY_PK => {
                    // Compressed SEC1 P-256 point (33 bytes).
                    if ext_len != 33 {
                        shared_salt_raw.zeroize();
                        return Err(DiscoveryError::Wire("invite: tls_cert_verify_pk length"));
                    }
                    let mut pk = [0u8; 33];
                    pk.copy_from_slice(val);
                    tls_cert_verify_pk = Some(pk);
                }
                INVITE_EXT_CLAIM_ID => {
                    if ext_len != 32 {
                        shared_salt_raw.zeroize();
                        return Err(DiscoveryError::Wire("invite: claim_id length"));
                    }
                    let mut cid = [0u8; 32];
                    cid.copy_from_slice(val);
                    claim_id = Some(cid);
                }
                INVITE_EXT_MOTHER_ED25519_PK => {
                    if ext_len != 32 {
                        shared_salt_raw.zeroize();
                        return Err(DiscoveryError::Wire("invite: mother_ed25519_pk length"));
                    }
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(val);
                    mother_ed25519_pk = Some(pk);
                }
                INVITE_EXT_SIGNING_POLICY => {
                    if ext_len != 1 {
                        shared_salt_raw.zeroize();
                        return Err(DiscoveryError::Wire("invite: signing_policy length"));
                    }
                    signing_policy = Some(val[0]);
                }
                INVITE_EXT_PORT_HOP => {
                    if ext_len != 4 {
                        shared_salt_raw.zeroize();
                        return Err(DiscoveryError::Wire(
                            "invite: port_hop extension length must be 4",
                        ));
                    }
                    let base = u16::from_be_bytes([val[0], val[1]]);
                    let range = u16::from_be_bytes([val[2], val[3]]);
                    port_hop = Some((base, range));
                }
                INVITE_EXT_QUIC_OBFS_SECRET => {
                    if ext_len != 32 {
                        shared_salt_raw.zeroize();
                        return Err(DiscoveryError::Wire("invite: obfs_secret length"));
                    }
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(val);
                    obfs_secret = Some(secret);
                }
                INVITE_EXT_REALITY_PROBE_ROOT => {
                    if ext_len != 32 {
                        shared_salt_raw.zeroize();
                        return Err(DiscoveryError::Wire("invite: probe_root length"));
                    }
                    let mut root = [0u8; 32];
                    root.copy_from_slice(val);
                    probe_root = Some(root);
                }
                INVITE_EXT_ECH_CONFIG => {
                    if ext_len == 0 || ext_len > MAX_ECH_CONFIG_BYTES {
                        shared_salt_raw.zeroize();
                        return Err(DiscoveryError::Wire("invite: ech_config length"));
                    }
                    ech_config_list = Some(val.to_vec());
                }
                INVITE_EXT_FORWARD_SECRET_RENDEZVOUS => {
                    if ext_len != 0 {
                        shared_salt_raw.zeroize();
                        return Err(DiscoveryError::Wire("invite: fs_rendezvous flag length"));
                    }
                    forward_secret_rendezvous = true;
                }
                INVITE_EXT_FS_BOOTSTRAP_TOKENS => {
                    // count(1) || count x 248-byte FS token. Strict length + a
                    // count cap (mirroring MAX_BOOTSTRAP_TOKENS) so a forged
                    // invite can't inflate parse work or memory.
                    if ext_len < 1 {
                        shared_salt_raw.zeroize();
                        return Err(DiscoveryError::Wire("invite: fs_bootstrap_tokens empty"));
                    }
                    let count = val[0] as usize;
                    if count > MAX_BOOTSTRAP_TOKENS {
                        shared_salt_raw.zeroize();
                        return Err(DiscoveryError::Wire("invite: too many fs bootstrap tokens"));
                    }
                    if ext_len != 1 + count * FS_TOKEN_LEN {
                        shared_salt_raw.zeroize();
                        return Err(DiscoveryError::Wire("invite: fs_bootstrap_tokens length"));
                    }
                    let mut toks = Vec::with_capacity(count);
                    for c in 0..count {
                        let s = 1 + c * FS_TOKEN_LEN;
                        match FsCapabilityToken::decode(&val[s..s + FS_TOKEN_LEN]) {
                            Ok(tok) => toks.push(tok),
                            Err(_) => {
                                shared_salt_raw.zeroize();
                                return Err(DiscoveryError::Wire(
                                    "invite: fs bootstrap token decode",
                                ));
                            }
                        }
                    }
                    fs_bootstrap_tokens = toks;
                }
                _ => {
                    // Forward-compat: unknown extension types are
                    // silently skipped. An invite carrying a brand-
                    // new extension still decodes on an older client.
                }
            }
            i += 3 + ext_len;
        }

        // Cross-extension consistency check: mother key requires a
        // non-single-key policy; reject inconsistent invites at
        // decode time so callers don't have to re-validate.
        if let (Some(_), Some(p)) = (mother_ed25519_pk, signing_policy) {
            if p == SIGNING_POLICY_SINGLE_KEY {
                shared_salt_raw.zeroize();
                return Err(DiscoveryError::Wire(
                    "invite: mother_pk with single-key policy",
                ));
            }
        }
        // v0.1t refuses to instantiate threshold-policy invites
        // (no verification path yet).
        if signing_policy == Some(SIGNING_POLICY_THRESHOLD_KOFN) {
            shared_salt_raw.zeroize();
            return Err(DiscoveryError::Wire(
                "invite: threshold k-of-n policy not implemented in v0.1t",
            ));
        }

        let out = Self {
            operator_ed25519_pk,
            shared_salt: Zeroizing::new(shared_salt_raw),
            issued_at,
            expires_at,
            channel_hints,
            bootstrap_tokens,
            bootstrap_announcement,
            tls_cert_verify_pk,
            claim_id,
            mother_ed25519_pk,
            signing_policy,
            port_hop,
            obfs_secret,
            probe_root,
            ech_config_list,
            forward_secret_rendezvous,
            fs_bootstrap_tokens,
        };
        Ok(out)
    }

    /// Encode to a base64-url (no padding) text form suitable for URLs,
    /// QR codes, or secure messengers.
    pub fn encode_text(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        URL_SAFE_NO_PAD.encode(self.encode())
    }

    /// Decode from the base64-url text form.
    pub fn decode_text(text: &str) -> Result<Self, DiscoveryError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let bytes = URL_SAFE_NO_PAD
            .decode(text.as_bytes())
            .map_err(|_| DiscoveryError::Wire("invite: not valid base64-url"))?;
        Self::decode(&bytes)
    }
}

// Manual Debug: never print the salt, even on accident.
impl core::fmt::Debug for MasterInvite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MasterInvite")
            .field(
                "operator_ed25519_pk",
                &format_args!("{}...", hex::encode_prefix(&self.operator_ed25519_pk, 8)),
            )
            .field("shared_salt", &"<redacted: 32 bytes>")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("channel_hints_bytes", &self.channel_hints.len())
            .field("bootstrap_token_count", &self.bootstrap_tokens.len())
            .field(
                "has_bootstrap_announcement",
                &self.bootstrap_announcement.is_some(),
            )
            .finish()
    }
}

// Local minimal hex helper so we don't need to pull in a new dep.
mod hex {
    pub fn encode_prefix(bytes: &[u8], n: usize) -> String {
        let take = n.min(bytes.len());
        let mut s = String::with_capacity(take * 2);
        for b in &bytes[..take] {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{transport_caps, Endpoint, SIG_LEN};

    fn sample_ann() -> Announcement {
        Announcement {
            issued_at: 1_000_000,
            expires_at: 1_003_600,
            bridge_ed25519_pk: [0x11u8; 32],
            bridge_x25519_pk: [0x22u8; 32],
            transport_caps: transport_caps::REALITY_V2,
            endpoint: Endpoint::Ipv4 {
                addr: [192, 0, 2, 10],
                port: 443,
            },
            extra_endpoints: Vec::new(),
            signature: [0xAAu8; SIG_LEN],
        }
    }

    fn sample_token(tag: u8) -> BootstrapToken {
        CapabilityToken {
            token_id: [tag; 32],
            bridge_ed25519_pk: [tag.wrapping_add(2); 32],
            expires_at: 1_500_000,
            signature: [tag.wrapping_add(1); 64],
        }
    }

    fn sample_invite() -> MasterInvite {
        MasterInvite::new(
            [0xEEu8; 32],
            *b"abcdef0123456789abcdef0123456789",
            1_000_000,
            1_500_000,
            br#"{"nostr":["wss://r1","wss://r2"]}"#.to_vec(),
            vec![sample_token(1), sample_token(2)],
            Some(sample_ann()),
        )
        .unwrap()
    }

    fn sample_invite_with_pk() -> MasterInvite {
        MasterInvite::new_with_extensions(
            [0xEEu8; 32],
            *b"abcdef0123456789abcdef0123456789",
            1_000_000,
            1_500_000,
            Vec::new(),
            vec![sample_token(1)],
            Some(sample_ann()),
            Some([0x7Au8; 33]),
            None,
            None,
            None,
            None,
        )
        .unwrap()
    }

    fn sample_invite_with_claim_id() -> MasterInvite {
        MasterInvite::new_with_extensions(
            [0xEEu8; 32],
            *b"abcdef0123456789abcdef0123456789",
            1_000_000,
            1_500_000,
            Vec::new(),
            vec![sample_token(1)],
            Some(sample_ann()),
            None,
            Some([0x5Au8; 32]),
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn claim_id_roundtrip() {
        let inv = sample_invite_with_claim_id();
        let bytes = inv.encode();
        let back = MasterInvite::decode(&bytes).unwrap();
        assert_eq!(back.claim_id, Some([0x5Au8; 32]));
    }

    #[test]
    fn invite_with_both_extensions_roundtrips() {
        let inv = MasterInvite::new_with_extensions(
            [0xEEu8; 32],
            *b"abcdef0123456789abcdef0123456789",
            1_000_000,
            1_500_000,
            Vec::new(),
            vec![sample_token(1)],
            Some(sample_ann()),
            Some([0x7Au8; 33]),
            Some([0x5Au8; 32]),
            None,
            None,
            None,
        )
        .unwrap();
        let bytes = inv.encode();
        let back = MasterInvite::decode(&bytes).unwrap();
        assert_eq!(back.tls_cert_verify_pk, Some([0x7Au8; 33]));
        assert_eq!(back.claim_id, Some([0x5Au8; 32]));
    }

    #[test]
    fn mother_pinned_invite_roundtrips() {
        // an invite with mother_pk + signing_policy
        // SIGNING_POLICY_MOTHER_PINNED encodes, decodes, and reports
        // the policy correctly.
        let mother_pk = [0x9Eu8; 32];
        let inv = MasterInvite::new_with_extensions(
            [0xEEu8; 32],
            *b"abcdef0123456789abcdef0123456789",
            1_000_000,
            1_500_000,
            Vec::new(),
            vec![sample_token(1)],
            Some(sample_ann()),
            None,
            None,
            Some(mother_pk),
            Some(SIGNING_POLICY_MOTHER_PINNED),
            None,
        )
        .unwrap();
        let bytes = inv.encode();
        let back = MasterInvite::decode(&bytes).unwrap();
        assert_eq!(back.mother_ed25519_pk, Some(mother_pk));
        assert_eq!(back.signing_policy, Some(SIGNING_POLICY_MOTHER_PINNED));
        assert_eq!(
            back.effective_signing_policy(),
            SIGNING_POLICY_MOTHER_PINNED
        );
    }

    #[test]
    fn invite_rejects_mother_pk_with_single_key_policy() {
        // cross-extension consistency. A mother_pk pinned
        // alongside SIGNING_POLICY_SINGLE_KEY is misconfigured -
        // refuse at construction so the operator can't ship it.
        let err = MasterInvite::new_with_extensions(
            [0xEEu8; 32],
            *b"abcdef0123456789abcdef0123456789",
            1_000_000,
            1_500_000,
            Vec::new(),
            vec![sample_token(1)],
            Some(sample_ann()),
            None,
            None,
            Some([0x9Eu8; 32]),
            Some(SIGNING_POLICY_SINGLE_KEY),
            None,
        )
        .unwrap_err();
        assert!(format!("{err:?}").contains("single-key"));
    }

    #[test]
    fn invite_rejects_threshold_policy_v0_1() {
        // threshold k-of-n is v0.2; v0.1t implementations
        // refuse to mint or accept invites that declare it.
        let err = MasterInvite::new_with_extensions(
            [0xEEu8; 32],
            *b"abcdef0123456789abcdef0123456789",
            1_000_000,
            1_500_000,
            Vec::new(),
            vec![sample_token(1)],
            Some(sample_ann()),
            None,
            None,
            None,
            Some(SIGNING_POLICY_THRESHOLD_KOFN),
            None,
        )
        .unwrap_err();
        assert!(format!("{err:?}").contains("v0.2"));
    }

    #[test]
    fn invite_default_policy_is_single_key() {
        // legacy v0.1 invites have no signing_policy
        // extension; effective_signing_policy() must return the
        // single-key default for them.
        let inv = sample_invite_with_pk();
        assert_eq!(inv.signing_policy, None);
        assert_eq!(inv.effective_signing_policy(), SIGNING_POLICY_SINGLE_KEY);
    }

    #[test]
    fn tls_cert_verify_pk_roundtrip() {
        let inv = sample_invite_with_pk();
        let bytes = inv.encode();
        let back = MasterInvite::decode(&bytes).unwrap();
        assert_eq!(back.tls_cert_verify_pk, Some([0x7Au8; 33]));
    }

    #[test]
    fn ephemeral_invite_has_no_tls_cert_verify_pk() {
        let inv = sample_invite();
        let bytes = inv.encode();
        let back = MasterInvite::decode(&bytes).unwrap();
        assert!(back.tls_cert_verify_pk.is_none());
    }

    #[test]
    fn port_hop_roundtrip() {
        // A35: port_hop extension encodes, decodes, and preserves both fields.
        let inv = MasterInvite::new_with_extensions(
            [0xEEu8; 32],
            *b"abcdef0123456789abcdef0123456789",
            1_000_000,
            1_500_000,
            Vec::new(),
            vec![sample_token(1)],
            Some(sample_ann()),
            None,
            None,
            None,
            None,
            Some((8000u16, 500u16)),
        )
        .unwrap();
        let bytes = inv.encode();
        let back = MasterInvite::decode(&bytes).unwrap();
        assert_eq!(back.port_hop, Some((8000, 500)));
    }

    #[test]
    fn port_hop_absent_is_none() {
        // An invite without INVITE_EXT_PORT_HOP has port_hop == None.
        let inv = sample_invite();
        let bytes = inv.encode();
        let back = MasterInvite::decode(&bytes).unwrap();
        assert_eq!(back.port_hop, None);
    }

    #[test]
    fn obfs_secret_roundtrip() {
        // The QUIC obfs secret encodes as ext 0x06, decodes verbatim, and
        // survives the text (mirage://) round-trip alongside other extensions.
        let secret = [0x5Au8; 32];
        let inv = sample_invite().with_obfs_secret(secret);
        let back = MasterInvite::decode(&inv.encode()).unwrap();
        assert_eq!(back.obfs_secret, Some(secret));
        let text = inv.encode_text();
        let back_text = MasterInvite::decode_text(&text).unwrap();
        assert_eq!(back_text.obfs_secret, Some(secret));
    }

    #[test]
    fn obfs_secret_absent_is_none() {
        // An invite without ext 0x06 has obfs_secret == None (old invites and
        // the pubkey-derived-default path stay backward-compatible).
        let back = MasterInvite::decode(&sample_invite().encode()).unwrap();
        assert_eq!(back.obfs_secret, None);
    }

    #[test]
    fn forward_secret_rendezvous_flag_roundtrip() {
        // Absent by default; the flag (ext 0x07, zero-length) round-trips true.
        let base = MasterInvite::decode(&sample_invite().encode()).unwrap();
        assert!(!base.forward_secret_rendezvous);

        let inv = sample_invite().with_forward_secret_rendezvous();
        let back = MasterInvite::decode(&inv.encode()).unwrap();
        assert!(back.forward_secret_rendezvous);
        // Anchor epoch is the invite's issue epoch.
        assert_eq!(
            back.fs_anchor_epoch(),
            crate::derive::epoch_for_time(inv.issued_at)
        );
        // Text form preserves it alongside other extensions.
        let back_text = MasterInvite::decode_text(&inv.encode_text()).unwrap();
        assert!(back_text.forward_secret_rendezvous);
    }

    #[test]
    fn forward_secret_rendezvous_flag_rejects_nonzero_length() {
        let mut bytes = sample_invite().encode();
        bytes.push(INVITE_EXT_FORWARD_SECRET_RENDEZVOUS);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.push(0xFF);
        assert!(MasterInvite::decode(&bytes).is_err());
    }

    fn sample_fs_tokens(n: usize) -> Vec<FsCapabilityToken> {
        use crate::token_fs::EpochSigner;
        use mirage_crypto::ed25519_dalek::SigningKey;
        let root = SigningKey::from_bytes(&[7u8; 32]);
        let signer = EpochSigner::generate(&root, 1, 2_000_000).unwrap();
        (0..n)
            .map(|i| signer.sign_token([i as u8; 32], [0xEEu8; 32], 1_400_000))
            .collect()
    }

    #[test]
    fn fs_bootstrap_tokens_roundtrip_and_dual_mint() {
        // ext 0x08 carries FS tokens ALONGSIDE the legacy bootstrap_tokens
        // (sample_invite already has 2). Both survive binary + text round-trip.
        let toks = sample_fs_tokens(2);
        let inv = sample_invite().with_fs_bootstrap_tokens(toks.clone());
        let back = MasterInvite::decode(&inv.encode()).unwrap();
        assert_eq!(back.bootstrap_tokens.len(), 2, "legacy tokens preserved");
        assert_eq!(back.fs_bootstrap_tokens, toks, "FS tokens preserved");
        let back_text = MasterInvite::decode_text(&inv.encode_text()).unwrap();
        assert_eq!(back_text.fs_bootstrap_tokens, toks);
    }

    #[test]
    fn fs_bootstrap_tokens_absent_is_empty() {
        // Old / legacy-only invites decode with an empty FS pool.
        let back = MasterInvite::decode(&sample_invite().encode()).unwrap();
        assert!(back.fs_bootstrap_tokens.is_empty());
    }

    #[test]
    fn fs_bootstrap_tokens_rejects_wrong_length() {
        // ext_len that doesn't equal 1 + count*248 must be rejected, not
        // silently truncated (mirrors the strict discipline of every ext arm).
        let mut bytes = sample_invite().encode();
        bytes.push(INVITE_EXT_FS_BOOTSTRAP_TOKENS);
        bytes.extend_from_slice(&50u16.to_be_bytes()); // ext_len = 50
        bytes.push(1); // count = 1 => requires 249 bytes, not 50
        bytes.extend_from_slice(&[0u8; 49]);
        assert!(MasterInvite::decode(&bytes).is_err());
    }

    #[test]
    fn fs_bootstrap_tokens_rejects_count_over_cap() {
        let mut bytes = sample_invite().encode();
        bytes.push(INVITE_EXT_FS_BOOTSTRAP_TOKENS);
        bytes.extend_from_slice(&1u16.to_be_bytes()); // ext_len = 1 (count only)
        bytes.push((MAX_BOOTSTRAP_TOKENS + 1) as u8); // count = 17 > cap
        assert!(MasterInvite::decode(&bytes).is_err());
    }

    #[test]
    fn fs_bootstrap_tokens_builder_truncates_to_cap() {
        // Passing more than the cap can't produce an invite that fails its own
        // decode round-trip; the builder clamps.
        let toks = sample_fs_tokens(MAX_BOOTSTRAP_TOKENS + 4);
        let inv = sample_invite().with_fs_bootstrap_tokens(toks);
        assert_eq!(inv.fs_bootstrap_tokens.len(), MAX_BOOTSTRAP_TOKENS);
        // And it still round-trips.
        let back = MasterInvite::decode(&inv.encode()).unwrap();
        assert_eq!(back.fs_bootstrap_tokens.len(), MAX_BOOTSTRAP_TOKENS);
    }

    #[test]
    fn obfs_secret_rejects_wrong_length() {
        // A hand-forged ext 0x06 with a non-32 length must be rejected, not
        // silently truncated.
        let mut bytes = sample_invite().encode();
        bytes.push(INVITE_EXT_QUIC_OBFS_SECRET);
        bytes.extend_from_slice(&16u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        assert!(MasterInvite::decode(&bytes).is_err());
    }

    #[test]
    fn probe_root_roundtrip() {
        // The Reality probe root encodes as ext 0x09, decodes verbatim, and
        // survives the text (mirage://) round-trip alongside other extensions.
        let root = [0xA5u8; 32];
        let inv = sample_invite().with_probe_root(root);
        let back = MasterInvite::decode(&inv.encode()).unwrap();
        assert_eq!(back.probe_root, Some(root));
        let text = inv.encode_text();
        let back_text = MasterInvite::decode_text(&text).unwrap();
        assert_eq!(back_text.probe_root, Some(root));
    }

    #[test]
    fn ech_config_roundtrip() {
        // A variable-length ECHConfigList encodes as ext 0x0a, decodes verbatim, and
        // survives the text (mirage://) round-trip. Absent -> None (backward-compatible).
        let ech: Vec<u8> = (0..200u16).map(|i| (i % 251) as u8).collect();
        let inv = sample_invite().with_ech_config(ech.clone());
        let back = MasterInvite::decode(&inv.encode()).unwrap();
        assert_eq!(back.ech_config_list, Some(ech.clone()));
        let back_text = MasterInvite::decode_text(&inv.encode_text()).unwrap();
        assert_eq!(back_text.ech_config_list, Some(ech));
        assert_eq!(
            MasterInvite::decode(&sample_invite().encode())
                .unwrap()
                .ech_config_list,
            None
        );
    }

    #[test]
    fn probe_root_absent_is_none() {
        // An invite without ext 0x09 has probe_root == None (old invites and
        // bridges that never provisioned one), so the client falls back to a
        // legacy probe.
        let back = MasterInvite::decode(&sample_invite().encode()).unwrap();
        assert_eq!(back.probe_root, None);
    }

    #[test]
    fn probe_root_and_obfs_secret_coexist() {
        // Both 32-byte secret extensions (0x06 + 0x09) must survive together -
        // they occupy adjacent ext slots and a bridge sets both.
        let obfs = [0x11u8; 32];
        let root = [0x22u8; 32];
        let inv = sample_invite().with_obfs_secret(obfs).with_probe_root(root);
        let back = MasterInvite::decode(&inv.encode()).unwrap();
        assert_eq!(back.obfs_secret, Some(obfs));
        assert_eq!(back.probe_root, Some(root));
    }

    #[test]
    fn probe_root_rejects_wrong_length() {
        // A hand-forged ext 0x09 with a non-32 length must be rejected.
        let mut bytes = sample_invite().encode();
        bytes.push(INVITE_EXT_REALITY_PROBE_ROOT);
        bytes.extend_from_slice(&16u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        assert!(MasterInvite::decode(&bytes).is_err());
    }

    #[test]
    fn port_hop_rejects_privileged_base() {
        let err = MasterInvite::new_with_extensions(
            [0xEEu8; 32],
            *b"abcdef0123456789abcdef0123456789",
            1_000_000,
            1_500_000,
            Vec::new(),
            vec![sample_token(1)],
            Some(sample_ann()),
            None,
            None,
            None,
            None,
            Some((80u16, 10u16)), // privileged port
        )
        .unwrap_err();
        assert!(format!("{err:?}").contains("1024"));
    }

    #[test]
    fn unknown_extension_is_silently_ignored() {
        // Construct an invite then append an unknown extension:
        // type=0x42, len=3, value="abc". Decoder must accept.
        let inv = sample_invite();
        let mut bytes = inv.encode();
        bytes.push(0x42);
        bytes.extend_from_slice(&3u16.to_be_bytes());
        bytes.extend_from_slice(b"abc");
        let back = MasterInvite::decode(&bytes).unwrap();
        assert_eq!(back.tls_cert_verify_pk, None);
    }

    #[test]
    fn roundtrip_binary() {
        let inv = sample_invite();
        let bytes = inv.encode();
        let back = MasterInvite::decode(&bytes).unwrap();
        assert_eq!(back.operator_ed25519_pk, inv.operator_ed25519_pk);
        assert_eq!(back.shared_salt.as_ref(), inv.shared_salt.as_ref());
        assert_eq!(back.issued_at, inv.issued_at);
        assert_eq!(back.expires_at, inv.expires_at);
        assert_eq!(back.channel_hints, inv.channel_hints);
        assert_eq!(back.bootstrap_tokens.len(), inv.bootstrap_tokens.len());
        assert_eq!(
            back.bootstrap_tokens[0].token_id,
            inv.bootstrap_tokens[0].token_id
        );
        assert_eq!(
            back.bootstrap_announcement.is_some(),
            inv.bootstrap_announcement.is_some()
        );
    }

    #[test]
    fn roundtrip_text() {
        let inv = sample_invite();
        let text = inv.encode_text();
        let back = MasterInvite::decode_text(&text).unwrap();
        assert_eq!(back.operator_ed25519_pk, inv.operator_ed25519_pk);
        assert_eq!(back.shared_salt.as_ref(), inv.shared_salt.as_ref());
    }

    #[test]
    fn empty_options_encode_decode() {
        let inv =
            MasterInvite::new([0u8; 32], [0u8; 32], 1, 2, Vec::new(), Vec::new(), None).unwrap();
        let back = MasterInvite::decode(&inv.encode()).unwrap();
        assert!(back.channel_hints.is_empty());
        assert!(back.bootstrap_tokens.is_empty());
        assert!(back.bootstrap_announcement.is_none());
    }

    #[test]
    fn is_valid_at_honors_window() {
        let inv = sample_invite();
        assert!(!inv.is_valid_at(999_999));
        assert!(inv.is_valid_at(1_000_000));
        assert!(inv.is_valid_at(1_499_999));
        assert!(!inv.is_valid_at(1_500_000));
    }

    #[test]
    fn rejects_bad_magic() {
        let inv = sample_invite();
        let mut bytes = inv.encode();
        bytes[0] = 0xFF;
        match MasterInvite::decode(&bytes) {
            Err(DiscoveryError::Wire(m)) => assert!(m.contains("magic")),
            other => panic!("expected magic rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_doc_type() {
        let inv = sample_invite();
        let mut bytes = inv.encode();
        bytes[2] = 0x20;
        assert!(MasterInvite::decode(&bytes).is_err());
    }

    #[test]
    fn rejects_unsupported_version() {
        let inv = sample_invite();
        let mut bytes = inv.encode();
        bytes[3] = 0x02;
        assert!(MasterInvite::decode(&bytes).is_err());
    }

    #[test]
    fn rejects_expires_before_issued() {
        let err = MasterInvite::new(
            [0u8; 32],
            [0u8; 32],
            1000,
            500,
            Vec::new(),
            Vec::new(),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, DiscoveryError::Wire(_)));
    }

    #[test]
    fn rejects_too_many_bootstrap_tokens() {
        let tokens: Vec<_> = (0..17).map(|i| sample_token(i as u8)).collect();
        let err =
            MasterInvite::new([0u8; 32], [0u8; 32], 1, 2, Vec::new(), tokens, None).unwrap_err();
        assert!(matches!(err, DiscoveryError::Wire(_)));
    }

    #[test]
    fn rejects_oversized_channel_hints() {
        let hints = vec![b'x'; MAX_CHANNEL_HINTS_BYTES + 1];
        let err =
            MasterInvite::new([0u8; 32], [0u8; 32], 1, 2, hints, Vec::new(), None).unwrap_err();
        assert!(matches!(err, DiscoveryError::Wire(_)));
    }

    #[test]
    fn rejects_non_utf8_channel_hints() {
        let err = MasterInvite::new(
            [0u8; 32],
            [0u8; 32],
            1,
            2,
            vec![0xFFu8, 0xFE, 0xFD],
            Vec::new(),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, DiscoveryError::Wire(_)));
    }

    #[test]
    fn rejects_truncated_input() {
        let inv = sample_invite();
        let bytes = inv.encode();
        for cutoff in (0..bytes.len()).step_by(13) {
            // Must not panic on any truncation.
            let _ = MasterInvite::decode(&bytes[..cutoff]);
        }
    }

    #[test]
    fn rejects_truncated_extension_header() {
        // With the TLV-extension block now allowed at the tail of
        // every invite, "one trailing byte" is a truncated ext
        // header (needs type(1) + len(2) = 3 bytes minimum), which
        // is a distinct error.
        let inv =
            MasterInvite::new([0u8; 32], [0u8; 32], 1, 2, Vec::new(), Vec::new(), None).unwrap();
        let mut bytes = inv.encode();
        bytes.push(0xAB);
        match MasterInvite::decode(&bytes) {
            Err(DiscoveryError::Wire(m)) => {
                assert!(m.contains("extension"), "got: {m}");
            }
            other => panic!("expected extension-header rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_announcement_flag() {
        let inv =
            MasterInvite::new([0u8; 32], [0u8; 32], 1, 2, Vec::new(), Vec::new(), None).unwrap();
        let mut bytes = inv.encode();
        // Last byte is the has_bootstrap_announcement flag. Replace with 0x42.
        *bytes.last_mut().unwrap() = 0x42;
        assert!(MasterInvite::decode(&bytes).is_err());
    }

    #[test]
    fn debug_impl_redacts_salt() {
        let inv = sample_invite();
        let rendered = format!("{:?}", inv);
        let salt_hex: String = inv.shared_salt.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !rendered.contains(&salt_hex),
            "shared_salt leaked into Debug: {rendered}"
        );
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn fuzz_arbitrary_never_panics() {
        use proptest::prelude::*;
        proptest!(ProptestConfig::with_cases(256), |(bytes in prop::collection::vec(any::<u8>(), 0..4096))| {
            let _ = MasterInvite::decode(&bytes);
        });
    }
}
