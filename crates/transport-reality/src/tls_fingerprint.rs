//! TLS ClientHello fingerprint templates for A17 (client-side
//! JA3/JA4 mimicry) and A26 (drift detection).
//!
//! # Why
//!
//! The BYTES of a Mirage client's outbound ClientHello must match a
//! currently-deployed browser's fingerprint. A novel JA3/JA4 makes
//! Mirage itself detectable by passive DPI that classifies on TLS
//! stack shape - the inner Reality auth probe becomes irrelevant
//! if the enclosing ClientHello already says "I'm a Mirage client."
//!
//! Pre-v0.1k the generator hard-coded one cipher-suite list +
//! extension order + signature-algorithm list. This module turns
//! that into a pluggable [`TlsFingerprintTemplate`] with built-in
//! Chrome / Firefox / Safari variants, and pins each template's
//! JA3 string as a regression so accidental drift in the library
//! produces a loud test failure.
//!
//! A CI job that scrapes real-world browser fingerprints weekly and
//! compares them to these pinned strings is the A26 drift-
//! detection step. That's a repository-level automation concern
//! landing alongside the Nix flake work - this module ships the
//! template + string + pinned hash primitives it needs.
//!
//! # JA3 string
//!
//! Per the Salesforce spec
//! (<https://github.com/salesforce/ja3>):
//!
//! ```text
//!   SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
//! ```
//!
//! - `SSLVersion` - decimal form of `legacy_version` (e.g. 771 = 0x0303).
//! - `Cipher` - `-`-joined decimal cipher-suite values.
//! - `SSLExtension` - `-`-joined decimal extension-type values,
//!   EXCLUDING GREASE (0x?A?A). Mirage DOES emit GREASE on the wire
//!   (RFC 8701 - first + last extension slots, cipher, groups,
//!   key_share, supported_versions) but excludes it from the JA3
//!   string, so this is the full non-GREASE extension-type list.
//! - `EllipticCurve` - `-`-joined decimal `supported_groups`.
//! - `EllipticCurvePointFormat` - `-`-joined decimal values from
//!   the `ec_point_formats` extension. TLS 1.3 typically omits
//!   this extension; we emit `0` for compatibility with tools
//!   that expect at least one format byte.
//!
//! # JA4
//!
//! The newer FoxIO JA4 fingerprint adds richer proto+version+SNI
//! discrimination. Left for a follow-up - the JA3 primitive is
//! load-bearing for the passive-DPI case today.

use std::fmt::Write;

// Template struct

/// One signed parameter set describing how to emit a ClientHello
/// with a specific JA3/JA4 fingerprint.
///
/// Ownership: all dynamic fields are `&'static` because templates
/// live for the lifetime of the binary. An operator who wants a
/// custom template constructs a `TlsFingerprintTemplate` by hand at
/// runtime (using `Vec<u16>` etc. if they need owned data); the
/// generator accepts any instance satisfying the struct shape
/// through plain refs.
#[derive(Debug, Clone)]
pub struct TlsFingerprintTemplate {
    /// Diagnostic name, used in logs + metrics labels.
    pub name: &'static str,
    /// `legacy_version` advertised in the ClientHello record body.
    /// TLS 1.3 clients write `0x0303` here and signal real
    /// version via the `supported_versions` extension.
    pub legacy_version: [u8; 2],
    /// Cipher suites, in wire order. Must be non-empty.
    pub cipher_suites: &'static [u16],
    /// Extension types to emit, in wire order. For each type the
    /// generator calls the matching writer. Must include
    /// `EXT_KEY_SHARE` + `EXT_SUPPORTED_VERSIONS` + `EXT_SERVER_NAME`
    /// since Mirage's bridge verifier needs those.
    pub extension_order: &'static [u16],
    /// Entries for the `supported_groups` extension.
    pub supported_groups: &'static [u16],
    /// Entries for the `signature_algorithms` extension.
    pub sig_algs: &'static [u16],
    /// Entries for the ALPN extension. Empty = omit.
    pub alpn_protos: &'static [&'static [u8]],
    /// Entries for the `ec_point_formats` extension. Empty = omit.
    /// TLS 1.3 rarely uses this, but some browser fingerprints
    /// still advertise `0x00` (uncompressed).
    pub ec_point_formats: &'static [u8],
    /// Entries for the `psk_key_exchange_modes` extension. Empty =
    /// omit. Chrome emits `1` (psk_dhe_ke) when session resumption
    /// is enabled.
    pub psk_key_exchange_modes: &'static [u8],
    /// If true, emit the `extended_master_secret` extension (empty
    /// body). Chrome + Firefox both emit it.
    pub extended_master_secret: bool,
    /// If true, emit the `renegotiation_info` extension with an
    /// empty body. Legacy compat; most browsers still emit it.
    pub renegotiation_info: bool,
    /// If Some, emit the `record_size_limit` extension with this
    /// 16-bit value. Firefox emits this; Chrome does not.
    pub record_size_limit: Option<u16>,
    /// Compression methods. Always `[0x00]` in practice.
    pub compression_methods: &'static [u8],
}

// Extension type constants (RFC 8446 + IANA TLS ExtensionType Values)

/// `server_name` (SNI).
pub const EXT_SERVER_NAME: u16 = 0x0000;
/// `ec_point_formats`.
pub const EXT_EC_POINT_FORMATS: u16 = 0x000B;
/// `supported_groups` (named curves).
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000A;
/// `signature_algorithms`.
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000D;
/// `application_layer_protocol_negotiation` (ALPN).
pub const EXT_ALPN: u16 = 0x0010;
/// `extended_master_secret`.
pub const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
/// `record_size_limit`.
pub const EXT_RECORD_SIZE_LIMIT: u16 = 0x001C;
/// `supported_versions`.
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
/// `psk_key_exchange_modes`.
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002D;
/// `key_share`.
pub const EXT_KEY_SHARE: u16 = 0x0033;
/// `renegotiation_info` (RFC 5746). Legacy but still common.
pub const EXT_RENEGOTIATION_INFO: u16 = 0xFF01;
/// `status_request` (OCSP stapling). Chrome sends `status_type=ocsp` with
/// empty responder-id + request-extensions lists.
pub const EXT_STATUS_REQUEST: u16 = 0x0005;
/// `signed_certificate_timestamp` (SCT, RFC 6962). Chrome sends it empty.
pub const EXT_SIGNED_CERT_TIMESTAMP: u16 = 0x0012;
/// `session_ticket` (RFC 5077). Chrome sends it with an empty body.
pub const EXT_SESSION_TICKET: u16 = 0x0023;
/// `compress_certificate` (RFC 8879). Chrome advertises brotli (0x0002).
pub const EXT_COMPRESS_CERTIFICATE: u16 = 0x001B;
/// `application_settings` (ALPS, draft-vvv-tls-alps). Chrome sends it carrying
/// the `h2` protocol. IANA codepoint 0x4469.
pub const EXT_APPLICATION_SETTINGS: u16 = 0x4469;
/// `encrypted_client_hello` (ECH, RFC 9180 / draft-ietf-tls-esni), codepoint
/// 0xfe0d. Chrome (>=M117) and Firefox (>=132) send a GREASE ECH extension on
/// essentially every TLS 1.3 ClientHello. A ClientHello that advertises the
/// X25519MLKEM768 PQ hybrid group (Chrome >=131) but omits ECH is a
/// browser-impossible combination a censor pins directly (red-team HIGH #1), so
/// the Chrome/Firefox templates MUST carry it.
pub const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

// Named group + sig alg constants (the ones built-in templates use)

/// `x25519`.
pub const GROUP_X25519: u16 = 0x001D;
/// `secp256r1`.
pub const GROUP_SECP256R1: u16 = 0x0017;
/// `secp384r1`.
pub const GROUP_SECP384R1: u16 = 0x0018;
/// `X25519MLKEM768` - post-quantum hybrid key share (draft-kwiatkowski-tls-ecdhe-mlkem
/// codepoint 0x11EC). Chrome enabled by default in 124+ (Apr 2024);
/// Firefox followed in 132 (Oct 2024). Templates that omit this on
/// modern Chrome / Firefox JA3 produce a noticeable mismatch - the
/// majority of real ClientHellos in 2026 advertise it as the FIRST
/// group in `supported_groups`.
pub const GROUP_X25519_MLKEM768: u16 = 0x11EC;

/// The 16 legal RFC 8701 GREASE values (both bytes equal, low nibble `0xA`).
/// Real Chrome/Firefox draw from these per-connection for one cipher, one
/// supported_group, one key_share entry, and an extension slot. JA3/JA4
/// fingerprinters MUST ignore GREASE, so emitting it does NOT change the
/// pinned JA3 string - it closes the "zero-GREASE TLS 1.3 => not a browser"
/// distinguisher, which a fingerprinter otherwise flags with ~100% specificity.
pub const GREASE_VALUES: [u16; 16] = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
];

/// Draw one GREASE value uniformly from [`GREASE_VALUES`] via the OS CSPRNG.
/// On CSPRNG failure falls back to the first value (still a legal GREASE
/// value, never a real codepoint).
pub fn pick_grease() -> u16 {
    let mut b = [0u8; 1];
    let idx = match getrandom::fill(&mut b) {
        Ok(()) => (b[0] & 0x0F) as usize,
        Err(_) => 0,
    };
    GREASE_VALUES[idx]
}

/// Per-connection GREASE selection for a ClientHello, drawn fresh per
/// connection. `group` is reused for BOTH the `supported_groups` GREASE entry
/// and the `key_share` GREASE entry (real Chrome correlates the two); `cipher`,
/// `ext_first`, and `version` are independent draws.
#[derive(Debug, Clone, Copy)]
pub struct GreaseValues {
    /// GREASE value prepended to the cipher-suite list.
    pub cipher: u16,
    /// GREASE value used for the `supported_groups` AND `key_share` entries.
    pub group: u16,
    /// GREASE value for the leading (first) extension slot.
    pub ext_first: u16,
    /// GREASE value for the trailing (last) extension slot. Chrome places a
    /// SECOND, distinct GREASE extension at the very end of the list; a single
    /// leading GREASE was itself a (subtle) distinguisher.
    pub ext_last: u16,
    /// GREASE value prepended to the `supported_versions` list (Chrome greases
    /// this too, ahead of TLS 1.3).
    pub version: u16,
}

impl GreaseValues {
    /// Draw a fresh per-connection GREASE set from the CSPRNG (one read for all
    /// positions). On CSPRNG failure, fall back to DISTINCT indices so a
    /// degraded host never emits an all-identical GREASE pattern - and note a
    /// true RNG outage also breaks `ch_random`, failing the handshake upstream.
    pub fn random() -> Self {
        let mut b = [0u8; 5];
        let idx = match getrandom::fill(&mut b) {
            Ok(()) => [b[0], b[1], b[2], b[3], b[4]],
            Err(_) => [0, 1, 2, 3, 4],
        };
        Self {
            cipher: GREASE_VALUES[(idx[0] & 0x0F) as usize],
            group: GREASE_VALUES[(idx[1] & 0x0F) as usize],
            ext_first: GREASE_VALUES[(idx[2] & 0x0F) as usize],
            ext_last: GREASE_VALUES[(idx[4] & 0x0F) as usize],
            version: GREASE_VALUES[(idx[3] & 0x0F) as usize],
        }
    }
}

/// `ed25519` (0x0807). RETAINED ONLY as a named constant for the negative
/// assertion in tests - it must NOT appear in any template's `sig_algs`.
///
/// JA4 RESIDUAL - RESOLVED: desktop Chrome/Firefox/Safari do not advertise
/// ed25519, so neither does Reality anymore. The bridge's ephemeral cert +
/// CertVerify were migrated to `ecdsa_secp256r1_sha256` (0x0403, see
/// `tls_cert::build_self_signed_ecdsa_p256` and `tls_handshake_flight::
/// build_certificate_verify`), and 0x0807 was dropped from every template, so
/// advertised == signed == a scheme every browser offers. JA4 now matches the
/// mimicked browser.
pub const SIG_ED25519: u16 = 0x0807;
/// `ecdsa_secp256r1_sha256`.
pub const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
/// `rsa_pss_rsae_sha256`.
pub const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
/// `rsa_pkcs1_sha256`.
pub const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;
/// `ecdsa_secp384r1_sha384`.
pub const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
/// `rsa_pss_rsae_sha384`.
pub const SIG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
/// `rsa_pkcs1_sha384`.
pub const SIG_RSA_PKCS1_SHA384: u16 = 0x0501;
/// `rsa_pss_rsae_sha512`.
pub const SIG_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
/// `rsa_pkcs1_sha512`.
pub const SIG_RSA_PKCS1_SHA512: u16 = 0x0601;

// Built-in templates

/// Chrome desktop stable-ish fingerprint template.
///
/// Extension order, cipher suites, and sig-alg list are modelled on
/// a captured Chrome 120+ ClientHello. GREASE values (0x?A?A) are
/// intentionally OMITTED - they're random per-connection and don't
/// contribute to JA3 discrimination anyway.
pub const CHROME_DESKTOP: TlsFingerprintTemplate = TlsFingerprintTemplate {
    name: "chrome-desktop",
    legacy_version: [0x03, 0x03],
    cipher_suites: &[
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0xC02B, // ECDHE_ECDSA_AES128_GCM_SHA256
        0xC02F, // ECDHE_RSA_AES128_GCM_SHA256
        0xC02C, // ECDHE_ECDSA_AES256_GCM_SHA384
        0xC030, // ECDHE_RSA_AES256_GCM_SHA384
        0xCCA9, // ECDHE_ECDSA_CHACHA20_POLY1305_SHA256
        0xCCA8, // ECDHE_RSA_CHACHA20_POLY1305_SHA256
        0xC013, // ECDHE_RSA_AES128_SHA
        0xC014, // ECDHE_RSA_AES256_SHA
        0x009C, // RSA_AES128_GCM_SHA256
        0x009D, // RSA_AES256_GCM_SHA384
        0x002F, // RSA_AES128_SHA
        0x0035, // RSA_AES256_SHA
    ],
    // Full modern-Chrome extension set (Chrome 124+, X25519MLKEM768 era). The
    // ClientHello carries the ~1.2 KB hybrid key_share, so it exceeds 512 bytes
    // and Chrome does NOT append the `padding` extension. Real Chrome shuffles
    // this order per connection (see `shuffle_extensions` in the generator);
    // GREASE occupies
    // the first + last slots (emitted at build time, out of the JA3 string).
    extension_order: &[
        EXT_SERVER_NAME,
        EXT_EXTENDED_MASTER_SECRET,
        EXT_RENEGOTIATION_INFO,
        EXT_SUPPORTED_GROUPS,
        EXT_EC_POINT_FORMATS,
        EXT_SESSION_TICKET,
        EXT_ALPN,
        EXT_STATUS_REQUEST,
        EXT_SIGNATURE_ALGORITHMS,
        EXT_SIGNED_CERT_TIMESTAMP,
        EXT_KEY_SHARE,
        EXT_PSK_KEY_EXCHANGE_MODES,
        EXT_SUPPORTED_VERSIONS,
        EXT_COMPRESS_CERTIFICATE,
        EXT_APPLICATION_SETTINGS,
        // GREASE ECH - Chrome (>=M117) sends it on every TLS 1.3 CH, late in the
        // order. Required alongside the ML-KEM group (red-team HIGH #1).
        EXT_ENCRYPTED_CLIENT_HELLO,
    ],
    supported_groups: &[
        GROUP_X25519_MLKEM768,
        GROUP_X25519,
        GROUP_SECP256R1,
        GROUP_SECP384R1,
    ],
    sig_algs: &[
        SIG_ECDSA_SECP256R1_SHA256,
        SIG_RSA_PSS_RSAE_SHA256,
        SIG_RSA_PKCS1_SHA256,
        SIG_ECDSA_SECP384R1_SHA384,
        SIG_RSA_PSS_RSAE_SHA384,
        SIG_RSA_PKCS1_SHA384,
        SIG_RSA_PSS_RSAE_SHA512,
        SIG_RSA_PKCS1_SHA512,
    ],
    alpn_protos: &[b"h2", b"http/1.1"],
    ec_point_formats: &[0x00],
    psk_key_exchange_modes: &[0x01],
    extended_master_secret: true,
    renegotiation_info: true,
    record_size_limit: None,
    compression_methods: &[0x00],
};

/// Firefox desktop stable-ish fingerprint template.
///
/// Firefox tends to emit `record_size_limit` and orders extensions
/// differently from Chrome. A client that looks like Chrome on a
/// network where Firefox is dominant (or vice versa) is another
/// signal - operators should pick the template matching the
/// majority baseline of their deployment's users.
pub const FIREFOX_DESKTOP: TlsFingerprintTemplate = TlsFingerprintTemplate {
    name: "firefox-desktop",
    legacy_version: [0x03, 0x03],
    cipher_suites: &[
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F,
        0x0035,
    ],
    extension_order: &[
        EXT_SERVER_NAME,
        EXT_EXTENDED_MASTER_SECRET,
        EXT_RENEGOTIATION_INFO,
        EXT_SUPPORTED_GROUPS,
        EXT_EC_POINT_FORMATS,
        EXT_ALPN,
        EXT_SIGNATURE_ALGORITHMS,
        EXT_SUPPORTED_VERSIONS,
        EXT_PSK_KEY_EXCHANGE_MODES,
        EXT_RECORD_SIZE_LIMIT,
        EXT_KEY_SHARE,
        // GREASE ECH - Firefox (>=132) sends it alongside the ML-KEM group
        // (red-team HIGH #1).
        EXT_ENCRYPTED_CLIENT_HELLO,
    ],
    supported_groups: &[
        GROUP_X25519_MLKEM768,
        GROUP_X25519,
        GROUP_SECP256R1,
        GROUP_SECP384R1,
    ],
    sig_algs: &[
        SIG_ECDSA_SECP256R1_SHA256,
        SIG_ECDSA_SECP384R1_SHA384,
        SIG_RSA_PSS_RSAE_SHA256,
        SIG_RSA_PSS_RSAE_SHA384,
        SIG_RSA_PSS_RSAE_SHA512,
        SIG_RSA_PKCS1_SHA256,
        SIG_RSA_PKCS1_SHA384,
        SIG_RSA_PKCS1_SHA512,
    ],
    alpn_protos: &[b"h2", b"http/1.1"],
    ec_point_formats: &[0x00],
    psk_key_exchange_modes: &[0x01],
    extended_master_secret: true,
    renegotiation_info: true,
    record_size_limit: Some(16385),
    compression_methods: &[0x00],
};

/// Safari desktop stable-ish fingerprint template.
///
/// Safari has a narrower cipher-suite list and does not advertise
/// `psk_key_exchange_modes` in the common baseline. Suitable as a
/// "third option" so a network fingerprinting operators sees more
/// diversity across a Mirage deployment.
pub const SAFARI_DESKTOP: TlsFingerprintTemplate = TlsFingerprintTemplate {
    name: "safari-desktop",
    legacy_version: [0x03, 0x03],
    cipher_suites: &[
        0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xC030, 0xC02F, 0x009D, 0x009C, 0x0035, 0x002F,
        0xC024, 0xC023, 0xC028, 0xC027,
    ],
    extension_order: &[
        EXT_SERVER_NAME,
        EXT_EXTENDED_MASTER_SECRET,
        EXT_RENEGOTIATION_INFO,
        EXT_SUPPORTED_GROUPS,
        EXT_EC_POINT_FORMATS,
        EXT_ALPN,
        EXT_SUPPORTED_VERSIONS,
        EXT_SIGNATURE_ALGORITHMS,
        EXT_KEY_SHARE,
    ],
    supported_groups: &[GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1],
    sig_algs: &[
        SIG_ECDSA_SECP256R1_SHA256,
        SIG_RSA_PSS_RSAE_SHA256,
        SIG_RSA_PKCS1_SHA256,
        SIG_ECDSA_SECP384R1_SHA384,
        SIG_RSA_PSS_RSAE_SHA384,
        SIG_RSA_PKCS1_SHA384,
        SIG_RSA_PSS_RSAE_SHA512,
        SIG_RSA_PKCS1_SHA512,
    ],
    alpn_protos: &[b"h2", b"http/1.1"],
    ec_point_formats: &[0x00],
    psk_key_exchange_modes: &[],
    extended_master_secret: true,
    renegotiation_info: true,
    record_size_limit: None,
    compression_methods: &[0x00],
};

/// Look up a template by its diagnostic name. `None` on unknown.
pub fn lookup(name: &str) -> Option<&'static TlsFingerprintTemplate> {
    match name {
        "chrome-desktop" => Some(&CHROME_DESKTOP),
        "firefox-desktop" => Some(&FIREFOX_DESKTOP),
        "safari-desktop" => Some(&SAFARI_DESKTOP),
        _ => None,
    }
}

/// All built-in fingerprint templates, in stable order. Used by
/// [`pick_random_template`] for per-session rotation.
pub const ALL_TEMPLATES: &[&TlsFingerprintTemplate] =
    &[&CHROME_DESKTOP, &FIREFOX_DESKTOP, &SAFARI_DESKTOP];

/// Pick a fingerprint template uniformly at random from
/// [`ALL_TEMPLATES`]. Used per-session to defeat the "Mirage always
/// looks like Chrome" passive distinguisher.
///
/// Rationale: freshness +
/// the v0.1t analyst-finding response (per-session diversity beats
/// per-deployment diversity for population-statistics resistance).
///
/// Determinism: uses the OS CSPRNG. On RNG failure (vanishingly
/// rare; typically only on a misconfigured container without
/// /dev/urandom) falls back to [`CHROME_DESKTOP`] rather than
/// panicking.
///
/// Prefer [`pick_weighted_template`] in production: uniform
/// rotation makes Mirage look like a population that's
/// ~33% Firefox, but real-world traffic is closer to 75% Chrome,
/// 15% Safari, 10% Firefox. The weighted variant matches that
/// distribution, closing the population-statistics tail of
/// [RT-CN-4].
pub fn pick_random_template() -> &'static TlsFingerprintTemplate {
    let mut byte = [0u8; 1];
    let idx: usize = match getrandom::fill(&mut byte) {
        Ok(_) => byte[0] as usize % ALL_TEMPLATES.len(),
        Err(_) => 0,
    };
    ALL_TEMPLATES[idx]
}

/// Pick a fingerprint template weighted by approximate
/// real-world browser-population shares. Closes [RT-CN-4]
/// (population-statistics tail): uniform random over {Chrome,
/// Firefox, Safari} produces a 33%-each distribution; real-world
/// passive observation sees ~75% Chrome / 15% Safari / 10%
/// Firefox (rough StatCounter-style numbers, late 2025). With
/// uniform rotation, a censor running a long-flow population
/// classifier would see "this network has too much Firefox" -
/// itself a Mirage signature. Weighted rotation makes Mirage's
/// JA3 distribution match the host network's real distribution.
///
/// Operators in regions with different browser-share patterns
/// (e.g., heavy QQ Browser in CN, Yandex in RU) SHOULD inject a
/// custom template + adjust weights via [`pick_weighted_from`];
/// the built-in defaults are tuned for global-average traffic.
///
/// CSPRNG failure: falls back to [`CHROME_DESKTOP`] (the highest-
/// share template), preserving population blending under
/// degraded conditions.
pub fn pick_weighted_template() -> &'static TlsFingerprintTemplate {
    // Red-team round 2: pick ONCE per process and reuse it for every Reality
    // connection. A real device runs ONE browser, so drawing a fresh
    // browser-family template per connection means one source IP flips
    // Chrome/Firefox/Safari across reconnects - a zero-false-positive passive
    // correlation tell (the same class as the WS persona fix). The weighted draw
    // still shapes the population ACROSS clients (each client is a stable sample
    // from the Chrome-75/Safari-15/Firefox-10 distribution); it just no longer
    // rotates WITHIN one client.
    static PINNED: std::sync::OnceLock<&'static TlsFingerprintTemplate> =
        std::sync::OnceLock::new();
    PINNED.get_or_init(pick_weighted_population)
}

/// The per-client population draw underlying [`pick_weighted_template`], WITHOUT
/// the per-process pin.
///
/// A fresh client calls [`pick_weighted_template`] once and reuses the pinned
/// result for every connection (one device runs one browser). This exposes the
/// same weighted draw un-pinned, so population-level analysis - e.g. an
/// adversary modelling a censor's JA3 sample across MANY independent clients -
/// can simulate N separate clients by calling this N times. Weights and template
/// set live here in one place so the pinned and population views never drift.
pub fn pick_weighted_population() -> &'static TlsFingerprintTemplate {
    // Weights: Chrome 75, Safari 15, Firefox 10 -> bucket sum 100.
    // Order matches ALL_TEMPLATES order.
    pick_weighted_from(&[
        (&CHROME_DESKTOP, 75),
        (&FIREFOX_DESKTOP, 10),
        (&SAFARI_DESKTOP, 15),
    ])
}

/// Generic weighted picker. Operators with region-specific
/// distributions (e.g., heavy WeChat / Yandex / Samsung Internet)
/// can pass their own (`template`, `weight`) pairs. Weights need
/// not sum to 100; the picker normalises.
///
/// Returns [`CHROME_DESKTOP`] if the slice is empty or weights
/// sum to zero (defensive - a misconfigured pool shouldn't
/// crash).
pub fn pick_weighted_from(
    pool: &[(&'static TlsFingerprintTemplate, u32)],
) -> &'static TlsFingerprintTemplate {
    let total: u32 = pool.iter().map(|&(_, w)| w).sum();
    if total == 0 || pool.is_empty() {
        return &CHROME_DESKTOP;
    }
    let mut buf = [0u8; 4];
    let pick: u32 = match getrandom::fill(&mut buf) {
        Ok(()) => u32::from_le_bytes(buf) % total,
        Err(_) => return &CHROME_DESKTOP,
    };
    let mut acc: u32 = 0;
    for &(tpl, w) in pool {
        acc = acc.saturating_add(w);
        if pick < acc {
            return tpl;
        }
    }
    pool[pool.len() - 1].0
}

// JA3 computation

/// Compute the JA3 fingerprint STRING for a template. This is the
/// input to the MD5 hash step if a caller wants the standard JA3
/// hash; the string alone is sufficient for regression / drift
/// comparison and is what CI pins.
pub fn ja3_string(t: &TlsFingerprintTemplate) -> String {
    let mut s = String::with_capacity(256);
    // SSLVersion
    let v = u16::from_be_bytes(t.legacy_version);
    let _ = write!(s, "{v},");
    // Cipher
    write_u16_list(&mut s, t.cipher_suites);
    s.push(',');
    // SSLExtension (GREASE excluded from the JA3 string - still emitted on the wire)
    write_u16_list(&mut s, t.extension_order);
    s.push(',');
    // EllipticCurve
    write_u16_list(&mut s, t.supported_groups);
    s.push(',');
    // EllipticCurvePointFormat
    write_u8_list(&mut s, t.ec_point_formats);
    s
}

fn write_u16_list(out: &mut String, xs: &[u16]) {
    for (i, x) in xs.iter().enumerate() {
        if i > 0 {
            out.push('-');
        }
        let _ = write!(out, "{x}");
    }
}

fn write_u8_list(out: &mut String, xs: &[u8]) {
    for (i, x) in xs.iter().enumerate() {
        if i > 0 {
            out.push('-');
        }
        let _ = write!(out, "{x}");
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // ----------- JA3 string pinning (A26 drift detection) -----------

    #[test]
    fn chrome_ja3_string_pinned() {
        // If this fails after a library change, the Chrome template
        // has drifted. Compare against a known-current Chrome JA3
        // before accepting the change - operators rely on the
        // template matching real Chrome wire shape.
        //
        // 4588 = X25519MLKEM768 (post-quantum hybrid). Chrome 124+
        // ships this as the first entry in supported_groups; templates
        // missing it stand out against modern population baselines.
        let got = ja3_string(&CHROME_DESKTOP);
        // 65037 = 0xfe0d encrypted_client_hello (GREASE ECH). Not a GREASE
        // codepoint, so it legitimately appears in JA3 - real Chrome (>=M117)
        // includes it too (red-team HIGH #1).
        let want = "771,\
                    4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
                    0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-65037,\
                    4588-29-23-24,\
                    0";
        assert_eq!(got, want, "Chrome JA3 string drift");
    }

    #[test]
    fn firefox_ja3_string_pinned() {
        // Firefox 132+ also advertises X25519MLKEM768 (4588) ahead of
        // x25519. See chrome pin above for context.
        let got = ja3_string(&FIREFOX_DESKTOP);
        // 65037 = 0xfe0d encrypted_client_hello (GREASE ECH); Firefox >=132
        // sends it too (red-team HIGH #1).
        let want = "771,\
                    4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,\
                    0-23-65281-10-11-16-13-43-45-28-51-65037,\
                    4588-29-23-24,\
                    0";
        assert_eq!(got, want, "Firefox JA3 string drift");
    }

    #[test]
    fn safari_ja3_string_pinned() {
        let got = ja3_string(&SAFARI_DESKTOP);
        let want = "771,\
                    4865-4866-4867-49196-49195-49200-49199-157-156-53-47-49188-49187-49192-49191,\
                    0-23-65281-10-11-16-43-13-51,\
                    29-23-24,\
                    0";
        assert_eq!(got, want, "Safari JA3 string drift");
    }

    // ----------- no cross-template collisions -----------

    #[test]
    fn templates_have_distinct_ja3() {
        let c = ja3_string(&CHROME_DESKTOP);
        let f = ja3_string(&FIREFOX_DESKTOP);
        let s = ja3_string(&SAFARI_DESKTOP);
        assert_ne!(c, f, "Chrome != Firefox");
        assert_ne!(c, s, "Chrome != Safari");
        assert_ne!(f, s, "Firefox != Safari");
    }

    // ----------- lookup -----------

    #[test]
    fn lookup_returns_each_template() {
        assert_eq!(lookup("chrome-desktop").unwrap().name, "chrome-desktop");
        assert_eq!(lookup("firefox-desktop").unwrap().name, "firefox-desktop");
        assert_eq!(lookup("safari-desktop").unwrap().name, "safari-desktop");
        assert!(lookup("wat").is_none());
    }

    // ----------- sanity on required extensions -----------

    #[test]
    fn each_template_advertises_key_share_and_supported_versions() {
        for t in [&CHROME_DESKTOP, &FIREFOX_DESKTOP, &SAFARI_DESKTOP] {
            assert!(
                t.extension_order.contains(&EXT_KEY_SHARE),
                "{}: key_share missing",
                t.name
            );
            assert!(
                t.extension_order.contains(&EXT_SUPPORTED_VERSIONS),
                "{}: supported_versions missing",
                t.name
            );
            assert!(
                t.extension_order.contains(&EXT_SERVER_NAME),
                "{}: server_name missing",
                t.name
            );
            assert!(
                t.supported_groups.contains(&GROUP_X25519),
                "{}: x25519 group missing",
                t.name
            );
            assert!(
                t.sig_algs.contains(&SIG_ECDSA_SECP256R1_SHA256),
                "{}: ecdsa_secp256r1_sha256 missing (Mirage bridge signs CertVerify with it)",
                t.name
            );
            assert!(
                !t.sig_algs.contains(&SIG_ED25519),
                "{}: ed25519 (0x0807) must NOT be advertised - no desktop browser does (JA4 tell)",
                t.name
            );
        }
    }

    #[test]
    fn modern_browsers_advertise_pq_hybrid_group() {
        // Chrome 124+ and Firefox 132+ both advertise X25519MLKEM768.
        // Templates that don't carry it look dated against current
        // population baselines.
        for t in [&CHROME_DESKTOP, &FIREFOX_DESKTOP] {
            assert!(
                t.supported_groups.contains(&GROUP_X25519_MLKEM768),
                "{}: missing X25519MLKEM768",
                t.name
            );
            // It should be the FIRST entry (Chrome ships it first;
            // Firefox follows the same convention).
            assert_eq!(
                t.supported_groups[0], GROUP_X25519_MLKEM768,
                "{}: X25519MLKEM768 should be first in supported_groups",
                t.name
            );
        }
    }

    // ----------- v0.1t per-session rotation (analyst finding) -----------

    #[test]
    #[allow(clippy::const_is_empty)] // deliberately asserts the template pool is populated
    fn all_templates_set_is_non_empty() {
        assert!(!ALL_TEMPLATES.is_empty(), "rotation pool must be populated");
    }

    #[test]
    fn pick_random_template_returns_known_template() {
        // Every random pick must come from the registered set so a
        // misconfigured rng never produces an unknown fingerprint.
        let names: std::collections::HashSet<&'static str> =
            ALL_TEMPLATES.iter().map(|t| t.name).collect();
        for _ in 0..32 {
            let pick = pick_random_template();
            assert!(
                names.contains(pick.name),
                "rotation produced template not in ALL_TEMPLATES: {}",
                pick.name
            );
        }
    }

    #[test]
    fn rotation_actually_rotates() {
        // Across 256 picks at uniform 1/3 probability per template,
        // the chance of any single template being missed entirely
        // is `(2/3)^256` ~ 10^-46, statistically zero. So a rotation
        // pool of >= 2 templates MUST surface every template in this
        // sample window.
        let mut seen: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
        for _ in 0..256 {
            seen.insert(pick_random_template().name);
        }
        assert_eq!(
            seen.len(),
            ALL_TEMPLATES.len(),
            "rotation must touch every template in the pool"
        );
    }

    // ----------- RT-CN-4: weighted population blending -----------

    #[test]
    fn weighted_template_distribution_matches_real_world() {
        // Sample 10_000 picks; expected counts:
        //   Chrome ~7500 (75%)
        //   Firefox ~1000 (10%)
        //   Safari ~1500 (15%)
        // Allow +/-10% absolute slack for binomial variance.
        let mut chrome = 0;
        let mut firefox = 0;
        let mut safari = 0;
        // Exercise the underlying weighted picker directly: `pick_weighted_template`
        // is now pinned per-process (red-team round 2: one client = one browser),
        // so it would return a single template here. The population shape lives in
        // `pick_weighted_from`, which is what each fresh client draws from once.
        let pool: &[(&'static TlsFingerprintTemplate, u32)] = &[
            (&CHROME_DESKTOP, 75),
            (&FIREFOX_DESKTOP, 10),
            (&SAFARI_DESKTOP, 15),
        ];
        for _ in 0..10_000 {
            match pick_weighted_from(pool).name {
                "chrome-desktop" => chrome += 1,
                "firefox-desktop" => firefox += 1,
                "safari-desktop" => safari += 1,
                other => panic!("unknown template name: {other}"),
            }
        }
        assert!(
            (6500..=8500).contains(&chrome),
            "chrome share off: {chrome}/10000 (expected ~7500)"
        );
        assert!(
            (500..=1500).contains(&firefox),
            "firefox share off: {firefox}/10000 (expected ~1000)"
        );
        assert!(
            (1000..=2000).contains(&safari),
            "safari share off: {safari}/10000 (expected ~1500)"
        );
    }

    #[test]
    fn pick_weighted_template_is_pinned_per_process() {
        // Red-team round 2: a real device runs ONE browser, so the auto-picked
        // fingerprint MUST be stable within a process - otherwise one source IP
        // flips Chrome/Firefox/Safari across reconnects (a passive tell).
        let first = pick_weighted_template().name;
        for _ in 0..1000 {
            assert_eq!(
                pick_weighted_template().name,
                first,
                "pick_weighted_template must return a stable per-process fingerprint"
            );
        }
    }

    #[test]
    fn pick_weighted_from_with_zero_weights_falls_back_to_chrome() {
        let pool: Vec<(&'static TlsFingerprintTemplate, u32)> =
            vec![(&FIREFOX_DESKTOP, 0), (&SAFARI_DESKTOP, 0)];
        let pick = pick_weighted_from(&pool);
        assert_eq!(pick.name, "chrome-desktop");
    }

    #[test]
    fn pick_weighted_from_with_empty_pool_falls_back_to_chrome() {
        let pool: Vec<(&'static TlsFingerprintTemplate, u32)> = Vec::new();
        let pick = pick_weighted_from(&pool);
        assert_eq!(pick.name, "chrome-desktop");
    }

    #[test]
    fn pick_weighted_from_respects_single_template_pool() {
        let pool = vec![(&FIREFOX_DESKTOP, 100)];
        for _ in 0..100 {
            let pick = pick_weighted_from(&pool);
            assert_eq!(pick.name, "firefox-desktop");
        }
    }
}
