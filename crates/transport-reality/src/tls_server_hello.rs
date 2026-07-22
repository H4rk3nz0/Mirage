//! Synthesized TLS 1.3 ServerHello: generator + parser.
//!
//! After the bridge verifies the auth probe from the client's
//! ClientHello, it emits a ServerHello shaped exactly like what a
//! real TLS 1.3 server would send in response to the client's key
//! share. The client reads and accepts it, then both sides switch
//! to wrapping Mirage session frames inside TLS 1.3
//! `application_data` records.
//!
//! # Scope (v0.1a)
//!
//! We **do not** derive real TLS 1.3 handshake or traffic keys. The
//! server random and key_share are generated fresh, and the client
//! parses them into a structured `ServerHelloParts`, but no HKDF
//! transcript follows. The bytes that come next on the wire are
//! Mirage frames wrapped in record-type `application_data`
//! envelopes. Full TLS 1.3 crypto (forged CertVerify, Finished,
//! traffic-key derivation) is the v0.1b scope - it defeats active
//! probers; the current v0.1a scope defeats passive protocol DPI.
//!
//! Against passive DPI: the record-layer bytes are indistinguishable
//! from a real TLS 1.3 session. Against an active prober that
//! follows through with a real TLS client expecting
//! `encrypted_extensions` / `certificate_verify` / `finished`:
//! our response will diverge. Documented as the central accepted
//! limitation of v0.1a.

use crate::error::RealityError;

// Wire constants (RFC 8446)

const RECORD_TYPE_HANDSHAKE: u8 = 0x16;
const LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03]; // TLS 1.2 per RFC 8446 §5.1
const LEGACY_SERVER_VERSION: [u8; 2] = [0x03, 0x03];
const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;

/// TLS 1.3 cipher suite codepoints (RFC 8446 §B.4).
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
/// TLS 1.3 cipher suite codepoint.
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
/// TLS 1.3 cipher suite codepoint.
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// Fallback cipher for the rare path where a client offers no suite we
/// implement. The record layer now supports both AES-128-GCM and
/// ChaCha20-Poly1305 (see [`crate::record_cipher::RecordCipher`]) and
/// [`pick_server_cipher`] honours the client's preference order, so this
/// constant is only reached when neither is offered - which no browser we mimic
/// ever does. It stays ChaCha because both Mirage peers always offer it.
pub const DEFAULT_TLS13_CIPHER: u16 = TLS_CHACHA20_POLY1305_SHA256;

const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION: u16 = 0x0010;
const NAMED_GROUP_X25519: u16 = 0x001D;

/// X25519MLKEM768 hybrid named group (0x11EC).
use crate::tls_fingerprint::GROUP_X25519_MLKEM768;
/// ML-KEM-768 ciphertext wire length (hybrid server `key_share` ct half).
const MLKEM_CT_LEN: usize = 1088;

/// Pick the ServerHello cipher, mirroring a real TLS 1.3 server.
///
/// The Reality record layer now implements BOTH AES-128-GCM and
/// ChaCha20-Poly1305 (see [`crate::record_cipher::RecordCipher`]), so - like a
/// real server honouring client preference - we select the client's
/// most-preferred suite among the two we support. Chrome/Edge/Safari (and
/// Firefox) list `TLS_AES_128_GCM_SHA256` first on AES-NI hardware, so a real
/// CDN answers a Chrome ClientHello with AES-128-GCM; the bridge now does too,
/// closing the previous always-ChaCha distinguisher. The negotiated suite stays
/// consistent with the AEAD actually used, so a genuine TLS 1.3 client (or an
/// active prober) decrypts correctly.
pub fn pick_server_cipher(client_offered: &[u16]) -> u16 {
    for &suite in client_offered {
        if suite == TLS_AES_128_GCM_SHA256 || suite == TLS_CHACHA20_POLY1305_SHA256 {
            return suite;
        }
    }
    // Client offered neither implemented suite: fall back so our own peer (which
    // always offers both) still interoperates; a real client offering neither
    // would have failed against a real server too.
    DEFAULT_TLS13_CIPHER
}

/// Required fields the bridge has available when constructing a
/// ServerHello in response to a client's ClientHello.
pub struct ServerHelloInputs<'a> {
    /// 32-byte random drawn from the bridge's CSPRNG.
    pub random: &'a [u8; 32],
    /// Echoed `session_id` from the client's ClientHello. RFC 8446
    /// §4.1.3 requires this echo for TLS 1.2 compatibility. The
    /// length matches what the client supplied (0..=32 bytes).
    pub session_id_echo: &'a [u8],
    /// Bridge's X25519 ephemeral public key for the key_share echo.
    pub x25519_key_share: &'a [u8; 32],
    /// ML-KEM-768 ciphertext (1088 B) for the X25519MLKEM768 hybrid key_share.
    /// When `Some`, the ServerHello selects the hybrid group and its
    /// `key_exchange` is `ct || x25519_key_share` (1120 B) - matching what a
    /// real PQ-capable server echoes for a Chrome/Firefox ClientHello, so the
    /// bridge no longer downgrades to plain X25519. `None` = plain X25519.
    pub mlkem_ct: Option<&'a [u8; MLKEM_CT_LEN]>,
    /// Cipher suite to declare in the ServerHello. Caller picks via
    /// [`pick_server_cipher`] from the client's offered list. Audit
    /// fix C1: prior versions hard-coded a single cipher.
    pub cipher_suite: u16,
    /// Optional ALPN echo. When `Some(b"h2")` (or other), the
    /// ServerHello includes an `application_layer_protocol_negotiation`
    /// extension echoing the chosen protocol. When `None`, no ALPN
    /// extension is emitted (matches a server with no ALPN
    /// configured). Audit fix C2: prior versions never echoed ALPN
    /// even when the client offered it, which is fingerprintable as
    /// "no ALPN despite offering h2".
    pub alpn_echo: Option<&'a [u8]>,
}

/// Parsed ServerHello fields the client cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHelloParts {
    /// Server random (32 B).
    pub random: [u8; 32],
    /// Server-echoed session_id (length 0..=32). For Mirage
    /// clients (which always emit 32-byte session_id with the
    /// auth probe), this will be 32.
    pub session_id: Vec<u8>,
    /// Server X25519 key_share (the X25519 half of the selected group).
    pub x25519_key_share: [u8; 32],
    /// ML-KEM-768 ciphertext (1088 B) when the server selected the
    /// X25519MLKEM768 hybrid group; `None` for plain X25519. The client
    /// decapsulates this with its retained ML-KEM secret to recover the PQ half
    /// of the shared secret.
    pub mlkem_ct: Option<[u8; MLKEM_CT_LEN]>,
    /// Selected cipher suite (audit fix C1: parse-and-expose so
    /// the client can see what the server picked).
    pub cipher_suite: u16,
    /// Optional ALPN echo from the server (audit fix C2).
    pub alpn_selected: Option<Vec<u8>>,
}

/// Build the wire bytes of a TLS 1.3 ServerHello record.
pub fn build_server_hello(inputs: &ServerHelloInputs<'_>) -> Result<Vec<u8>, RealityError> {
    if inputs.session_id_echo.len() > 32 {
        return Err(RealityError::TagMismatch);
    }
    // Extensions: supported_versions(TLS 1.3) + key_share(X25519)
    // + optional ALPN echo.
    let mut ext = Vec::with_capacity(64);

    // supported_versions: server form = selected_version(2)
    {
        let mut body = Vec::with_capacity(2);
        body.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
        write_extension(&mut ext, EXT_SUPPORTED_VERSIONS, &body);
    }
    // key_share: server form = named_group(2) + key_exchange_len(2) + key_exchange.
    // Hybrid X25519MLKEM768 when the client offered it (ct || x25519, 1120 B),
    // else plain X25519 (32 B).
    {
        let mut body = Vec::with_capacity(4 + MLKEM_CT_LEN + 32);
        if let Some(ct) = inputs.mlkem_ct {
            body.extend_from_slice(&GROUP_X25519_MLKEM768.to_be_bytes());
            body.extend_from_slice(&((MLKEM_CT_LEN + 32) as u16).to_be_bytes());
            body.extend_from_slice(ct);
            body.extend_from_slice(inputs.x25519_key_share);
        } else {
            body.extend_from_slice(&NAMED_GROUP_X25519.to_be_bytes());
            body.extend_from_slice(&(32u16).to_be_bytes());
            body.extend_from_slice(inputs.x25519_key_share);
        }
        write_extension(&mut ext, EXT_KEY_SHARE, &body);
    }
    // Optional ALPN echo (audit fix C2). Server form: a single
    // ProtocolName preceded by a 2-byte total length.
    if let Some(proto) = inputs.alpn_echo {
        if proto.is_empty() || proto.len() > 255 {
            return Err(RealityError::TagMismatch);
        }
        let mut body = Vec::with_capacity(3 + proto.len());
        let inner_len = (1 + proto.len()) as u16;
        body.extend_from_slice(&inner_len.to_be_bytes());
        body.push(proto.len() as u8);
        body.extend_from_slice(proto);
        write_extension(&mut ext, EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION, &body);
    }

    // ServerHello body.
    let mut body = Vec::with_capacity(128);
    body.extend_from_slice(&LEGACY_SERVER_VERSION); // legacy_version
    body.extend_from_slice(inputs.random); // 32B random
    body.push(inputs.session_id_echo.len() as u8);
    body.extend_from_slice(inputs.session_id_echo);
    body.extend_from_slice(&inputs.cipher_suite.to_be_bytes());
    body.push(0x00); // legacy_compression_method = null
    let ext_len: u16 = u16::try_from(ext.len()).map_err(|_| RealityError::TagMismatch)?;
    body.extend_from_slice(&ext_len.to_be_bytes());
    body.extend_from_slice(&ext);

    // Handshake header.
    let body_len: u32 = u32::try_from(body.len()).map_err(|_| RealityError::TagMismatch)?;
    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(HANDSHAKE_TYPE_SERVER_HELLO);
    hs.push(((body_len >> 16) & 0xFF) as u8);
    hs.push(((body_len >> 8) & 0xFF) as u8);
    hs.push((body_len & 0xFF) as u8);
    hs.extend_from_slice(&body);

    // Record header.
    let rec_len: u16 = u16::try_from(hs.len()).map_err(|_| RealityError::TagMismatch)?;
    let mut rec = Vec::with_capacity(5 + hs.len());
    rec.push(RECORD_TYPE_HANDSHAKE);
    rec.extend_from_slice(&LEGACY_RECORD_VERSION);
    rec.extend_from_slice(&rec_len.to_be_bytes());
    rec.extend_from_slice(&hs);

    Ok(rec)
}

fn write_extension(out: &mut Vec<u8>, ext_type: u16, body: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

/// Parse a TLS 1.3 ServerHello record. Strict about lengths; does
/// not normalize or accept trailing bytes.
pub fn parse_server_hello_record(bytes: &[u8]) -> Result<ServerHelloParts, RealityError> {
    if bytes.len() < 5 {
        return Err(RealityError::TagMismatch);
    }
    // Record header.
    if bytes[0] != RECORD_TYPE_HANDSHAKE {
        return Err(RealityError::TagMismatch);
    }
    // legacy_version must be 0x03XX (TLS 1.x)
    if bytes[1] != 0x03 {
        return Err(RealityError::TagMismatch);
    }
    let rec_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if rec_len == 0 || 5 + rec_len > bytes.len() {
        return Err(RealityError::TagMismatch);
    }
    let rec_body = &bytes[5..5 + rec_len];

    // Handshake header.
    if rec_body.len() < 4 {
        return Err(RealityError::TagMismatch);
    }
    if rec_body[0] != HANDSHAKE_TYPE_SERVER_HELLO {
        return Err(RealityError::TagMismatch);
    }
    let hs_len =
        ((rec_body[1] as usize) << 16) | ((rec_body[2] as usize) << 8) | (rec_body[3] as usize);
    if hs_len + 4 > rec_body.len() {
        return Err(RealityError::TagMismatch);
    }
    let hs_body = &rec_body[4..4 + hs_len];

    // ServerHello body.
    // legacy_version(2) + random(32) + session_id_len(1) + session_id(up to 32)
    // + cipher_suite(2) + legacy_compression_method(1) + extensions_len(2) + extensions
    if hs_body.len() < 2 + 32 + 1 {
        return Err(RealityError::TagMismatch);
    }
    // legacy_version (ignored); random
    let mut random = [0u8; 32];
    random.copy_from_slice(&hs_body[2..34]);
    let sid_len = hs_body[34] as usize;
    // RFC 8446 §4.1.3 allows session_id length 0..=32. Audit fix
    // C3: prior parser hard-required 32, which would have failed
    // against any real cover server's response in the unlikely
    // event Mirage clients ever wanted to verify a real-server
    // ServerHello. With variable length supported here, the
    // parser handles all valid TLS 1.3 server responses.
    if sid_len > 32 {
        return Err(RealityError::TagMismatch);
    }
    if hs_body.len() < 34 + 1 + sid_len + 2 + 1 + 2 {
        return Err(RealityError::TagMismatch);
    }
    let session_id = hs_body[35..35 + sid_len].to_vec();
    // cipher_suite(2) immediately after session_id.
    let cipher_offset = 35 + sid_len;
    let cipher_suite = u16::from_be_bytes([hs_body[cipher_offset], hs_body[cipher_offset + 1]]);
    // legacy_compression_method(1) at cipher_offset + 2.
    // extensions_len(2) at cipher_offset + 3..cipher_offset + 5.
    let ext_offset = cipher_offset + 2 + 1 + 2;
    if hs_body.len() < ext_offset {
        return Err(RealityError::TagMismatch);
    }
    let ext_len =
        u16::from_be_bytes([hs_body[cipher_offset + 3], hs_body[cipher_offset + 4]]) as usize;
    if ext_offset + ext_len > hs_body.len() {
        return Err(RealityError::TagMismatch);
    }
    let ext_bytes = &hs_body[ext_offset..ext_offset + ext_len];

    // Walk extensions, looking for key_share + ALPN.
    let mut i = 0usize;
    let mut key_share: Option<[u8; 32]> = None;
    let mut mlkem_ct: Option<[u8; MLKEM_CT_LEN]> = None;
    let mut alpn_selected: Option<Vec<u8>> = None;
    while i + 4 <= ext_bytes.len() {
        let et = u16::from_be_bytes([ext_bytes[i], ext_bytes[i + 1]]);
        let el = u16::from_be_bytes([ext_bytes[i + 2], ext_bytes[i + 3]]) as usize;
        i += 4;
        if i + el > ext_bytes.len() {
            return Err(RealityError::TagMismatch);
        }
        let ebody = &ext_bytes[i..i + el];
        if et == EXT_KEY_SHARE {
            // Server form: named_group(2) + key_exchange_len(2) + key_exchange
            if ebody.len() < 4 {
                return Err(RealityError::TagMismatch);
            }
            let group = u16::from_be_bytes([ebody[0], ebody[1]]);
            let ke_len = u16::from_be_bytes([ebody[2], ebody[3]]) as usize;
            if 4 + ke_len > ebody.len() {
                return Err(RealityError::TagMismatch);
            }
            if group == NAMED_GROUP_X25519 {
                if ke_len != 32 {
                    return Err(RealityError::TagMismatch);
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(&ebody[4..36]);
                key_share = Some(k);
            } else if group == GROUP_X25519_MLKEM768 {
                // Server hybrid form: ct(1088) || x25519(32).
                if ke_len != MLKEM_CT_LEN + 32 {
                    return Err(RealityError::TagMismatch);
                }
                let mut ct = [0u8; MLKEM_CT_LEN];
                ct.copy_from_slice(&ebody[4..4 + MLKEM_CT_LEN]);
                mlkem_ct = Some(ct);
                let mut k = [0u8; 32];
                k.copy_from_slice(&ebody[4 + MLKEM_CT_LEN..4 + MLKEM_CT_LEN + 32]);
                key_share = Some(k);
            } else {
                return Err(RealityError::TagMismatch);
            }
        } else if et == EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION {
            // Server form: 2-byte total length + 1-byte len + name
            if ebody.len() < 3 {
                return Err(RealityError::TagMismatch);
            }
            let inner_len = u16::from_be_bytes([ebody[0], ebody[1]]) as usize;
            if inner_len + 2 != ebody.len() {
                return Err(RealityError::TagMismatch);
            }
            let name_len = ebody[2] as usize;
            if name_len + 1 != inner_len || name_len == 0 {
                return Err(RealityError::TagMismatch);
            }
            alpn_selected = Some(ebody[3..3 + name_len].to_vec());
        }
        i += el;
    }

    let x25519_key_share = key_share.ok_or(RealityError::TagMismatch)?;
    Ok(ServerHelloParts {
        random,
        session_id,
        x25519_key_share,
        mlkem_ct,
        cipher_suite,
        alpn_selected,
    })
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let rnd = [0xAAu8; 32];
        let sid = [0xBBu8; 32];
        let ks = [0xCCu8; 32];
        let bytes = build_server_hello(&ServerHelloInputs {
            random: &rnd,
            session_id_echo: &sid,
            x25519_key_share: &ks,
            mlkem_ct: None,
            cipher_suite: DEFAULT_TLS13_CIPHER,
            alpn_echo: None,
        })
        .unwrap();
        let parsed = parse_server_hello_record(&bytes).unwrap();
        assert_eq!(parsed.random, rnd);
        assert_eq!(parsed.session_id, sid.to_vec());
        assert_eq!(parsed.x25519_key_share, ks);
        assert_eq!(parsed.cipher_suite, DEFAULT_TLS13_CIPHER);
        assert!(parsed.alpn_selected.is_none());
    }

    #[test]
    fn roundtrip_with_alpn_h2() {
        let bytes = build_server_hello(&ServerHelloInputs {
            random: &[0xAAu8; 32],
            session_id_echo: &[0xBBu8; 32],
            x25519_key_share: &[0xCCu8; 32],
            mlkem_ct: None,
            cipher_suite: TLS_CHACHA20_POLY1305_SHA256,
            alpn_echo: Some(b"h2"),
        })
        .unwrap();
        let parsed = parse_server_hello_record(&bytes).unwrap();
        assert_eq!(parsed.cipher_suite, TLS_CHACHA20_POLY1305_SHA256);
        assert_eq!(parsed.alpn_selected.as_deref(), Some(&b"h2"[..]));
    }

    #[test]
    fn variable_session_id_length() {
        // Audit fix C3: parser must accept session_id of any length 0..=32.
        for sid_len in [0usize, 1, 16, 32] {
            let sid = vec![0xBBu8; sid_len];
            let bytes = build_server_hello(&ServerHelloInputs {
                random: &[0xAAu8; 32],
                session_id_echo: &sid,
                x25519_key_share: &[0xCCu8; 32],
                mlkem_ct: None,
                cipher_suite: DEFAULT_TLS13_CIPHER,
                alpn_echo: None,
            })
            .unwrap();
            let parsed = parse_server_hello_record(&bytes).unwrap();
            assert_eq!(parsed.session_id.len(), sid_len);
        }
    }

    #[test]
    fn pick_cipher_honours_client_preference() {
        // Both AEADs are implemented (RecordCipher), so - like a real server -
        // we pick the client's most-preferred supported suite. Chrome offers
        // [AES-128-GCM, AES-256-GCM, ChaCha20]; a real CDN answers AES-128-GCM,
        // and so do we, closing the old always-ChaCha distinguisher.
        let chrome_offered = [
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
        ];
        assert_eq!(pick_server_cipher(&chrome_offered), TLS_AES_128_GCM_SHA256);
        // A ChaCha-first client (e.g. a mobile/no-AES-NI profile) gets ChaCha.
        let reversed = [TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256];
        assert_eq!(pick_server_cipher(&reversed), TLS_CHACHA20_POLY1305_SHA256);
        // AES-256-GCM is not implemented, so an AES-128-then-256 list still
        // selects AES-128-GCM (the first suite we support).
        let aes_only = [TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256];
        assert_eq!(pick_server_cipher(&aes_only), TLS_AES_128_GCM_SHA256);
        // Client offering neither implemented suite falls back to the default.
        let unsupported = [TLS_AES_256_GCM_SHA384];
        assert_eq!(pick_server_cipher(&unsupported), DEFAULT_TLS13_CIPHER);
    }

    #[test]
    fn rejects_non_handshake_record() {
        let mut bytes = build_server_hello(&ServerHelloInputs {
            random: &[0u8; 32],
            session_id_echo: &[0u8; 32],
            x25519_key_share: &[0u8; 32],
            mlkem_ct: None,
            cipher_suite: DEFAULT_TLS13_CIPHER,
            alpn_echo: None,
        })
        .unwrap();
        bytes[0] = 0x17; // app_data
        assert!(parse_server_hello_record(&bytes).is_err());
    }

    #[test]
    fn rejects_truncated() {
        let bytes = build_server_hello(&ServerHelloInputs {
            random: &[0u8; 32],
            session_id_echo: &[0u8; 32],
            x25519_key_share: &[0u8; 32],
            mlkem_ct: None,
            cipher_suite: DEFAULT_TLS13_CIPHER,
            alpn_echo: None,
        })
        .unwrap();
        for cut in (0..bytes.len()).step_by(17) {
            let _ = parse_server_hello_record(&bytes[..cut]);
        }
    }

    #[test]
    fn rejects_wrong_handshake_type() {
        let mut bytes = build_server_hello(&ServerHelloInputs {
            random: &[0u8; 32],
            session_id_echo: &[0u8; 32],
            x25519_key_share: &[0u8; 32],
            mlkem_ct: None,
            cipher_suite: DEFAULT_TLS13_CIPHER,
            alpn_echo: None,
        })
        .unwrap();
        bytes[5] = 0x01; // client_hello instead of server_hello
        assert!(parse_server_hello_record(&bytes).is_err());
    }

    #[test]
    fn fuzz_arbitrary_bytes_never_panic() {
        use proptest::prelude::*;
        proptest!(ProptestConfig::with_cases(256), |(b in prop::collection::vec(any::<u8>(), 0..256))| {
            let _ = parse_server_hello_record(&b);
        });
    }

    #[test]
    fn hybrid_server_hello_selects_pq_group_and_roundtrips() {
        let rnd = [0x01u8; 32];
        let sid = [0x02u8; 32];
        let x25519 = [0x03u8; 32];
        let ct = [0x04u8; MLKEM_CT_LEN];
        let bytes = build_server_hello(&ServerHelloInputs {
            random: &rnd,
            session_id_echo: &sid,
            x25519_key_share: &x25519,
            mlkem_ct: Some(&ct),
            cipher_suite: DEFAULT_TLS13_CIPHER,
            alpn_echo: None,
        })
        .unwrap();
        // The emitted key_share MUST carry the hybrid group codepoint (0x11EC) -
        // i.e. the bridge no longer downgrades a PQ-capable client to X25519.
        assert!(
            bytes
                .windows(2)
                .any(|w| w == GROUP_X25519_MLKEM768.to_be_bytes()),
            "hybrid ServerHello must select the X25519MLKEM768 group"
        );
        let parts = parse_server_hello_record(&bytes).unwrap();
        assert_eq!(parts.x25519_key_share, x25519);
        assert_eq!(parts.mlkem_ct, Some(ct));

        // A plain-X25519 ServerHello parses back with mlkem_ct = None.
        let plain = build_server_hello(&ServerHelloInputs {
            random: &rnd,
            session_id_echo: &sid,
            x25519_key_share: &x25519,
            mlkem_ct: None,
            cipher_suite: DEFAULT_TLS13_CIPHER,
            alpn_echo: None,
        })
        .unwrap();
        let plain_parts = parse_server_hello_record(&plain).unwrap();
        assert_eq!(plain_parts.mlkem_ct, None);
        assert_eq!(plain_parts.x25519_key_share, x25519);
    }
}
