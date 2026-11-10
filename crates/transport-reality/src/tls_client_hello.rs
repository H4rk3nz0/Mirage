//! Minimal TLS 1.3 ClientHello parser.
//!
//! The bridge consumes incoming TLS ClientHellos and must extract:
//! - `legacy_session_id` (32 B candidate auth probe)
//! - `ClientHello.random` (32 B MAC input)
//! - X25519 `key_share` entry (32 B client ephemeral pubkey)
//!
//! This parser is **read-only, allocation-bounded, and refuses to panic
//! on ANY input**. Its hostile-threat properties are fuzz-validated.
//!
//! ## What this parser intentionally does NOT do
//!
//! - Verify any signatures (none at this layer).
//! - Validate cipher suites or supported versions.
//! - Normalize the ClientHello.
//! - Touch any extension other than `key_share`.
//!
//! Anything more than the three fields above is irrelevant for the
//! Reality auth-probe decision; additional parsing expands the attack
//! surface without adding security.

use crate::error::RealityError;

// TLS constants (RFC 8446)

/// TLS record content_type = `handshake`.
const RECORD_TYPE_HANDSHAKE: u8 = 0x16;

/// TLS handshake_type = `client_hello`.
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// TLS `legacy_version` expected in a TLS 1.3 ClientHello record header (0x0301).
/// We accept 0x0303 too because some stacks set it that way; RFC 8446 allows
/// either. Caller can validate further if needed.
const ALLOWED_RECORD_VERSION_MAJOR: u8 = 0x03;

/// TLS 1.3 `key_share` extension type.
const EXT_TYPE_KEY_SHARE: u16 = 0x0033;
const EXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION: u16 = 0x0010;
/// RFC 8446 §4.2.1 - `supported_versions` extension.
const EXT_TYPE_SUPPORTED_VERSIONS: u16 = 0x002b;
/// TLS 1.3 version identifier as it appears in `supported_versions`.
const TLS_VERSION_1_3: u16 = 0x0304;

/// TLS 1.3 named group for X25519.
const NAMED_GROUP_X25519: u16 = 0x001D;

/// TLS 1.3 named group for the X25519MLKEM768 post-quantum hybrid (0x11EC).
use crate::tls_fingerprint::GROUP_X25519_MLKEM768;

/// ML-KEM-768 encapsulation-key wire length (hybrid `key_share` ek half).
const MLKEM_EK_LEN: usize = 1184;

/// Maximum ClientHello we ever bother parsing (RFC 8446 caps handshake
/// messages at 16 MiB minus 1, but 16 KB covers every realistic CH and
/// any larger value is almost certainly adversarial garbage).
pub const MAX_CLIENT_HELLO_SIZE: usize = 16_384;

/// Fixed-size output of a successful parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedClientHello {
    /// `ClientHello.random` (32 B).
    pub random: [u8; 32],
    /// `legacy_session_id` (length-prefixed on the wire; canonicalized to
    /// exactly 32 bytes here since shorter/longer values are not valid
    /// Reality auth probes).
    pub session_id: [u8; 32],
    /// X25519 key_share public key (32 B). The client reuses this same
    /// ephemeral for the X25519 half of the hybrid entry, so it pairs with
    /// [`Self::mlkem_ek`] for the X25519MLKEM768 key exchange.
    pub x25519_key_share: [u8; 32],
    /// ML-KEM-768 encapsulation key (1184 B) from the client's X25519MLKEM768
    /// hybrid `key_share` entry, when present. `Some` means the client offered
    /// the post-quantum hybrid group and the bridge can complete it (encapsulate
    /// against this ek) instead of downgrading to plain X25519.
    pub mlkem_ek: Option<[u8; MLKEM_EK_LEN]>,
    /// Offered cipher suites (TLS 1.3 codepoints, in client preference
    /// order). Audit fix C1: bridges echo a cipher chosen from the
    /// client's offered list rather than hard-coding one.
    pub cipher_suites: Vec<u16>,
    /// Offered ALPN protocol names, in client preference order
    /// (each is the inner ProtocolName bytes, e.g., `b"h2"`,
    /// `b"http/1.1"`). Empty when the client did not offer ALPN.
    /// Audit fix C2.
    pub alpn_protocols: Vec<Vec<u8>>,
}

// Cursor: strict bounds-checked byte reader

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    #[inline]
    fn need(&mut self, n: usize) -> Result<&'a [u8], RealityError> {
        if self.remaining() < n {
            return Err(RealityError::TagMismatch); // remapped at caller; internally: "short read"
        }
        // Use checked arithmetic for the slice indices and the
        // position update - defence in depth on top of the
        // remaining() check. Matches the wire-parser discipline
        // used elsewhere; closes [RT-N2].
        let end = self.pos.checked_add(n).ok_or(RealityError::TagMismatch)?;
        if end > self.bytes.len() {
            return Err(RealityError::TagMismatch);
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    #[inline]
    fn u8(&mut self) -> Result<u8, RealityError> {
        Ok(self.need(1)?[0])
    }

    #[inline]
    fn u16_be(&mut self) -> Result<u16, RealityError> {
        let b = self.need(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// 24-bit big-endian (TLS handshake message length).
    #[inline]
    fn u24_be(&mut self) -> Result<usize, RealityError> {
        let b = self.need(3)?;
        Ok(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize))
    }
}

// Public parser

/// Parse a TLS ClientHello record and extract the fields needed for the
/// Reality auth probe decision.
///
/// Accepts bytes as they arrive on the wire: one complete TLS record
/// containing a ClientHello handshake message. Returns a specific
/// [`RealityError`] on any parsing failure.
///
/// **Security note**: the returned errors are for internal use only.
/// Callers MUST map ANY error to cover-service forwarding and MUST NOT
/// signal the specific error to the peer.
pub fn parse_client_hello_record(bytes: &[u8]) -> Result<ParsedClientHello, RealityError> {
    if bytes.len() > MAX_CLIENT_HELLO_SIZE {
        return Err(RealityError::TagMismatch);
    }
    let mut c = Cursor::new(bytes);

    // ---- Record header (5 bytes) ----
    let rec_type = c.u8()?;
    if rec_type != RECORD_TYPE_HANDSHAKE {
        return Err(RealityError::TagMismatch);
    }
    let rec_ver_major = c.u8()?;
    let _rec_ver_minor = c.u8()?;
    if rec_ver_major != ALLOWED_RECORD_VERSION_MAJOR {
        return Err(RealityError::TagMismatch);
    }
    let rec_len = c.u16_be()? as usize;
    if rec_len == 0 || c.remaining() < rec_len {
        return Err(RealityError::TagMismatch);
    }

    // ---- Handshake header (4 bytes) ----
    let hs_type = c.u8()?;
    if hs_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(RealityError::TagMismatch);
    }
    let hs_len = c.u24_be()?;
    if hs_len == 0 || c.remaining() < hs_len {
        return Err(RealityError::TagMismatch);
    }

    // ---- ClientHello body ----
    // legacy_version (2 B) - ignored.
    let _legacy_version = c.u16_be()?;

    // random (32 B)
    let random_bytes = c.need(32)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(random_bytes);

    // legacy_session_id: 1 B length + content
    let sid_len = c.u8()? as usize;
    if sid_len != 32 {
        // Mirage Reality requires session_id to be EXACTLY 32 bytes (spec §4).
        // Shorter/longer is not a Mirage probe; fall through to cover.
        return Err(RealityError::SessionIdLen);
    }
    let sid_bytes = c.need(32)?;
    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(sid_bytes);

    // cipher_suites: 2 B length + content, capture into Vec.
    let cs_len = c.u16_be()? as usize;
    if cs_len == 0 || cs_len % 2 != 0 {
        // Invalid TLS CH; not a Mirage probe.
        return Err(RealityError::TagMismatch);
    }
    let cs_bytes = c.need(cs_len)?;
    let mut cipher_suites: Vec<u16> = Vec::with_capacity(cs_len / 2);
    for chunk in cs_bytes.chunks_exact(2) {
        cipher_suites.push(u16::from_be_bytes([chunk[0], chunk[1]]));
    }

    // compression_methods: 1 B length + content, skip.
    let comp_len = c.u8()? as usize;
    let _ = c.need(comp_len)?;

    // extensions: 2 B length + content
    let ext_total = c.u16_be()? as usize;
    if c.remaining() < ext_total {
        return Err(RealityError::TagMismatch);
    }
    let ext_end = c.pos + ext_total;

    // Walk extensions looking for key_share + ALPN + supported_versions.
    let mut x25519_key_share: Option<[u8; 32]> = None;
    let mut mlkem_ek: Option<[u8; MLKEM_EK_LEN]> = None;
    let mut alpn_protocols: Vec<Vec<u8>> = Vec::new();
    let mut tls13_offered = false;
    while c.pos < ext_end {
        let ext_type = c.u16_be()?;
        let ext_len = c.u16_be()? as usize;
        if c.remaining() < ext_len || c.pos + ext_len > ext_end {
            return Err(RealityError::TagMismatch);
        }
        if ext_type == EXT_TYPE_SUPPORTED_VERSIONS {
            // Client form: 1-byte list length + Nx2-byte version values.
            if ext_len < 3 {
                return Err(RealityError::TagMismatch);
            }
            let list_len = c.u8()? as usize;
            if list_len + 1 != ext_len || list_len % 2 != 0 {
                return Err(RealityError::TagMismatch);
            }
            let list_end = c.pos + list_len;
            while c.pos < list_end {
                let ver = c.u16_be()?;
                if ver == TLS_VERSION_1_3 {
                    tls13_offered = true;
                }
            }
        } else if ext_type == EXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION {
            // ALPN: 2-byte total list length + repeated 1-byte
            // name_len + name. Per RFC 7301 §3.1.
            let list_len_inner = c.u16_be()? as usize;
            if list_len_inner + 2 != ext_len {
                return Err(RealityError::TagMismatch);
            }
            let list_end = c.pos + list_len_inner;
            while c.pos < list_end {
                let name_len = c.u8()? as usize;
                if name_len == 0 || c.pos + name_len > list_end {
                    return Err(RealityError::TagMismatch);
                }
                alpn_protocols.push(c.need(name_len)?.to_vec());
            }
        } else if ext_type == EXT_TYPE_KEY_SHARE {
            // key_share extension: 2 B list length, then entries of
            //   2 B group || 2 B length || N B key_exchange.
            if ext_len < 2 {
                return Err(RealityError::TagMismatch);
            }
            let list_len = c.u16_be()? as usize;
            if list_len + 2 != ext_len {
                // List length must equal the ext_len minus the list-length field itself.
                return Err(RealityError::TagMismatch);
            }
            let list_end = c.pos + list_len;
            while c.pos < list_end {
                if list_end - c.pos < 4 {
                    return Err(RealityError::TagMismatch);
                }
                let group = c.u16_be()?;
                let key_len = c.u16_be()? as usize;
                if key_len > list_end - c.pos {
                    return Err(RealityError::TagMismatch);
                }
                if group == NAMED_GROUP_X25519 {
                    if key_len != 32 {
                        return Err(RealityError::TagMismatch);
                    }
                    let key_bytes = c.need(32)?;
                    let mut key = [0u8; 32];
                    key.copy_from_slice(key_bytes);
                    x25519_key_share = Some(key);
                } else if group == GROUP_X25519_MLKEM768 {
                    // Hybrid entry: key_exchange = ML-KEM-768 ek (1184) || X25519
                    // (32). The X25519 half is the same ephemeral captured from
                    // the standalone entry, so we only need the ek here.
                    if key_len != MLKEM_EK_LEN + 32 {
                        return Err(RealityError::TagMismatch);
                    }
                    let entry = c.need(key_len)?;
                    let mut ek = [0u8; MLKEM_EK_LEN];
                    ek.copy_from_slice(&entry[..MLKEM_EK_LEN]);
                    mlkem_ek = Some(ek);
                } else {
                    let _ = c.need(key_len)?;
                }
            }
        } else {
            // Skip other extensions.
            let _ = c.need(ext_len)?;
        }
    }

    // Reject anything that doesn't advertise TLS 1.3 - forward to cover.
    // A missing supported_versions extension is itself TLS-pre-1.3 behaviour.
    if !tls13_offered {
        return Err(RealityError::TagMismatch);
    }
    let x25519_key_share = x25519_key_share.ok_or(RealityError::TagMismatch)?;
    Ok(ParsedClientHello {
        random,
        session_id,
        x25519_key_share,
        mlkem_ek,
        cipher_suites,
        alpn_protocols,
    })
}

// Tests - build a real-ish TLS 1.3 ClientHello and parse it back

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid TLS 1.3 ClientHello builder for tests. Emits the
    /// wire layout specified in RFC 8446 §4.1.2, with the fields Reality
    /// cares about set to caller-provided values and everything else
    /// set to sensible minimal defaults.
    fn build_ch(random: &[u8; 32], session_id: &[u8; 32], x25519_pubkey: &[u8; 32]) -> Vec<u8> {
        let mut body = Vec::new();
        // legacy_version: 0x0303 (TLS 1.2, per RFC 8446)
        body.extend_from_slice(&[0x03, 0x03]);
        // random
        body.extend_from_slice(random);
        // session_id: 0x20 (32) length + 32 bytes
        body.push(0x20);
        body.extend_from_slice(session_id);
        // cipher_suites: length=2, one suite (TLS_AES_128_GCM_SHA256 = 0x1301)
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        // compression_methods: length=1, null
        body.extend_from_slice(&[0x01, 0x00]);

        // Extensions: supported_versions + key_share
        let mut exts = Vec::new();

        // supported_versions (0x002b): list of (1B length + N x 2B), value = 0x0304
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        // key_share (0x0033): list of (2B length + entries), entry = group(2)+len(2)+key
        //   group = 0x001D (X25519), key_len = 0x0020 (32), key bytes
        let mut ks_entry = Vec::new();
        ks_entry.extend_from_slice(&[0x00, 0x1D, 0x00, 0x20]);
        ks_entry.extend_from_slice(x25519_pubkey);
        let ks_list_len = ks_entry.len() as u16;
        let ks_ext_len = (2 + ks_entry.len()) as u16;
        exts.extend_from_slice(&[0x00, 0x33]); // ext type key_share
        exts.extend_from_slice(&ks_ext_len.to_be_bytes());
        exts.extend_from_slice(&ks_list_len.to_be_bytes());
        exts.extend_from_slice(&ks_entry);

        // extensions total length prefix
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        // Handshake header
        let mut hs = Vec::new();
        hs.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // u24 BE
        hs.extend_from_slice(&body);

        // Record header
        let mut record = Vec::new();
        record.push(RECORD_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]); // legacy TLS 1.0 for record version
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn parse_valid_clienthello() {
        let random = [0xAAu8; 32];
        let session_id = [0xBBu8; 32];
        let x25519 = [0xCCu8; 32];
        let wire = build_ch(&random, &session_id, &x25519);
        let parsed = parse_client_hello_record(&wire).expect("parse");
        assert_eq!(parsed.random, random);
        assert_eq!(parsed.session_id, session_id);
        assert_eq!(parsed.x25519_key_share, x25519);
    }

    #[test]
    fn rejects_non_handshake_record() {
        let random = [0xAAu8; 32];
        let session_id = [0xBBu8; 32];
        let x25519 = [0xCCu8; 32];
        let mut wire = build_ch(&random, &session_id, &x25519);
        wire[0] = 0x17; // application_data instead of handshake
        assert!(parse_client_hello_record(&wire).is_err());
    }

    #[test]
    fn rejects_non_client_hello_handshake() {
        let random = [0xAAu8; 32];
        let session_id = [0xBBu8; 32];
        let x25519 = [0xCCu8; 32];
        let mut wire = build_ch(&random, &session_id, &x25519);
        // Handshake type byte: offset 5 = record header done, next byte is hs_type.
        wire[5] = 0x02; // server_hello instead of client_hello
        assert!(parse_client_hello_record(&wire).is_err());
    }

    #[test]
    fn rejects_short_session_id() {
        let random = [0xAAu8; 32];
        let x25519 = [0xCCu8; 32];
        // Build a CH with session_id of length 16 (not 32).
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&random);
        body.push(0x10); // session_id length = 16
        body.extend_from_slice(&[0xDD; 16]);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // compression null

        let mut ks_entry = Vec::new();
        ks_entry.extend_from_slice(&[0x00, 0x1D, 0x00, 0x20]);
        ks_entry.extend_from_slice(&x25519);
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x33]); // key_share type
        exts.extend_from_slice(&((2 + ks_entry.len()) as u16).to_be_bytes());
        exts.extend_from_slice(&(ks_entry.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ks_entry);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![HANDSHAKE_TYPE_CLIENT_HELLO];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut rec = vec![RECORD_TYPE_HANDSHAKE, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        assert_eq!(
            parse_client_hello_record(&rec).unwrap_err(),
            RealityError::SessionIdLen
        );
    }

    #[test]
    fn rejects_missing_x25519_keyshare() {
        let random = [0xAAu8; 32];
        let session_id = [0xBBu8; 32];
        // Build CH with a key_share that contains a different group (e.g., secp256r1 0x0017).
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(0x20);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);

        let mut ks_entry = Vec::new();
        ks_entry.extend_from_slice(&[0x00, 0x17, 0x00, 0x41]); // secp256r1, 65 bytes
        ks_entry.extend_from_slice(&[0xEEu8; 65]);
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x33]);
        exts.extend_from_slice(&((2 + ks_entry.len()) as u16).to_be_bytes());
        exts.extend_from_slice(&(ks_entry.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ks_entry);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![HANDSHAKE_TYPE_CLIENT_HELLO];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![RECORD_TYPE_HANDSHAKE, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        assert_eq!(
            parse_client_hello_record(&rec).unwrap_err(),
            RealityError::TagMismatch
        );
    }

    #[test]
    fn rejects_truncated_record() {
        let random = [0xAAu8; 32];
        let session_id = [0xBBu8; 32];
        let x25519 = [0xCCu8; 32];
        let wire = build_ch(&random, &session_id, &x25519);
        // Truncate by 10 bytes.
        let truncated = &wire[..wire.len() - 10];
        assert!(parse_client_hello_record(truncated).is_err());
    }

    #[test]
    fn rejects_oversized() {
        let oversized = vec![0x16u8; MAX_CLIENT_HELLO_SIZE + 1];
        assert!(parse_client_hello_record(&oversized).is_err());
    }

    #[test]
    fn extracts_x25519_when_multiple_groups_present() {
        let random = [0xAAu8; 32];
        let session_id = [0xBBu8; 32];
        let x25519 = [0xCCu8; 32];
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(0x20);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);

        // Two key_share entries: secp256r1 then X25519
        let mut ks_list = Vec::new();
        ks_list.extend_from_slice(&[0x00, 0x17, 0x00, 0x41]);
        ks_list.extend_from_slice(&[0xDDu8; 65]);
        ks_list.extend_from_slice(&[0x00, 0x1D, 0x00, 0x20]);
        ks_list.extend_from_slice(&x25519);

        let mut exts = Vec::new();
        // supported_versions = [0x0304] (TLS 1.3) - required since we enforce 1.3 minimum.
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        exts.extend_from_slice(&[0x00, 0x33]);
        exts.extend_from_slice(&((2 + ks_list.len()) as u16).to_be_bytes());
        exts.extend_from_slice(&(ks_list.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ks_list);

        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![HANDSHAKE_TYPE_CLIENT_HELLO];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![RECORD_TYPE_HANDSHAKE, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        let parsed = parse_client_hello_record(&rec).unwrap();
        assert_eq!(parsed.x25519_key_share, x25519);
    }

    #[test]
    fn rejects_empty_input() {
        assert!(parse_client_hello_record(&[]).is_err());
    }

    #[test]
    fn rejects_partial_record_header() {
        assert!(parse_client_hello_record(&[0x16]).is_err());
        assert!(parse_client_hello_record(&[0x16, 0x03, 0x01]).is_err());
    }

    /// A ClientHello without `supported_versions` is TLS <= 1.2 behaviour -
    /// must be rejected and forwarded to the cover destination.
    #[test]
    fn rejects_no_supported_versions_extension() {
        let random = [0xAAu8; 32];
        let session_id = [0xBBu8; 32];
        let x25519 = [0xCCu8; 32];

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(0x20);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);

        // key_share only - NO supported_versions extension.
        let mut ks_entry = Vec::new();
        ks_entry.extend_from_slice(&[0x00, 0x1D, 0x00, 0x20]);
        ks_entry.extend_from_slice(&x25519);
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x33]);
        exts.extend_from_slice(&((2 + ks_entry.len()) as u16).to_be_bytes());
        exts.extend_from_slice(&(ks_entry.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ks_entry);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![HANDSHAKE_TYPE_CLIENT_HELLO];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![RECORD_TYPE_HANDSHAKE, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        assert!(
            parse_client_hello_record(&rec).is_err(),
            "TLS <= 1.2 ClientHello must be rejected"
        );
    }

    /// A ClientHello advertising only TLS 1.2 in supported_versions (no 1.3)
    /// must be rejected.
    #[test]
    fn rejects_tls12_only_supported_versions() {
        let random = [0xAAu8; 32];
        let session_id = [0xBBu8; 32];
        let x25519 = [0xCCu8; 32];

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&random);
        body.push(0x20);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x35]); // TLS_RSA_WITH_AES_256_CBC_SHA
        body.extend_from_slice(&[0x01, 0x00]);

        let mut exts = Vec::new();
        // supported_versions = [0x0303] (TLS 1.2 only, no 0x0304)
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x03]);
        // key_share
        let mut ks_entry = Vec::new();
        ks_entry.extend_from_slice(&[0x00, 0x1D, 0x00, 0x20]);
        ks_entry.extend_from_slice(&x25519);
        exts.extend_from_slice(&[0x00, 0x33]);
        exts.extend_from_slice(&((2 + ks_entry.len()) as u16).to_be_bytes());
        exts.extend_from_slice(&(ks_entry.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ks_entry);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![HANDSHAKE_TYPE_CLIENT_HELLO];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![RECORD_TYPE_HANDSHAKE, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);

        assert!(
            parse_client_hello_record(&rec).is_err(),
            "TLS 1.2-only supported_versions must be rejected"
        );
    }
}
