//! QUIC Initial-packet decrypter + Chrome-fingerprint comparator.
//!
//! # Why this exists (the ground-truth harness for QUIC mimicry)
//!
//! QUIC Initial packets are encrypted with keys derived from a **published**
//! salt and the client's (on-wire, cleartext) Destination Connection ID
//! (RFC 9001 §5.2). So *anyone* - a browser, a censor's DPI, or this module -
//! can decrypt a QUIC Initial and read the TLS ClientHello + transport
//! parameters inside. That is exactly why a real QUIC flow is NOT a
//! "fully-encrypted" random blob to a censor: it parses as QUIC, and its
//! ClientHello fingerprint is inspectable.
//!
//! This is the regression oracle for making Mirage's QUIC carriers present a
//! **Chrome** fingerprint instead of a **quinn/rustls** one: decrypt a captured
//! Chrome Initial and Mirage's own Initial with the same public procedure, parse
//! both into a canonical [`QuicFingerprint`], and diff. Without it, matching
//! Chrome's bytes is guesswork.
//!
//! Reuses Mirage's existing TLS-1.3 key schedule (`hkdf_expand_label`, whose
//! `"tls13 "` label prefix is exactly RFC 9001's) and AES-128-GCM. Correctness
//! is pinned to RFC 9001 Appendix A's worked vectors (see tests).

// Byte-level QUIC/TLS packet parsing with explicit length checks throughout;
// indexing is intentional + guarded, varint loops use terse names, and the docs
// reference protocol terms (RFC 9001, AES-128-GCM, ...). Same posture as
// `crates/quic-obfs`.
#![allow(
    clippy::indexing_slicing,
    clippy::doc_markdown,
    clippy::many_single_char_names
)]

use mirage_crypto::aes_gcm::aead::{Aead, KeyInit, Payload};
use mirage_crypto::aes_gcm::{Aes128Gcm, Key, Nonce};
use mirage_crypto::hkdf::Hkdf;
use mirage_crypto::sha2::Sha256;
use mirage_transport_reality::tls_keyschedule::hkdf_expand_label;

/// QUIC v1 Initial salt (RFC 9001 §5.2).
pub const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC v1 version number.
pub const QUIC_V1: u32 = 0x0000_0001;

/// Error decoding/decrypting a QUIC Initial.
#[derive(Debug, PartialEq, Eq)]
pub enum QuicError {
    /// Not a long-header Initial packet (wrong first byte / version / type).
    NotInitial,
    /// Truncated or malformed header/field.
    Malformed(&'static str),
    /// AEAD authentication failed (wrong keys / tampered).
    Decrypt,
}

/// HKDF-Extract (RFC 5869) = HMAC-SHA256(salt, ikm).
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

/// The Initial secret for a connection, from its Destination Connection ID.
pub fn initial_secret(dcid: &[u8]) -> [u8; 32] {
    hkdf_extract(&INITIAL_SALT_V1, dcid)
}

fn expand32(secret: &[u8; 32], label: &str) -> [u8; 32] {
    let v = hkdf_expand_label(secret, label, &[], 32);
    let mut o = [0u8; 32];
    o.copy_from_slice(&v);
    o
}

/// Client Initial secret = Expand-Label(initial_secret, "client in").
pub fn client_initial_secret(dcid: &[u8]) -> [u8; 32] {
    expand32(&initial_secret(dcid), "client in")
}

/// Server Initial secret = Expand-Label(initial_secret, "server in").
pub fn server_initial_secret(dcid: &[u8]) -> [u8; 32] {
    expand32(&initial_secret(dcid), "server in")
}

/// Packet-protection keys derived from an Initial secret (RFC 9001 §5.1).
#[derive(Clone)]
pub struct PacketKeys {
    /// AEAD key (AES-128-GCM, 16 bytes).
    pub key: [u8; 16],
    /// AEAD IV (12 bytes; XORed with the packet number to form the nonce).
    pub iv: [u8; 12],
    /// Header-protection key (AES-128-ECB, 16 bytes).
    pub hp: [u8; 16],
}

/// Derive `(key, iv, hp)` from a packet-protection secret.
pub fn packet_keys(secret: &[u8; 32]) -> PacketKeys {
    let key = hkdf_expand_label(secret, "quic key", &[], 16);
    let iv = hkdf_expand_label(secret, "quic iv", &[], 12);
    let hp = hkdf_expand_label(secret, "quic hp", &[], 16);
    let mut k = [0u8; 16];
    k.copy_from_slice(&key);
    let mut i = [0u8; 12];
    i.copy_from_slice(&iv);
    let mut h = [0u8; 16];
    h.copy_from_slice(&hp);
    PacketKeys {
        key: k,
        iv: i,
        hp: h,
    }
}

/// AES-128-ECB header-protection mask over a 16-byte ciphertext sample
/// (RFC 9001 §5.4.3). Returns the 5-byte mask (byte0 mask + 4 pn-byte masks).
fn hp_mask(hp_key: &[u8; 16], sample: &[u8; 16]) -> [u8; 5] {
    use mirage_crypto::aes_gcm::aes::cipher::{
        generic_array::GenericArray, BlockEncrypt, KeyInit as _,
    };
    use mirage_crypto::aes_gcm::aes::Aes128;
    let cipher = Aes128::new(GenericArray::from_slice(hp_key));
    let mut block = *GenericArray::from_slice(sample);
    cipher.encrypt_block(&mut block);
    [block[0], block[1], block[2], block[3], block[4]]
}

/// Read a QUIC variable-length integer (RFC 9000 §16). Returns `(value, len)`.
fn read_varint(buf: &[u8]) -> Result<(u64, usize), QuicError> {
    let first = *buf.first().ok_or(QuicError::Malformed("varint eof"))?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return Err(QuicError::Malformed("varint truncated"));
    }
    let mut v = u64::from(first & 0x3f);
    for &b in &buf[1..len] {
        v = (v << 8) | u64::from(b);
    }
    Ok((v, len))
}

/// A decoded (decrypted) QUIC Initial packet.
pub struct DecodedInitial {
    /// QUIC version.
    pub version: u32,
    /// Destination Connection ID (as on the wire).
    pub dcid: Vec<u8>,
    /// Source Connection ID.
    pub scid: Vec<u8>,
    /// Reassembled CRYPTO-stream bytes (the TLS handshake, i.e. the ClientHello
    /// for a client Initial). Contiguous from offset 0.
    pub crypto: Vec<u8>,
}

/// Decrypt a QUIC v1 Initial packet at the START of `datagram`.
///
/// `from_server`: whether this packet was sent by the server (uses the server
/// Initial keys) vs the client. The Initial keys derive from the *client's
/// original DCID*, which for a client's first Initial is the packet's own DCID.
/// For decrypting a server Initial, pass the client's original DCID via
/// [`decrypt_initial_with_dcid`].
pub fn decrypt_initial(datagram: &[u8], from_server: bool) -> Result<DecodedInitial, QuicError> {
    let dcid = parse_long_header_dcid(datagram)?;
    decrypt_initial_with_dcid(datagram, &dcid, from_server)
}

/// Peek the DCID of a long-header packet without decrypting.
pub fn parse_long_header_dcid(datagram: &[u8]) -> Result<Vec<u8>, QuicError> {
    if datagram.len() < 7 {
        return Err(QuicError::Malformed("short"));
    }
    let b0 = datagram[0];
    // Long header form (0x80) + fixed bit (0x40); long type Initial = 0b00.
    if b0 & 0xc0 != 0xc0 {
        return Err(QuicError::NotInitial);
    }
    let version = u32::from_be_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]);
    if version != QUIC_V1 {
        return Err(QuicError::NotInitial);
    }
    if (b0 & 0x30) != 0x00 {
        return Err(QuicError::NotInitial); // long type != Initial
    }
    let dcil = datagram[5] as usize;
    let dstart = 6;
    if datagram.len() < dstart + dcil {
        return Err(QuicError::Malformed("dcid"));
    }
    Ok(datagram[dstart..dstart + dcil].to_vec())
}

/// Decrypt an Initial using an explicit Initial-keys DCID (the client's original
/// DCID) - needed to decrypt a *server* Initial, whose own DCID differs.
pub fn decrypt_initial_with_dcid(
    datagram: &[u8],
    keys_dcid: &[u8],
    from_server: bool,
) -> Result<DecodedInitial, QuicError> {
    // ---- parse the cleartext long header ----
    if datagram.len() < 7 {
        return Err(QuicError::Malformed("short"));
    }
    let b0 = datagram[0];
    if b0 & 0xc0 != 0xc0 {
        return Err(QuicError::NotInitial);
    }
    let version = u32::from_be_bytes([datagram[1], datagram[2], datagram[3], datagram[4]]);
    let mut off = 5usize;
    let dcil = datagram[off] as usize;
    off += 1;
    let dcid = datagram
        .get(off..off + dcil)
        .ok_or(QuicError::Malformed("dcid"))?
        .to_vec();
    off += dcil;
    let scil = *datagram.get(off).ok_or(QuicError::Malformed("scil"))? as usize;
    off += 1;
    let scid = datagram
        .get(off..off + scil)
        .ok_or(QuicError::Malformed("scid"))?
        .to_vec();
    off += scil;
    // Token length + token (Initial only).
    let (token_len, tl) = read_varint(datagram.get(off..).ok_or(QuicError::Malformed("tok"))?)?;
    off += tl + token_len as usize;
    // Length (of packet number + payload).
    let (length, ll) = read_varint(datagram.get(off..).ok_or(QuicError::Malformed("len"))?)?;
    off += ll;
    let pn_offset = off;
    let payload_end = pn_offset + length as usize;
    if datagram.len() < payload_end {
        return Err(QuicError::Malformed("payload"));
    }

    // ---- remove header protection ----
    let secret = if from_server {
        server_initial_secret(keys_dcid)
    } else {
        client_initial_secret(keys_dcid)
    };
    let pk = packet_keys(&secret);
    // Sample starts 4 bytes after the pn_offset (max pn length).
    let sample_off = pn_offset + 4;
    let mut sample = [0u8; 16];
    sample.copy_from_slice(
        datagram
            .get(sample_off..sample_off + 16)
            .ok_or(QuicError::Malformed("sample"))?,
    );
    let mask = hp_mask(&pk.hp, &sample);
    let unmasked_b0 = b0 ^ (mask[0] & 0x0f); // long header: low 4 bits protected
    let pn_len = ((unmasked_b0 & 0x03) + 1) as usize;
    let mut pn_bytes = [0u8; 4];
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        let byte = datagram[pn_offset + i] ^ mask[1 + i];
        pn_bytes[i] = byte;
        pn = (pn << 8) | u64::from(byte);
    }
    let header_len = pn_offset + pn_len;

    // ---- build AEAD nonce + AAD, decrypt ----
    let mut nonce = pk.iv;
    let pn_be = pn.to_be_bytes(); // 8 bytes
    for i in 0..8 {
        nonce[4 + i] ^= pn_be[i];
    }
    let mut aad = datagram[..header_len].to_vec();
    aad[0] = unmasked_b0;
    aad[pn_offset..(pn_len + pn_offset)].copy_from_slice(&pn_bytes[..pn_len]);
    let ct = &datagram[header_len..payload_end];
    let plaintext = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&pk.key))
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| QuicError::Decrypt)?;

    let crypto = reassemble_crypto(&plaintext)?;
    Ok(DecodedInitial {
        version,
        dcid,
        scid,
        crypto,
    })
}

/// Walk QUIC frames in the decrypted payload and reassemble the CRYPTO stream
/// (contiguous from offset 0). Ignores PADDING/PING/ACK; other frame types in an
/// Initial are unexpected but skipped conservatively where their length is known.
fn reassemble_crypto(payload: &[u8]) -> Result<Vec<u8>, QuicError> {
    use std::collections::BTreeMap;
    let mut chunks: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut i = 0usize;
    while i < payload.len() {
        let ft = payload[i];
        i += 1;
        match ft {
            0x00 | 0x01 => {} // PADDING / PING: no body
            0x02 | 0x03 => {
                // ACK: largest, delay, range_count, first_range, [gap,len]*
                let (_, a) = read_varint(&payload[i..])?;
                i += a;
                let (_, b) = read_varint(&payload[i..])?;
                i += b;
                let (rc, c) = read_varint(&payload[i..])?;
                i += c;
                let (_, d) = read_varint(&payload[i..])?;
                i += d;
                for _ in 0..rc {
                    let (_, g) = read_varint(&payload[i..])?;
                    i += g;
                    let (_, l) = read_varint(&payload[i..])?;
                    i += l;
                }
                if ft == 0x03 {
                    for _ in 0..3 {
                        let (_, e) = read_varint(&payload[i..])?;
                        i += e;
                    }
                }
            }
            0x06 => {
                // CRYPTO: offset, length, data
                let (offset, a) = read_varint(&payload[i..])?;
                i += a;
                let (len, b) = read_varint(&payload[i..])?;
                i += b;
                let end = i + len as usize;
                let data = payload
                    .get(i..end)
                    .ok_or(QuicError::Malformed("crypto frame"))?;
                chunks.insert(offset, data.to_vec());
                i = end;
            }
            _ => return Err(QuicError::Malformed("unexpected frame type")),
        }
    }
    // Concatenate contiguous chunks from offset 0.
    let mut out = Vec::new();
    let mut next = 0u64;
    for (&off, data) in &chunks {
        if off != next {
            break;
        }
        out.extend_from_slice(data);
        next += data.len() as u64;
    }
    Ok(out)
}

/// A canonical, comparable QUIC-handshake fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QuicFingerprint {
    /// QUIC version from the Initial header.
    pub version: u32,
    /// Destination Connection ID length (bytes). Chrome=8, quinn default=20.
    pub dcid_len: usize,
    /// Source Connection ID length (bytes).
    pub scid_len: usize,
    /// TLS ClientHello cipher suites, in order.
    pub cipher_suites: Vec<u16>,
    /// ClientHello extension type codes, in order.
    pub extensions: Vec<u16>,
    /// Whether any GREASE (RFC 8701) codepoint appears in ciphers/extensions/groups.
    pub has_grease: bool,
    /// `supported_groups` (0x000a) values, in order.
    pub groups: Vec<u16>,
    /// ALPN protocol strings.
    pub alpn: Vec<String>,
    /// QUIC transport-parameter IDs (ext 0x39), in order.
    pub transport_param_ids: Vec<u64>,
    /// Whether the `min_ack_delay` draft param (0xFF04DE1B) is present (a quinn
    /// tell; Chrome QUIC v1 does not send it).
    pub has_min_ack_delay: bool,
}

/// True if `v` is a GREASE codepoint (RFC 8701): `0x?a?a` with both bytes equal
/// and low nibble `a`.
fn is_grease16(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

/// Extract a [`QuicFingerprint`] from a QUIC Initial datagram (client-sent).
pub fn fingerprint_from_initial(datagram: &[u8]) -> Result<QuicFingerprint, QuicError> {
    let dec = decrypt_initial(datagram, false)?;
    let mut fp = parse_client_hello(&dec.crypto)?;
    fp.version = dec.version;
    fp.dcid_len = dec.dcid.len();
    fp.scid_len = dec.scid.len();
    Ok(fp)
}

/// Parse a TLS 1.3 ClientHello handshake message into fingerprint fields.
pub fn parse_client_hello(hs: &[u8]) -> Result<QuicFingerprint, QuicError> {
    let mut fp = QuicFingerprint::default();
    // Handshake header: type(1)=0x01 + length(3).
    if hs.len() < 4 || hs[0] != 0x01 {
        return Err(QuicError::Malformed("not a ClientHello"));
    }
    let mut p = 4usize;
    p += 2; // legacy_version
    p += 32; // random
    let sid_len = *hs.get(p).ok_or(QuicError::Malformed("sid"))? as usize;
    p += 1 + sid_len;
    // cipher_suites
    let cs_len = u16::from_be_bytes([
        *hs.get(p).ok_or(QuicError::Malformed("cs"))?,
        *hs.get(p + 1).ok_or(QuicError::Malformed("cs"))?,
    ]) as usize;
    p += 2;
    for c in hs
        .get(p..p + cs_len)
        .ok_or(QuicError::Malformed("cs"))?
        .chunks(2)
    {
        let v = u16::from_be_bytes([c[0], c[1]]);
        fp.cipher_suites.push(v);
        fp.has_grease |= is_grease16(v);
    }
    p += cs_len;
    let comp_len = *hs.get(p).ok_or(QuicError::Malformed("comp"))? as usize;
    p += 1 + comp_len;
    // extensions
    let ext_total = u16::from_be_bytes([
        *hs.get(p).ok_or(QuicError::Malformed("ext"))?,
        *hs.get(p + 1).ok_or(QuicError::Malformed("ext"))?,
    ]) as usize;
    p += 2;
    let ext_end = p + ext_total;
    while p + 4 <= ext_end {
        let etype = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let elen = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        p += 4;
        let body = hs
            .get(p..p + elen)
            .ok_or(QuicError::Malformed("ext body"))?;
        fp.extensions.push(etype);
        fp.has_grease |= is_grease16(etype);
        match etype {
            0x000a => {
                // supported_groups
                if body.len() >= 2 {
                    let n = u16::from_be_bytes([body[0], body[1]]) as usize;
                    for g in body.get(2..2 + n).unwrap_or(&[]).chunks(2) {
                        let v = u16::from_be_bytes([g[0], g[1]]);
                        fp.groups.push(v);
                        fp.has_grease |= is_grease16(v);
                    }
                }
            }
            0x0010 => {
                // ALPN
                if body.len() >= 2 {
                    let mut i = 2usize;
                    while i < body.len() {
                        let l = body[i] as usize;
                        i += 1;
                        if let Some(s) = body.get(i..i + l) {
                            fp.alpn.push(String::from_utf8_lossy(s).into_owned());
                        }
                        i += l;
                    }
                }
            }
            0x0039 => {
                // quic_transport_parameters
                let mut i = 0usize;
                while i < body.len() {
                    let (id, a) = read_varint(&body[i..])?;
                    i += a;
                    let (plen, b) = read_varint(&body[i..])?;
                    i += b + plen as usize;
                    fp.transport_param_ids.push(id);
                    if id == 0xFF04_DE1B {
                        fp.has_min_ack_delay = true;
                    }
                }
            }
            _ => {}
        }
        p += elen;
    }
    Ok(fp)
}

impl QuicFingerprint {
    /// Human-readable field-by-field diff vs another fingerprint (e.g. Chrome).
    /// Empty = identical on the compared fields.
    pub fn diff(&self, other: &QuicFingerprint) -> Vec<String> {
        let mut d = Vec::new();
        if self.version != other.version {
            d.push(format!(
                "version {:#x} != {:#x}",
                self.version, other.version
            ));
        }
        if self.dcid_len != other.dcid_len {
            d.push(format!("dcid_len {} != {}", self.dcid_len, other.dcid_len));
        }
        if self.cipher_suites != other.cipher_suites {
            d.push("cipher_suites differ".into());
        }
        if self.extensions != other.extensions {
            d.push("extension set/order differ".into());
        }
        if self.has_grease != other.has_grease {
            d.push(format!(
                "has_grease {} != {}",
                self.has_grease, other.has_grease
            ));
        }
        if self.groups != other.groups {
            d.push("supported_groups differ".into());
        }
        if self.alpn != other.alpn {
            d.push(format!("alpn {:?} != {:?}", self.alpn, other.alpn));
        }
        if self.transport_param_ids != other.transport_param_ids {
            d.push("transport-parameter set/order differ".into());
        }
        if self.has_min_ack_delay != other.has_min_ack_delay {
            d.push(format!(
                "has_min_ack_delay {} != {} (quinn tell)",
                self.has_min_ack_delay, other.has_min_ack_delay
            ));
        }
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9001 Appendix A.1 worked example: DCID = 0x8394c8f03e515708.
    const RFC_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn rfc9001_a1_initial_and_client_secrets() {
        assert_eq!(
            hex(&initial_secret(&RFC_DCID)),
            "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
        );
        assert_eq!(
            hex(&client_initial_secret(&RFC_DCID)),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        );
    }

    #[test]
    fn rfc9001_a1_client_packet_keys() {
        let pk = packet_keys(&client_initial_secret(&RFC_DCID));
        assert_eq!(hex(&pk.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex(&pk.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex(&pk.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn rfc9001_a1_server_packet_keys() {
        let pk = packet_keys(&server_initial_secret(&RFC_DCID));
        assert_eq!(hex(&pk.key), "cf3a5331653c364c88f0f379b6067e37");
        assert_eq!(hex(&pk.iv), "0ac1493ca1905853b0bba03e");
        assert_eq!(hex(&pk.hp), "c206b8d9b9f0f37644430b490eeaa314");
    }

    #[test]
    fn grease_detection() {
        assert!(is_grease16(0x0a0a));
        assert!(is_grease16(0x1a1a));
        assert!(is_grease16(0xdada));
        assert!(!is_grease16(0x1301)); // TLS_AES_128_GCM_SHA256
        assert!(!is_grease16(0x0a1a)); // bytes not equal
    }

    #[test]
    fn client_hello_parser_extracts_fields() {
        // Minimal hand-built TLS 1.3 ClientHello: 1 GREASE + 1 real cipher, one
        // extension (supported_groups with a GREASE + x25519), to exercise the
        // parser + GREASE + group extraction.
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // legacy_version
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0); // session_id len
        ch.extend_from_slice(&[0x00, 0x04]); // cipher_suites len = 4
        ch.extend_from_slice(&[0x1a, 0x1a, 0x13, 0x01]); // GREASE, AES128-GCM
        ch.extend_from_slice(&[0x01, 0x00]); // compression: 1 method (null)
                                             // extensions: supported_groups(0x000a)
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x0a]); // type
        let groups = [0x0a, 0x0au8, 0x00, 0x1d]; // GREASE, x25519 (list body)
        let glist_len = groups.len() as u16;
        ext.extend_from_slice(&(glist_len + 2).to_be_bytes()); // ext len
        ext.extend_from_slice(&glist_len.to_be_bytes()); // group list len
        ext.extend_from_slice(&groups);
        ch.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        ch.extend_from_slice(&ext);

        // Wrap in the handshake header (type 0x01 + 3-byte length).
        let mut hs = vec![0x01];
        hs.extend_from_slice(&(ch.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&ch);

        let fp = parse_client_hello(&hs).unwrap();
        assert_eq!(fp.cipher_suites, vec![0x1a1a, 0x1301]);
        assert_eq!(fp.extensions, vec![0x000a]);
        assert!(fp.has_grease);
        assert_eq!(fp.groups, vec![0x0a0a, 0x001d]);
    }

    #[test]
    fn diff_flags_the_quinn_tells() {
        let chrome = QuicFingerprint {
            dcid_len: 8,
            has_grease: true,
            has_min_ack_delay: false,
            ..Default::default()
        };
        let quinn = QuicFingerprint {
            dcid_len: 20,
            has_grease: false,
            has_min_ack_delay: true,
            ..Default::default()
        };
        let d = quinn.diff(&chrome);
        assert!(d.iter().any(|s| s.contains("dcid_len")));
        assert!(d.iter().any(|s| s.contains("has_grease")));
        assert!(d.iter().any(|s| s.contains("min_ack_delay")));
    }
}
