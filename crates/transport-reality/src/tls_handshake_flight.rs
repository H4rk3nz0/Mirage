//! Post-ServerHello TLS 1.3 handshake flight builders + parsers.
//!
//! After the ClientHello / ServerHello exchange, a real TLS 1.3
//! server sends four encrypted handshake messages (RFC 8446 §4.1):
//!
//! ```text
//! {EncryptedExtensions}
//! {Certificate}
//! {CertificateVerify}
//! {Finished}
//! ```
//!
//! (Curly braces mean the messages are wrapped inside a
//! `TLSCiphertext` record encrypted under the server handshake
//! traffic key.) The client then replies with its own `{Finished}`.
//!
//! This module emits the plaintext `HandshakeMessage` bytes for
//! each of the four server-side flight messages and parses the
//! incoming client Finished. Encryption into records is handled by
//! [`crate::carrier`]; this module keeps all the TLS wire-format
//! work in one place.
//!
//! # Scope (v0.1c)
//!
//! - `EncryptedExtensions`: empty extensions list.
//! - `Certificate`: one-entry certificate list, no context.
//! - `CertificateVerify`: `ecdsa_secp256r1_sha256` (0x0403) signature over the
//!   CertVerify context string per RFC 8446 §4.4.3 (browser-realistic scheme).
//! - `Finished`: HMAC-SHA256 over the transcript hash using
//!   `finished_key`.

use mirage_crypto::hkdf::hmac::{Hmac, Mac};
use mirage_crypto::sha2::Sha256;
use mirage_crypto::zeroize::Zeroizing;
use p256::ecdsa::{signature::Signer, Signature as P256Signature, SigningKey as P256SigningKey};

use crate::error::RealityError;

/// TLS 1.3 handshake message type bytes (RFC 8446 §B.3).
pub const HS_TYPE_CLIENT_HELLO: u8 = 0x01;
/// TLS 1.3 ServerHello handshake type.
pub const HS_TYPE_SERVER_HELLO: u8 = 0x02;
/// TLS 1.3 EncryptedExtensions handshake type.
pub const HS_TYPE_ENCRYPTED_EXTENSIONS: u8 = 0x08;
/// TLS 1.3 Certificate handshake type.
pub const HS_TYPE_CERTIFICATE: u8 = 0x0B;
/// TLS 1.3 CertificateVerify handshake type.
pub const HS_TYPE_CERTIFICATE_VERIFY: u8 = 0x0F;
/// TLS 1.3 Finished handshake type.
pub const HS_TYPE_FINISHED: u8 = 0x14;

/// TLS 1.3 `SignatureScheme.ecdsa_secp256r1_sha256` (RFC 8446 §4.2.3) - the
/// scheme every desktop browser signs its CertVerify with, so Reality uses it
/// too (Ed25519/0x0807 would be a JA4 tell no browser produces).
pub const SIG_SCHEME_ECDSA_SECP256R1_SHA256: u16 = 0x0403;

/// Wrap an arbitrary `body` into a handshake message with the
/// 1-byte msg_type + 3-byte length prefix.
pub fn wrap_handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    let len = body.len() as u32;
    out.push(((len >> 16) & 0xFF) as u8);
    out.push(((len >> 8) & 0xFF) as u8);
    out.push((len & 0xFF) as u8);
    out.extend_from_slice(body);
    out
}

/// Read the handshake header from `buf`. Returns `(msg_type,
/// payload_slice)` on success. Validates the 24-bit length field
/// against the buffer size.
pub fn read_handshake(buf: &[u8]) -> Result<(u8, &[u8]), RealityError> {
    if buf.len() < 4 {
        return Err(RealityError::TagMismatch);
    }
    let msg_type = buf[0];
    let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
    if 4 + len != buf.len() {
        return Err(RealityError::TagMismatch);
    }
    Ok((msg_type, &buf[4..]))
}

/// TLS `application_layer_protocol_negotiation` extension type.
pub const EXT_ALPN: u16 = 0x0010;

/// Build `EncryptedExtensions`. When `alpn` is `Some(proto)`, includes the ALPN
/// extension carrying the negotiated protocol - this is where TLS 1.3 REQUIRES
/// ALPN (RFC 8446 §4.3.1), *encrypted*, rather than in the cleartext
/// ServerHello. The prior placement (ALPN echoed in the ServerHello) was
/// protocol-illegal and a passive conformance tell (F3); a real TLS 1.3 server
/// never emits ALPN in the ServerHello.
pub fn build_encrypted_extensions(alpn: Option<&[u8]>) -> Vec<u8> {
    let mut exts = Vec::new();
    if let Some(proto) = alpn {
        // ALPN ext body: ProtocolNameList = u16 list_len + (u8 name_len + name).
        let list_len = (proto.len() + 1) as u16;
        let mut ext_body = Vec::with_capacity(3 + proto.len());
        ext_body.extend_from_slice(&list_len.to_be_bytes());
        ext_body.push(proto.len() as u8);
        ext_body.extend_from_slice(proto);
        exts.extend_from_slice(&EXT_ALPN.to_be_bytes());
        exts.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext_body);
    }
    let mut body = Vec::with_capacity(2 + exts.len());
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    wrap_handshake(HS_TYPE_ENCRYPTED_EXTENSIONS, &body)
}

/// Build `Certificate` carrying a single cert_data entry and no
/// context or extensions (RFC 8446 §4.4.2):
///
/// ```text
/// struct {
///   opaque certificate_request_context<0..255> = "";
///   CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
///
/// struct {
///   select (certificate_type) {
///     case X509: opaque cert_data<1..2^24-1>;
///   };
///   Extension extensions<0..2^16-1>;
/// } CertificateEntry;
/// ```
pub fn build_certificate(cert_der: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(cert_der.len() + 32);
    // certificate_request_context: opaque <0..255> with length 0.
    body.push(0x00);

    // certificate_list: a single CertificateEntry.
    // Each entry: cert_data<1..2^24-1> + extensions<0..2^16-1>(empty).
    let mut entry_list = Vec::with_capacity(cert_der.len() + 16);
    let cd_len = cert_der.len() as u32;
    entry_list.push(((cd_len >> 16) & 0xFF) as u8);
    entry_list.push(((cd_len >> 8) & 0xFF) as u8);
    entry_list.push((cd_len & 0xFF) as u8);
    entry_list.extend_from_slice(cert_der);
    // empty extensions
    entry_list.push(0x00);
    entry_list.push(0x00);

    // certificate_list length (u24)
    let el_len = entry_list.len() as u32;
    body.push(((el_len >> 16) & 0xFF) as u8);
    body.push(((el_len >> 8) & 0xFF) as u8);
    body.push((el_len & 0xFF) as u8);
    body.extend_from_slice(&entry_list);

    wrap_handshake(HS_TYPE_CERTIFICATE, &body)
}

/// Compute the "TLS 1.3 server CertificateVerify" signing input
/// per RFC 8446 §4.4.3:
///
/// ```text
/// 64 x 0x20    || "TLS 1.3, server CertificateVerify" || 0x00 ||
/// transcript_hash
/// ```
fn cert_verify_signing_input(transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + 33 + 1 + 32);
    out.extend_from_slice(&[0x20u8; 64]);
    out.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    out.push(0x00);
    out.extend_from_slice(transcript_hash);
    out
}

/// Build `CertificateVerify` signed by `signing_key` over the RFC-prescribed
/// preamble + `transcript_hash`. Signature scheme is
/// `ecdsa_secp256r1_sha256` (0x0403); the signature is the DER-encoded
/// (`SEQUENCE { r, s }`) ECDSA signature over SHA-256 of the signing input, so
/// its length is variable (~70-72 B), unlike Ed25519's fixed 64.
pub fn build_certificate_verify(
    signing_key: &P256SigningKey,
    transcript_hash: &[u8; 32],
) -> Vec<u8> {
    let to_sign = cert_verify_signing_input(transcript_hash);
    let sig: P256Signature = signing_key.sign(&to_sign);
    let sig_der = sig.to_der();
    let sig_bytes = sig_der.as_bytes();

    let mut body = Vec::with_capacity(4 + sig_bytes.len());
    body.extend_from_slice(&SIG_SCHEME_ECDSA_SECP256R1_SHA256.to_be_bytes());
    body.extend_from_slice(&(sig_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(sig_bytes);

    wrap_handshake(HS_TYPE_CERTIFICATE_VERIFY, &body)
}

/// Build `Finished` per RFC 8446 §4.4.4:
/// `verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))`.
/// The `*` means "if present"; both are for us.
pub fn build_finished(finished_key: &[u8; 32], transcript_hash: &[u8; 32]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(finished_key).expect("hmac-sha256 new");
    mac.update(transcript_hash);
    let tag = mac.finalize().into_bytes();
    wrap_handshake(HS_TYPE_FINISHED, &tag)
}

/// TLS 1.3 `new_session_ticket` handshake type (RFC 8446 §4.6.1).
pub const HS_TYPE_NEW_SESSION_TICKET: u8 = 0x04;

/// Build a `NewSessionTicket` message (RFC 8446 §4.6.1) - audit #16.
///
/// A genuine TLS 1.3 server issues one (or two) of these right after the
/// handshake so clients can resume; a "server" that NEVER does is a behavioural
/// tell, and the encrypted record it rides in also shapes the post-handshake
/// wire (size/timing) a passive observer sees. Mirage's Reality carrier appends
/// one to its 0.5-RTT flight so that shape matches a real endpoint. The ticket
/// itself is an opaque CSPRNG blob of realistic size: Reality does not perform
/// PSK resumption with it (that would need full 0-RTT machinery), so the client
/// simply parses and discards it - its only job is wire realism.
///
/// ```text
/// struct {
///   uint32 ticket_lifetime;
///   uint32 ticket_age_add;
///   opaque ticket_nonce<0..255>;
///   opaque ticket<1..2^16-1>;
///   Extension extensions<0..2^16-2>;
/// } NewSessionTicket;
/// ```
pub fn build_new_session_ticket(
    lifetime_secs: u32,
    age_add: u32,
    ticket_nonce: &[u8],
    ticket: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + 4 + 1 + ticket_nonce.len() + 2 + ticket.len() + 2);
    body.extend_from_slice(&lifetime_secs.to_be_bytes());
    body.extend_from_slice(&age_add.to_be_bytes());
    // ticket_nonce<0..255>: 1-byte length prefix.
    body.push(u8::try_from(ticket_nonce.len()).unwrap_or(0));
    body.extend_from_slice(ticket_nonce);
    // ticket<1..2^16-1>: 2-byte length prefix.
    body.extend_from_slice(&u16::try_from(ticket.len()).unwrap_or(0).to_be_bytes());
    body.extend_from_slice(ticket);
    // extensions<0..2^16-2>: empty (no early_data / max_early_data_size), matching
    // a resumption-only ticket from a server that does not offer 0-RTT.
    body.extend_from_slice(&0u16.to_be_bytes());
    wrap_handshake(HS_TYPE_NEW_SESSION_TICKET, &body)
}

/// Verify a received `Finished` from a peer. Returns `Ok(())` if
/// the HMAC tag matches what we compute from our transcript hash
/// + their `finished_key`. Uses constant-time MAC verification.
pub fn verify_finished(
    finished_msg: &[u8],
    peer_finished_key: &[u8; 32],
    transcript_hash_before_peer_finished: &[u8; 32],
) -> Result<(), RealityError> {
    let (msg_type, body) = read_handshake(finished_msg)?;
    if msg_type != HS_TYPE_FINISHED {
        return Err(RealityError::TagMismatch);
    }
    if body.len() != 32 {
        return Err(RealityError::TagMismatch);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(peer_finished_key).expect("hmac-sha256 new");
    mac.update(transcript_hash_before_peer_finished);
    mac.verify_slice(body)
        .map_err(|_| RealityError::TagMismatch)
}

/// TLS 1.3 inner plaintext: `handshake_msg || content_type(u8) ||
/// zero-padding`. RFC 8446 §5.2. The record-layer code wraps this
/// in AEAD and prepends a TLSCiphertext header.
pub const INNER_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
/// TLS 1.3 inner content type byte for `application_data`.
pub const INNER_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

/// Append a TLS 1.3 inner content type byte. Returns a new Vec
/// containing `msg || content_type` with no padding. Padding
/// (optional traffic-shape defense) is deliberately not used here
/// because the caller's record-layer already determines the size
/// of each write.
pub fn with_inner_content_type(msg: &[u8], ct: u8) -> Zeroizing<Vec<u8>> {
    let mut v = Vec::with_capacity(msg.len() + 1);
    v.extend_from_slice(msg);
    v.push(ct);
    Zeroizing::new(v)
}

/// Strip the TLS 1.3 inner content type trailing byte (RFC 8446
/// §5.2). Returns the payload plaintext and the content type.
/// Rejects records whose plaintext is shorter than 1 byte or whose
/// content type is not recognized for our use case.
pub fn strip_inner_content_type(plaintext: &[u8]) -> Result<(u8, &[u8]), RealityError> {
    // TLS 1.3 allows optional zero-padding after the content type
    // byte. We scan from the end skipping zeros to find it.
    let mut end = plaintext.len();
    while end > 0 && plaintext[end - 1] == 0x00 {
        end -= 1;
    }
    if end == 0 {
        return Err(RealityError::TagMismatch);
    }
    let ct = plaintext[end - 1];
    Ok((ct, &plaintext[..end - 1]))
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_read_roundtrip() {
        let body = b"payload";
        let msg = wrap_handshake(HS_TYPE_CERTIFICATE, body);
        assert_eq!(msg[0], HS_TYPE_CERTIFICATE);
        let (t, p) = read_handshake(&msg).unwrap();
        assert_eq!(t, HS_TYPE_CERTIFICATE);
        assert_eq!(p, body);
    }

    #[test]
    fn read_rejects_short_or_length_mismatch() {
        assert!(read_handshake(&[]).is_err());
        assert!(read_handshake(&[0x01, 0, 0, 5, 1, 2]).is_err()); // claims 5 bytes, has 2
    }

    #[test]
    fn new_session_ticket_shape_is_wellformed() {
        // Audit #16: the ticket message parses back to the exact RFC 8446 §4.6.1
        // field layout.
        let nonce = [0xAAu8; 8];
        let ticket = [0xBBu8; 64];
        let msg = build_new_session_ticket(7200, 0x1234_5678, &nonce, &ticket);
        let (ty, body) = read_handshake(&msg).unwrap();
        assert_eq!(ty, HS_TYPE_NEW_SESSION_TICKET);
        // lifetime(4) + age_add(4) + nonce_len(1) + nonce + ticket_len(2) + ticket
        // + ext_len(2).
        assert_eq!(u32::from_be_bytes(body[0..4].try_into().unwrap()), 7200);
        assert_eq!(
            u32::from_be_bytes(body[4..8].try_into().unwrap()),
            0x1234_5678
        );
        assert_eq!(body[8] as usize, nonce.len());
        let nofs = 9 + nonce.len();
        assert_eq!(&body[9..nofs], &nonce);
        let tlen = u16::from_be_bytes(body[nofs..nofs + 2].try_into().unwrap()) as usize;
        assert_eq!(tlen, ticket.len());
        let tofs = nofs + 2;
        assert_eq!(&body[tofs..tofs + tlen], &ticket);
        // trailing empty extensions vector.
        assert_eq!(
            u16::from_be_bytes(body[tofs + tlen..tofs + tlen + 2].try_into().unwrap()),
            0
        );
        assert_eq!(body.len(), tofs + tlen + 2);
    }

    #[test]
    fn encrypted_extensions_empty_and_with_alpn() {
        // No ALPN => empty extensions list.
        let ee = build_encrypted_extensions(None);
        let (t, p) = read_handshake(&ee).unwrap();
        assert_eq!(t, HS_TYPE_ENCRYPTED_EXTENSIONS);
        assert_eq!(p, &[0x00, 0x00]);

        // With ALPN => the negotiated protocol rides in EncryptedExtensions
        // (encrypted), per TLS 1.3 - NOT in the cleartext ServerHello (F3).
        let ee = build_encrypted_extensions(Some(b"h2"));
        let (t, p) = read_handshake(&ee).unwrap();
        assert_eq!(t, HS_TYPE_ENCRYPTED_EXTENSIONS);
        // exts_len(2) | ext_type(0x0010) | ext_len(2) | list_len(2) | 1 | 'h','2'
        assert_eq!(&p[2..4], &EXT_ALPN.to_be_bytes(), "ALPN extension present");
        assert_eq!(p[p.len() - 2..].to_vec(), b"h2".to_vec(), "protocol echoed");
    }

    #[test]
    fn certificate_roundtrip_shape() {
        let cert = vec![0xABu8; 128];
        let msg = build_certificate(&cert);
        let (t, p) = read_handshake(&msg).unwrap();
        assert_eq!(t, HS_TYPE_CERTIFICATE);
        // body = context_len(1=0) + list_len(3) + entry(cert_len(3) + cert + ext_len(2=0))
        assert_eq!(p[0], 0x00, "context length 0");
        // list_len:
        let list_len = ((p[1] as usize) << 16) | ((p[2] as usize) << 8) | p[3] as usize;
        assert_eq!(list_len, 3 + cert.len() + 2);
    }

    #[test]
    fn certificate_verify_is_signed_over_rfc_preamble() {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let sk = P256SigningKey::from_bytes(&[0x7Au8; 32].into()).unwrap();
        let th = [0x11u8; 32];
        let msg = build_certificate_verify(&sk, &th);
        let (t, body) = read_handshake(&msg).unwrap();
        assert_eq!(t, HS_TYPE_CERTIFICATE_VERIFY);
        // scheme(2) + sig_len(2) + DER ECDSA sig (variable, ~70-72 B).
        let scheme = u16::from_be_bytes([body[0], body[1]]);
        assert_eq!(scheme, SIG_SCHEME_ECDSA_SECP256R1_SHA256);
        let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
        assert_eq!(4 + sig_len, body.len(), "sig length field matches body");
        // Verify the DER ECDSA signature against the RFC preamble + transcript.
        let sig = Signature::from_der(&body[4..4 + sig_len]).unwrap();
        let vk = VerifyingKey::from(&sk);
        let preamble = cert_verify_signing_input(&th);
        vk.verify(&preamble, &sig).unwrap();
    }

    #[test]
    fn finished_verifies_when_keys_match() {
        let fk = [0x99u8; 32];
        let th = [0x22u8; 32];
        let msg = build_finished(&fk, &th);
        verify_finished(&msg, &fk, &th).unwrap();
    }

    #[test]
    fn finished_rejects_wrong_key() {
        let fk = [0x99u8; 32];
        let th = [0x22u8; 32];
        let msg = build_finished(&fk, &th);
        let other = [0x00u8; 32];
        assert!(verify_finished(&msg, &other, &th).is_err());
    }

    #[test]
    fn finished_rejects_tampered_tag() {
        let fk = [0x99u8; 32];
        let th = [0x22u8; 32];
        let mut msg = build_finished(&fk, &th);
        let last = msg.len() - 1;
        msg[last] ^= 0xFF;
        assert!(verify_finished(&msg, &fk, &th).is_err());
    }

    #[test]
    fn content_type_roundtrip() {
        let msg = b"hello";
        let plain = with_inner_content_type(msg, INNER_CONTENT_TYPE_HANDSHAKE);
        let (ct, body) = strip_inner_content_type(&plain).unwrap();
        assert_eq!(ct, INNER_CONTENT_TYPE_HANDSHAKE);
        assert_eq!(body, msg);
    }

    #[test]
    fn content_type_strip_handles_padding() {
        // msg + ct + 3 pad zeros
        let mut v = Vec::new();
        v.extend_from_slice(b"abc");
        v.push(INNER_CONTENT_TYPE_APPLICATION_DATA);
        v.extend_from_slice(&[0u8; 3]);
        let (ct, body) = strip_inner_content_type(&v).unwrap();
        assert_eq!(ct, INNER_CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(body, b"abc");
    }

    #[test]
    fn content_type_rejects_all_zero() {
        let zeros = vec![0u8; 5];
        assert!(strip_inner_content_type(&zeros).is_err());
    }
}
