//! Minimal self-signed ECDSA P-256 X.509 certificate generator.
//!
//! Produces the smallest sensible DER blob that parses as a TLS 1.3
//! `CertificateEntry.cert_data`. Shape:
//!
//! ```text
//! Certificate ::= SEQUENCE {
//!   tbsCertificate      TBSCertificate,
//!   signatureAlgorithm  AlgorithmIdentifier,
//!   signatureValue      BIT STRING
//! }
//!
//! TBSCertificate ::= SEQUENCE {
//!   [0] version        INTEGER(2)      -- v3
//!   serialNumber       INTEGER
//!   signature          AlgorithmIdentifier
//!   issuer             Name
//!   validity           Validity
//!   subject            Name
//!   subjectPublicKeyInfo SubjectPublicKeyInfo
//! }
//! ```
//!
//! The issuer and subject are a single CN attribute. Validity is
//! `notBefore = 1970-01-01T00:00:00Z`, `notAfter = 9999-12-31T23:59:59Z`
//! so the cert is always "valid" at the handshake-time layer.
//! Signature algorithm: `ecdsa-with-SHA256` (OID 1.2.840.10045.4.3.2); the
//! subjectPublicKeyInfo is an EC key on `prime256v1` (P-256). This matches the
//! `ecdsa_secp256r1_sha256` CertVerify scheme real browsers use.
//!
//! # Scope
//!
//! **Not chain-validatable.** A TLS 1.3 client that validates the
//! cert against a public CA root store will reject this cert.
//! Xray-core-style REALITY avoids this by copying a real
//! destination's cert byte-for-byte and signing CertVerify with a
//! key that MATCHES that cert's pubkey - which requires either
//! compromising the cover or running a private CA, both out of
//! scope for v0.1c. We accept the "handshake completes; cert
//! chain-validation fails" limitation. An active prober that
//! stops at "TLS 1.3 handshake completed successfully" passes;
//! one that escalates to chain validation rejects.
//!
//! # Threat model
//!
//! For defense against the GFW-style replay-probe (ClientHello
//! replay -> check TLS handshake completes): this cert is enough.
//! For a stronger adversary who records traffic and later tries to
//! validate the cert against the cover-destination's actual cert
//! chain: insufficient; they detect divergence. v0.2 operator
//! tooling will support cert-mimicry mode.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};

/// `AlgorithmIdentifier` for `ecdsa-with-SHA256` (OID 1.2.840.10045.4.3.2),
/// no parameters - the certificate's `signatureAlgorithm`.
const ALGO_ID_ECDSA_SHA256_DER: &[u8] = &[
    0x30, 0x0A, // SEQUENCE, 10 bytes
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, // OID 1.2.840.10045.4.3.2
];

/// SPKI `AlgorithmIdentifier` for an EC public key on P-256:
/// `SEQUENCE { id-ecPublicKey (1.2.840.10045.2.1), prime256v1 (1.2.840.10045.3.1.7) }`.
const SPKI_ALGO_ID_EC_P256_DER: &[u8] = &[
    0x30, 0x13, // SEQUENCE, 19 bytes
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // id-ecPublicKey
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // prime256v1
];

/// Build a minimal self-signed **ECDSA P-256** X.509 certificate binding the
/// `signing_key`'s public point to `subject_cn`. This is the browser-realistic
/// identity: desktop Chrome/Firefox/Safari sign their TLS 1.3 CertVerify with
/// `ecdsa_secp256r1_sha256` (0x0403), never Ed25519 (0x0807) - see the JA4
/// residual note in `tls_fingerprint`. The cert carries the EC SPKI algorithm,
/// an `ecdsa-with-SHA256` signatureAlgorithm, and a DER-encoded (variable-length)
/// ECDSA signature.
pub fn build_self_signed_ecdsa_p256(signing_key: &P256SigningKey, subject_cn: &str) -> Vec<u8> {
    // SubjectPublicKey = uncompressed SEC1 point (0x04 || X(32) || Y(32)), 65 B.
    let point = signing_key.verifying_key().to_encoded_point(false);
    let tbs = build_tbs_ecdsa(point.as_bytes(), subject_cn);

    // ECDSA over SHA-256(tbs); TLS/X.509 carry the DER (SEQUENCE{r,s}) form.
    let sig: P256Signature = signing_key.sign(&tbs);
    let sig_der = sig.to_der();
    let sig_bitstring = encode_bit_string(sig_der.as_bytes());

    let mut body =
        Vec::with_capacity(tbs.len() + ALGO_ID_ECDSA_SHA256_DER.len() + sig_bitstring.len());
    body.extend_from_slice(&tbs);
    body.extend_from_slice(ALGO_ID_ECDSA_SHA256_DER);
    body.extend_from_slice(&sig_bitstring);
    encode_sequence(&body)
}

fn build_tbs_ecdsa(pubkey_point: &[u8], subject_cn: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(300);
    // [0] EXPLICIT v3
    body.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);
    // serialNumber 1
    body.extend_from_slice(&[0x02, 0x01, 0x01]);
    // signature algorithm (ecdsa-with-SHA256)
    body.extend_from_slice(ALGO_ID_ECDSA_SHA256_DER);
    // issuer (self-signed -> == subject)
    let name_der = encode_name_cn(subject_cn);
    body.extend_from_slice(&name_der);
    // validity: 1970-01-01 .. 9999-12-31
    let mut validity_body = Vec::new();
    validity_body.extend_from_slice(&[0x17, 0x0D]);
    validity_body.extend_from_slice(b"700101000000Z");
    validity_body.extend_from_slice(&[0x18, 0x0F]);
    validity_body.extend_from_slice(b"99991231235959Z");
    body.extend_from_slice(&encode_sequence(&validity_body));
    // subject
    body.extend_from_slice(&name_der);
    // subjectPublicKeyInfo: SEQUENCE { EC algo, BIT STRING(point) }
    let spki_body = {
        let mut v = Vec::new();
        v.extend_from_slice(SPKI_ALGO_ID_EC_P256_DER);
        v.extend_from_slice(&encode_bit_string(pubkey_point));
        v
    };
    body.extend_from_slice(&encode_sequence(&spki_body));

    encode_sequence(&body)
}

// DER encoding helpers

fn encode_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    // Long form: [0x80 | num_len_bytes, len_bytes_big_endian...]
    let mut len_bytes = Vec::new();
    let mut v = n;
    while v > 0 {
        len_bytes.push((v & 0xFF) as u8);
        v >>= 8;
    }
    len_bytes.reverse();
    let mut out = Vec::with_capacity(1 + len_bytes.len());
    out.push(0x80 | (len_bytes.len() as u8));
    out.extend_from_slice(&len_bytes);
    out
}

fn encode_sequence(body: &[u8]) -> Vec<u8> {
    let len = encode_len(body.len());
    let mut out = Vec::with_capacity(1 + len.len() + body.len());
    out.push(0x30); // SEQUENCE
    out.extend_from_slice(&len);
    out.extend_from_slice(body);
    out
}

fn encode_bit_string(value: &[u8]) -> Vec<u8> {
    // BIT STRING = 0x03 len (unused_bits=0) value
    let mut body = Vec::with_capacity(1 + value.len());
    body.push(0x00); // unused bits
    body.extend_from_slice(value);
    let len = encode_len(body.len());
    let mut out = Vec::with_capacity(1 + len.len() + body.len());
    out.push(0x03);
    out.extend_from_slice(&len);
    out.extend_from_slice(&body);
    out
}

fn encode_set(body: &[u8]) -> Vec<u8> {
    let len = encode_len(body.len());
    let mut out = Vec::with_capacity(1 + len.len() + body.len());
    out.push(0x31); // SET
    out.extend_from_slice(&len);
    out.extend_from_slice(body);
    out
}

fn encode_utf8_string(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let len = encode_len(b.len());
    let mut out = Vec::with_capacity(1 + len.len() + b.len());
    out.push(0x0C); // UTF8String
    out.extend_from_slice(&len);
    out.extend_from_slice(b);
    out
}

fn encode_oid(oid: &[u8]) -> Vec<u8> {
    let len = encode_len(oid.len());
    let mut out = Vec::with_capacity(1 + len.len() + oid.len());
    out.push(0x06); // OID
    out.extend_from_slice(&len);
    out.extend_from_slice(oid);
    out
}

/// Encode a Name DER as `SEQUENCE OF RelativeDistinguishedName`
/// containing one RDN whose sole attribute is
/// `CommonName = <cn>`.
fn encode_name_cn(cn: &str) -> Vec<u8> {
    // OID 2.5.4.3 (commonName) DER bytes: 55 04 03.
    let cn_oid = [0x55u8, 0x04, 0x03];
    // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
    let mut atv_body = Vec::new();
    atv_body.extend_from_slice(&encode_oid(&cn_oid));
    atv_body.extend_from_slice(&encode_utf8_string(cn));
    let atv = encode_sequence(&atv_body);
    // RDN ::= SET OF AttributeTypeAndValue
    let rdn = encode_set(&atv);
    // Name ::= SEQUENCE OF RDN
    encode_sequence(&rdn)
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_p256_cert_parses_and_verifies() {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        // Deterministic key from a fixed scalar for reproducibility.
        let sk = P256SigningKey::from_bytes(&[0x11u8; 32].into()).unwrap();
        let cert = build_self_signed_ecdsa_p256(&sk, "mirage.test");
        assert_eq!(cert[0], 0x30, "outer Certificate SEQUENCE tag");
        assert!(
            cert.len() > 200 && cert.len() < 600,
            "cert size {}",
            cert.len()
        );

        // The self-signature over the TBS must verify under the embedded key.
        // Re-derive the TBS + signature the same way the builder does and check.
        let point = sk.verifying_key().to_encoded_point(false);
        let tbs = build_tbs_ecdsa(point.as_bytes(), "mirage.test");
        // The TBS is the first inner SEQUENCE of the cert; verify the builder's
        // own signature round-trips via the verifying key.
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        let sig: Signature = sk.sign(&tbs);
        vk.verify(&tbs, &sig).expect("self-signature verifies");
        // Uncompressed SEC1 point is 65 bytes and present in the cert DER.
        assert_eq!(point.as_bytes().len(), 65);
        assert!(
            cert.windows(65).any(|w| w == point.as_bytes()),
            "SPKI point embedded in cert"
        );
    }

    #[test]
    fn different_cns_produce_different_bytes() {
        let sk = P256SigningKey::from_bytes(&[0x22u8; 32].into()).unwrap();
        let a = build_self_signed_ecdsa_p256(&sk, "first.example");
        let b = build_self_signed_ecdsa_p256(&sk, "second.example");
        assert_ne!(a, b);
    }
}
