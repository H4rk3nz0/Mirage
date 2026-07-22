// ChaCha20-Poly1305 AEAD for (D)TLS 1.2 — RFC 7905.
//
// MIRAGE FINGERPRINT PATCH: Chrome/libwebrtc offers
// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA9) and
// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xCCA8) in its DTLS ClientHello.
// Upstream webrtc-dtls does not implement this suite, so a Mirage WebRTC peer
// that advertises Chrome's cipher list must also be able to *negotiate* it.
//
// Unlike AES-GCM, RFC 7905 uses an IMPLICIT per-record nonce — nothing extra is
// placed on the wire (record_iv_length = 0). The nonce is:
//
//     padded_seq = 0x00_00_00_00 || seq_num(8)          // 12 bytes
//     nonce      = write_IV(12) XOR padded_seq           // 12 bytes
//
// where seq_num is the 8-byte DTLS record epoch(2) || sequence_number(6). The
// AAD is the standard 13-byte (D)TLS 1.2 AAD over the *plaintext* length. This
// is a different record layout than crypto_gcm.rs (which carries an 8-byte
// explicit nonce), so it is a separate module, not a parameterization of GCM.

use std::io::Cursor;

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use super::*;
use crate::content::*;
use crate::error::*;
use crate::record_layer::record_layer_header::*;

const CRYPTO_CHACHA20_POLY1305_TAG_LENGTH: usize = 16;
const CRYPTO_CHACHA20_POLY1305_NONCE_LENGTH: usize = 12;

// State needed to handle encrypted input/output.
#[derive(Clone)]
pub struct CryptoChaCha20Poly1305 {
    local_cipher: ChaCha20Poly1305,
    remote_cipher: ChaCha20Poly1305,
    local_write_iv: Vec<u8>,
    remote_write_iv: Vec<u8>,
}

// Reconstruct the 8-byte AEAD sequence number (epoch(2) || sequence_number(6))
// from a record header — the same value generate_aead_additional_data() uses.
fn seq_bytes(epoch: u16, sequence_number: u64) -> [u8; 8] {
    let mut seq = sequence_number.to_be_bytes();
    seq[..2].copy_from_slice(&epoch.to_be_bytes());
    seq
}

// RFC 7905 §2 nonce: write_IV XOR (0x00000000 || seq_num), 12 bytes.
fn build_nonce(write_iv: &[u8], epoch: u16, sequence_number: u64) -> [u8; CRYPTO_CHACHA20_POLY1305_NONCE_LENGTH] {
    let mut nonce = [0u8; CRYPTO_CHACHA20_POLY1305_NONCE_LENGTH];
    nonce.copy_from_slice(&write_iv[..CRYPTO_CHACHA20_POLY1305_NONCE_LENGTH]);
    let seq = seq_bytes(epoch, sequence_number);
    // seq is 8 bytes, left-padded with 4 zero bytes -> XOR into the low 8 bytes.
    for (i, b) in seq.iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    nonce
}

impl CryptoChaCha20Poly1305 {
    pub fn new(
        local_key: &[u8],
        local_write_iv: &[u8],
        remote_key: &[u8],
        remote_write_iv: &[u8],
    ) -> Self {
        let local_cipher = ChaCha20Poly1305::new(GenericArray::from_slice(local_key));
        let remote_cipher = ChaCha20Poly1305::new(GenericArray::from_slice(remote_key));

        CryptoChaCha20Poly1305 {
            local_cipher,
            local_write_iv: local_write_iv.to_vec(),
            remote_cipher,
            remote_write_iv: remote_write_iv.to_vec(),
        }
    }

    pub fn encrypt(&self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        let payload = &raw[RECORD_LAYER_HEADER_SIZE..];
        let header = &raw[..RECORD_LAYER_HEADER_SIZE];

        let nonce = build_nonce(
            &self.local_write_iv,
            pkt_rlh.epoch,
            pkt_rlh.sequence_number,
        );
        let nonce = GenericArray::from_slice(&nonce);

        // AAD uses the plaintext length (RFC 5246 §6.2.3.3 / RFC 7905).
        let additional_data = generate_aead_additional_data(pkt_rlh, payload.len());

        let mut buffer: Vec<u8> = Vec::with_capacity(payload.len() + CRYPTO_CHACHA20_POLY1305_TAG_LENGTH);
        buffer.extend_from_slice(payload);

        self.local_cipher
            .encrypt_in_place(nonce, &additional_data, &mut buffer)
            .map_err(|e| Error::Other(e.to_string()))?;

        // No explicit nonce on the wire (record_iv_length = 0): header || ct || tag.
        let mut r = Vec::with_capacity(header.len() + buffer.len());
        r.extend_from_slice(header);
        r.extend_from_slice(&buffer);

        // Rewrite the record-layer length to cover ciphertext + tag.
        let r_len = (r.len() - RECORD_LAYER_HEADER_SIZE) as u16;
        r[RECORD_LAYER_HEADER_SIZE - 2..RECORD_LAYER_HEADER_SIZE]
            .copy_from_slice(&r_len.to_be_bytes());

        Ok(r)
    }

    pub fn decrypt(&self, r: &[u8]) -> Result<Vec<u8>> {
        let mut reader = Cursor::new(r);
        let h = RecordLayerHeader::unmarshal(&mut reader)?;
        if h.content_type == ContentType::ChangeCipherSpec {
            // Nothing to decrypt with ChangeCipherSpec.
            return Ok(r.to_vec());
        }

        if r.len() <= RECORD_LAYER_HEADER_SIZE + CRYPTO_CHACHA20_POLY1305_TAG_LENGTH {
            return Err(Error::ErrNotEnoughRoomForNonce);
        }

        let nonce = build_nonce(&self.remote_write_iv, h.epoch, h.sequence_number);
        let nonce = GenericArray::from_slice(&nonce);

        let out = &r[RECORD_LAYER_HEADER_SIZE..];
        let additional_data =
            generate_aead_additional_data(&h, out.len() - CRYPTO_CHACHA20_POLY1305_TAG_LENGTH);

        let mut buffer: Vec<u8> = Vec::with_capacity(out.len());
        buffer.extend_from_slice(out);

        self.remote_cipher
            .decrypt_in_place(nonce, &additional_data, &mut buffer)
            .map_err(|e| Error::Other(e.to_string()))?;

        let mut d = Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + buffer.len());
        d.extend_from_slice(&r[..RECORD_LAYER_HEADER_SIZE]);
        d.extend_from_slice(&buffer);

        Ok(d)
    }
}

#[cfg(test)]
mod test {
    use chacha20poly1305::aead::{Aead, Payload};

    use super::*;

    // Validate our DTLS record framing against an INDEPENDENT RFC 7905 sealing.
    // A loopback handshake (both peers ours) can share a symmetric nonce bug and
    // still succeed, so we cross-check the on-wire ciphertext byte-for-byte
    // against a reference nonce/AAD construction using the raw AEAD — this is the
    // check that would catch a wrong-but-consistent implicit-nonce derivation.
    #[test]
    fn test_chacha20_poly1305_framing_matches_reference() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 12];
        let crypto = CryptoChaCha20Poly1305::new(&key, &iv, &key, &iv);

        let payload: &[u8] = b"mirage chacha20-poly1305 dtls record";
        let epoch: u16 = 1;
        let seqno: u64 = 0x0000_0000_0042; // 48-bit sequence number
        let header = RecordLayerHeader {
            content_type: ContentType::ApplicationData,
            protocol_version: PROTOCOL_VERSION1_2,
            epoch,
            sequence_number: seqno,
            content_len: payload.len() as u16,
        };

        let mut raw = Vec::new();
        header.marshal(&mut raw).unwrap();
        raw.extend_from_slice(payload);

        let sealed = crypto.encrypt(&header, &raw).unwrap();

        // Reference: RFC 7905 nonce = write_IV XOR (0x00000000 || seq8),
        // seq8 = epoch(2) || sequence_number(6); AAD is the standard 13-byte
        // (D)TLS 1.2 AAD over the PLAINTEXT length.
        let mut seq8 = seqno.to_be_bytes();
        seq8[..2].copy_from_slice(&epoch.to_be_bytes());
        let mut ref_nonce = iv;
        for i in 0..8 {
            ref_nonce[4 + i] ^= seq8[i];
        }
        let aad = generate_aead_additional_data(&header, payload.len());
        let ref_ct = ChaCha20Poly1305::new(GenericArray::from_slice(&key))
            .encrypt(
                GenericArray::from_slice(&ref_nonce),
                Payload { msg: payload, aad: &aad },
            )
            .unwrap();

        // No explicit nonce on the wire: sealed = header(13) || ct || tag.
        assert_eq!(
            &sealed[RECORD_LAYER_HEADER_SIZE..],
            &ref_ct[..],
            "on-wire ciphertext must match an independent RFC 7905 sealing"
        );
        // Record-layer length must cover ciphertext + 16-byte tag, nothing else.
        let wire_len = u16::from_be_bytes([sealed[11], sealed[12]]) as usize;
        assert_eq!(wire_len, payload.len() + CRYPTO_CHACHA20_POLY1305_TAG_LENGTH);

        // And the decrypt path recovers the plaintext.
        let opened = crypto.decrypt(&sealed).unwrap();
        assert_eq!(&opened[RECORD_LAYER_HEADER_SIZE..], payload);
    }
}
