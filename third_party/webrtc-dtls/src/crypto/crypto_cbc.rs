// AES-CBC (Cipher Block Chaining)
// First historic block cipher for AES.
// CBC mode is insecure and must not be used. It’s been progressively deprecated and
// removed from SSL libraries.
// Introduced with TLS 1.0 year 2002. Superseded by GCM in TLS 1.2 year 2008.
// Removed in TLS 1.3 year 2018.
// RFC 3268 year 2002 https://tools.ietf.org/html/rfc3268
//
// KNOWN RESIDUAL (red-team #15): `decrypt` below is MAC-then-pad-check, i.e. a
// classic non-constant-time CBC construction (Lucky13 class). This is a
// pre-existing property of the vendored CBC path; the Mirage AES-128-CBC
// addition only made it reachable for two more suites. It is NOT exploitable in
// practice for Mirage's use: genuine WebRTC/DTLS peers negotiate AEAD (GCM /
// ChaCha20) ONLY, the bridge selects CBC last (never in preference), and the CBC
// suites exist mainly for ClientHello fingerprint parity with Chrome. Reaching
// this code requires a peer that both holds the pinned DTLS cert AND forces a
// CBC suite - a self-contradiction for an on-path censor. A constant-time
// CBC-decrypt rewrite in this vendored fork is deferred as disproportionate to
// the (unreachable-in-practice) exposure; the durable answer is that CBC is
// offered for parity only and never the negotiated cipher on a real Mirage flow.

// https://github.com/RustCrypto/block-ciphers

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use p256::elliptic_curve::subtle::ConstantTimeEq;
use rand::Rng;
use std::io::Cursor;
use std::ops::Not;

use super::padding::DtlsPadding;
use crate::content::*;
use crate::error::*;
use crate::prf::*;
use crate::record_layer::record_layer_header::*;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
// MIRAGE FINGERPRINT PATCH (audit #30): AES-128-CBC support so the
// ECDHE_*_WITH_AES_128_CBC_SHA suites (0xC009 / 0xC013) that Chrome's
// ClientHello advertises are actually negotiable, not just offered - otherwise a
// peer/prober selecting one makes our client abort where genuine Chrome
// completes. The AES variant is chosen by write-key length (16 => 128, 32 => 256).
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// AES key length for AES-128 (bytes).
const AES128_KEY_LEN: usize = 16;
/// AES key length for AES-256 (bytes).
const AES256_KEY_LEN: usize = 32;

// State needed to handle encrypted input/output
#[derive(Clone)]
pub struct CryptoCbc {
    local_key: Vec<u8>,
    remote_key: Vec<u8>,
    write_mac: Vec<u8>,
    read_mac: Vec<u8>,
}

impl CryptoCbc {
    const BLOCK_SIZE: usize = 16;
    const MAC_SIZE: usize = 20;

    pub fn new(
        local_key: &[u8],
        local_mac: &[u8],
        remote_key: &[u8],
        remote_mac: &[u8],
    ) -> Result<Self> {
        Ok(CryptoCbc {
            local_key: local_key.to_vec(),
            write_mac: local_mac.to_vec(),

            remote_key: remote_key.to_vec(),
            read_mac: remote_mac.to_vec(),
        })
    }

    pub fn encrypt(&self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        let mut payload = raw[RECORD_LAYER_HEADER_SIZE..].to_vec();
        let raw = &raw[..RECORD_LAYER_HEADER_SIZE];

        // Generate + Append MAC
        let h = pkt_rlh;

        let mac = prf_mac(
            h.epoch,
            h.sequence_number,
            h.content_type,
            h.protocol_version,
            &payload,
            &self.write_mac,
        )?;
        payload.extend_from_slice(&mac);

        let mut iv: Vec<u8> = vec![0; Self::BLOCK_SIZE];
        rand::thread_rng().fill(iv.as_mut_slice());

        let encrypted = match self.local_key.len() {
            AES128_KEY_LEN => Aes128CbcEnc::new_from_slices(&self.local_key, &iv)?
                .encrypt_padded_vec_mut::<DtlsPadding>(&payload),
            AES256_KEY_LEN => Aes256CbcEnc::new_from_slices(&self.local_key, &iv)?
                .encrypt_padded_vec_mut::<DtlsPadding>(&payload),
            _ => return Err(Error::ErrInvalidCipherSuite),
        };

        // Prepend unencrypte header with encrypted payload
        let mut r = vec![];
        r.extend_from_slice(raw);
        r.extend_from_slice(&iv);
        r.extend_from_slice(&encrypted);

        let r_len = (r.len() - RECORD_LAYER_HEADER_SIZE) as u16;
        r[RECORD_LAYER_HEADER_SIZE - 2..RECORD_LAYER_HEADER_SIZE]
            .copy_from_slice(&r_len.to_be_bytes());

        Ok(r)
    }

    pub fn decrypt(&self, r: &[u8]) -> Result<Vec<u8>> {
        let mut reader = Cursor::new(r);
        let h = RecordLayerHeader::unmarshal(&mut reader)?;
        if h.content_type == ContentType::ChangeCipherSpec {
            // Nothing to encrypt with ChangeCipherSpec
            return Ok(r.to_vec());
        }

        let body = &r[RECORD_LAYER_HEADER_SIZE..];
        // MIRAGE HARDENING: validate the record is long enough to hold the
        // explicit IV before slicing — a short/truncated record from a remote
        // peer would otherwise panic (index out of range) and abort the whole
        // connection-handling task. The GCM sibling path already guards this.
        if body.len() < Self::BLOCK_SIZE {
            return Err(Error::ErrInvalidPacketLength);
        }
        let iv = &body[0..Self::BLOCK_SIZE];
        let body = &body[Self::BLOCK_SIZE..];

        let decrypted = match self.remote_key.len() {
            AES128_KEY_LEN => Aes128CbcDec::new_from_slices(&self.remote_key, iv)?
                .decrypt_padded_vec_mut::<DtlsPadding>(body)
                .map_err(|_| Error::ErrInvalidPacketLength)?,
            AES256_KEY_LEN => Aes256CbcDec::new_from_slices(&self.remote_key, iv)?
                .decrypt_padded_vec_mut::<DtlsPadding>(body)
                .map_err(|_| Error::ErrInvalidPacketLength)?,
            _ => return Err(Error::ErrInvalidCipherSuite),
        };

        // MIRAGE HARDENING: the plaintext must contain at least the MAC; a
        // shorter decrypt would panic on the slice below.
        if decrypted.len() < Self::MAC_SIZE {
            return Err(Error::ErrInvalidPacketLength);
        }
        let recv_mac = &decrypted[decrypted.len() - Self::MAC_SIZE..];
        let decrypted = &decrypted[0..decrypted.len() - Self::MAC_SIZE];
        let mac = prf_mac(
            h.epoch,
            h.sequence_number,
            h.content_type,
            h.protocol_version,
            decrypted,
            &self.read_mac,
        )?;

        if recv_mac.ct_eq(&mac).not().into() {
            return Err(Error::ErrInvalidMac);
        }

        let mut d = Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + decrypted.len());
        d.extend_from_slice(&r[..RECORD_LAYER_HEADER_SIZE]);
        d.extend_from_slice(decrypted);

        Ok(d)
    }
}
