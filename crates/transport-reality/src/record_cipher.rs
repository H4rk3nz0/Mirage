//! Cipher-agnostic TLS 1.3 record AEAD for the Reality carrier.
//!
//! A real TLS 1.3 server picks the AEAD from the client's offered list -
//! AES-128-GCM for a Chrome/Firefox ClientHello on AES-NI hardware,
//! ChaCha20-Poly1305 for ChaCha-preferring clients. The Reality record layer
//! historically implemented ONLY ChaCha20-Poly1305, so the bridge had to
//! advertise (and use) ChaCha for every connection - a passive distinguisher
//! vs. real covers that select AES-128-GCM. [`RecordCipher`] wraps both AEADs
//! behind one seal/open API so the bridge can mirror whichever suite the client
//! prefers, and the client uses whichever the ServerHello selected.
//!
//! Both AEADs are RustCrypto `aead` implementations with 12-byte nonces and
//! 16-byte tags, so the nonce/AAD construction (spec §4.3) is cipher-independent;
//! only the key length (32 vs 16) and the concrete cipher type differ.

use mirage_crypto::zeroize::Zeroizing;

use crate::error::RealityError;
use crate::tls_keyschedule::{traffic_keys_aes128, traffic_keys_chacha, HASH_LEN};
use crate::tls_server_hello::TLS_AES_128_GCM_SHA256;

/// The AEAD used for Reality TLS records, selected by the negotiated suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordCipher {
    /// `TLS_CHACHA20_POLY1305_SHA256` (0x1303) - 32-byte key.
    ChaCha20Poly1305,
    /// `TLS_AES_128_GCM_SHA256` (0x1301) - 16-byte key.
    Aes128Gcm,
}

impl RecordCipher {
    /// Map a negotiated TLS 1.3 cipher-suite codepoint to the record AEAD.
    /// Only these two suites are ever negotiated by the Reality handshake; any
    /// other value defaults to ChaCha (the peer would have failed already).
    pub fn from_cipher_suite(suite: u16) -> Self {
        if suite == TLS_AES_128_GCM_SHA256 {
            Self::Aes128Gcm
        } else {
            Self::ChaCha20Poly1305
        }
    }

    /// AEAD key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 32,
            Self::Aes128Gcm => 16,
        }
    }

    /// Derive `(key, iv)` traffic keys for `secret` under this cipher. The key
    /// is returned as a variable-length zeroizing buffer (32 or 16 bytes).
    pub fn traffic_keys(self, secret: &[u8; HASH_LEN]) -> (Zeroizing<Vec<u8>>, [u8; 12]) {
        match self {
            Self::ChaCha20Poly1305 => {
                let (k, iv) = traffic_keys_chacha(secret);
                (Zeroizing::new(k.to_vec()), iv)
            }
            Self::Aes128Gcm => {
                let (k, iv) = traffic_keys_aes128(secret);
                (Zeroizing::new(k.to_vec()), iv)
            }
        }
    }

    /// AEAD-seal `plaintext` with associated data `aad`. `key` must be
    /// [`Self::key_len`] bytes and `nonce` 12 bytes.
    pub fn seal(
        self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, RealityError> {
        match self {
            Self::ChaCha20Poly1305 => {
                use mirage_crypto::chacha20poly1305::{
                    aead::{Aead, KeyInit, Payload},
                    ChaCha20Poly1305, Key, Nonce,
                };
                ChaCha20Poly1305::new(Key::from_slice(key))
                    .encrypt(
                        Nonce::from_slice(nonce),
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|_| RealityError::TagMismatch)
            }
            Self::Aes128Gcm => {
                use mirage_crypto::aes_gcm::{
                    aead::{Aead, KeyInit, Payload},
                    Aes128Gcm, Key, Nonce,
                };
                Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key))
                    .encrypt(
                        Nonce::from_slice(nonce),
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|_| RealityError::TagMismatch)
            }
        }
    }

    /// AEAD-open `ciphertext` with associated data `aad`. Returns the plaintext
    /// on tag success.
    pub fn open(
        self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, RealityError> {
        match self {
            Self::ChaCha20Poly1305 => {
                use mirage_crypto::chacha20poly1305::{
                    aead::{Aead, KeyInit, Payload},
                    ChaCha20Poly1305, Key, Nonce,
                };
                ChaCha20Poly1305::new(Key::from_slice(key))
                    .decrypt(
                        Nonce::from_slice(nonce),
                        Payload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| RealityError::TagMismatch)
            }
            Self::Aes128Gcm => {
                use mirage_crypto::aes_gcm::{
                    aead::{Aead, KeyInit, Payload},
                    Aes128Gcm, Key, Nonce,
                };
                Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key))
                    .decrypt(
                        Nonce::from_slice(nonce),
                        Payload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| RealityError::TagMismatch)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_server_hello::{TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256};

    #[test]
    fn suite_mapping() {
        assert_eq!(
            RecordCipher::from_cipher_suite(TLS_AES_128_GCM_SHA256),
            RecordCipher::Aes128Gcm
        );
        assert_eq!(
            RecordCipher::from_cipher_suite(TLS_CHACHA20_POLY1305_SHA256),
            RecordCipher::ChaCha20Poly1305
        );
        assert_eq!(RecordCipher::Aes128Gcm.key_len(), 16);
        assert_eq!(RecordCipher::ChaCha20Poly1305.key_len(), 32);
    }

    #[test]
    fn seal_open_roundtrip_both_ciphers() {
        for cipher in [RecordCipher::ChaCha20Poly1305, RecordCipher::Aes128Gcm] {
            let key = vec![0x42u8; cipher.key_len()];
            let nonce = [0x07u8; 12];
            let aad = b"tls-1.3-record-aad";
            let pt = b"mirage session frame bytes";
            let ct = cipher.seal(&key, &nonce, aad, pt).unwrap();
            assert_ne!(
                &ct[..pt.len()],
                &pt[..],
                "ciphertext must differ from plaintext"
            );
            let got = cipher.open(&key, &nonce, aad, &ct).unwrap();
            assert_eq!(got, pt);
            // Wrong AAD or a bit-flip fails the tag.
            assert!(cipher.open(&key, &nonce, b"other-aad", &ct).is_err());
            let mut tampered = ct.clone();
            tampered[0] ^= 1;
            assert!(cipher.open(&key, &nonce, aad, &tampered).is_err());
        }
    }

    #[test]
    fn traffic_keys_have_correct_length() {
        let secret = [0x11u8; HASH_LEN];
        assert_eq!(RecordCipher::Aes128Gcm.traffic_keys(&secret).0.len(), 16);
        assert_eq!(
            RecordCipher::ChaCha20Poly1305.traffic_keys(&secret).0.len(),
            32
        );
    }
}
