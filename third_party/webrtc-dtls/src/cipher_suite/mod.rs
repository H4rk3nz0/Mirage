pub mod cipher_suite_aes_128_cbc_sha;
pub mod cipher_suite_aes_128_ccm;
pub mod cipher_suite_aes_128_gcm_sha256;
pub mod cipher_suite_aes_256_cbc_sha;
// MIRAGE FINGERPRINT PATCH: ChaCha20-Poly1305 (RFC 7905) for Chrome DTLS parity.
pub mod cipher_suite_chacha20_poly1305_sha256;
pub mod cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm;
pub mod cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm8;
pub mod cipher_suite_tls_psk_with_aes_128_ccm;
pub mod cipher_suite_tls_psk_with_aes_128_ccm8;
pub mod cipher_suite_tls_psk_with_aes_128_gcm_sha256;

use std::fmt;
use std::marker::{Send, Sync};

use cipher_suite_aes_128_cbc_sha::*;
use cipher_suite_aes_128_gcm_sha256::*;
use cipher_suite_aes_256_cbc_sha::*;
use cipher_suite_chacha20_poly1305_sha256::*;
use cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm::*;
use cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm8::*;
use cipher_suite_tls_psk_with_aes_128_ccm::*;
use cipher_suite_tls_psk_with_aes_128_ccm8::*;
use cipher_suite_tls_psk_with_aes_128_gcm_sha256::*;

use super::client_certificate_type::*;
use super::error::*;
use super::record_layer::record_layer_header::*;

// CipherSuiteID is an ID for our supported CipherSuites
// Supported Cipher Suites
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CipherSuiteId {
    // AES-128-CCM
    Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm = 0xc0ac,
    Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8 = 0xc0ae,

    // AES-128-GCM-SHA256
    Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256 = 0xc02b,
    Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256 = 0xc02f,

    // MIRAGE FINGERPRINT PATCH: ChaCha20-Poly1305 (0xCCA9/0xCCA8) — Chrome/
    // libwebrtc offers these; fully implemented (RFC 7905), so negotiable.
    Tls_Ecdhe_Ecdsa_With_Chacha20_Poly1305_Sha256 = 0xcca9,
    Tls_Ecdhe_Rsa_With_Chacha20_Poly1305_Sha256 = 0xcca8,

    // MIRAGE FINGERPRINT PATCH: AES-128-CBC-SHA (0xC009/0xC013) — present in
    // Chrome's DTLS ClientHello. NEGOTIABLE (audit #30): fully implemented in
    // cipher_suite_aes_128_cbc_sha and in the acceptance set, so a peer/prober
    // selecting one completes the handshake exactly as genuine Chrome would
    // rather than aborting (which was a fingerprint distinguisher). Still never
    // *preferred* over the AEAD suites a real WebRTC peer always picks.
    Tls_Ecdhe_Ecdsa_With_Aes_128_Cbc_Sha = 0xc009,
    Tls_Ecdhe_Rsa_With_Aes_128_Cbc_Sha = 0xc013,

    // AES-256-CBC-SHA
    Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha = 0xc00a,
    Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha = 0xc014,

    // MIRAGE FINGERPRINT PATCH: static-RSA fallback suites (0x009C/0x002F/
    // 0x0035) that Chrome's DTLS ClientHello also lists. WebRTC is ECDHE-only,
    // so these are offer-only (marshaled for parity, never negotiated).
    Tls_Rsa_With_Aes_128_Gcm_Sha256 = 0x009c,
    Tls_Rsa_With_Aes_128_Cbc_Sha = 0x002f,
    Tls_Rsa_With_Aes_256_Cbc_Sha = 0x0035,

    Tls_Psk_With_Aes_128_Ccm = 0xc0a4,
    Tls_Psk_With_Aes_128_Ccm_8 = 0xc0a8,
    Tls_Psk_With_Aes_128_Gcm_Sha256 = 0x00a8,

    Unsupported,
}

impl fmt::Display for CipherSuiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM")
            }
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8 => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8")
            }
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256 => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
            }
            CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256 => {
                write!(f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
            }
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Chacha20_Poly1305_Sha256 => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")
            }
            CipherSuiteId::Tls_Ecdhe_Rsa_With_Chacha20_Poly1305_Sha256 => {
                write!(f, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")
            }
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Cbc_Sha => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")
            }
            CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Cbc_Sha => {
                write!(f, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
            }
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha => {
                write!(f, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA")
            }
            CipherSuiteId::Tls_Rsa_With_Aes_128_Gcm_Sha256 => {
                write!(f, "TLS_RSA_WITH_AES_128_GCM_SHA256")
            }
            CipherSuiteId::Tls_Rsa_With_Aes_128_Cbc_Sha => {
                write!(f, "TLS_RSA_WITH_AES_128_CBC_SHA")
            }
            CipherSuiteId::Tls_Rsa_With_Aes_256_Cbc_Sha => {
                write!(f, "TLS_RSA_WITH_AES_256_CBC_SHA")
            }
            CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha => {
                write!(f, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA")
            }
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm => write!(f, "TLS_PSK_WITH_AES_128_CCM"),
            CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8 => write!(f, "TLS_PSK_WITH_AES_128_CCM_8"),
            CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256 => {
                write!(f, "TLS_PSK_WITH_AES_128_GCM_SHA256")
            }
            _ => write!(f, "Unsupported CipherSuiteID"),
        }
    }
}

impl From<u16> for CipherSuiteId {
    fn from(val: u16) -> Self {
        match val {
            // AES-128-CCM
            0xc0ac => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm,
            0xc0ae => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8,

            // AES-128-GCM-SHA256
            0xc02b => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
            0xc02f => CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256,

            // ChaCha20-Poly1305 (MIRAGE)
            0xcca9 => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Chacha20_Poly1305_Sha256,
            0xcca8 => CipherSuiteId::Tls_Ecdhe_Rsa_With_Chacha20_Poly1305_Sha256,

            // AES-128-CBC-SHA (MIRAGE, offer-only)
            0xc009 => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Cbc_Sha,
            0xc013 => CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Cbc_Sha,

            // AES-256-CBC-SHA
            0xc00a => CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
            0xc014 => CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha,

            // static-RSA fallbacks (MIRAGE, offer-only)
            0x009c => CipherSuiteId::Tls_Rsa_With_Aes_128_Gcm_Sha256,
            0x002f => CipherSuiteId::Tls_Rsa_With_Aes_128_Cbc_Sha,
            0x0035 => CipherSuiteId::Tls_Rsa_With_Aes_256_Cbc_Sha,

            0xc0a4 => CipherSuiteId::Tls_Psk_With_Aes_128_Ccm,
            0xc0a8 => CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
            0x00a8 => CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,

            _ => CipherSuiteId::Unsupported,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum CipherSuiteHash {
    Sha256,
    // MIRAGE FINGERPRINT PATCH: SHA384 for AES-256-GCM-SHA384 (Chrome offers it).
    Sha384,
}

impl CipherSuiteHash {
    pub(crate) fn size(&self) -> usize {
        match *self {
            CipherSuiteHash::Sha256 => 32,
            CipherSuiteHash::Sha384 => 48,
        }
    }
}

pub trait CipherSuite {
    fn to_string(&self) -> String;
    fn id(&self) -> CipherSuiteId;
    fn certificate_type(&self) -> ClientCertificateType;
    fn hash_func(&self) -> CipherSuiteHash;
    fn is_psk(&self) -> bool;
    fn is_initialized(&self) -> bool;

    // Generate the internal encryption state
    fn init(
        &mut self,
        master_secret: &[u8],
        client_random: &[u8],
        server_random: &[u8],
        is_client: bool,
    ) -> Result<()>;

    fn encrypt(&self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>>;
}

// Taken from https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
// A cipher_suite is a specific combination of key agreement, cipher and MAC
// function.
pub fn cipher_suite_for_id(id: CipherSuiteId) -> Result<Box<dyn CipherSuite + Send + Sync>> {
    match id {
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm => {
            Ok(Box::new(new_cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm()))
        }
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8 => Ok(Box::new(
            new_cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm8(),
        )),
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256 => {
            Ok(Box::new(CipherSuiteAes128GcmSha256::new(false)))
        }
        CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256 => {
            Ok(Box::new(CipherSuiteAes128GcmSha256::new(true)))
        }
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Chacha20_Poly1305_Sha256 => {
            Ok(Box::new(CipherSuiteChaCha20Poly1305Sha256::new(false)))
        }
        CipherSuiteId::Tls_Ecdhe_Rsa_With_Chacha20_Poly1305_Sha256 => {
            Ok(Box::new(CipherSuiteChaCha20Poly1305Sha256::new(true)))
        }
        CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha => {
            Ok(Box::new(CipherSuiteAes256CbcSha::new(true)))
        }
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha => {
            Ok(Box::new(CipherSuiteAes256CbcSha::new(false)))
        }
        // MIRAGE FINGERPRINT PATCH (audit #30): the AES-128-CBC ECDHE suites
        // Chrome advertises are now negotiable, not offer-only.
        CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Cbc_Sha => {
            Ok(Box::new(CipherSuiteAes128CbcSha::new(true)))
        }
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Cbc_Sha => {
            Ok(Box::new(CipherSuiteAes128CbcSha::new(false)))
        }
        CipherSuiteId::Tls_Psk_With_Aes_128_Ccm => {
            Ok(Box::new(new_cipher_suite_tls_psk_with_aes_128_ccm()))
        }
        CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8 => {
            Ok(Box::new(new_cipher_suite_tls_psk_with_aes_128_ccm8()))
        }
        CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256 => {
            Ok(Box::<CipherSuiteTlsPskWithAes128GcmSha256>::default())
        }
        _ => Err(Error::ErrInvalidCipherSuite),
    }
}

// The suites we can actually NEGOTIATE (accept as a server, validate as a
// client), in preference order. This is deliberately DECOUPLED from the suites
// we OFFER on the wire — see chrome_dtls_cipher_suites() below. Mirage's
// ClientHello advertises Chrome's full 11-suite list for fingerprint parity,
// but only the subset here has a working crypto implementation; our bridge only
// ever selects from this set, so an offer-only suite is never chosen.
//
// MIRAGE FINGERPRINT PATCH: added ChaCha20-Poly1305 (Chrome's preferred AEAD on
// mobile). AES-256-GCM is intentionally ABSENT — libwebrtc's cipher string
// (`!AESGCM+AES256`) strips it, so a real Chrome WebRTC peer never offers it.
//
// MIRAGE FINGERPRINT PATCH (audit #30): the AES-128-CBC ECDHE suites are
// appended LAST so they are accepted if a peer/prober selects one (matching what
// Chrome's own ClientHello offers), yet never preferred over the AEAD suites a
// genuine WebRTC peer always selects. This closes the offered-but-not-negotiable
// gap for every ECDHE suite Chrome advertises. The three trailing RSA
// key-transport suites (0x009C/0x002F/0x0035) remain intentionally offer-only:
// they require an RSA certificate, which is incompatible with the ECDSA
// self-signed cert every WebRTC peer uses, so a genuine Chrome client also
// cannot complete them — our rejection matches, not diverges from, real Chrome.
pub(crate) fn default_cipher_suites() -> Vec<Box<dyn CipherSuite + Send + Sync>> {
    vec![
        Box::new(CipherSuiteAes128GcmSha256::new(false)),
        Box::new(CipherSuiteChaCha20Poly1305Sha256::new(false)),
        Box::new(CipherSuiteAes256CbcSha::new(false)),
        Box::new(CipherSuiteAes128GcmSha256::new(true)),
        Box::new(CipherSuiteChaCha20Poly1305Sha256::new(true)),
        Box::new(CipherSuiteAes256CbcSha::new(true)),
        Box::new(CipherSuiteAes128CbcSha::new(false)),
        Box::new(CipherSuiteAes128CbcSha::new(true)),
    ]
}

// MIRAGE FINGERPRINT PATCH: the exact cipher-suite list a Chrome/libwebrtc DTLS
// 1.2 ClientHello offers, in order (11 suites, NO GREASE). Empirically verified
// against real Chrome captures (covert-dtls, FOCI 2025) and derived from
// libwebrtc's `SSL_CTX_set_cipher_list` string. This is the OFFERED list marshaled
// into our ClientHello (flight1/flight3); it is intentionally a superset of
// default_cipher_suites() — the trailing static-RSA and AES-128-CBC suites are
// advertised for parity but never negotiated (WebRTC is ECDHE-AEAD in practice).
pub(crate) fn chrome_dtls_cipher_suites() -> Vec<CipherSuiteId> {
    vec![
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256, // 0xC02B
        CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256,   // 0xC02F
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Chacha20_Poly1305_Sha256, // 0xCCA9
        CipherSuiteId::Tls_Ecdhe_Rsa_With_Chacha20_Poly1305_Sha256,   // 0xCCA8
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Cbc_Sha,    // 0xC009
        CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Cbc_Sha,      // 0xC013
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,    // 0xC00A
        CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha,      // 0xC014
        CipherSuiteId::Tls_Rsa_With_Aes_128_Gcm_Sha256,         // 0x009C
        CipherSuiteId::Tls_Rsa_With_Aes_128_Cbc_Sha,            // 0x002F
        CipherSuiteId::Tls_Rsa_With_Aes_256_Cbc_Sha,            // 0x0035
    ]
}

fn all_cipher_suites() -> Vec<Box<dyn CipherSuite + Send + Sync>> {
    vec![
        Box::new(new_cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm()),
        Box::new(new_cipher_suite_tls_ecdhe_ecdsa_with_aes_128_ccm8()),
        Box::new(CipherSuiteAes128GcmSha256::new(false)),
        Box::new(CipherSuiteAes128GcmSha256::new(true)),
        Box::new(CipherSuiteAes256CbcSha::new(false)),
        Box::new(CipherSuiteAes256CbcSha::new(true)),
        Box::new(new_cipher_suite_tls_psk_with_aes_128_ccm()),
        Box::new(new_cipher_suite_tls_psk_with_aes_128_ccm8()),
        Box::<CipherSuiteTlsPskWithAes128GcmSha256>::default(),
    ]
}

fn cipher_suites_for_ids(ids: &[CipherSuiteId]) -> Result<Vec<Box<dyn CipherSuite + Send + Sync>>> {
    let mut cipher_suites = vec![];
    for id in ids {
        cipher_suites.push(cipher_suite_for_id(*id)?);
    }
    Ok(cipher_suites)
}

pub(crate) fn parse_cipher_suites(
    user_selected_suites: &[CipherSuiteId],
    exclude_psk: bool,
    exclude_non_psk: bool,
) -> Result<Vec<Box<dyn CipherSuite + Send + Sync>>> {
    let cipher_suites = if !user_selected_suites.is_empty() {
        cipher_suites_for_ids(user_selected_suites)?
    } else {
        default_cipher_suites()
    };

    let filtered_cipher_suites: Vec<Box<dyn CipherSuite + Send + Sync>> = cipher_suites
        .into_iter()
        .filter(|c| !((exclude_psk && c.is_psk()) || (exclude_non_psk && !c.is_psk())))
        .collect();

    if filtered_cipher_suites.is_empty() {
        Err(Error::ErrNoAvailableCipherSuites)
    } else {
        Ok(filtered_cipher_suites)
    }
}

#[cfg(test)]
mod mirage_fingerprint_tests {
    use super::*;

    /// Audit #30: every ECDHE cipher suite Chrome's ClientHello OFFERS must also
    /// be NEGOTIABLE - resolvable via `cipher_suite_for_id` AND present in the
    /// acceptance set `default_cipher_suites()` - otherwise a peer/prober
    /// selecting one makes us abort where genuine Chrome completes. The three RSA
    /// key-transport suites are exempt: they need an RSA cert, incompatible with
    /// the ECDSA cert every WebRTC peer uses, so genuine Chrome also cannot
    /// complete them and our rejection matches real behaviour.
    #[test]
    fn every_offered_ecdhe_suite_is_negotiable() {
        let rsa_kx_offer_only = [
            CipherSuiteId::Tls_Rsa_With_Aes_128_Gcm_Sha256, // 0x009C
            CipherSuiteId::Tls_Rsa_With_Aes_128_Cbc_Sha,    // 0x002F
            CipherSuiteId::Tls_Rsa_With_Aes_256_Cbc_Sha,    // 0x0035
        ];
        let accept_ids: Vec<CipherSuiteId> =
            default_cipher_suites().iter().map(|c| c.id()).collect();

        for id in chrome_dtls_cipher_suites() {
            if rsa_kx_offer_only.contains(&id) {
                continue;
            }
            assert!(
                cipher_suite_for_id(id).is_ok(),
                "offered ECDHE suite {id} must be instantiable",
            );
            assert!(
                accept_ids.contains(&id),
                "offered ECDHE suite {id} must be in the acceptance set",
            );
        }
    }

    /// The new AES-128-CBC suites must actually encrypt/decrypt (the shared
    /// `CryptoCbc` selecting AES-128 by key length).
    #[test]
    fn aes128_cbc_suite_roundtrips() {
        use crate::cipher_suite::cipher_suite_aes_128_cbc_sha::CipherSuiteAes128CbcSha;
        use crate::content::ContentType;
        use crate::record_layer::record_layer_header::{
            RecordLayerHeader, PROTOCOL_VERSION1_2, RECORD_LAYER_HEADER_SIZE,
        };

        let master = [0x11u8; 48];
        let cr = [0x22u8; 32];
        let sr = [0x33u8; 32];
        let mut client = CipherSuiteAes128CbcSha::new(false);
        let mut server = CipherSuiteAes128CbcSha::new(false);
        client.init(&master, &cr, &sr, true).unwrap();
        server.init(&master, &cr, &sr, false).unwrap();
        assert!(client.is_initialized() && server.is_initialized());

        let plaintext = b"mirage aes-128-cbc dtls record payload";
        let h = RecordLayerHeader {
            content_type: ContentType::ApplicationData,
            protocol_version: PROTOCOL_VERSION1_2,
            epoch: 1,
            sequence_number: 1,
            content_len: plaintext.len() as u16,
        };
        // `encrypt` copies raw[..RECORD_LAYER_HEADER_SIZE] verbatim as the output
        // record header, so it must be a real marshaled header, not zeros.
        let mut raw = Vec::new();
        h.marshal(&mut raw).unwrap();
        assert_eq!(raw.len(), RECORD_LAYER_HEADER_SIZE);
        raw.extend_from_slice(plaintext);

        let ct = client.encrypt(&h, &raw).unwrap();
        let pt = server.decrypt(&ct).unwrap();
        assert_eq!(
            &pt[RECORD_LAYER_HEADER_SIZE..],
            plaintext,
            "server must recover client's plaintext"
        );
    }
}
