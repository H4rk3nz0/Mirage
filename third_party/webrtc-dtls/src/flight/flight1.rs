use std::fmt;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use rand::Rng;

use super::flight3::*;
use super::*;
use crate::cipher_suite::{chrome_dtls_cipher_suites, CipherSuiteId};
use crate::compression_methods::*;
use crate::config::*;
use crate::conn::*;
use crate::content::*;
use crate::curve::named_curve::*;
use crate::error::Error;
use crate::extension::extension_server_name::*;
use crate::extension::extension_supported_elliptic_curves::*;
use crate::extension::extension_supported_point_formats::*;
use crate::extension::extension_supported_signature_algorithms::*;
use crate::extension::extension_use_extended_master_secret::*;
use crate::extension::extension_use_srtp::*;
use crate::extension::renegotiation_info::ExtensionRenegotiationInfo;
use crate::extension::*;
use crate::handshake::handshake_message_client_hello::*;
use crate::handshake::*;
use crate::handshaker::HandshakeConfig;
use crate::record_layer::record_layer_header::*;
use crate::record_layer::*;
use crate::signature_hash_algorithm::chrome_dtls_signature_schemes;

#[derive(Debug, PartialEq)]
pub(crate) struct Flight1;

impl fmt::Display for Flight1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flight 1")
    }
}

#[async_trait]
impl Flight for Flight1 {
    async fn parse(
        &self,
        tx: &mut mpsc::Sender<mpsc::Sender<()>>,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Box<dyn Flight + Send + Sync>, (Option<Alert>, Option<Error>)> {
        // HelloVerifyRequest can be skipped by the server,
        // so allow ServerHello during flight1 also
        let (seq, msgs) = match cache
            .full_pull_map(
                state.handshake_recv_sequence,
                &[
                    HandshakeCachePullRule {
                        typ: HandshakeType::HelloVerifyRequest,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: true,
                    },
                    HandshakeCachePullRule {
                        typ: HandshakeType::ServerHello,
                        epoch: cfg.initial_epoch,
                        is_client: false,
                        optional: true,
                    },
                ],
            )
            .await
        {
            // No valid message received. Keep reading
            Ok((seq, msgs)) => (seq, msgs),
            Err(_) => return Err((None, None)),
        };

        if msgs.contains_key(&HandshakeType::ServerHello) {
            // Flight1 and flight2 were skipped.
            // Parse as flight3.
            let flight3 = Flight3 {};
            return flight3.parse(tx, state, cache, cfg).await;
        }

        if let Some(message) = msgs.get(&HandshakeType::HelloVerifyRequest) {
            // DTLS 1.2 clients must not assume that the server will use the protocol version
            // specified in HelloVerifyRequest message. RFC 6347 Section 4.2.1
            let h = match message {
                HandshakeMessage::HelloVerifyRequest(h) => h,
                _ => {
                    return Err((
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::InternalError,
                        }),
                        None,
                    ))
                }
            };

            if h.version != PROTOCOL_VERSION1_0 && h.version != PROTOCOL_VERSION1_2 {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::ProtocolVersion,
                    }),
                    Some(Error::ErrUnsupportedProtocolVersion),
                ));
            }

            state.cookie = h.cookie.clone();
            state.handshake_recv_sequence = seq;
            Ok(Box::new(Flight3 {}))
        } else {
            Err((
                Some(Alert {
                    alert_level: AlertLevel::Fatal,
                    alert_description: AlertDescription::InternalError,
                }),
                None,
            ))
        }
    }

    async fn generate(
        &self,
        state: &mut State,
        _cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Vec<Packet>, (Option<Alert>, Option<Error>)> {
        let zero_epoch = 0;
        state.local_epoch.store(zero_epoch, Ordering::SeqCst);
        state.remote_epoch.store(zero_epoch, Ordering::SeqCst);

        state.named_curve = DEFAULT_NAMED_CURVE;
        state.cookie = vec![];
        state.local_random.populate();

        // MIRAGE FINGERPRINT PATCH: generate the extension-permutation seed once,
        // from fresh CSPRNG entropy that is NOT any wire-visible value. Seeding
        // from client_random (as before) would make `ext_order = f(client_random)`
        // for a public f — a censor could recompute it and detect us, since real
        // Chrome permutes with an RNG independent of its random. Cache it in State
        // so the flight3 cookie-retransmit reproduces the identical order.
        if state.ch_ext_perm_seed == [0u8; 32] {
            rand::thread_rng().fill(&mut state.ch_ext_perm_seed);
        }

        // MIRAGE FINGERPRINT PATCH (keep in sync with flight3.rs): emit a
        // Chrome/libwebrtc-shaped DTLS ClientHello — the 6 real extensions with
        // NO GREASE and NO SNI, permuted per-connection (Chrome M120+), byte-
        // identical across the cookie retransmit. Only in the default ECDHE case;
        // a caller that pinned suites/PSK keeps upstream behavior. See FINGERPRINT.md.
        let (extensions, cipher_suites) = client_hello_body(cfg, &state.ch_ext_perm_seed);

        Ok(vec![Packet {
            record: RecordLayer::new(
                // MIRAGE FINGERPRINT PATCH: the initial ClientHello RECORD carries
                // DTLS 1.0 (0xfeff), not 1.2 — the record version is not yet
                // negotiated (RFC 6347 §4.2.1), and every real Chrome/BoringSSL
                // WebRTC capture shows record=0xfeff while the ClientHello BODY
                // client_version stays 0xfefd (set below). Upstream webrtc-rs
                // stamped 0xfefd on this record too — a distinguisher on the very
                // first datagram byte-pattern. Later flights use 0xfefd normally.
                PROTOCOL_VERSION1_0,
                0,
                Content::Handshake(Handshake::new(HandshakeMessage::ClientHello(
                    HandshakeMessageClientHello {
                        version: PROTOCOL_VERSION1_2,
                        random: state.local_random.clone(),
                        cookie: state.cookie.clone(),

                        cipher_suites,
                        compression_methods: default_compression_methods(),
                        extensions,
                    },
                ))),
            ),
            should_encrypt: false,
            reset_local_sequence_number: false,
        }])
    }
}

// MIRAGE FINGERPRINT PATCH: build the DTLS ClientHello extension block the way a
// Chrome/libwebrtc peer does — and NOT the way upstream webrtc-rs did.
//
// Empirically (real Chrome captures via covert-dtls / FOCI 2025, plus BoringSSL
// + libwebrtc source), a Chrome WebRTC DTLS 1.2 ClientHello carries exactly six
// extensions — extended_master_secret, renegotiation_info, supported_groups,
// ec_point_formats, signature_algorithms, use_srtp — with:
//   * NO GREASE anywhere (libwebrtc does not enable BoringSSL GREASE on its DTLS
//     context; the earlier Mirage GREASE injection was itself a distinguisher),
//   * NO server_name (a P2P DTLS ClientHello never carries SNI),
//   * supported_groups = X25519, secp256r1, secp384r1 (X25519 first),
//   * signature_algorithms = the raw 9-entry BoringSSL default (RSA-PSS + SHA-1
//     tail, no ed25519),
//   * the six extensions PERMUTED per-connection (Chrome M120+ Fisher–Yates).
//
// The permutation is deterministic in `seed` (the client_random) so flight1 and
// the flight3 cookie-retransmit emit an identical ClientHello, while different
// connections vary — matching Chrome and defeating extension-order fingerprints.
// MIRAGE FINGERPRINT PATCH: assemble the ClientHello extension block + offered
// cipher-suite list, shared by flight1 (initial) and flight3 (cookie retransmit)
// so they are byte-identical. When offer_chrome_fingerprint is set (the default
// ECDHE case), emit Chrome's exact lists; otherwise fall back to advertising the
// caller's configured suites/schemes (PSK or explicitly-pinned-suite callers),
// preserving upstream negotiation semantics.
pub(crate) fn client_hello_body(
    cfg: &HandshakeConfig,
    seed: &[u8],
) -> (Vec<Extension>, Vec<CipherSuiteId>) {
    if cfg.offer_chrome_fingerprint {
        return (
            chrome_client_hello_extensions(cfg, seed),
            chrome_dtls_cipher_suites(),
        );
    }

    // Upstream/default path: advertise exactly what was configured.
    let mut extensions = vec![];

    if cfg.extended_master_secret == ExtendedMasterSecretType::Request
        || cfg.extended_master_secret == ExtendedMasterSecretType::Require
    {
        extensions.push(Extension::UseExtendedMasterSecret(
            ExtensionUseExtendedMasterSecret { supported: true },
        ));
    }

    extensions.push(Extension::RenegotiationInfo(ExtensionRenegotiationInfo {
        renegotiated_connection: 0,
    }));

    if cfg.local_psk_callback.is_none() {
        extensions.push(Extension::SupportedEllipticCurves(
            ExtensionSupportedEllipticCurves {
                elliptic_curves: vec![NamedCurve::X25519, NamedCurve::P256, NamedCurve::P384],
            },
        ));
        extensions.push(Extension::SupportedPointFormats(
            ExtensionSupportedPointFormats {
                point_formats: vec![ELLIPTIC_CURVE_POINT_FORMAT_UNCOMPRESSED],
            },
        ));
    }

    extensions.push(Extension::SupportedSignatureAlgorithms(
        ExtensionSupportedSignatureAlgorithms {
            // Convert the internal {hash,sig} schemes to their raw u16 code
            // points (byte-identical to the legacy pair encoding).
            signature_schemes: cfg
                .local_signature_schemes
                .iter()
                .map(|s| ((s.hash as u16) << 8) | (s.signature as u16))
                .collect(),
        },
    ));

    if !cfg.local_srtp_protection_profiles.is_empty() {
        extensions.push(Extension::UseSrtp(ExtensionUseSrtp {
            protection_profiles: cfg.local_srtp_protection_profiles.clone(),
        }));
    }

    if !cfg.server_name.is_empty() {
        extensions.push(Extension::ServerName(ExtensionServerName {
            server_name: cfg.server_name.clone(),
        }));
    }

    (extensions, cfg.local_cipher_suites.clone())
}

pub(crate) fn chrome_client_hello_extensions(
    cfg: &HandshakeConfig,
    seed: &[u8],
) -> Vec<Extension> {
    let mut extensions = Vec::with_capacity(6);

    if cfg.extended_master_secret == ExtendedMasterSecretType::Request
        || cfg.extended_master_secret == ExtendedMasterSecretType::Require
    {
        extensions.push(Extension::UseExtendedMasterSecret(
            ExtensionUseExtendedMasterSecret { supported: true },
        ));
    }

    extensions.push(Extension::RenegotiationInfo(ExtensionRenegotiationInfo {
        renegotiated_connection: 0,
    }));

    if cfg.local_psk_callback.is_none() {
        extensions.push(Extension::SupportedEllipticCurves(
            ExtensionSupportedEllipticCurves {
                elliptic_curves: vec![NamedCurve::X25519, NamedCurve::P256, NamedCurve::P384],
            },
        ));
        extensions.push(Extension::SupportedPointFormats(
            ExtensionSupportedPointFormats {
                point_formats: vec![ELLIPTIC_CURVE_POINT_FORMAT_UNCOMPRESSED],
            },
        ));
    }

    extensions.push(Extension::SupportedSignatureAlgorithms(
        ExtensionSupportedSignatureAlgorithms {
            signature_schemes: chrome_dtls_signature_schemes(),
        },
    ));

    if !cfg.local_srtp_protection_profiles.is_empty() {
        extensions.push(Extension::UseSrtp(ExtensionUseSrtp {
            protection_profiles: cfg.local_srtp_protection_profiles.clone(),
        }));
    }

    permute_extensions(&mut extensions, seed);
    extensions
}

// Deterministic Fisher–Yates over the extension list, seeded from the
// client_random. Uses an inlined xorshift64* PRNG so the shuffle needs no
// external RNG and is reproducible for a given client_random (keeping the
// initial and cookie-retransmit ClientHello identical). Our own answerer parses
// extensions by type, order-independently, so any permutation is accepted.
fn permute_extensions(exts: &mut [Extension], seed: &[u8]) {
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
    for (i, b) in seed.iter().enumerate() {
        s ^= (*b as u64)
            .wrapping_add(0x517c_c1b7_2722_0a95)
            .rotate_left((i as u32) & 63);
        s = s.wrapping_mul(0x2545_F491_4F6C_DD1D);
    }
    // xorshift64*: guard against an all-zero state.
    if s == 0 {
        s = 0x9e37_79b9_7f4a_7c15;
    }
    let n = exts.len();
    for i in (1..n).rev() {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        let r = s.wrapping_mul(0x2545_F491_4F6C_DD1D);
        let j = (r % (i as u64 + 1)) as usize;
        exts.swap(i, j);
    }
}

#[cfg(test)]
mod fingerprint_test {
    use super::*;
    use crate::extension::extension_use_srtp::SrtpProtectionProfile;
    use crate::handshake::handshake_message_client_hello::HandshakeMessageClientHello;
    use crate::handshake::handshake_random::HandshakeRandom;

    fn chrome_cfg() -> HandshakeConfig {
        HandshakeConfig {
            offer_chrome_fingerprint: true,
            extended_master_secret: ExtendedMasterSecretType::Request,
            local_srtp_protection_profiles: vec![
                SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            ],
            ..Default::default()
        }
    }

    fn find(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn marshal_client_hello(cfg: &HandshakeConfig, seed: &[u8]) -> Vec<u8> {
        let (extensions, cipher_suites) = client_hello_body(cfg, seed);
        let ch = HandshakeMessageClientHello {
            version: PROTOCOL_VERSION1_2,
            random: HandshakeRandom::default(),
            cookie: vec![],
            cipher_suites,
            compression_methods: default_compression_methods(),
            extensions,
        };
        let mut raw = vec![];
        ch.marshal(&mut raw).unwrap();
        raw
    }

    // Definitive in-sandbox proof: marshal the Chrome-profile ClientHello and
    // assert its wire bytes are the exact Chrome/libwebrtc DTLS fingerprint —
    // cipher list, signature_algorithms, supported_groups, extension membership
    // — with NO GREASE and NO SNI anywhere. Verified against real Chrome captures
    // (covert-dtls / FOCI 2025) in the research spec.
    #[test]
    fn test_chrome_client_hello_wire_fingerprint() {
        let cfg = chrome_cfg();
        let (extensions, cipher_suites) = client_hello_body(&cfg, &[7u8; 28]);

        // Cipher list: exact 11-suite Chrome order, no GREASE.
        let ids: Vec<u16> = cipher_suites.iter().map(|c| *c as u16).collect();
        assert_eq!(
            ids,
            vec![
                0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x002f,
                0x0035
            ],
            "cipher list must be Chrome's exact 11-suite DTLS order"
        );

        // Exactly 6 extensions; none GREASE, none SNI.
        assert_eq!(extensions.len(), 6, "Chrome DTLS ClientHello has 6 extensions");
        for e in &extensions {
            let v = e.extension_value();
            assert_ne!(v, ExtensionValue::Grease, "no GREASE extension");
            assert_ne!(v, ExtensionValue::ServerName, "no SNI in a P2P DTLS ClientHello");
        }
        // The 6 canonical members are all present (order is permuted).
        let mut present: Vec<ExtensionValue> = extensions.iter().map(|e| e.extension_value()).collect();
        present.sort_by_key(|v| format!("{v:?}"));
        let mut want = vec![
            ExtensionValue::UseExtendedMasterSecret,
            ExtensionValue::RenegotiationInfo,
            ExtensionValue::SupportedEllipticCurves,
            ExtensionValue::SupportedPointFormats,
            ExtensionValue::SupportedSignatureAlgorithms,
            ExtensionValue::UseSrtp,
        ];
        want.sort_by_key(|v| format!("{v:?}"));
        assert_eq!(present, want);

        // Byte-level assertions on the marshaled ClientHello.
        let raw = marshal_client_hello(&cfg, &[7u8; 28]);
        // cipher-suite bytes, in order.
        assert!(
            find(
                &raw,
                &[
                    0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x09, 0xc0, 0x13, 0xc0,
                    0x0a, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x2f, 0x00, 0x35
                ]
            ),
            "cipher_suites wire bytes"
        );
        // signature_algorithms: ecdsa/pss/pkcs1 triads + SHA-1 tail (RSA-PSS incl).
        assert!(
            find(
                &raw,
                &[
                    0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08,
                    0x06, 0x06, 0x01, 0x02, 0x01
                ]
            ),
            "signature_algorithms wire bytes (with RSA-PSS + SHA-1 tail)"
        );
        // supported_groups: X25519, secp256r1, secp384r1 — no GREASE group.
        assert!(find(&raw, &[0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]), "supported_groups bytes");
        // No GREASE anywhere (cipher 0x0a0a, group 0x1a1a, extension 0x2a2a).
        assert!(!find(&raw, &[0x0a, 0x0a]), "no GREASE cipher");
        assert!(!find(&raw, &[0x1a, 0x1a]), "no GREASE group");
        assert!(!find(&raw, &[0x2a, 0x2a]), "no GREASE extension");
    }

    // The extension permutation must be STABLE for a given client_random (so the
    // flight1 initial and flight3 cookie-retransmit ClientHellos are byte-
    // identical), and vary across different client_randoms (like Chrome M120+).
    #[test]
    fn test_extension_permutation_stable_across_retransmit() {
        let cfg = chrome_cfg();
        let a = marshal_client_hello(&cfg, &[3u8; 28]);
        let b = marshal_client_hello(&cfg, &[3u8; 28]);
        assert_eq!(a, b, "same client_random must yield an identical ClientHello");

        // Across several distinct seeds the emitted extension order should not be
        // constant (defeating order-based fingerprints). Collect the order for a
        // handful of seeds and assert at least two differ.
        let orders: Vec<Vec<ExtensionValue>> = (0u8..8)
            .map(|k| {
                client_hello_body(&cfg, &[k; 28])
                    .0
                    .iter()
                    .map(|e| e.extension_value())
                    .collect()
            })
            .collect();
        assert!(
            orders.iter().any(|o| *o != orders[0]),
            "extension order must vary across client_randoms"
        );
    }
}
