use std::io::{BufReader, BufWriter};
use std::time::{Duration, SystemTime};

use super::*;
use crate::curve::named_curve::*;
use crate::extension::extension_supported_elliptic_curves::*;

#[test]
fn test_handshake_message_client_hello() -> Result<()> {
    let raw_client_hello = vec![
        0xfe, 0xfd, 0xb6, 0x2f, 0xce, 0x5c, 0x42, 0x54, 0xff, 0x86, 0xe1, 0x24, 0x41, 0x91, 0x42,
        0x62, 0x15, 0xad, 0x16, 0xc9, 0x15, 0x8d, 0x95, 0x71, 0x8a, 0xbb, 0x22, 0xd7, 0x47, 0xec,
        0xd8, 0x3d, 0xdc, 0x4b, 0x00, 0x14, 0xe6, 0x14, 0x3a, 0x1b, 0x04, 0xea, 0x9e, 0x7a, 0x14,
        0xd6, 0x6c, 0x57, 0xd0, 0x0e, 0x32, 0x85, 0x76, 0x18, 0xde, 0xd8, 0x00, 0x04, 0xc0, 0x2b,
        0xc0, 0x0a, 0x01, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d,
    ];

    let gmt_unix_time = if let Some(unix_time) =
        SystemTime::UNIX_EPOCH.checked_add(Duration::new(3056586332u64, 0))
    {
        unix_time
    } else {
        SystemTime::UNIX_EPOCH
    };
    let parsed_client_hello = HandshakeMessageClientHello {
        version: ProtocolVersion {
            major: 0xFE,
            minor: 0xFD,
        },
        random: HandshakeRandom {
            gmt_unix_time,
            random_bytes: [
                0x42, 0x54, 0xff, 0x86, 0xe1, 0x24, 0x41, 0x91, 0x42, 0x62, 0x15, 0xad, 0x16, 0xc9,
                0x15, 0x8d, 0x95, 0x71, 0x8a, 0xbb, 0x22, 0xd7, 0x47, 0xec, 0xd8, 0x3d, 0xdc, 0x4b,
            ],
        },
        cookie: vec![
            0xe6, 0x14, 0x3a, 0x1b, 0x04, 0xea, 0x9e, 0x7a, 0x14, 0xd6, 0x6c, 0x57, 0xd0, 0x0e,
            0x32, 0x85, 0x76, 0x18, 0xde, 0xd8,
        ],
        cipher_suites: vec![
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
            //Box::<CipherSuiteTLSEcdheEcdsaWithAes128GcmSha256>::default(),
            //Box::<CipherSuiteTLSEcdheEcdsaWithAes256CbcSha>::default(),
        ],
        compression_methods: CompressionMethods {
            ids: vec![CompressionMethodId::Null],
        },
        extensions: vec![Extension::SupportedEllipticCurves(
            ExtensionSupportedEllipticCurves {
                elliptic_curves: vec![NamedCurve::X25519],
            },
        )],
    };

    let mut reader = BufReader::new(raw_client_hello.as_slice());
    let c = HandshakeMessageClientHello::unmarshal(&mut reader)?;
    assert_eq!(
        c, parsed_client_hello,
        "handshakeMessageClientHello unmarshal: got {c:?}, want {parsed_client_hello:?}"
    );

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        c.marshal(&mut writer)?;
    }
    assert_eq!(
        raw, raw_client_hello,
        "handshakeMessageClientHello marshal: got {raw:?}, want {raw_client_hello:?}"
    );

    Ok(())
}

// Regression: a ClientHello whose declared extension block is truncated
// mid-header (fewer than 4 bytes remaining) must not panic while parsing --
// this is attacker-controlled and reached pre-authentication.
#[test]
fn test_client_hello_truncated_extension_block_no_panic() {
    // version(2) + random(32) + session_id_len(1) + cookie_len(1)
    // + cipher_suites_len(2)=0 + compression_methods(len=1, one method)
    // + extensions_len(2) = 2, then only 2 bytes of extension data (a bare
    // 2-byte type with no length field) -> the old code indexed [offset+2]
    // out of bounds.
    let mut raw = vec![0xfe, 0xfd]; // ProtocolVersion 1.2
    raw.extend_from_slice(&[0u8; 32]); // random
    raw.push(0x00); // session id length
    raw.push(0x00); // cookie length
    raw.extend_from_slice(&[0x00, 0x00]); // cipher suites length = 0
    raw.extend_from_slice(&[0x01, 0x00]); // compression methods: len 1, method 0
    raw.extend_from_slice(&[0x00, 0x02]); // extensions length = 2
    raw.extend_from_slice(&[0x00, 0x0a]); // 2 bytes, truncated extension header

    let mut reader = BufReader::new(raw.as_slice());
    // Must return cleanly (Ok or Err), never panic.
    let _ = HandshakeMessageClientHello::unmarshal(&mut reader);
}
