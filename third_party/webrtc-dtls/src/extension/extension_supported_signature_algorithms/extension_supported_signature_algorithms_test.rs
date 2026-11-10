use std::io::{BufReader, BufWriter};

use super::*;

#[test]
fn test_extension_supported_signature_algorithms() -> Result<()> {
    // MIRAGE FINGERPRINT PATCH: the extension now carries raw u16 SignatureScheme
    // codes. The wire bytes are unchanged for non-PSS schemes: 0x0403
    // (ecdsa_secp256r1_sha256), 0x0503 (ecdsa_secp384r1_sha384), 0x0603
    // (ecdsa_secp521r1_sha512).
    let raw_extension_supported_signature_algorithms =
        vec![0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03]; //0x00, 0x0d,
    let parsed_extension_supported_signature_algorithms = ExtensionSupportedSignatureAlgorithms {
        signature_schemes: vec![0x0403, 0x0503, 0x0603],
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        parsed_extension_supported_signature_algorithms.marshal(&mut writer)?;
    }

    assert_eq!(
        raw, raw_extension_supported_signature_algorithms,
        "extensionSupportedSignatureAlgorithms marshal: got {raw:?}, want {raw_extension_supported_signature_algorithms:?}"
    );

    let mut reader = BufReader::new(raw.as_slice());
    let new_extension_supported_signature_algorithms =
        ExtensionSupportedSignatureAlgorithms::unmarshal(&mut reader)?;

    assert_eq!(
        new_extension_supported_signature_algorithms,
        parsed_extension_supported_signature_algorithms,
        "extensionSupportedSignatureAlgorithms unmarshal: got {new_extension_supported_signature_algorithms:?}, want {parsed_extension_supported_signature_algorithms:?}"
    );

    // MIRAGE: also assert PSS round-trips (the whole point of the rework) — the
    // legacy {hash,sig} representation could not express 0x0804.
    let pss = ExtensionSupportedSignatureAlgorithms {
        signature_schemes: vec![0x0804, 0x0805, 0x0806],
    };
    let mut raw2 = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw2.as_mut());
        pss.marshal(&mut writer)?;
    }
    assert_eq!(raw2, vec![0x00, 0x08, 0x00, 0x06, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06]);
    let mut reader2 = BufReader::new(raw2.as_slice());
    assert_eq!(
        ExtensionSupportedSignatureAlgorithms::unmarshal(&mut reader2)?,
        pss
    );

    Ok(())
}
