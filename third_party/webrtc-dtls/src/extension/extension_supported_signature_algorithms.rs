#[cfg(test)]
mod extension_supported_signature_algorithms_test;

use super::*;

// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
//
// MIRAGE FINGERPRINT PATCH: this extension now carries RAW 2-byte
// SignatureScheme code points (RFC 8446 §4.2.3), not the legacy TLS-1.2
// {HashAlgorithm(1), SignatureAlgorithm(1)} byte pairs. That legacy split
// cannot express RSA-PSS (`rsa_pss_rsae_sha256` = 0x0804; 0x08 is not a valid
// HashAlgorithm), so it was impossible to advertise Chrome's real DTLS
// signature_algorithms list. On the wire a raw u16 is byte-identical to the
// legacy pair for every non-PSS scheme (e.g. ecdsa_secp256r1_sha256 = 0x0403 =
// {hash=4, sig=3}), so this change is wire-compatible for existing schemes and
// additionally lets us emit the PSS + SHA-1-tail entries Chrome sends.
//
// The decoded value is never consumed for signing/verification selection in
// this stack (each side selects from its own local_signature_schemes), so the
// list is purely a wire fingerprint — see cipher_suite::chrome_dtls_cipher_suites
// and signature_hash_algorithm::chrome_dtls_signature_schemes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionSupportedSignatureAlgorithms {
    pub(crate) signature_schemes: Vec<u16>,
}

impl ExtensionSupportedSignatureAlgorithms {
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::SupportedSignatureAlgorithms
    }

    pub fn size(&self) -> usize {
        2 + 2 + self.signature_schemes.len() * 2
    }

    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(2 + 2 * self.signature_schemes.len() as u16)?;
        writer.write_u16::<BigEndian>(2 * self.signature_schemes.len() as u16)?;
        for v in &self.signature_schemes {
            writer.write_u16::<BigEndian>(*v)?;
        }

        Ok(writer.flush()?)
    }

    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let _ = reader.read_u16::<BigEndian>()?;

        let scheme_count = reader.read_u16::<BigEndian>()? as usize / 2;
        let mut signature_schemes = vec![];
        for _ in 0..scheme_count {
            signature_schemes.push(reader.read_u16::<BigEndian>()?);
        }

        Ok(ExtensionSupportedSignatureAlgorithms { signature_schemes })
    }
}
