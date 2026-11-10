// MIRAGE FINGERPRINT PATCH (audit #30): ECDHE_*_WITH_AES_128_CBC_SHA
// (0xC009 ECDSA / 0xC013 RSA). Chrome/libwebrtc's DTLS ClientHello advertises
// these two suites; before this file they were OFFERED but not NEGOTIABLE, so a
// peer or active prober selecting one made our client abort at ServerHello where
// a genuine Chrome client completes. Identical to the AES-256-CBC-SHA suite
// except the AES key is 16 bytes (`PRF_KEY_LEN = 16`); the shared `CryptoCbc`
// picks AES-128 vs AES-256 by write-key length.
use super::*;
use crate::crypto::crypto_cbc::*;
use crate::prf::*;

#[derive(Clone)]
pub struct CipherSuiteAes128CbcSha {
    cbc: Option<CryptoCbc>,
    rsa: bool,
}

impl CipherSuiteAes128CbcSha {
    const PRF_MAC_LEN: usize = 20;
    const PRF_KEY_LEN: usize = 16;
    const PRF_IV_LEN: usize = 16;

    pub fn new(rsa: bool) -> Self {
        CipherSuiteAes128CbcSha { cbc: None, rsa }
    }
}

impl CipherSuite for CipherSuiteAes128CbcSha {
    fn to_string(&self) -> String {
        if self.rsa {
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".to_owned()
        } else {
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA".to_owned()
        }
    }

    fn id(&self) -> CipherSuiteId {
        if self.rsa {
            CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Cbc_Sha
        } else {
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Cbc_Sha
        }
    }

    fn certificate_type(&self) -> ClientCertificateType {
        if self.rsa {
            ClientCertificateType::RsaSign
        } else {
            ClientCertificateType::EcdsaSign
        }
    }

    fn hash_func(&self) -> CipherSuiteHash {
        CipherSuiteHash::Sha256
    }

    fn is_psk(&self) -> bool {
        false
    }

    fn is_initialized(&self) -> bool {
        self.cbc.is_some()
    }

    fn init(
        &mut self,
        master_secret: &[u8],
        client_random: &[u8],
        server_random: &[u8],
        is_client: bool,
    ) -> Result<()> {
        let keys = prf_encryption_keys(
            master_secret,
            client_random,
            server_random,
            CipherSuiteAes128CbcSha::PRF_MAC_LEN,
            CipherSuiteAes128CbcSha::PRF_KEY_LEN,
            CipherSuiteAes128CbcSha::PRF_IV_LEN,
            self.hash_func(),
        )?;

        if is_client {
            self.cbc = Some(CryptoCbc::new(
                &keys.client_write_key,
                &keys.client_mac_key,
                &keys.server_write_key,
                &keys.server_mac_key,
            )?);
        } else {
            self.cbc = Some(CryptoCbc::new(
                &keys.server_write_key,
                &keys.server_mac_key,
                &keys.client_write_key,
                &keys.client_mac_key,
            )?);
        }

        Ok(())
    }

    fn encrypt(&self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        if let Some(cg) = &self.cbc {
            cg.encrypt(pkt_rlh, raw)
        } else {
            Err(Error::Other(
                "CipherSuite has not been initialized, unable to encrypt".to_owned(),
            ))
        }
    }

    fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        if let Some(cg) = &self.cbc {
            cg.decrypt(input)
        } else {
            Err(Error::Other(
                "CipherSuite has not been initialized, unable to decrypt".to_owned(),
            ))
        }
    }
}
