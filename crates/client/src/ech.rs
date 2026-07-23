//! Hand-rolled RFC 9180 HPKE for Encrypted Client Hello (ECH), over the pure-Rust
//! primitives already in the tree (x25519-dalek, hkdf, sha2, aes-gcm) - ZERO new
//! dependencies. Suite: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, the
//! suite Cloudflare's ECH deployment uses.
//!
//! Wrapped in rustls's `crypto::hpke::Hpke` trait so `ClientConfig::with_ech` drives
//! it. Validated against the RFC 9180 Appendix A.1 known-answer vectors (see tests):
//! encap/decap shared secret, the full key schedule, and the seq-0 seal ciphertext.
//!
//! Coupling caveat: rustls 0.23.39 only exposes `HpkeKem`/`HpkeKdf`/`HpkeAead` via its
//! `internal` (doc-hidden, explicitly "not a stable interface") module, so this is tied
//! to that exact rustls version. The workspace pins `rustls = "=0.23.39"`, so it is
//! stable in practice; revisit this file on any rustls bump.

use std::fmt;

use mirage_crypto::aes_gcm::aead::{Aead, KeyInit, Payload};
use mirage_crypto::aes_gcm::{Aes128Gcm, Nonce};
use mirage_crypto::hkdf::Hkdf;
use mirage_crypto::sha2::Sha256;
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use tokio_rustls::rustls::client::EchMode;
use tokio_rustls::rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use tokio_rustls::rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use tokio_rustls::rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use tokio_rustls::rustls::Error;

const KEM_ID: u16 = 0x0020; // DHKEM(X25519, HKDF-SHA256)
const KDF_ID: u16 = 0x0001; // HKDF-SHA256
const AEAD_ID: u16 = 0x0001; // AES-128-GCM
const NK: usize = 16; // AES-128 key length
const NN: usize = 12; // GCM nonce length
const NSECRET: usize = 32; // KEM shared-secret / SHA-256 length

fn kem_suite_id() -> Vec<u8> {
    let mut v = b"KEM".to_vec();
    v.extend_from_slice(&KEM_ID.to_be_bytes());
    v
}

fn hpke_suite_id() -> Vec<u8> {
    let mut v = b"HPKE".to_vec();
    v.extend_from_slice(&KEM_ID.to_be_bytes());
    v.extend_from_slice(&KDF_ID.to_be_bytes());
    v.extend_from_slice(&AEAD_ID.to_be_bytes());
    v
}

/// RFC 9180 LabeledExtract -> 32-byte PRK.
fn labeled_extract(salt: &[u8], suite_id: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut labeled_ikm = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(prk.as_slice());
    out
}

/// RFC 9180 LabeledExpand -> `l` bytes.
fn labeled_expand(prk: &[u8], suite_id: &[u8], label: &[u8], info: &[u8], l: usize) -> Vec<u8> {
    let mut labeled_info = Vec::with_capacity(9 + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&(l as u16).to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("prk >= 32 bytes");
    let mut okm = vec![0u8; l];
    hk.expand(&labeled_info, &mut okm)
        .expect("valid expand length");
    okm
}

/// DHKEM ExtractAndExpand(dh, kem_context) -> 32-byte shared secret.
fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> [u8; 32] {
    let sid = kem_suite_id();
    let eae_prk = labeled_extract(b"", &sid, b"eae_prk", dh);
    let ss = labeled_expand(&eae_prk, &sid, b"shared_secret", kem_context, NSECRET);
    let mut out = [0u8; 32];
    out.copy_from_slice(&ss);
    out
}

/// DHKEM(X25519) Encap with a caller-supplied ephemeral scalar (deterministic - the RNG
/// path just draws `sk_e` randomly). Returns `(enc = pkE, shared_secret)`.
fn encap(pk_r: &[u8; 32], sk_e: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let sk_e = StaticSecret::from(sk_e);
    let enc = PublicKey::from(&sk_e).to_bytes();
    let dh = sk_e.diffie_hellman(&PublicKey::from(*pk_r));
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(pk_r);
    (enc, extract_and_expand(dh.as_bytes(), &kem_context))
}

/// DHKEM(X25519) Decap. Returns the shared secret.
fn decap(enc: &[u8; 32], sk_r: &[u8; 32]) -> [u8; 32] {
    let sk_r = StaticSecret::from(*sk_r);
    let pk_r = PublicKey::from(&sk_r);
    let dh = sk_r.diffie_hellman(&PublicKey::from(*enc));
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(pk_r.as_bytes());
    extract_and_expand(dh.as_bytes(), &kem_context)
}

/// RFC 9180 KeySchedule (Base mode). Returns (key[16], base_nonce[12], exporter[32]).
fn key_schedule_base(shared_secret: &[u8; 32], info: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let sid = hpke_suite_id();
    let psk_id_hash = labeled_extract(b"", &sid, b"psk_id_hash", b"");
    let info_hash = labeled_extract(b"", &sid, b"info_hash", info);
    let mut ksc = Vec::with_capacity(1 + 32 + 32);
    ksc.push(0x00); // mode_base
    ksc.extend_from_slice(&psk_id_hash);
    ksc.extend_from_slice(&info_hash);
    let secret = labeled_extract(shared_secret, &sid, b"secret", b"");
    let key = labeled_expand(&secret, &sid, b"key", &ksc, NK);
    let base_nonce = labeled_expand(&secret, &sid, b"base_nonce", &ksc, NN);
    let exporter = labeled_expand(&secret, &sid, b"exp", &ksc, NSECRET);
    (key, base_nonce, exporter)
}

/// Per-message nonce: base_nonce XOR seq (seq right-aligned into the 12-byte nonce).
fn compute_nonce(base_nonce: &[u8], seq: u64) -> [u8; NN] {
    let mut nonce = [0u8; NN];
    nonce.copy_from_slice(&base_nonce[..NN]);
    let seq_be = seq.to_be_bytes();
    for (i, b) in seq_be.iter().enumerate() {
        nonce[NN - 8 + i] ^= *b;
    }
    nonce
}

fn bad(msg: &'static str) -> Error {
    Error::General(msg.into())
}

fn to_arr32(b: &[u8]) -> Result<[u8; 32], Error> {
    b.try_into().map_err(|_| bad("hpke: expected 32-byte key"))
}

/// Stateful AEAD context (sealer or opener share the same shape).
struct Context {
    cipher: Aes128Gcm,
    base_nonce: Vec<u8>,
    seq: u64,
}

impl Context {
    fn new(key: &[u8], base_nonce: Vec<u8>) -> Result<Self, Error> {
        let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| bad("hpke: aes key"))?;
        Ok(Self {
            cipher,
            base_nonce,
            seq: 0,
        })
    }

    fn next_nonce(&mut self) -> Result<[u8; NN], Error> {
        let n = compute_nonce(&self.base_nonce, self.seq);
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| bad("hpke: seq overflow"))?;
        Ok(n)
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("hpke::Context")
    }
}

impl HpkeSealer for Context {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.next_nonce()?;
        self.cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| bad("hpke: seal"))
    }
}

impl HpkeOpener for Context {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.next_nonce()?;
        self.cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| bad("hpke: open"))
    }
}

fn random_scalar() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("getrandom");
    b
}

/// rustls HPKE provider for DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-128-GCM.
#[derive(Debug)]
pub struct EchHpke;

/// A `'static` handle for `EchConfig::new(list, &[ECH_HPKE_SUITE])`.
pub static ECH_HPKE_SUITE: &dyn Hpke = &EchHpke;

/// Build an ECH `EchMode::Enable` from a CDN's published ECHConfigList (raw bytes, as
/// delivered in the invite), backed by the hand-rolled HPKE suite above. Feed the result
/// to `ClientConfig::builder_with_provider(..).with_ech(..)`.
pub fn ech_mode(ech_config_list: &[u8]) -> Result<EchMode, Error> {
    use tokio_rustls::rustls::client::EchConfig;
    use tokio_rustls::rustls::pki_types::EchConfigListBytes;
    EchConfig::new(EchConfigListBytes::from(ech_config_list), &[ECH_HPKE_SUITE])
        .map(EchMode::Enable)
}

impl Hpke for EchHpke {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let pk_r = to_arr32(&pub_key.0)?;
        let (enc, ss) = encap(&pk_r, random_scalar());
        let (key, base_nonce, _) = key_schedule_base(&ss, info);
        let ct = Context::new(&key, base_nonce)?.seal(aad, plaintext)?;
        Ok((EncapsulatedSecret(enc.to_vec()), ct))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let pk_r = to_arr32(&pub_key.0)?;
        let (enc, ss) = encap(&pk_r, random_scalar());
        let (key, base_nonce, _) = key_schedule_base(&ss, info);
        Ok((
            EncapsulatedSecret(enc.to_vec()),
            Box::new(Context::new(&key, base_nonce)?),
        ))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        let sk_r = to_arr32(secret_key.secret_bytes())?;
        let ss = decap(&to_arr32(&enc.0)?, &sk_r);
        let (key, base_nonce, _) = key_schedule_base(&ss, info);
        Context::new(&key, base_nonce)?.open(aad, ciphertext)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        let sk_r = to_arr32(secret_key.secret_bytes())?;
        let ss = decap(&to_arr32(&enc.0)?, &sk_r);
        let (key, base_nonce, _) = key_schedule_base(&ss, info);
        Ok(Box::new(Context::new(&key, base_nonce)?))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let sk = random_scalar();
        let pk = PublicKey::from(&StaticSecret::from(sk));
        Ok((
            HpkePublicKey(pk.to_bytes().to_vec()),
            HpkePrivateKey::from(sk.to_vec()),
        ))
    }

    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::AES_128_GCM,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn a32(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }

    // RFC 9180 Appendix A.1 - DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-128-GCM.
    const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
    const SK_EM: &str = "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";
    const PK_EM: &str = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
    const SK_RM: &str = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8";
    const PK_RM: &str = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d";
    const SHARED: &str = "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc";
    const KEY: &str = "4531685d41d65f03dc48f6b8302c05b0";
    const BASE_NONCE: &str = "56d890e5accaaf011cff4b7d";
    const EXPORTER: &str = "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8";
    const AAD0: &str = "436f756e742d30";
    const PT0: &str = "4265617574792069732074727574682c20747275746820626561757479";
    const CT0: &str = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a";

    #[test]
    fn rfc9180_a1_encap_matches() {
        let (enc, ss) = encap(&a32(PK_RM), a32(SK_EM));
        assert_eq!(enc.to_vec(), h(PK_EM), "encapsulated key (enc = pkEm)");
        assert_eq!(ss.to_vec(), h(SHARED), "encap shared secret");
    }

    #[test]
    fn rfc9180_a1_decap_matches() {
        let ss = decap(&a32(PK_EM), &a32(SK_RM));
        assert_eq!(ss.to_vec(), h(SHARED), "decap shared secret");
    }

    #[test]
    fn rfc9180_a1_key_schedule_matches() {
        let (key, base_nonce, exporter) = key_schedule_base(&a32(SHARED), &h(INFO));
        assert_eq!(key, h(KEY), "key");
        assert_eq!(base_nonce, h(BASE_NONCE), "base_nonce");
        assert_eq!(exporter, h(EXPORTER), "exporter_secret");
    }

    #[test]
    fn rfc9180_a1_seal_seq0_matches() {
        let mut ctx = Context::new(&h(KEY), h(BASE_NONCE)).unwrap();
        let ct = HpkeSealer::seal(&mut ctx, &h(AAD0), &h(PT0)).unwrap();
        assert_eq!(ct, h(CT0), "seq-0 ciphertext");
    }

    #[test]
    fn trait_roundtrip_seal_open() {
        // Full trait path: sender seals to the receiver's public key, receiver opens.
        let sk_r = a32(SK_RM);
        let pk_r = HpkePublicKey(
            PublicKey::from(&StaticSecret::from(sk_r))
                .to_bytes()
                .to_vec(),
        );
        let info = b"mirage ech test";
        let (enc, mut sealer) = EchHpke.setup_sealer(info, &pk_r).unwrap();
        let ct = sealer.seal(b"aad", b"hello proteus").unwrap();
        let mut opener = EchHpke
            .setup_opener(&enc, info, &HpkePrivateKey::from(sk_r.to_vec()))
            .unwrap();
        assert_eq!(opener.open(b"aad", &ct).unwrap(), b"hello proteus");
        // Wrong AAD must fail.
        let (enc2, mut s2) = EchHpke.setup_sealer(info, &pk_r).unwrap();
        let ct2 = s2.seal(b"aad", b"x").unwrap();
        let mut o2 = EchHpke
            .setup_opener(&enc2, info, &HpkePrivateKey::from(sk_r.to_vec()))
            .unwrap();
        assert!(o2.open(b"WRONG", &ct2).is_err());
    }
}
