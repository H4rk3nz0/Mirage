//! Per-hop key derivation for circuit onion layers.
//!
//! Given the shared secret produced by a per-hop Mirage handshake
//! (the `K_session_*` direction roots from
//! [`mirage_session::handshake::SessionKeys`] §3.5), derive four
//! AEAD parameters for the circuit cell layer:
//!
//! - `c2h_key` / `c2h_iv` - client->hop direction.
//! - `h2c_key` / `h2c_iv` - hop->client direction.
//!
//! The keys are domain-separated from the session-frame keys: a
//! key derived for the cell layer cannot decrypt a session frame
//! and vice versa.
//!
//! ```text
//!   c2h_key = BLAKE3-keyed(K_session_i2r, "mirage-circuit-c2h-key-v1")
//!   c2h_iv  = BLAKE3-keyed(K_session_i2r, "mirage-circuit-c2h-iv-v1")[0..12]
//!   h2c_key = BLAKE3-keyed(K_session_r2i, "mirage-circuit-h2c-key-v1")
//!   h2c_iv  = BLAKE3-keyed(K_session_r2i, "mirage-circuit-h2c-iv-v1")[0..12]
//! ```

use crate::onion::{OnionLayer, ONION_IV_LEN, ONION_KEY_LEN};
use mirage_crypto::blake3;
use mirage_crypto::zeroize::Zeroizing;

const LABEL_C2H_KEY: &[u8] = b"mirage-circuit-c2h-key-v1";
const LABEL_C2H_IV: &[u8] = b"mirage-circuit-c2h-iv-v1";
const LABEL_H2C_KEY: &[u8] = b"mirage-circuit-h2c-key-v1";
const LABEL_H2C_IV: &[u8] = b"mirage-circuit-h2c-iv-v1";

/// Direction-root label for client->responder traffic. Matches
/// `mirage-session::frames::direction_root` exactly - callers
/// of [`derive_hop_keys_from_handshake`] rely on this constant
/// reproducing the session crate's derivation. Cross-crate
/// consistency is verified by `tests/cross_crate_consistency.rs`
/// in `mirage-runtime`.
pub const SESSION_DIRECTION_LABEL_I2R: &[u8] = b"mirage-key-i2r-v1";
/// Direction-root label for responder->client traffic. See
/// [`SESSION_DIRECTION_LABEL_I2R`].
pub const SESSION_DIRECTION_LABEL_R2I: &[u8] = b"mirage-key-r2i-v1";

/// One hop's pair of onion layers (forward + reverse direction).
#[derive(Debug, Clone)]
pub struct HopKeys {
    /// Client -> hop layer (used by client to seal cells going AWAY,
    /// and by hop to peel them).
    pub forward: OnionLayer,
    /// Hop -> client layer (used by hop to seal cells coming BACK,
    /// and by client to peel them).
    pub reverse: OnionLayer,
}

/// Derive a hop's circuit keys from the per-hop Mirage handshake's
/// direction roots. `k_session_i2r` and `k_session_r2i` are the
/// 32-byte BLAKE3 outputs from
/// [`mirage_session::handshake::derive_session_root`] / §3.5.
///
/// The function takes plain `[u8;32]` rather than session-key
/// types to keep this crate from depending on the full session
/// crate. The caller (typically `mirage_circuit::client::extend_*`)
/// extracts the roots from the per-hop session and passes them in.
pub fn derive_hop_keys(k_session_i2r: &[u8; 32], k_session_r2i: &[u8; 32]) -> HopKeys {
    let c2h_key = derive32(k_session_i2r, LABEL_C2H_KEY);
    let c2h_iv = derive_iv(k_session_i2r, LABEL_C2H_IV);
    let h2c_key = derive32(k_session_r2i, LABEL_H2C_KEY);
    let h2c_iv = derive_iv(k_session_r2i, LABEL_H2C_IV);
    HopKeys {
        forward: OnionLayer {
            key: *c2h_key,
            iv: c2h_iv,
        },
        reverse: OnionLayer {
            key: *h2c_key,
            iv: h2c_iv,
        },
    }
}

/// Derive hop keys directly from the per-hop session handshake's
/// `mlkem_ss` (32-byte ML-KEM shared secret) and `session_binding`
/// (32-byte BLAKE3 of the Noise transcript + ML-KEM bytes).
///
/// This is the canonical one-call derivation Phase 2 runtime
/// adapters SHOULD use instead of manually composing
/// `direction_root` + [`derive_hop_keys`]. Closes [RT-M7]: blind-
/// key acceptance is reduced because the runtime no longer
/// computes direction roots by hand.
///
/// The labels [`SESSION_DIRECTION_LABEL_I2R`] /
/// [`SESSION_DIRECTION_LABEL_R2I`] match
/// `mirage-session::frames::direction_root` exactly. Cross-crate
/// consistency is enforced by an integration test in
/// `mirage-runtime`.
///
/// # Algorithm
///
/// ```text
///   k_i2r = BLAKE3(label_i2r || mlkem_ss || session_binding)  // 32 B
///   k_r2i = BLAKE3(label_r2i || mlkem_ss || session_binding)  // 32 B
///   then derive_hop_keys(&k_i2r, &k_r2i) -> HopKeys
/// ```
pub fn derive_hop_keys_from_handshake(mlkem_ss: &[u8; 32], session_binding: &[u8; 32]) -> HopKeys {
    let k_i2r = direction_root(SESSION_DIRECTION_LABEL_I2R, mlkem_ss, session_binding);
    let k_r2i = direction_root(SESSION_DIRECTION_LABEL_R2I, mlkem_ss, session_binding);
    derive_hop_keys(&k_i2r, &k_r2i)
}

/// Re-derived `direction_root` from `mirage-session::frames`. The
/// formula MUST match exactly - `mirage-runtime`'s cross-crate
/// consistency test catches drift. Made `pub(crate)` rather than
/// public to keep the public API surface narrow; the public entry
/// point is [`derive_hop_keys_from_handshake`].
///
/// Returns `Zeroizing` so the direction-root secret is wiped when its
/// binding drops: these roots are key-equivalent (`derive_hop_keys` is
/// deterministic, so recovering a root reconstructs both onion-cell keys for
/// the hop), and the module's FS discipline (see [`OnionLayer`], `derive32`,
/// `combine_kem_secret`) zeroizes every other copy of this material - this
/// intermediate must not be the one gap left un-wiped on the stack.
fn direction_root(
    label: &[u8],
    k_pq: &[u8; 32],
    session_binding: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label);
    hasher.update(k_pq);
    hasher.update(session_binding);
    Zeroizing::new(*hasher.finalize().as_bytes())
}

fn derive32(key: &[u8; 32], label: &[u8]) -> Zeroizing<[u8; ONION_KEY_LEN]> {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(label);
    Zeroizing::new(*h.finalize().as_bytes())
}

fn derive_iv(key: &[u8; 32], label: &[u8]) -> [u8; ONION_IV_LEN] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(label);
    let full = *h.finalize().as_bytes();
    let mut iv = [0u8; ONION_IV_LEN];
    iv.copy_from_slice(&full[..ONION_IV_LEN]);
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let i2r = [0xAAu8; 32];
        let r2i = [0xBBu8; 32];
        let a = derive_hop_keys(&i2r, &r2i);
        let b = derive_hop_keys(&i2r, &r2i);
        assert_eq!(a.forward.key, b.forward.key);
        assert_eq!(a.reverse.iv, b.reverse.iv);
    }

    #[test]
    fn forward_and_reverse_are_distinct() {
        let i2r = [0xAAu8; 32];
        let r2i = [0xBBu8; 32];
        let h = derive_hop_keys(&i2r, &r2i);
        assert_ne!(h.forward.key, h.reverse.key);
        assert_ne!(h.forward.iv, h.reverse.iv);
    }

    #[test]
    fn different_session_roots_yield_different_circuit_keys() {
        let h1 = derive_hop_keys(&[0u8; 32], &[1u8; 32]);
        let h2 = derive_hop_keys(&[2u8; 32], &[3u8; 32]);
        assert_ne!(h1.forward.key, h2.forward.key);
        assert_ne!(h1.reverse.key, h2.reverse.key);
    }

    #[test]
    fn key_iv_labels_are_distinct() {
        // Same root with different labels must produce different
        // outputs. (Defense against label-collision regressions.)
        let r = [0x99u8; 32];
        let key1 = derive32(&r, LABEL_C2H_KEY);
        let key2 = derive32(&r, LABEL_H2C_KEY);
        assert_ne!(*key1, *key2);
        let iv1 = derive_iv(&r, LABEL_C2H_IV);
        let iv2 = derive_iv(&r, LABEL_H2C_IV);
        assert_ne!(iv1, iv2);
    }

    #[test]
    fn from_handshake_yields_consistent_keys() {
        // RT-M7 closure: same (mlkem_ss, session_binding) input ->
        // same HopKeys output. Distinct inputs -> distinct outputs.
        let ss1 = [0xAAu8; 32];
        let sb1 = [0xBBu8; 32];
        let a = derive_hop_keys_from_handshake(&ss1, &sb1);
        let b = derive_hop_keys_from_handshake(&ss1, &sb1);
        assert_eq!(a.forward.key, b.forward.key);
        assert_eq!(a.reverse.key, b.reverse.key);

        let ss2 = [0xCCu8; 32];
        let c = derive_hop_keys_from_handshake(&ss2, &sb1);
        assert_ne!(a.forward.key, c.forward.key);
    }

    #[test]
    fn from_handshake_recomputes_to_derive_hop_keys() {
        // Equivalence to the lower-level path: feeding direction
        // roots manually computed by the same formula MUST match
        // the high-level helper's output. Catches drift in either
        // implementation.
        let ss = [0x77u8; 32];
        let sb = [0x88u8; 32];
        let high_level = derive_hop_keys_from_handshake(&ss, &sb);
        let manual_i2r = direction_root(SESSION_DIRECTION_LABEL_I2R, &ss, &sb);
        let manual_r2i = direction_root(SESSION_DIRECTION_LABEL_R2I, &ss, &sb);
        let low_level = derive_hop_keys(&manual_i2r, &manual_r2i);
        assert_eq!(high_level.forward.key, low_level.forward.key);
        assert_eq!(high_level.forward.iv, low_level.forward.iv);
        assert_eq!(high_level.reverse.key, low_level.reverse.key);
        assert_eq!(high_level.reverse.iv, low_level.reverse.iv);
    }

    #[test]
    fn key_and_iv_for_same_label_share_root_but_differ() {
        // c2h_key and c2h_iv come from the same root but different
        // labels - the labels MUST keep them distinct.
        let r = [0x77u8; 32];
        let key = derive32(&r, LABEL_C2H_KEY);
        let iv_full = blake3::Hasher::new_keyed(&r)
            .update(LABEL_C2H_IV)
            .finalize();
        let iv = *iv_full.as_bytes();
        assert_ne!(&iv[..ONION_IV_LEN], &key[..ONION_IV_LEN]);
    }
}
