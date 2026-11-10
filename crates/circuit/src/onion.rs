//! Onion-AEAD layering for circuit relay cells.
//!
//! A `RELAY` cell sent from the client to the exit hop is encrypted
//! N times - once per hop - using each hop's per-direction AEAD key.
//! Each intermediate hop peels exactly one layer (decrypts with its
//! own key) and forwards the ciphertext that's still wrapped with
//! the keys for the remaining hops. The exit hop peels the final
//! layer and processes the plaintext.
//!
//! ```text
//!  Client                Hop 1               Hop 2              Hop 3 (exit)
//!  ------                -----               -----              ------------
//!  Enc_K3 ( Enc_K2 ( Enc_K1 ( payload ) ) )
//!         ----------> Dec_K1 -> Enc_K2 ( Enc_K3 ( payload ) )
//!                            ----------> Dec_K2 -> Enc_K3 ( payload )
//!                                                ----------> Dec_K3 -> payload
//! ```
//!
//! The reverse direction (exit -> client) wraps in the opposite
//! order: exit encrypts once with K3, hop 2 wraps with K2, hop 1
//! wraps with K1, client peels all three.
//!
//! # Cipher
//!
//! ChaCha20-Poly1305, identical to Mirage's session-frame AEAD.
//! Per-hop key + IV pair derived from the per-hop Mirage handshake's
//! `K_session_*` (see `mirage_session::handshake::SessionKeys`).
//! Nonce per cell = `IV XOR (direction (1 B) || epoch_low24 (3 B BE) ||
//! seq (8 B BE))` - exactly 12 bytes. The FULL 64-bit `seq` is preserved
//! (truncating it once caused per-cell nonce reuse - see [`nonce`]); the
//! epoch is packed in 24 bits and bounded by [`ONION_MAX_EPOCH`] so the
//! truncation is lossless. The full 32-bit epoch + direction are also
//! bound into the AAD, and the cell keys are namespaced by a circuit-cell
//! label so cell + frame keys cannot collide.
//!
//! # Threat-model fit
//!
//! - **Bridge-on-bridge collusion (Hop A, Hop C colluding to
//!   identify Hop B's traffic):** an attacker controlling the
//!   non-exit endpoints of a 3-hop circuit is the canonical Tor-
//!   threat tier. Mirage's onion-AEAD provides no defense against
//!   timing correlation between Hop A's RELAY traffic and Hop C's
//!   exit traffic - that's a traffic-shaping concern. At the
//!   cryptographic layer, the layering ensures Hop A
//!   and Hop C learn NOTHING about each other's keys.
//! - **Per-hop forward secrecy:** each hop's `K_session`_* are
//!   ephemeral to that circuit's lifetime. Compromise of Hop B's
//!   long-term identity does not retroactively decrypt past
//!   circuit traffic.
//! - **Traffic-confirmation / cell counting (#23, OUT OF SCOPE at this
//!   layer):** cells are fixed-size (1024 B) and forwarded 1:1 - each
//!   client->exit RELAY produces exactly one cell per hop, and each
//!   response likewise - so cell count and inter-cell timing at the entry
//!   ingress match the exit egress one-for-one. A global passive observer,
//!   or colluding entry+exit, can confirm a flow end-to-end by counting.
//!   The `CMD_PADDING` cell type is RESERVED (see [`crate::cell`]) for a
//!   future padding-machine / constant-rate cover-traffic defense but is NOT
//!   emitted anywhere today. This is an inherent, documented limitation of
//!   the crypto layer, not a defect - AND it is doubly moot for the
//!   single-hop mode that actually ships (see the circuit-relay wiring
//!   status), where entry == exit and there is no correlation to resist.
//!   Do not present circuit-relay as resisting traffic confirmation until a
//!   padding machine is wired and the multi-hop path is live.

use mirage_crypto::chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use mirage_crypto::zeroize::{Zeroize, ZeroizeOnDrop};
use thiserror::Error;

/// Maximum representable epoch. The per-cell nonce packs only the LOW 24
/// bits of the epoch (see [`nonce`]); enforcing `epoch < 2^24` at the
/// seal/open boundary makes that truncation provably lossless, so two
/// distinct epochs can never collide into one nonce under one key. Epoch
/// advances only on rekey (never per-cell), so 2^24 rekeys is unreachable
/// in practice - this is belt-and-suspenders for the latent path.
pub const ONION_MAX_EPOCH: u32 = (1 << 24) - 1;

/// AEAD per-direction key length.
pub const ONION_KEY_LEN: usize = 32;
/// AEAD per-direction IV length.
pub const ONION_IV_LEN: usize = 12;
/// AAD prefix for onion cells. Domain-separates from session-frame
/// AAD so the same K cannot decrypt both.
const ONION_AAD_PREFIX: &[u8] = b"mirage-onion-cell-v1";

/// Errors produced by the onion-AEAD layer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OnionError {
    /// AEAD authentication failed for a layer. Caller MUST drop the
    /// circuit (an upstream attacker injected garbage, or one of
    /// the hop keys is wrong).
    #[error("aead auth failed")]
    AuthFailed,
    /// Caller passed an empty layer set to `seal` / `open`.
    #[error("no layers")]
    NoLayers,
    /// `epoch` exceeded [`ONION_MAX_EPOCH`]; the per-cell nonce only packs
    /// 24 epoch bits, so a larger epoch could alias another epoch's nonce
    /// under one key. Reaching this requires 2^24 rekeys - treated as a
    /// hard error rather than silently truncating.
    #[error("epoch exceeds 24-bit nonce field")]
    EpochOverflow,
}

/// Per-hop AEAD layer state.
///
/// Holds the per-hop circuit key, so it is [`Zeroize`] + [`ZeroizeOnDrop`]:
/// the key bytes are wiped when the layer (and the `Circuit` / `HopKeys`
/// that own it) drop. Without this the ephemeral per-hop keys lingered in
/// freed heap/stack, undermining the per-hop forward-secrecy claim - a
/// later memory disclosure could recover keys for already-closed circuits.
/// `Debug` is hand-written to redact the key (a derived `Debug` would print
/// it into logs).
#[derive(Clone)]
pub struct OnionLayer {
    /// 32-byte ChaCha20-Poly1305 key.
    pub key: [u8; ONION_KEY_LEN],
    /// 12-byte static IV; XOR with the per-cell counter to form the
    /// nonce.
    pub iv: [u8; ONION_IV_LEN],
}

// Manual Zeroize/ZeroizeOnDrop (via the mirage_crypto re-export) rather than
// the derive macro, which emits an absolute `::zeroize` path that would
// require adding `zeroize` as a direct dependency of this crate.
impl Zeroize for OnionLayer {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl Drop for OnionLayer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OnionLayer {}

impl std::fmt::Debug for OnionLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionLayer")
            .field("key", &"<redacted>")
            .field("iv", &"<redacted>")
            .finish()
    }
}

impl OnionLayer {
    /// Construct a layer from raw bytes.
    pub fn new(key: [u8; ONION_KEY_LEN], iv: [u8; ONION_IV_LEN]) -> Self {
        Self { key, iv }
    }
}

fn nonce(iv: &[u8; ONION_IV_LEN], direction: u8, epoch: u32, seq: u64) -> [u8; ONION_IV_LEN] {
    // Per-cell nonce: iv XOR (direction(1) || epoch_be_low24(3) || seq_be(8)).
    // The 12-byte nonce packs the direction byte, the low 24 bits of the
    // epoch, and the FULL 64-bit per-cell sequence counter - exactly 12 bytes.
    //
    // History: an earlier layout was direction(1)||epoch(4)||seq(8) = 13 bytes
    // copied into a 12-byte buffer with a `.min()`-clamped slice, which silently
    // dropped the LEAST-significant byte of seq. That made seq=N and seq=N+1
    // (and every pair within a 256-block) produce the SAME nonce, i.e.
    // ChaCha20-Poly1305 (key, nonce) reuse on every consecutive RELAY cell -
    // a catastrophic confidentiality+integrity break. Keeping the full 64-bit
    // seq is the load-bearing invariant; epoch headroom of 24 bits is ample
    // because epoch only advances on rekey (never per-cell), and direction is
    // additionally bound in the AAD and via direction-distinct layer keys.
    let mut counter = [0u8; ONION_IV_LEN];
    counter[0] = direction;
    let epoch_be = epoch.to_be_bytes();
    counter[1..4].copy_from_slice(&epoch_be[1..4]); // low 24 bits of epoch
    counter[4..12].copy_from_slice(&seq.to_be_bytes()); // full 64-bit seq
    let mut n = *iv;
    for i in 0..ONION_IV_LEN {
        n[i] ^= counter[i];
    }
    n
}

fn aad(direction: u8, epoch: u32, seq: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ONION_AAD_PREFIX.len() + 1 + 4 + 8);
    aad.extend_from_slice(ONION_AAD_PREFIX);
    aad.push(direction);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(&seq.to_be_bytes());
    aad
}

/// Apply N onion layers to `plaintext`, in `layers[0] -> layers[N-1]`
/// order. The OUTERMOST layer is `layers[0]` (the first hop's key);
/// the INNERMOST is `layers[N-1]` (the exit's key). Each layer
/// expands the ciphertext by 16 bytes (Poly1305 tag).
///
/// `direction`, `epoch`, `seq` are common across all layers - the
/// per-cell nonce for hop `i` is derived from `(direction, epoch,
/// seq)` using `layers[i].iv`. Callers SHOULD increment `seq` per
/// cell sent in a given direction.
pub fn onion_seal(
    layers: &[OnionLayer],
    plaintext: &[u8],
    direction: u8,
    epoch: u32,
    seq: u64,
) -> Result<Vec<u8>, OnionError> {
    if layers.is_empty() {
        return Err(OnionError::NoLayers);
    }
    if epoch > ONION_MAX_EPOCH {
        return Err(OnionError::EpochOverflow);
    }
    let mut payload = plaintext.to_vec();
    // Iterate layers OUTERMOST-first. We seal innermost first
    // (layers[N-1]), then wrap layers[N-2], ..., then layers[0].
    // So we walk the slice in reverse.
    for layer in layers.iter().rev() {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&layer.key));
        let n = nonce(&layer.iv, direction, epoch, seq);
        let aad_bytes = aad(direction, epoch, seq);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&n),
                Payload {
                    msg: &payload,
                    aad: &aad_bytes,
                },
            )
            .map_err(|_| OnionError::AuthFailed)?;
        payload = ct;
    }
    Ok(payload)
}

/// Peel N onion layers from `ciphertext`, in `layers[0] -> layers[N-1]`
/// order - i.e., layers[0] is peeled first (it's the outermost wrap
/// applied by [`onion_seal`]). Returns the unwrapped plaintext.
///
/// Used in two ways:
/// - **By a single hop in the forwarding path:** with one layer
///   (its own key), peeling reveals the wire bytes the hop should
///   forward to the next hop.
/// - **By the client receiving an exit->client cell:** with all N
///   layers, peeling reveals the original payload.
pub fn onion_open(
    layers: &[OnionLayer],
    ciphertext: &[u8],
    direction: u8,
    epoch: u32,
    seq: u64,
) -> Result<Vec<u8>, OnionError> {
    if layers.is_empty() {
        return Err(OnionError::NoLayers);
    }
    if epoch > ONION_MAX_EPOCH {
        return Err(OnionError::EpochOverflow);
    }
    let mut payload = ciphertext.to_vec();
    // Peel OUTER-first (layers[0]) so the order matches what
    // `onion_seal` applied.
    for layer in layers {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&layer.key));
        let n = nonce(&layer.iv, direction, epoch, seq);
        let aad_bytes = aad(direction, epoch, seq);
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&n),
                Payload {
                    msg: &payload,
                    aad: &aad_bytes,
                },
            )
            .map_err(|_| OnionError::AuthFailed)?;
        payload = pt;
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn layer(tag: u8) -> OnionLayer {
        OnionLayer::new([tag; ONION_KEY_LEN], [tag.wrapping_add(0x40); ONION_IV_LEN])
    }

    #[test]
    fn single_layer_roundtrip() {
        let l = layer(1);
        let pt = b"hello onion".to_vec();
        let ct = onion_seal(std::slice::from_ref(&l), &pt, 0, 0, 0).unwrap();
        let back = onion_open(std::slice::from_ref(&l), &ct, 0, 0, 0).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn consecutive_seq_do_not_reuse_keystream() {
        // Regression: the onion nonce once dropped the LSB of the 64-bit
        // seq, so seq=N and seq=N+1 produced the SAME ChaCha20-Poly1305
        // nonce - keystream reuse on every consecutive RELAY cell. Sealing
        // the SAME plaintext under one layer at adjacent seq values MUST
        // yield different keystream, i.e. the ciphertext body before the
        // 16-byte tag must differ. (AAD alone is insufficient: ChaCha20's
        // keystream is independent of AAD, so reuse leaks plaintext XOR
        // even though the Poly1305 tags differ.)
        let l = layer(7);
        let pt = vec![0xAAu8; 48];
        let body = pt.len(); // bytes preceding the 16-byte Poly1305 tag
        for base in [0u64, 1, 255, 256, 1000, u32::MAX as u64, u64::MAX - 1] {
            let next = base.wrapping_add(1);
            let ct_a = onion_seal(std::slice::from_ref(&l), &pt, 0, 0, base).unwrap();
            let ct_b = onion_seal(std::slice::from_ref(&l), &pt, 0, 0, next).unwrap();
            assert_ne!(
                &ct_a[..body],
                &ct_b[..body],
                "keystream reused across seq {base} and {next} (nonce collision)"
            );
        }
    }

    #[test]
    fn no_nonce_collision_across_256_block() {
        // The old bug collapsed every block of 256 consecutive seq values
        // onto a single nonce. Sweep a 512-span: distinct seq must yield
        // distinct keystream (detected as distinct ciphertext bodies).
        let l = layer(9);
        let pt = vec![0x5Au8; 16];
        let mut seen = std::collections::HashSet::new();
        for seq in 0u64..512 {
            let ct = onion_seal(std::slice::from_ref(&l), &pt, 0, 0, seq).unwrap();
            assert!(
                seen.insert(ct[..pt.len()].to_vec()),
                "ciphertext-body collision at seq {seq} - nonce reuse"
            );
        }
    }

    #[test]
    fn three_layer_full_roundtrip() {
        // Client wraps with [A, B, C]; the only entity that holds
        // all three keys is the client itself, who can also peel
        // all three to recover the plaintext.
        let layers = [layer(1), layer(2), layer(3)];
        let pt = b"3-hop cleartext".to_vec();
        let ct = onion_seal(&layers, &pt, 0, 0, 0).unwrap();
        let back = onion_open(&layers, &ct, 0, 0, 0).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn three_layer_hop_by_hop_peeling() {
        // Simulate the forwarding-path semantics:
        //   1. Client wraps with [A, B, C].
        //   2. Hop A peels A. Result is `wrap[B,C](pt)`.
        //   3. Hop B peels B. Result is `wrap[C](pt)`.
        //   4. Hop C peels C. Result is the plaintext.
        let layers = [layer(1), layer(2), layer(3)];
        let pt = b"client-to-exit data".to_vec();
        let mut wire = onion_seal(&layers, &pt, 0, 0, 0).unwrap();
        // Each hop knows ONE layer; peels it.
        wire = onion_open(&[layers[0].clone()], &wire, 0, 0, 0).unwrap();
        wire = onion_open(&[layers[1].clone()], &wire, 0, 0, 0).unwrap();
        wire = onion_open(&[layers[2].clone()], &wire, 0, 0, 0).unwrap();
        assert_eq!(wire, pt);
    }

    #[test]
    fn three_layer_reverse_path_client_unwraps_all() {
        // Reverse direction: exit->client. Each forwarding hop
        // wraps in turn; the client unwraps all three.
        // Exit C wraps once with C: ct = Enc_C(pt).
        // Hop B wraps with B: ct = Enc_B(Enc_C(pt)).
        // Hop A wraps with A: ct = Enc_A(Enc_B(Enc_C(pt))).
        // Client peels [A, B, C] in order.
        let layers = [layer(1), layer(2), layer(3)];
        let pt = b"exit-to-client data".to_vec();
        // Step 1: exit C seals with its key only.
        let mut wire = onion_seal(&[layers[2].clone()], &pt, 1, 0, 0).unwrap();
        // Step 2: hop B wraps.
        wire = onion_seal(&[layers[1].clone()], &wire, 1, 0, 0).unwrap();
        // Step 3: hop A wraps.
        wire = onion_seal(&[layers[0].clone()], &wire, 1, 0, 0).unwrap();
        // Step 4: client unwraps all three.
        let back = onion_open(&layers, &wire, 1, 0, 0).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn auth_fail_on_tampered_outer_layer() {
        let layers = [layer(1), layer(2)];
        let pt = b"data".to_vec();
        let mut ct = onion_seal(&layers, &pt, 0, 0, 0).unwrap();
        ct[0] ^= 0x01; // flip one byte in the outer layer
        let err = onion_open(&[layers[0].clone()], &ct, 0, 0, 0).unwrap_err();
        assert_eq!(err, OnionError::AuthFailed);
    }

    #[test]
    fn auth_fail_on_wrong_layer_key() {
        let layers = [layer(1)];
        let pt = b"data".to_vec();
        let ct = onion_seal(&layers, &pt, 0, 0, 0).unwrap();
        // Try to open with the wrong key.
        let wrong = [layer(2)];
        let err = onion_open(&wrong, &ct, 0, 0, 0).unwrap_err();
        assert_eq!(err, OnionError::AuthFailed);
    }

    #[test]
    fn auth_fail_on_wrong_direction_byte() {
        let layers = [layer(1)];
        let pt = b"data".to_vec();
        let ct = onion_seal(&layers, &pt, 0, 0, 0).unwrap();
        // Direction is part of nonce + AAD, so swapping it must fail.
        let err = onion_open(&layers, &ct, 1, 0, 0).unwrap_err();
        assert_eq!(err, OnionError::AuthFailed);
    }

    #[test]
    fn auth_fail_on_wrong_seq() {
        let layers = [layer(1)];
        let pt = b"data".to_vec();
        let ct = onion_seal(&layers, &pt, 0, 0, 0).unwrap();
        let err = onion_open(&layers, &ct, 0, 0, 1).unwrap_err();
        assert_eq!(err, OnionError::AuthFailed);
    }

    #[test]
    fn empty_layers_rejected() {
        assert_eq!(
            onion_seal(&[], b"", 0, 0, 0).unwrap_err(),
            OnionError::NoLayers
        );
        assert_eq!(
            onion_open(&[], b"", 0, 0, 0).unwrap_err(),
            OnionError::NoLayers
        );
    }

    #[test]
    fn each_layer_adds_16_bytes_of_overhead() {
        let pt = b"x";
        let one_ct = onion_seal(&[layer(1)], pt, 0, 0, 0).unwrap();
        let two_ct = onion_seal(&[layer(1), layer(2)], pt, 0, 0, 0).unwrap();
        let three_ct = onion_seal(&[layer(1), layer(2), layer(3)], pt, 0, 0, 0).unwrap();
        assert_eq!(one_ct.len(), pt.len() + 16);
        assert_eq!(two_ct.len(), pt.len() + 32);
        assert_eq!(three_ct.len(), pt.len() + 48);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn proptest_n_layer_roundtrip(
            n_layers in 1usize..=5,
            seq in 0u64..1000,
            payload in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            let layers: Vec<OnionLayer> = (0..n_layers)
                .map(|i| layer(i as u8 + 1))
                .collect();
            let ct = onion_seal(&layers, &payload, 0, 0, seq).unwrap();
            let back = onion_open(&layers, &ct, 0, 0, seq).unwrap();
            prop_assert_eq!(back, payload);
        }
    }
}
