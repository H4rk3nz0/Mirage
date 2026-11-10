//! Post-handshake session framing.
//!
//! # Architecture (double-AEAD)
//!
//! Every frame is encrypted twice:
//!
//! 1. **Inner layer**: Noise [`snow::TransportState`] retained from the
//!    handshake. Uses snow's internal nonce counter and handshake-transcript
//!    AAD. Provides classical (X25519 / ChaCha20-Poly1305) confidentiality.
//! 2. **Outer layer**: ChaCha20-Poly1305 with keys derived from `K_pq`
//!    (ML-KEM-768 shared secret) and `session_binding`. Uses explicit
//!    `(epoch, seq)` nonce construction and `session_binding + direction +
//!    epoch + seq` AAD.
//!
//! An adversary who breaks only the classical keys still faces the
//! ML-KEM-derived outer layer. An adversary who breaks only ML-KEM still
//! faces Noise-XX's authenticated DH. Both must fall for confidentiality to
//! be lost - the hybrid-PQ property spec §4.0 requires.
//!
//! # Time ratchet (§5.1)
//!
//! On [`SessionFramer::advance_epoch`], the outer-layer direction roots advance
//! via a BLAKE3 hash chain:
//! `K_session_*_next = BLAKE3(label || K_session_*_prev || epoch || session_binding)`.
//! BLAKE3 preimage resistance yields **forward secrecy**: compromising epoch-n
//! keys does not allow derivation of epoch-n-1 keys or earlier once the previous
//! material is cleared.
//!
//! The ratchet is DRIVEN on the live path by [`crate::stream::SessionStream`],
//! which advances on wall-clock epoch boundaries. Because the two peers advance
//! on their own clocks over a duplex link, an advance is **skew-tolerant**:
//!
//! - [`SessionFramer::advance_epoch`] retains the just-superseded recv keys as a
//!   one-epoch **grace window** ([`SessionFramer::recv`] tries current -> prev ->
//!   next), so a frame in flight across the boundary still decrypts and a peer
//!   that advanced first is reactively followed. [`SessionFramer::expire_prev_recv`]
//!   (called from the recv path once the peer sends under our current epoch) then
//!   restores full forward secrecy.
//! - The inner snow layer is deliberately NOT rekeyed on advance: snow's rekey is
//!   one-way and un-cloneable, which would make grace-window frames undecryptable.
//!   Forward secrecy is a property of the OUTER BLAKE3 chain + zeroize; the inner
//!   layer stays continuous (its 64-bit nonce space is never exhausted).
//!
//! # Post-compromise security (§5.2) - BUILT, NOT WIRED
//!
//! The forward secrecy above IS delivered and driven on the live path. Post-
//! compromise security (healing after a key seizure) is **not**. Healing needs
//! the asymmetric KEM ratchet [`SessionFramer::kem_reseed`], which folds a fresh
//! X25519+ML-KEM shared secret into both direction roots so an adversary who
//! seized the old roots cannot follow the reseed. That primitive is implemented
//! and unit-tested in this module, but it has **no live caller**: no bridge,
//! client, or session driver invokes it, and there is no control-frame protocol
//! to carry the fresh encapsulation in-band. Until it is wired, an adversary who
//! seizes both direction roots at any epoch can compute all FUTURE epoch keys
//! via the pure time-ratchet ([`SessionFramer::advance_epoch`]) - no fresh KEM
//! entropy is folded in live. Treat healing as future work; **do not rely on it
//! as a delivered property.**

use mirage_crypto::chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use mirage_crypto::hkdf::Hkdf;
use mirage_crypto::sha2::Sha256;
use mirage_crypto::zeroize::{Zeroize, Zeroizing};

use crate::error::SessionError;
use crate::handshake::SessionKeys;
use crate::Role;

// Constants (§4)

/// Noise / ChaCha20-Poly1305 tag length in bytes.
pub const AEAD_TAG_LEN: usize = 16;

/// Maximum plaintext per frame (§4.1).
pub const MAX_FRAME_PLAINTEXT: usize = 16384;

/// Maximum outer-ciphertext length (plaintext + two tags).
pub const MAX_OUTER_CT_LEN: usize = MAX_FRAME_PLAINTEXT + 2 * AEAD_TAG_LEN; // 16416

/// Minimum outer-ciphertext length (one plaintext byte + two tags).
pub const MIN_OUTER_CT_LEN: usize = 1 + 2 * AEAD_TAG_LEN; // 33

/// Wire-level length prefix size.
const LEN_PREFIX_SIZE: usize = 2;

/// Direction byte for AAD (§4.2).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Initiator -> Responder.
    I2R = 0,
    /// Responder -> Initiator.
    R2I = 1,
}

impl Direction {
    fn opposite(self) -> Self {
        match self {
            Direction::I2R => Direction::R2I,
            Direction::R2I => Direction::I2R,
        }
    }
}

// DirState - per-direction cipher state

/// Per-direction outer-layer cipher state. Zeroizes key + iv on drop.
struct DirState {
    key: [u8; 32],
    iv: [u8; 12],
    seq: u64,
}

impl Drop for DirState {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
        self.seq = 0;
    }
}

// Key schedule (§3.5 + §5.1)

fn direction_root(label: &[u8], k_pq: &[u8; 32], session_binding: &[u8; 32]) -> [u8; 32] {
    let mut hasher = mirage_crypto::blake3::Hasher::new();
    hasher.update(label);
    hasher.update(k_pq);
    hasher.update(session_binding);
    *hasher.finalize().as_bytes()
}

fn ratchet_root(label: &[u8], prev: &[u8; 32], epoch: u32, session_binding: &[u8; 32]) -> [u8; 32] {
    let mut hasher = mirage_crypto::blake3::Hasher::new();
    hasher.update(label);
    hasher.update(prev);
    hasher.update(&epoch.to_be_bytes());
    hasher.update(session_binding);
    *hasher.finalize().as_bytes()
}

// §5.2 KEM-ratchet (post-compromise security) - key-schedule primitives.
//
// NOT-WIRED (I6): these primitives are correct and unit-tested but have NO live
// caller. The healing property described below is therefore BUILT, not
// delivered on any live path - see the module-level "Post-compromise security"
// note. Reserved for future wiring into a §5.2 control-frame protocol; their
// mere presence is NOT evidence that sessions heal today.
//
// The §5.1 time-ratchet (`ratchet_root`) is a pure BLAKE3 hash chain: an
// adversary who seizes both direction roots computes every future epoch. The
// KEM-ratchet folds a FRESH X25519+ML-KEM shared secret (which the adversary
// lacks the ephemeral private keys for) into both roots, so that ONCE WIRED the
// session would heal. The derivation is domain-separated from `ratchet_root` by
// a leading context tag, so a KEM-mixed root can never alias a time-only root at
// the same epoch.

/// Combine the two fresh ratchet shared secrets into one 32-byte secret,
/// following the repo's `BLAKE3(x25519_ss || mlkem_ss)` hybrid convention
/// (crates/crypto/src/lib.rs). Returned zeroizing.
fn combine_kem_secret(x25519_ss: &[u8; 32], mlkem_ss: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = mirage_crypto::blake3::Hasher::new();
    hasher.update(b"mirage-kem-combine-v1");
    hasher.update(x25519_ss);
    hasher.update(mlkem_ss);
    Zeroizing::new(*hasher.finalize().as_bytes())
}

/// Reseed a direction root, folding the fresh KEM secret in. The leading
/// `mirage-kem-reseed-v1` context tag domain-separates this from the time-only
/// [`ratchet_root`] (which has no such prefix), so the two schedules cannot
/// collide even at the same `(label, prev, epoch, binding)`.
fn ratchet_root_kem(
    label: &[u8],
    prev: &[u8; 32],
    epoch: u32,
    session_binding: &[u8; 32],
    kem_secret: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = mirage_crypto::blake3::Hasher::new();
    hasher.update(b"mirage-kem-reseed-v1");
    hasher.update(label);
    hasher.update(prev);
    hasher.update(&epoch.to_be_bytes());
    hasher.update(session_binding);
    hasher.update(kem_secret);
    *hasher.finalize().as_bytes()
}

/// A confirmation tag binding both freshly-derived roots to the session +
/// epoch. ML-KEM decapsulation uses FIPS-203 implicit rejection: a tampered
/// ciphertext yields a DIFFERENT-but-valid secret with no error, so the two
/// peers could silently derive different roots and desync. Each side computes
/// this tag over its own new roots and exchanges it; equal tags prove both
/// derived the SAME secret, so the reseed is only committed to once confirmed.
fn kem_confirmation_tag(
    new_i2r: &[u8; 32],
    new_r2i: &[u8; 32],
    session_binding: &[u8; 32],
    epoch: u32,
) -> [u8; 32] {
    let mut hasher = mirage_crypto::blake3::Hasher::new();
    hasher.update(b"mirage-kem-confirm-v1");
    hasher.update(new_i2r);
    hasher.update(new_r2i);
    hasher.update(session_binding);
    hasher.update(&epoch.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn expand_cipher(root: &[u8; 32], epoch: u64) -> Result<([u8; 32], [u8; 12]), SessionError> {
    // Info: "mirage-cipher-v1-eN" where N is ASCII-decimal epoch.
    let info = format!("mirage-cipher-v1-e{}", epoch);
    let hk = Hkdf::<Sha256>::from_prk(root).map_err(|_| SessionError::State("hkdf from_prk"))?;
    let mut out = [0u8; 44];
    hk.expand(info.as_bytes(), &mut out)
        .map_err(|_| SessionError::State("hkdf expand"))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&out[32..]);
    out.zeroize();
    Ok((key, iv))
}

// AAD and nonce construction (§4.2, §4.3)

/// Build per-frame AAD: `session_binding(32) || direction(1) || epoch(4 BE) || seq(8 BE)`.
fn aad_bytes(session_binding: &[u8; 32], direction: Direction, epoch: u64, seq: u64) -> [u8; 45] {
    let mut out = [0u8; 45];
    out[0..32].copy_from_slice(session_binding);
    out[32] = direction as u8;
    // epoch truncates to u32; at 1h/epoch this covers ~489_000 years.
    let epoch_u32 = epoch as u32;
    out[33..37].copy_from_slice(&epoch_u32.to_be_bytes());
    out[37..45].copy_from_slice(&seq.to_be_bytes());
    out
}

/// Attempt one outer-layer (ChaCha20-Poly1305) decrypt under a specific
/// (key, iv, epoch, seq). Returns the inner ciphertext on success, `None` on
/// AEAD failure. Free function so [`SessionFramer::recv`] can trial several
/// candidate epochs without borrow-checker friction.
#[allow(clippy::too_many_arguments)]
fn try_outer_decrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    binding: &[u8; 32],
    direction: Direction,
    epoch: u64,
    seq: u64,
    outer_ct: &[u8],
) -> Option<Vec<u8>> {
    let aad = aad_bytes(binding, direction, epoch, seq);
    let nonce = nonce_bytes(iv, epoch, seq);
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: outer_ct,
                aad: &aad,
            },
        )
        .ok()
}

/// Build per-frame nonce: `iv_dir XOR (epoch(4) || seq(8))`.
fn nonce_bytes(iv: &[u8; 12], epoch: u64, seq: u64) -> [u8; 12] {
    let mut counter = [0u8; 12];
    counter[0..4].copy_from_slice(&(epoch as u32).to_be_bytes());
    counter[4..12].copy_from_slice(&seq.to_be_bytes());
    let mut nonce = *iv;
    for i in 0..12 {
        nonce[i] ^= counter[i];
    }
    nonce
}

// SessionFramer

/// Post-handshake session-layer encrypt/decrypt.
///
/// Owns the Noise `TransportState` (inner layer) plus the outer-layer
/// direction keys. Constructed from [`SessionKeys`] produced by the
/// handshake. Thread-unsafe by construction; wrap in a `tokio::sync::Mutex`
/// for concurrent-connection patterns.
pub struct SessionFramer {
    /// Handshake transcript binding - constant across a session.
    session_binding: [u8; 32],
    /// Current ratchet epoch. Starts at 0 post-handshake, bumped by
    /// [`SessionFramer::advance_epoch`].
    epoch: u64,
    /// Role determines which direction this side writes to.
    role: Role,
    /// Outer-layer root for i2r direction. Retained across epochs for
    /// ratchet derivation; zeroized on advance and on drop.
    k_session_i2r: [u8; 32],
    /// Outer-layer root for r2i direction. Same lifetime rules.
    k_session_r2i: [u8; 32],
    /// Per-direction send state (keys owned, not borrowed).
    send: DirState,
    /// Per-direction recv state.
    recv: DirState,
    /// Previous epoch's recv state, retained as a bounded grace window so
    /// frames still in flight when a ratchet advance happens (clock skew,
    /// reordering across the boundary) can still be decrypted. Zeroized on the
    /// next advance and by [`SessionFramer::expire_prev_recv`], so old keys
    /// live only for one grace window - the outer BLAKE3 chain still provides
    /// forward secrecy once this is cleared.
    recv_prev: Option<DirState>,
    /// Highest epoch we have successfully decrypted a peer frame under. Lets a
    /// wall-clock advance driver avoid racing more than one epoch ahead of the
    /// peer (which would exceed the single-epoch grace window).
    last_recv_epoch: u64,
    /// Inner layer: Noise TransportState from the handshake.
    inner: snow::TransportState,
}

/// Maximum epochs the send ratchet may advance ahead of the peer's confirmed
/// (last-received) epoch before it pauses. Generous enough that a one-directional
/// bulk flow keeps rotating its send keys for a long time without hearing back,
/// but bounded so we never outrun a peer that has fallen behind due to loss on an
/// unreliable carrier (the receiver keeps only current + previous epoch keys).
const MAX_SEND_LEAD_EPOCHS: u64 = 16;

impl SessionFramer {
    /// Construct a framer from the handshake's `SessionKeys`.
    ///
    /// Consumes the inner `transport` (Noise TransportState) and uses
    /// `mlkem_ss` to derive the outer-layer direction roots. After this,
    /// `keys.mlkem_ss` is zeroized (caller's copy still in scope goes away
    /// at the end of their stack frame).
    pub fn from_session_keys(mut keys: SessionKeys, role: Role) -> Result<Self, SessionError> {
        let session_binding = keys.session_binding;
        // Copy K_pq into a Zeroizing local so this copy is wiped on drop (arrays
        // are Copy, so a bare `[u8; 32]` copy would otherwise linger on the
        // stack), and immediately zero the field on the source struct.
        let k_pq = Zeroizing::new(keys.mlkem_ss);
        keys.zeroize_ss();

        // §3.5: K_session_{i2r,r2i} = BLAKE3(label || K_pq || session_binding).
        // Labels MUST match spec bytes exactly (17 bytes each).
        let k_session_i2r = direction_root(b"mirage-key-i2r-v1", &k_pq, &session_binding);
        let k_session_r2i = direction_root(b"mirage-key-r2i-v1", &k_pq, &session_binding);

        // §3.5: epoch-0 cipher keys + IVs
        let (k_i2r, iv_i2r) = expand_cipher(&k_session_i2r, 0)?;
        let (k_r2i, iv_r2i) = expand_cipher(&k_session_r2i, 0)?;

        let (send, recv) = match role {
            Role::Initiator => (
                DirState {
                    key: k_i2r,
                    iv: iv_i2r,
                    seq: 0,
                },
                DirState {
                    key: k_r2i,
                    iv: iv_r2i,
                    seq: 0,
                },
            ),
            Role::Responder => (
                DirState {
                    key: k_r2i,
                    iv: iv_r2i,
                    seq: 0,
                },
                DirState {
                    key: k_i2r,
                    iv: iv_i2r,
                    seq: 0,
                },
            ),
        };

        // `k_pq` is a Zeroizing local and wipes itself on drop at end of scope;
        // K_session_* remain for the ratchet and are zeroized by the framer's Drop.
        drop(k_pq);

        Ok(Self {
            session_binding,
            epoch: 0,
            role,
            k_session_i2r,
            k_session_r2i,
            send,
            recv,
            recv_prev: None,
            last_recv_epoch: 0,
            inner: keys.transport,
        })
    }

    /// Compute the recv-direction cipher key+iv for `next_epoch` without
    /// committing to it, used by [`SessionFramer::recv`] to trial-decrypt a
    /// frame from a peer that has already advanced. Pure; no state change.
    fn recv_material_for(&self, next_epoch: u64) -> Result<([u8; 32], [u8; 12]), SessionError> {
        let next_epoch_u32 =
            u32::try_from(next_epoch).map_err(|_| SessionError::State("epoch would exceed u32"))?;
        // recv reads the OPPOSITE direction to send.
        let (label, root) = match self.role {
            // Initiator sends i2r, receives r2i.
            Role::Initiator => (b"mirage-ratchet-r2i-v1".as_slice(), &self.k_session_r2i),
            // Responder sends r2i, receives i2r.
            Role::Responder => (b"mirage-ratchet-i2r-v1".as_slice(), &self.k_session_i2r),
        };
        let next_root = ratchet_root(label, root, next_epoch_u32, &self.session_binding);
        expand_cipher(&next_root, next_epoch)
    }

    /// Zeroize the retained previous-epoch recv keys, ending the grace window.
    /// A driver calls this once the grace period after an advance has elapsed;
    /// after this, forward secrecy for the previous epoch is fully restored.
    pub fn expire_prev_recv(&mut self) {
        self.recv_prev = None; // DirState::drop zeroizes
    }

    /// Highest epoch a peer frame has decrypted under (for advance gating).
    pub fn peer_epoch(&self) -> u64 {
        self.last_recv_epoch
    }

    /// Direction this framer writes in.
    fn send_direction(&self) -> Direction {
        match self.role {
            Role::Initiator => Direction::I2R,
            Role::Responder => Direction::R2I,
        }
    }

    /// Current ratchet epoch.
    pub fn current_epoch(&self) -> u64 {
        self.epoch
    }

    /// Test-only: forcibly set the epoch counter, bypassing ratchet
    /// derivation. Used to exercise boundary conditions (e.g., R27
    /// u32-overflow check). Crypto keys remain those of the framer's
    /// construction epoch; this method does NOT produce valid ciphertexts
    /// for the newly-set epoch. MUST NOT be used outside tests.
    #[cfg(test)]
    pub(crate) fn set_epoch_for_test(&mut self, e: u64) {
        self.epoch = e;
    }

    /// Encrypt `plaintext` and produce a wire-ready frame (`[length(2)] [outer_ct]`).
    ///
    /// Fails with [`SessionError::State`] if `plaintext.len() > MAX_FRAME_PLAINTEXT`.
    pub fn send(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        if plaintext.is_empty() {
            return Err(SessionError::State("empty plaintext"));
        }
        if plaintext.len() > MAX_FRAME_PLAINTEXT {
            return Err(SessionError::State("plaintext exceeds 16384"));
        }

        // --- Inner layer: snow TransportState ---
        let mut inner_buf = vec![0u8; plaintext.len() + AEAD_TAG_LEN];
        let inner_len = self
            .inner
            .write_message(plaintext, &mut inner_buf)
            .map_err(SessionError::Noise)?;
        inner_buf.truncate(inner_len);

        // --- Outer layer: ChaCha20-Poly1305 with our direction key ---
        let direction = self.send_direction();
        let aad = aad_bytes(&self.session_binding, direction, self.epoch, self.send.seq);
        let nonce = nonce_bytes(&self.send.iv, self.epoch, self.send.seq);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.send.key));
        let outer_ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &inner_buf,
                    aad: &aad,
                },
            )
            .map_err(|_| SessionError::State("outer aead encrypt failed"))?;

        inner_buf.zeroize();

        if outer_ct.len() > MAX_OUTER_CT_LEN {
            return Err(SessionError::State("outer ct exceeds max"));
        }

        // Advance seq AFTER successful encrypt. If encrypt fails, caller
        // retries with same seq (won't reuse nonce) - or, more honestly,
        // the session is probably toast and they should drop it.
        self.send.seq = self
            .send
            .seq
            .checked_add(1)
            .ok_or(SessionError::State("send seq overflow"))?;

        let mut wire = Vec::with_capacity(LEN_PREFIX_SIZE + outer_ct.len());
        wire.extend_from_slice(&(outer_ct.len() as u16).to_be_bytes());
        wire.extend_from_slice(&outer_ct);
        Ok(wire)
    }

    /// Decrypt a wire frame and return the plaintext.
    ///
    /// Expects `wire` to be exactly one frame: `[length(2)] [outer_ct]`.
    /// On ANY failure (length, outer decrypt, inner decrypt), the session
    /// is considered desynchronized and the caller SHOULD drop it.
    pub fn recv(&mut self, wire: &[u8]) -> Result<Vec<u8>, SessionError> {
        if wire.len() < LEN_PREFIX_SIZE {
            return Err(SessionError::Wire("frame shorter than length prefix"));
        }
        let claimed_len = u16::from_be_bytes([wire[0], wire[1]]) as usize;
        if wire.len() != LEN_PREFIX_SIZE + claimed_len {
            return Err(SessionError::Wire("frame length mismatch"));
        }
        if !(MIN_OUTER_CT_LEN..=MAX_OUTER_CT_LEN).contains(&claimed_len) {
            return Err(SessionError::Wire("outer ct length out of range"));
        }
        let outer_ct = &wire[LEN_PREFIX_SIZE..];

        // --- Outer layer decrypt: try current, then the grace window, then
        // the next epoch (ratchet is skew-tolerant, see advance_epoch). ---
        let direction = self.send_direction().opposite();

        enum Which {
            Current,
            Prev,
            Next,
        }

        let (mut inner_ct, which) = if let Some(ct) = try_outer_decrypt(
            &self.recv.key,
            &self.recv.iv,
            &self.session_binding,
            direction,
            self.epoch,
            self.recv.seq,
            outer_ct,
        ) {
            (ct, Which::Current)
        } else if let Some(ct) = self.epoch.checked_sub(1).and_then(|prev_epoch| {
            self.recv_prev.as_ref().and_then(|p| {
                try_outer_decrypt(
                    &p.key,
                    &p.iv,
                    &self.session_binding,
                    direction,
                    prev_epoch,
                    p.seq,
                    outer_ct,
                )
            })
        }) {
            // A straggler encrypted under the previous epoch's keys, in flight
            // when WE advanced. The grace window decrypts it.
            (ct, Which::Prev)
        } else {
            // The PEER advanced first: this frame is from the next epoch. Peek
            // the next-epoch recv keys and, if it decrypts, adopt the advance.
            let next_epoch = self
                .epoch
                .checked_add(1)
                .ok_or(SessionError::State("epoch overflow"))?;
            let (nk, niv) = self.recv_material_for(next_epoch)?;
            match try_outer_decrypt(
                &nk,
                &niv,
                &self.session_binding,
                direction,
                next_epoch,
                0,
                outer_ct,
            ) {
                Some(ct) => (ct, Which::Next),
                None => return Err(SessionError::State("outer aead decrypt failed")),
            }
        };

        // --- Inner layer decrypt (exactly once, in stream order) ---
        let mut plaintext = vec![0u8; inner_ct.len()];
        let read_result = self.inner.read_message(&inner_ct, &mut plaintext);
        // Zeroize the snow-ciphertext intermediate regardless of success (R38).
        inner_ct.zeroize();
        let plaintext_len = read_result.map_err(SessionError::Noise)?;
        plaintext.truncate(plaintext_len);

        // --- Advance the seq counter of whichever epoch matched / follow. ---
        match which {
            Which::Current => {
                self.recv.seq = self
                    .recv
                    .seq
                    .checked_add(1)
                    .ok_or(SessionError::State("recv seq overflow"))?;
                self.last_recv_epoch = self.epoch;
                // The peer has sent under OUR current epoch, so it has fully
                // moved off the previous one: over an ordered carrier no more
                // prev-epoch frames will arrive, so wipe the retained
                // previous-epoch receive keys now. This bounds the forward-secrecy
                // grace window to "until the peer's first current-epoch frame"
                // instead of leaving it open until the next advance (which never
                // comes on an idle session) - the fix for the unused
                // `expire_prev_recv` driver call.
                if self.recv_prev.is_some() {
                    self.expire_prev_recv();
                }
            }
            Which::Prev => {
                if let Some(p) = self.recv_prev.as_mut() {
                    p.seq = p
                        .seq
                        .checked_add(1)
                        .ok_or(SessionError::State("recv_prev seq overflow"))?;
                }
            }
            Which::Next => {
                // Adopt the peer's epoch: advance_epoch installs the next-epoch
                // keys (moving our current recv into the grace window). This
                // frame consumed the new recv's seq 0.
                self.advance_epoch()?;
                self.recv.seq = 1;
                self.last_recv_epoch = self.epoch;
            }
        }

        Ok(plaintext)
    }

    /// Advance toward `target_epoch` (typically derived from wall clock) if we
    /// are behind it AND not already a full epoch ahead of the peer (which
    /// would exceed the one-epoch grace window). Returns whether it advanced.
    /// Idempotent and safe to call on a timer from the session driver.
    pub fn maybe_advance(&mut self, target_epoch: u64) -> Result<bool, SessionError> {
        if self.epoch >= target_epoch {
            return Ok(false);
        }
        // Bounded lead over the peer's confirmed epoch. The OLD gate (`epoch >
        // last_recv_epoch`, i.e. lead of at most 1) STALLED the ratchet whenever
        // one direction was idle: a bulk download's server sends continuously but
        // hears nothing back, so `last_recv_epoch` never moves and its send keys
        // stop rotating after the first epoch. Each `maybe_advance` call steps
        // exactly one epoch and the driver calls it once per frame, so over a
        // reliable, ordered carrier every frame is at most one epoch ahead of the
        // last - the peer follows it via the `Which::Next` recv path. Allowing a
        // generous lead therefore keeps forward secrecy progressing on a
        // one-directional flow while still bounding how far we can outrun a peer
        // that has genuinely fallen behind (loss/reorder protection).
        if self.epoch >= self.last_recv_epoch.saturating_add(MAX_SEND_LEAD_EPOCHS) {
            return Ok(false);
        }
        self.advance_epoch()?;
        Ok(true)
    }

    /// Advance to the next ratchet epoch per §5.1.
    ///
    /// Derives fresh outer-layer keys via BLAKE3 chain, zeroizes previous
    /// material, resets seq counters, and rekeys the inner Noise layer.
    ///
    /// Returns an error if the next epoch would exceed `u32::MAX` (epoch
    /// serialization is u32 BE per spec §4.3 nonce construction; exceeding
    /// this would cause silent nonce collision under the current key).
    pub fn advance_epoch(&mut self) -> Result<(), SessionError> {
        let next_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(SessionError::State("epoch overflow (u64)"))?;
        // R27: epoch is serialized as u32 BE in the nonce. Cap at u32::MAX.
        if next_epoch > u32::MAX as u64 {
            return Err(SessionError::State("epoch would exceed u32::MAX"));
        }
        let next_epoch_u32 = next_epoch as u32;

        // --- Compute new state (all fallible ops here) ---
        let next_i2r = ratchet_root(
            b"mirage-ratchet-i2r-v1",
            &self.k_session_i2r,
            next_epoch_u32,
            &self.session_binding,
        );
        let next_r2i = ratchet_root(
            b"mirage-ratchet-r2i-v1",
            &self.k_session_r2i,
            next_epoch_u32,
            &self.session_binding,
        );
        let (k_i2r, iv_i2r) = expand_cipher(&next_i2r, next_epoch)?;
        let (k_r2i, iv_r2i) = expand_cipher(&next_r2i, next_epoch)?;
        let (new_send, new_recv) = match self.role {
            Role::Initiator => (
                DirState {
                    key: k_i2r,
                    iv: iv_i2r,
                    seq: 0,
                },
                DirState {
                    key: k_r2i,
                    iv: iv_r2i,
                    seq: 0,
                },
            ),
            Role::Responder => (
                DirState {
                    key: k_r2i,
                    iv: iv_r2i,
                    seq: 0,
                },
                DirState {
                    key: k_i2r,
                    iv: iv_i2r,
                    seq: 0,
                },
            ),
        };

        // --- Commit (all infallible beyond this point) ---
        self.k_session_i2r.zeroize();
        self.k_session_r2i.zeroize();
        self.k_session_i2r = next_i2r;
        self.k_session_r2i = next_r2i;
        self.send = new_send; // DirState::drop zeroizes previous
                              // Retain the just-superseded recv keys as a one-epoch grace window so a
                              // peer frame still in flight across the boundary decrypts. The OLD
                              // recv_prev (from two epochs ago) drops here and is zeroized, bounding
                              // retained key material to a single previous epoch.
        self.recv_prev = Some(std::mem::replace(&mut self.recv, new_recv));

        // NB: we deliberately do NOT rekey the inner snow layer here. snow's
        // rekey is one-way and un-cloneable, which would make grace-window
        // frames (encrypted under the previous epoch's OUTER keys but the same
        // inner state) undecryptable. Forward secrecy is provided by the OUTER
        // BLAKE3 ratchet chain + zeroize, not the inner rekey; the inner layer
        // stays continuous and its 64-bit nonce space is never exhausted.

        self.epoch = next_epoch;
        Ok(())
    }

    /// §5.2 KEM-ratchet: reseed BOTH direction roots with a fresh
    /// X25519+ML-KEM shared secret. DESIGNED to deliver post-compromise
    /// security - the session would heal after a key seizure because the
    /// adversary lacks the ephemeral private keys behind `x25519_ss`/`mlkem_ss`.
    ///
    /// **NOT WIRED (I6): this method has no live caller.** No bridge, client, or
    /// session driver invokes it, and there is no control-frame protocol to
    /// deliver the fresh encapsulation in-band, so the healing property is BUILT
    /// but NOT DELIVERED on any live path. It is exercised only by this crate's
    /// unit tests and reserved for future wiring. Callers MUST NOT assume a live
    /// session currently recovers from a key compromise; today only the
    /// time-ratchet ([`Self::advance_epoch`], which gives forward secrecy but
    /// not healing) runs on the wire.
    ///
    /// Structurally an epoch advance (fresh key+iv, `seq = 0`, one-epoch grace
    /// window retained, inner snow layer untouched) but the new roots fold in
    /// the KEM secret via [`ratchet_root_kem`] instead of a pure hash step.
    /// BOTH peers MUST call this with the IDENTICAL `(x25519_ss, mlkem_ss)` for
    /// the same epoch or they desync; the returned [`kem_confirmation_tag`] lets
    /// the transport layer verify that before relying on the new keys (ML-KEM
    /// implicit rejection means a tampered ciphertext silently yields a
    /// different secret). Returns the confirmation tag on success.
    ///
    /// NOTE: unlike [`Self::advance_epoch`], a KEM reseed is NOT reactively
    /// followable - the peer cannot trial-derive the new root without the fresh
    /// secret, so the transport must deliver the encapsulation in-band and gate
    /// the cutover on it (see the §5.2 control-frame protocol).
    pub fn kem_reseed(
        &mut self,
        x25519_ss: &[u8; 32],
        mlkem_ss: &[u8; 32],
    ) -> Result<[u8; 32], SessionError> {
        let next_epoch = self
            .epoch
            .checked_add(1)
            .ok_or(SessionError::State("epoch overflow (u64)"))?;
        if next_epoch > u32::MAX as u64 {
            return Err(SessionError::State("epoch would exceed u32::MAX"));
        }
        let next_epoch_u32 = next_epoch as u32;
        let secret = combine_kem_secret(x25519_ss, mlkem_ss);

        // --- Compute new state (all fallible ops here) ---
        let next_i2r = ratchet_root_kem(
            b"mirage-ratchet-i2r-v1",
            &self.k_session_i2r,
            next_epoch_u32,
            &self.session_binding,
            &secret,
        );
        let next_r2i = ratchet_root_kem(
            b"mirage-ratchet-r2i-v1",
            &self.k_session_r2i,
            next_epoch_u32,
            &self.session_binding,
            &secret,
        );
        let (k_i2r, iv_i2r) = expand_cipher(&next_i2r, next_epoch)?;
        let (k_r2i, iv_r2i) = expand_cipher(&next_r2i, next_epoch)?;
        let (new_send, new_recv) = match self.role {
            Role::Initiator => (
                DirState {
                    key: k_i2r,
                    iv: iv_i2r,
                    seq: 0,
                },
                DirState {
                    key: k_r2i,
                    iv: iv_r2i,
                    seq: 0,
                },
            ),
            Role::Responder => (
                DirState {
                    key: k_r2i,
                    iv: iv_r2i,
                    seq: 0,
                },
                DirState {
                    key: k_i2r,
                    iv: iv_i2r,
                    seq: 0,
                },
            ),
        };
        let confirmation =
            kem_confirmation_tag(&next_i2r, &next_r2i, &self.session_binding, next_epoch_u32);

        // --- Commit (infallible; mirrors advance_epoch) ---
        self.k_session_i2r.zeroize();
        self.k_session_r2i.zeroize();
        self.k_session_i2r = next_i2r;
        self.k_session_r2i = next_r2i;
        self.send = new_send;
        // One-epoch grace window so pre-reseed frames still in flight decrypt.
        self.recv_prev = Some(std::mem::replace(&mut self.recv, new_recv));
        // Inner snow layer deliberately untouched (see advance_epoch).
        self.epoch = next_epoch;
        // `secret` (Zeroizing) drops here, zeroizing the combined KEM secret.
        Ok(confirmation)
    }
}

impl Drop for SessionFramer {
    fn drop(&mut self) {
        self.k_session_i2r.zeroize();
        self.k_session_r2i.zeroize();
        // DirState::drop handles send/recv
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{HandshakeInitiator, HandshakeResponder, TokenVerifier};
    use crate::wire::{MSG_1_LEN, MSG_2_LEN, MSG_3_LEN_WITH_TOKEN};
    use mirage_crypto::ed25519_dalek::SigningKey;
    use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
    use mirage_discovery::replay::ReplaySet;
    use mirage_discovery::token::{sign_token, CapabilityToken};

    // ---- test setup helpers ----

    fn rand_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).unwrap();
        s
    }

    fn gen_x25519() -> ([u8; 32], [u8; 32]) {
        let sk = StaticSecret::from(rand_seed());
        let pk = PublicKey::from(&sk);
        (sk.to_bytes(), *pk.as_bytes())
    }

    fn gen_ed25519() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&rand_seed());
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn issue_token(bridge_pk: [u8; 32], op_sk: &SigningKey) -> CapabilityToken {
        sign_token([0x01u8; 32], bridge_pk, 2_000_000_000, op_sk)
    }

    /// Run a full handshake and return the two framers (i_framer, r_framer).
    fn run_handshake_pair() -> (SessionFramer, SessionFramer) {
        let (init_sk, _) = gen_x25519();
        let (resp_sk, resp_pk) = gen_x25519();
        let (_, bridge_id_pk) = gen_ed25519();
        let (op_sk, op_pk) = gen_ed25519();
        let token = issue_token(bridge_id_pk, &op_sk);

        let mut i = HandshakeInitiator::new(&init_sk, &resp_pk, &token).unwrap();
        let mut r = HandshakeResponder::new(&resp_sk, &bridge_id_pk, &op_pk).unwrap();

        let m1 = i.write_message_1().unwrap();
        assert_eq!(m1.len(), MSG_1_LEN);
        r.read_message_1(&m1).unwrap();

        let m2 = r.write_message_2().unwrap();
        assert_eq!(m2.len(), MSG_2_LEN);
        i.read_message_2(&m2).unwrap();

        let (m3, i_keys) = i.write_message_3().unwrap();
        assert_eq!(m3.len(), MSG_3_LEN_WITH_TOKEN);

        let mut rs = ReplaySet::new(16);
        let mut v = TokenVerifier::new(&mut rs, 1_700_000_000);
        let r_keys = r.read_message_3(&m3, &mut v).unwrap();

        // Both sides derived the same binding - sanity check.
        assert_eq!(i_keys.session_binding, r_keys.session_binding);
        assert_eq!(i_keys.mlkem_ss, r_keys.mlkem_ss);

        let i_framer = SessionFramer::from_session_keys(i_keys, Role::Initiator).unwrap();
        let r_framer = SessionFramer::from_session_keys(r_keys, Role::Responder).unwrap();
        (i_framer, r_framer)
    }

    // ---- tests ----

    #[test]
    fn roundtrip_both_directions() {
        let (mut i, mut r) = run_handshake_pair();

        let i2r = b"hello from initiator";
        let r2i = b"greetings from responder";

        let wire1 = i.send(i2r).unwrap();
        let decoded1 = r.recv(&wire1).unwrap();
        assert_eq!(decoded1, i2r);

        let wire2 = r.send(r2i).unwrap();
        let decoded2 = i.recv(&wire2).unwrap();
        assert_eq!(decoded2, r2i);
    }

    #[test]
    fn sequential_frames_in_order() {
        let (mut i, mut r) = run_handshake_pair();
        for n in 0u32..10 {
            let msg = format!("frame {}", n);
            let wire = i.send(msg.as_bytes()).unwrap();
            let got = r.recv(&wire).unwrap();
            assert_eq!(got, msg.as_bytes());
        }
    }

    #[test]
    fn replay_rejected() {
        let (mut i, mut r) = run_handshake_pair();
        let wire = i.send(b"once").unwrap();
        r.recv(&wire).unwrap();
        // Replaying the same wire bytes: recv seq has advanced, so nonce
        // no longer matches - outer decrypt fails.
        assert!(r.recv(&wire).is_err());
    }

    #[test]
    fn tamper_rejected() {
        let (mut i, mut r) = run_handshake_pair();
        let mut wire = i.send(b"tamper me").unwrap();
        // Flip a byte in the outer ciphertext region (skip length prefix).
        wire[5] ^= 0x01;
        assert!(r.recv(&wire).is_err());
    }

    #[test]
    fn wrong_direction_rejected() {
        // A frame sent by initiator should fail to decrypt if initiator
        // tries to decrypt it as if it were from responder.
        let (mut i, mut _r) = run_handshake_pair();
        let wire = i.send(b"wrong direction").unwrap();
        // Initiator trying to recv its own frame -> direction mismatch in AAD.
        assert!(i.recv(&wire).is_err());
    }

    #[test]
    fn cross_session_isolation() {
        let (mut i_a, _r_a) = run_handshake_pair();
        let (_i_b, mut r_b) = run_handshake_pair();
        let wire = i_a.send(b"from session A").unwrap();
        // Session B's responder has different keys; outer decrypt fails.
        assert!(r_b.recv(&wire).is_err());
    }

    #[test]
    fn advance_epoch_rotates_keys() {
        let (mut i, mut r) = run_handshake_pair();

        // Capture a pre-ratchet frame.
        let pre_wire = i.send(b"pre-epoch").unwrap();
        r.recv(&pre_wire).unwrap();

        assert_eq!(i.current_epoch(), 0);
        i.advance_epoch().unwrap();
        r.advance_epoch().unwrap();
        assert_eq!(i.current_epoch(), 1);
        assert_eq!(r.current_epoch(), 1);

        // Post-ratchet roundtrip works.
        let post_wire = i.send(b"post-epoch").unwrap();
        let got = r.recv(&post_wire).unwrap();
        assert_eq!(got, b"post-epoch");

        // Pre-ratchet wire bytes now invalid: different keys, different nonce space.
        // (Can't actually re-decrypt even with rewound counters - snow rekey'd too.)
    }

    // ---- §5.2 KEM-ratchet (post-compromise security) ----

    // Fresh ratchet shared secrets (in production: a live X25519 DH + ML-KEM
    // encapsulation done mid-session).
    const RESEED_X: [u8; 32] = [0xA1; 32];
    const RESEED_M: [u8; 32] = [0xB2; 32];

    #[test]
    fn kem_reseed_roundtrip_and_confirmation_match() {
        let (mut i, mut r) = run_handshake_pair();
        // Pre-reseed roundtrip.
        let w = i.send(b"pre").unwrap();
        assert_eq!(r.recv(&w).unwrap(), b"pre");

        // Both peers reseed with the IDENTICAL fresh secret.
        let tag_i = i.kem_reseed(&RESEED_X, &RESEED_M).unwrap();
        let tag_r = r.kem_reseed(&RESEED_X, &RESEED_M).unwrap();
        assert_eq!(tag_i, tag_r, "same secret => matching confirmation tag");
        assert_eq!(i.current_epoch(), 1);
        assert_eq!(r.current_epoch(), 1);

        // Post-reseed roundtrip works BOTH directions (both roots reseeded).
        let w2 = i.send(b"post i2r").unwrap();
        assert_eq!(r.recv(&w2).unwrap(), b"post i2r");
        let w3 = r.send(b"post r2i").unwrap();
        assert_eq!(i.recv(&w3).unwrap(), b"post r2i");
    }

    #[test]
    fn kem_reseed_diverging_secret_desyncs_and_tags_differ() {
        // ML-KEM implicit rejection can hand the two peers DIFFERENT secrets
        // with no error. The confirmation tag MUST differ so the protocol can
        // detect it before relying on the new keys.
        let (mut i, mut r) = run_handshake_pair();
        let tag_i = i.kem_reseed(&RESEED_X, &RESEED_M).unwrap();
        let tag_r = r.kem_reseed(&RESEED_X, &[0xC3; 32]).unwrap(); // divergent mlkem_ss
        assert_ne!(tag_i, tag_r, "divergent secrets MUST yield different tags");
        // And the roots genuinely diverged: no decryption is possible.
        let w = i.send(b"lost").unwrap();
        assert!(r.recv(&w).is_err(), "diverged roots => no decryption");
    }

    #[test]
    fn kem_reseed_is_not_a_plain_time_advance() {
        // The PCS property: a KEM reseed folds in fresh entropy, so a peer that
        // only knows the OLD roots (and does a plain time advance) CANNOT follow
        // it - even at the same epoch number the roots differ.
        let (mut i, mut r) = run_handshake_pair();
        i.kem_reseed(&RESEED_X, &RESEED_M).unwrap(); // initiator injects entropy
        r.advance_epoch().unwrap(); // responder time-advances (no secret)
        assert_eq!(i.current_epoch(), r.current_epoch(), "both at epoch 1");
        let w = i.send(b"needs the kem secret").unwrap();
        assert!(
            r.recv(&w).is_err(),
            "a time advance must NOT be able to follow a KEM reseed"
        );
    }

    #[test]
    fn kem_reseed_preserves_grace_window_then_restores_fs() {
        let (mut i, mut r) = run_handshake_pair();
        let pre = i.send(b"pre-reseed").unwrap();
        i.kem_reseed(&RESEED_X, &RESEED_M).unwrap();
        r.kem_reseed(&RESEED_X, &RESEED_M).unwrap();
        // Grace window: a pre-reseed frame still in flight decrypts.
        assert!(r.recv(&pre).is_ok());
        // Expire the window -> forward secrecy: the same bytes no longer decrypt.
        r.expire_prev_recv();
        assert!(r.recv(&pre).is_err());
    }

    #[test]
    fn kem_reseed_resets_seq_no_nonce_reuse() {
        // After a reseed both directions restart at seq 0 under a fresh key/iv;
        // many post-reseed frames must round-trip in order with no collision.
        let (mut i, mut r) = run_handshake_pair();
        // Burn some seq at epoch 0.
        for _ in 0..5 {
            let w = i.send(b"burn").unwrap();
            r.recv(&w).unwrap();
        }
        i.kem_reseed(&RESEED_X, &RESEED_M).unwrap();
        r.kem_reseed(&RESEED_X, &RESEED_M).unwrap();
        for n in 0u32..20 {
            let msg = format!("post {n}");
            let w = i.send(msg.as_bytes()).unwrap();
            assert_eq!(r.recv(&w).unwrap(), msg.as_bytes());
        }
    }

    #[test]
    fn forward_secrecy_after_grace_window_expires() {
        // FS is now grace-bounded: right after an advance the previous epoch's
        // recv keys are retained (so in-flight frames still decrypt), but once
        // the grace window is expired the old frame is permanently sealed.
        let (mut i, mut r) = run_handshake_pair();
        let pre_wire = i.send(b"sealed by past key").unwrap();

        i.advance_epoch().unwrap();
        r.advance_epoch().unwrap();

        // During the grace window: the epoch-0 frame STILL decrypts (this is
        // the skew-tolerance the ratchet needs, not a bug).
        assert!(r.recv(&pre_wire).is_ok());

        // Expire the grace window -> forward secrecy restored: the same bytes
        // no longer decrypt under any retained key.
        r.expire_prev_recv();
        assert!(r.recv(&pre_wire).is_err());
    }

    #[test]
    fn grace_window_decrypts_straggler_after_local_advance() {
        // A frame sent under epoch N arrives after the RECEIVER advanced to
        // N+1 (clock skew / reorder across the boundary). It must still decrypt.
        let (mut i, mut r) = run_handshake_pair();
        // i is still at epoch 0; it sends an epoch-0 frame.
        let straggler = i.send(b"in-flight across the boundary").unwrap();
        // r advances first (its clock crossed the boundary).
        r.advance_epoch().unwrap();
        assert_eq!(r.current_epoch(), 1);
        // The straggler decrypts via the grace window; r stays at epoch 1.
        assert_eq!(
            r.recv(&straggler).unwrap(),
            b"in-flight across the boundary"
        );
        assert_eq!(r.current_epoch(), 1);
    }

    #[test]
    fn receiver_reactively_follows_a_peer_that_advanced_first() {
        // The SENDER advances first and sends an epoch-1 frame to a receiver
        // still at epoch 0. The receiver must adopt (follow) epoch 1 and decrypt.
        let (mut i, mut r) = run_handshake_pair();
        i.advance_epoch().unwrap();
        assert_eq!(i.current_epoch(), 1);
        assert_eq!(r.current_epoch(), 0);
        let wire = i.send(b"peer is a step ahead").unwrap();
        assert_eq!(r.recv(&wire).unwrap(), b"peer is a step ahead");
        // r followed to epoch 1.
        assert_eq!(r.current_epoch(), 1);
        // And the reverse direction now works at the adopted epoch.
        let back = r.send(b"caught up").unwrap();
        assert_eq!(i.recv(&back).unwrap(), b"caught up");
    }

    #[test]
    fn duplex_survives_one_sided_skew_advance() {
        // Full duplex where only ONE side advances (max skew within the grace
        // window): traffic keeps flowing both directions without desync.
        let (mut i, mut r) = run_handshake_pair();
        // Both send under epoch 0.
        let i0 = i.send(b"i-epoch0").unwrap();
        let r0 = r.send(b"r-epoch0").unwrap();
        // i advances; r has not.
        i.advance_epoch().unwrap();
        // r receives i's epoch-0 straggler (grace not needed on r; r is at 0)
        assert_eq!(r.recv(&i0).unwrap(), b"i-epoch0");
        // i receives r's epoch-0 frame via ITS grace window (i is at epoch 1).
        assert_eq!(i.recv(&r0).unwrap(), b"r-epoch0");
        // i sends epoch-1; r reactively follows.
        let i1 = i.send(b"i-epoch1").unwrap();
        assert_eq!(r.recv(&i1).unwrap(), b"i-epoch1");
        assert_eq!(r.current_epoch(), 1);
    }

    #[test]
    fn maybe_advance_is_gated_and_bounded() {
        let (mut i, _r) = run_handshake_pair();
        // Never advances past the wall-clock target.
        assert!(i.maybe_advance(1).unwrap());
        assert_eq!(i.current_epoch(), 1);
        assert!(!i.maybe_advance(1).unwrap(), "already at target");

        // A one-directional flow (peer stays idle, last_recv_epoch = 0) may now
        // keep advancing up to MAX_SEND_LEAD_EPOCHS ahead - this is the fix for
        // the ratchet stalling at epoch 1 on idle-reverse-direction sessions.
        // Drive the target high; it should climb to the lead bound, then pause.
        for _ in 0..(MAX_SEND_LEAD_EPOCHS + 5) {
            i.maybe_advance(1000).unwrap();
        }
        assert_eq!(
            i.current_epoch(),
            MAX_SEND_LEAD_EPOCHS,
            "send ratchet climbs to the lead bound over an idle peer, not just 1"
        );
        // Pinned at the bound until the peer is heard from.
        assert!(!i.maybe_advance(1000).unwrap());
        assert_eq!(i.current_epoch(), MAX_SEND_LEAD_EPOCHS);
    }

    #[test]
    fn empty_plaintext_rejected() {
        let (mut i, _r) = run_handshake_pair();
        assert!(i.send(&[]).is_err());
    }

    #[test]
    fn oversized_plaintext_rejected() {
        let (mut i, _r) = run_handshake_pair();
        let oversized = vec![0u8; MAX_FRAME_PLAINTEXT + 1];
        assert!(i.send(&oversized).is_err());
    }

    #[test]
    fn max_plaintext_accepted() {
        let (mut i, mut r) = run_handshake_pair();
        let max_pt = vec![0xABu8; MAX_FRAME_PLAINTEXT];
        let wire = i.send(&max_pt).unwrap();
        assert_eq!(wire.len(), LEN_PREFIX_SIZE + MAX_OUTER_CT_LEN);
        let got = r.recv(&wire).unwrap();
        assert_eq!(got.len(), MAX_FRAME_PLAINTEXT);
        assert_eq!(got, max_pt);
    }

    #[test]
    fn short_wire_rejected() {
        let (mut _i, mut r) = run_handshake_pair();
        assert!(r.recv(&[]).is_err());
        assert!(r.recv(&[0x00]).is_err());
        // Length prefix claims 100 but only 10 bytes follow.
        let mut short = vec![0u8, 100];
        short.extend_from_slice(&[0u8; 10]);
        assert!(r.recv(&short).is_err());
    }

    #[test]
    fn undersize_claimed_length_rejected() {
        let (mut _i, mut r) = run_handshake_pair();
        // Length prefix < MIN_OUTER_CT_LEN (33).
        let mut wire = vec![0u8, 10]; // claims 10 bytes
        wire.extend_from_slice(&[0u8; 10]);
        assert!(r.recv(&wire).is_err());
    }

    #[test]
    fn oversize_claimed_length_rejected() {
        let (mut _i, mut r) = run_handshake_pair();
        // Length prefix > MAX_OUTER_CT_LEN (16416).
        let oversize = (MAX_OUTER_CT_LEN as u16).wrapping_add(1);
        let mut wire = oversize.to_be_bytes().to_vec();
        wire.extend_from_slice(&vec![0u8; oversize as usize]);
        assert!(r.recv(&wire).is_err());
    }

    #[test]
    fn ratchet_advances_epoch_counter() {
        let (mut i, _r) = run_handshake_pair();
        assert_eq!(i.current_epoch(), 0);
        i.advance_epoch().unwrap();
        assert_eq!(i.current_epoch(), 1);
        i.advance_epoch().unwrap();
        assert_eq!(i.current_epoch(), 2);
    }

    /// R25: labels MUST match spec §3.5 exactly (`b"mirage-key-i2r-v1"`, 17 B).
    /// An earlier draft used padded 20-byte labels; this test fixes the bytes
    /// via the `direction_root` helper so a regression would be caught.
    #[test]
    fn direction_root_matches_spec_labels() {
        // Known inputs: both zero for reproducibility.
        let k_pq = [0u8; 32];
        let sb = [0u8; 32];

        // Recompute using the SAME label bytes the spec specifies, via a
        // direct BLAKE3 call (independent of the framer's internals).
        let expected_i2r = {
            let mut h = mirage_crypto::blake3::Hasher::new();
            h.update(b"mirage-key-i2r-v1");
            h.update(&k_pq);
            h.update(&sb);
            *h.finalize().as_bytes()
        };
        let got_i2r = super::direction_root(b"mirage-key-i2r-v1", &k_pq, &sb);
        assert_eq!(got_i2r, expected_i2r);

        let expected_r2i = {
            let mut h = mirage_crypto::blake3::Hasher::new();
            h.update(b"mirage-key-r2i-v1");
            h.update(&k_pq);
            h.update(&sb);
            *h.finalize().as_bytes()
        };
        let got_r2i = super::direction_root(b"mirage-key-r2i-v1", &k_pq, &sb);
        assert_eq!(got_r2i, expected_r2i);
    }

    /// R27: advancing past `u32::MAX` epochs must error, not silently
    /// truncate into a colliding nonce.
    #[test]
    fn advance_epoch_rejects_u32_overflow() {
        let (mut i, _r) = run_handshake_pair();
        // Poke the epoch field to just-below u32::MAX via a public API is
        // awkward; this test validates the boundary by asserting that
        // advancing FROM u32::MAX - 1 to u32::MAX succeeds, and advancing
        // FROM u32::MAX fails.
        //
        // We don't expose `set_epoch`, so we compute the check indirectly:
        // verify `advance_epoch` returns Ok for epoch N and Err for u32::MAX.
        // We do this by setting state via a #[cfg(test)] helper below.
        i.set_epoch_for_test(u32::MAX as u64 - 1);
        assert!(i.advance_epoch().is_ok());
        assert_eq!(i.current_epoch(), u32::MAX as u64);
        // Now one more would overflow u32.
        match i.advance_epoch() {
            Err(SessionError::State(msg)) => {
                assert!(msg.contains("u32"), "unexpected msg: {}", msg);
            }
            Ok(_) => panic!("advance past u32::MAX must fail"),
            Err(e) => panic!("unexpected error variant: {}", e),
        }
    }

    #[test]
    fn bidirectional_flow_over_ratchets() {
        // Send and receive frames across multiple epoch boundaries in both
        // directions to ensure both framers maintain state correctly.
        let (mut i, mut r) = run_handshake_pair();

        for epoch_count in 0..3 {
            for n in 0u32..5 {
                let i_msg = format!("e{} i2r #{}", epoch_count, n);
                let wire = i.send(i_msg.as_bytes()).unwrap();
                assert_eq!(r.recv(&wire).unwrap(), i_msg.as_bytes());

                let r_msg = format!("e{} r2i #{}", epoch_count, n);
                let wire = r.send(r_msg.as_bytes()).unwrap();
                assert_eq!(i.recv(&wire).unwrap(), r_msg.as_bytes());
            }
            i.advance_epoch().unwrap();
            r.advance_epoch().unwrap();
        }
    }
}
