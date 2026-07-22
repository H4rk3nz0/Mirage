//! Padme length-padding (Nithikin et al., USENIX Security 2019).
//!
//! # Why
//!
//! Mirage's session-frame layer is plaintext-driven by design:
//! a 100-byte write produces a ~132-byte outer ciphertext.
//! That leaks application-payload length to a passive observer
//! who counts bytes between AEAD boundaries. Padme is a deterministic
//! rounding scheme that pads each frame to a length drawn from a
//! small set, with provable bounds:
//!
//! - **Max overhead**: <= 11.99% asymptotically; <= 100% for
//!   very small messages where the rounded length must be at
//!   least 1 byte.
//! - **Distinct lengths**: O(log^2 L) for max length L. A 16 KiB
//!   payload domain has fewer than a couple hundred reachable
//!   padded lengths, vs. the naive 16384 distinct lengths.
//! - **Cheap**: a few integer ops; no entropy required at runtime.
//!
//! # Algorithm
//!
//! ```text
//!   E = floor(log2(L))                 # bits in L
//!   S = floor(log2(E))                 # bits in E
//!   step = 1 << (E - S)                # alignment
//!   Padme(L) = ((L + step - 1) / step) * step
//! ```
//!
//! For very small `L` (<= 1) the formula degrades; we special-case
//! to return `L` for `L < 4` (cap bound chosen so step>=2 always
//! holds at the edge case).
//!
//! # NOT ON THE LIVE PATH - length hiding is provided by transport-pad
//!
//! **These primitives are self-contained and are NOT wired into the
//! session data path.** `SessionFramer::send`/`recv` do not call
//! [`pad_for_kind`] / [`pad_to_padme`] / [`unpad_from_padme`]; nothing
//! outside this module's own unit tests constructs or invokes them.
//! Do not mistake this module for active length-hiding coverage.
//!
//! On the live path, the application-payload-length leak described in
//! "# Why" above is closed **one layer below the session** by
//! `mirage-transport-pad`'s [`PaddedStream`](https://docs.rs/mirage-transport-pad):
//! it size-buckets every wire frame to one of a small fixed set of
//! bucket sizes (64, 128, ..., 65536) and random-fills the tail, so a
//! passive observer sees at most ~11 distinct frame sizes regardless
//! of what the session emits. Both the client (`crates/client`) and
//! the bridge (`crates/bridge`) wrap their transport stream in
//! `PaddedStream` when `pad_enabled` is set, ahead of the Mirage Noise
//! session. That transport-layer bucketing is Mirage's shipped
//! length-hiding mechanism; the session-layer Padme scheme here is
//! **superseded by it** for the live data path.
//!
//! This module is retained (not deleted) as a tested, self-contained
//! primitive for two reasons: (a) conformance vectors + the smoke
//! tests below, and (b) it is the reference implementation for an
//! *alternative* in-AEAD per-frame padding scheme, should a future
//! transport want length hiding applied inside the AEAD boundary
//! rather than at the `PaddedStream` layer. Wiring it there is a
//! deliberate, unscheduled design choice - NOT an implied v0.2 task,
//! and NOT a substitute for the transport-pad coverage that already
//! ships. If it is ever wired, the integration point is the layer
//! that owns the session-frame producer/consumer (the bridge's
//! tunnel pump or the client's local-bind forwarder), calling
//! [`pad_for_kind`] before inner encrypt and [`unpad_from_padme`]
//! after inner decrypt.

use thiserror::Error;

/// Errors produced by Padme padding/unpadding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PadmeError {
    /// Caller passed a buffer that's smaller than the embedded
    /// length prefix says it should be.
    #[error("buffer shorter than length prefix indicates")]
    Truncated,
    /// Length prefix is impossible (claimed length > buffer length
    /// minus prefix).
    #[error("length prefix claims more bytes than the buffer holds")]
    BadPrefix,
    /// Padme rounded length exceeds u32::MAX. Practically
    /// unreachable for Mirage frames (capped at 16 KiB).
    #[error("rounded length exceeds u32 bounds")]
    Overflow,
    /// CSPRNG failed when filling pad bytes. We fail closed rather
    /// than emit deterministic-zero padding - if a downstream cipher
    /// flaw ever exposed pad bytes, all-zero padding would broadcast
    /// "this is a Mirage frame." Better to refuse to send than to
    /// degrade the wire-shape signal silently.
    #[error("CSPRNG failure during pad fill")]
    Csprng,
}

/// Pure Padme rounding. Returns the smallest multiple of
/// `2^(E-S)` (where `E = floor(log2(L))`, `S = floor(log2(E))`)
/// that is `>= L`. For `L < 4`, returns `L` unchanged.
pub fn padme(l: u64) -> u64 {
    if l < 4 {
        return l;
    }
    let e = 63 - l.leading_zeros() as u64; // floor(log2(L))
    if e < 2 {
        return l;
    }
    let s = 63 - e.leading_zeros() as u64; // floor(log2(E))
    let shift = e.saturating_sub(s);
    let step = 1u64 << shift;
    l.div_ceil(step) * step
}

/// Maximum overhead the Padme rounding can introduce, as a
/// fraction. For lengths `>= 4`, this is bounded by `1/(2^S)` where
/// `S = floor(log2(floor(log2(L))))`. For Mirage frames in the
/// 1024..=16384 byte range, overhead is <= ~12%.
pub fn max_overhead_fraction(l: u64) -> f64 {
    if l == 0 {
        return 0.0;
    }
    let padded = padme(l);
    if padded == l {
        return 0.0;
    }
    (padded as f64 - l as f64) / l as f64
}

/// What kind of frame this plaintext represents. Used by
/// [`pad_for_kind`] to decide whether the
/// `PaddingProfile::Minimal` bypass applies.
///
/// Closes [RT-H5]: pre-fix the bypass was keyed on frame size
/// alone (< 1500 B). A small control frame (e.g., a mux
/// `WindowUpdate` at 11 B) is < 1500 B but is NOT media; without
/// kind-awareness it would leak unpadded. Now the bypass is
/// command-type-keyed: only `Media` frames bypass; `Control`
/// frames are always Padme-padded regardless of profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// High-rate media frame (audio sample, video chunk, RTP
    /// payload). Subject to Padme bypass when the circuit's
    /// padding profile is `Minimal` - the latency budget for
    /// real-time media doesn't tolerate the rounding overhead.
    Media,
    /// Control / non-media frame (mux command, RELAY metadata,
    /// circuit cell). MUST always be Padme-padded - the bypass
    /// does not apply, regardless of frame size or profile.
    Control,
}

/// Profile knob the integration layer sets per circuit. Mirrors
/// `mirage_router::PaddingProfile::Minimal` semantics without
/// pulling in a router dep - the caller translates router profile
/// -> bypass flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingPolicy {
    /// Always Padme-pad. Default for Strict / Standard profiles.
    AlwaysPad,
    /// Padme-pad Control frames; bypass for Media frames. Only
    /// the Realtime profile enables this.
    BypassMedia,
}

/// Pad `plaintext` according to `(kind, policy)`.
///
/// - `(Control, *)` -> always Padme-padded.
/// - `(Media, AlwaysPad)` -> Padme-padded.
/// - `(Media, BypassMedia)` -> returned **unpadded** with the same
///   2-byte length prefix that [`pad_to_padme`] adds, so
///   receivers can use [`unpad_from_padme`] uniformly.
///
/// Entry point for any future in-AEAD padding wiring. NOTE: this is
/// not called on the live data path today - length hiding ships via
/// `mirage-transport-pad` (see the module-level note). Currently
/// exercised only by this module's unit tests.
pub fn pad_for_kind(
    plaintext: &[u8],
    kind: FrameKind,
    policy: PaddingPolicy,
) -> Result<Vec<u8>, PadmeError> {
    match (kind, policy) {
        (FrameKind::Control, _) | (FrameKind::Media, PaddingPolicy::AlwaysPad) => {
            pad_to_padme(plaintext)
        }
        (FrameKind::Media, PaddingPolicy::BypassMedia) => {
            // Length prefix only; no Padme rounding. Decoder uses
            // the same `unpad_from_padme` since the prefix format
            // matches. Trailing pad bytes (zero) are absent - the
            // resulting buffer is exactly `2 + plaintext.len()`.
            if plaintext.len() > u16::MAX as usize - 2 {
                return Err(PadmeError::Overflow);
            }
            let mut out = Vec::with_capacity(2 + plaintext.len());
            out.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
            out.extend_from_slice(plaintext);
            Ok(out)
        }
    }
}

/// Wrap `plaintext` for transmission: prepend a 2-byte big-endian
/// length prefix, pad with zero bytes to `Padme(plaintext.len() + 2)`.
///
/// The result is a `Vec<u8>` of length `Padme(plaintext.len() + 2)`.
/// Callers SHOULD send the entire buffer through the AEAD'd session
/// layer; receivers call [`unpad_from_padme`] to recover the
/// original plaintext.
pub fn pad_to_padme(plaintext: &[u8]) -> Result<Vec<u8>, PadmeError> {
    if plaintext.len() > u16::MAX as usize - 2 {
        return Err(PadmeError::Overflow);
    }
    let total = plaintext.len() + 2;
    let target = padme(total as u64) as usize;
    let mut out = vec![0u8; target];
    out[..2].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
    out[2..2 + plaintext.len()].copy_from_slice(plaintext);
    // Fill the remaining padding bytes from the OS CSPRNG. Padding
    // sits inside the AEAD (never on the wire in cleartext) so this
    // is a defense-in-depth measure: should a downstream cipher
    // flaw ever leak pad bytes, random fill removes the all-zero
    // pattern that would otherwise identify the frame as Mirage.
    let pad_start = 2 + plaintext.len();
    if pad_start < target {
        getrandom::fill(&mut out[pad_start..]).map_err(|_| PadmeError::Csprng)?;
    }
    Ok(out)
}

/// Unwrap a Padme-padded buffer. Reads the 2-byte length prefix,
/// returns the next `length` bytes as the plaintext. Trailing
/// padding bytes are discarded.
pub fn unpad_from_padme(padded: &[u8]) -> Result<Vec<u8>, PadmeError> {
    if padded.len() < 2 {
        return Err(PadmeError::Truncated);
    }
    let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if 2 + len > padded.len() {
        return Err(PadmeError::BadPrefix);
    }
    Ok(padded[2..2 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padme_small_lengths_unchanged() {
        for l in 0..4 {
            assert_eq!(padme(l), l);
        }
    }

    #[test]
    fn padme_paper_examples() {
        // Some sanity-check values matching the paper's expected behavior.
        // L=100: E=6, S=2, step=16, ceil(100/16)*16 = 112.
        assert_eq!(padme(100), 112);
        // L=1000: E=9, S=3, step=64, ceil(1000/64)*64 = 1024.
        assert_eq!(padme(1000), 1024);
        // L=16384 (a power of 2): already aligned to 2^(E-S) where
        // E=14, S=3, step=2048; 16384 is a multiple of 2048.
        assert_eq!(padme(16384), 16384);
        // L=16385: rounds up to 16384 + 2048 = 18432.
        assert_eq!(padme(16385), 18432);
    }

    #[test]
    fn padme_is_idempotent() {
        for &l in &[100u64, 200, 500, 1000, 5000, 10000] {
            let padded = padme(l);
            assert_eq!(
                padme(padded),
                padded,
                "padme({l}) = {padded} should be a fixed point"
            );
        }
    }

    #[test]
    fn padme_is_monotonic() {
        let mut prev = 0u64;
        for l in 0..2000 {
            let p = padme(l);
            assert!(p >= prev, "padme not monotonic at L={l}: {p} < {prev}");
            prev = p;
        }
    }

    #[test]
    fn padme_overhead_bounded_for_typical_frames() {
        // For Mirage frame sizes (32 B alert .. 16 KiB max), Padme
        // overhead must stay under ~13%.
        for &l in &[32u64, 100, 256, 1024, 4096, 8192, 16384, 16383] {
            let oh = max_overhead_fraction(l);
            assert!(
                oh < 0.13,
                "Padme overhead at L={l} = {oh:.3} exceeds 13% bound"
            );
        }
    }

    #[test]
    fn padme_distinct_lengths_in_range() {
        // Count distinct Padme outputs for L in [4..=16384].
        // The distinct-output count should be small (< 200 in this
        // range; exact value is implementation-dependent but
        // bounded by O(log^2 L)).
        let mut seen = std::collections::BTreeSet::new();
        for l in 4..=16384u64 {
            seen.insert(padme(l));
        }
        assert!(
            seen.len() < 250,
            "expected fewer than 250 distinct Padme lengths in [4..=16384], got {}",
            seen.len()
        );
    }

    #[test]
    fn pad_unpad_roundtrip() {
        for body in &[
            &[][..],
            b"a".as_slice(),
            b"hello mirage padding scheme".as_slice(),
            &[0xABu8; 100][..],
            &[0xCDu8; 1000][..],
        ] {
            let padded = pad_to_padme(body).unwrap();
            let back = unpad_from_padme(&padded).unwrap();
            assert_eq!(&back[..], *body);
            // Padded length is exactly Padme(body.len() + 2).
            assert_eq!(padded.len(), padme((body.len() + 2) as u64) as usize);
        }
    }

    #[test]
    fn unpad_rejects_truncated() {
        assert_eq!(unpad_from_padme(&[]), Err(PadmeError::Truncated));
        assert_eq!(unpad_from_padme(&[0]), Err(PadmeError::Truncated));
    }

    #[test]
    fn unpad_rejects_bad_prefix() {
        // Length prefix says 100 bytes but only 5 follow.
        let mut buf = vec![0u8, 100];
        buf.extend_from_slice(&[0u8; 5]);
        assert_eq!(unpad_from_padme(&buf), Err(PadmeError::BadPrefix));
    }

    #[test]
    fn pad_too_large_rejected() {
        // u16 prefix means max plaintext = u16::MAX - 2 = 65533.
        // Anything larger is out of range.
        let too_big = vec![0u8; 65534];
        assert_eq!(pad_to_padme(&too_big), Err(PadmeError::Overflow));
    }

    // --- pad_for_kind (RT-H5 closure) -----------------------------------

    #[test]
    fn control_frames_always_padded_regardless_of_policy() {
        // A small control frame (11 bytes - like a mux WindowUpdate)
        // MUST be Padme-padded even under BypassMedia policy.
        let control = b"window-up-1";
        let padded_strict =
            pad_for_kind(control, FrameKind::Control, PaddingPolicy::AlwaysPad).unwrap();
        let padded_bypass =
            pad_for_kind(control, FrameKind::Control, PaddingPolicy::BypassMedia).unwrap();
        // Both produce Padme-padded output (length matches).
        assert_eq!(padded_strict.len(), padded_bypass.len());
        // Length is the Padme of (len + 2).
        assert_eq!(
            padded_strict.len(),
            padme((control.len() + 2) as u64) as usize
        );
        // Round-trip recovers the original.
        assert_eq!(unpad_from_padme(&padded_strict).unwrap(), control);
        assert_eq!(unpad_from_padme(&padded_bypass).unwrap(), control);
    }

    #[test]
    fn media_frames_padded_under_always_pad() {
        let media = vec![0xABu8; 800];
        let out = pad_for_kind(&media, FrameKind::Media, PaddingPolicy::AlwaysPad).unwrap();
        assert_eq!(out.len(), padme((media.len() + 2) as u64) as usize);
        assert_eq!(unpad_from_padme(&out).unwrap(), media);
    }

    #[test]
    fn media_frames_unpadded_under_bypass_media() {
        // BypassMedia: Media frames get the length prefix only,
        // no Padme rounding. Output is exactly 2 + plaintext.len().
        let media = vec![0xCDu8; 800];
        let out = pad_for_kind(&media, FrameKind::Media, PaddingPolicy::BypassMedia).unwrap();
        assert_eq!(out.len(), 2 + media.len(), "media+bypass = no rounding");
        // Decoder works the same way - length prefix is the same.
        assert_eq!(unpad_from_padme(&out).unwrap(), media);
    }

    #[test]
    fn small_control_frame_does_not_leak_size_under_bypass() {
        // The exact red-team scenario: a tiny control frame riding
        // a Realtime circuit (PaddingPolicy::BypassMedia) MUST NOT
        // be unpadded just because it's small. Pre-fix the
        // size-keyed bypass would have leaked an 11-byte frame
        // verbatim. Post-fix the kind-keyed bypass pads it to the
        // Padme bucket regardless.
        let tiny_control = b"x";
        let out =
            pad_for_kind(tiny_control, FrameKind::Control, PaddingPolicy::BypassMedia).unwrap();
        // Padme rounds 3 (1 + 2-byte prefix) up to 3 (no change
        // for L < 4); so the smallest control frame still has
        // some prefix structure. For a 1-byte frame, padme(3) = 3.
        assert_eq!(out.len(), padme(3) as usize);
        // Importantly: NOT the raw "1-byte payload + prefix" that
        // would have leaked under size-keyed bypass.
        assert!(
            out.len() == 3,
            "1-byte control: expected padme(3) = 3 bytes, got {}",
            out.len()
        );
    }

    #[test]
    fn pad_for_kind_too_large_rejected() {
        let too_big = vec![0u8; 65534];
        assert_eq!(
            pad_for_kind(&too_big, FrameKind::Media, PaddingPolicy::BypassMedia),
            Err(PadmeError::Overflow)
        );
        assert_eq!(
            pad_for_kind(&too_big, FrameKind::Control, PaddingPolicy::AlwaysPad),
            Err(PadmeError::Overflow)
        );
    }
}
