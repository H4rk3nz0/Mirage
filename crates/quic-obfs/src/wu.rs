//! Wu-2023 fully-encrypted-traffic evasion for the QUIC obfuscator.
//!
//! The shared preamble primitive (the attack, the encoding, the honest scope)
//! lives in [`mirage_common::wu_preamble`]. This module applies it per QUIC
//! datagram: [`add_preamble`] prepends one printable run so the wire clears the
//! GFW's classifier, and [`strip_preamble`] recovers the offset on receive.
//!
//! Context specific to QUIC: real QUIC Initials dodge the classifier for free
//! (they are padded to >=1200 bytes with zero-valued PADDING frames, so their
//! popcount lands in the "few 1-bits" exempt region). Salamander XOR destroys
//! that - `salt || ciphertext` is uniformly random and hits none of the
//! exemptions - so the obfuscator, left alone, reads as MORE suspicious to this
//! specific deployed classifier than plain QUIC would. Gecko fixed the
//! packet-SIZE tell but not this byte-randomness one; the preamble closes it.

use mirage_common::wu_preamble as prim;

/// Prepend a fresh printable preamble to an already-obfuscated datagram.
/// Layout: `len_byte(1) || preamble(L printable) || obf`, so bytes `[0, 1 + L)`
/// form a single printable run of at least 25 bytes.
pub fn add_preamble(obf: &[u8]) -> Vec<u8> {
    let mut out = prim::make_preamble();
    out.extend_from_slice(obf);
    out
}

/// Strip the preamble, returning the offset where the obfuscated datagram
/// begins. `None` if the leading bytes are not a valid preamble (corrupt or
/// injected) - the caller then skips the datagram exactly as for any malformed
/// input. Defensively verifies the whole declared run is printable, so a random
/// non-preamble datagram is rejected rather than silently mis-framed.
pub fn strip_preamble(buf: &[u8]) -> Option<usize> {
    let l = prim::preamble_body_len(*buf.first()?)?;
    let start = 1 + l;
    if buf.len() < start {
        return None;
    }
    if buf[1..start].iter().any(|b| !prim::is_alphabet(*b)) {
        return None;
    }
    Some(start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_common::wu_preamble::MIN_PRE;

    /// Longest run of printable-ASCII bytes in `buf` (the GFW's Ex4 feature).
    fn longest_printable_run(buf: &[u8]) -> usize {
        let mut best = 0;
        let mut cur = 0;
        for &b in buf {
            if (0x20..=0x7e).contains(&b) {
                cur += 1;
                best = best.max(cur);
            } else {
                cur = 0;
            }
        }
        best
    }

    /// A faithful reimplementation of the GFW's fully-encrypted-traffic
    /// exemption rules (Wu et al., 2023). Returns true when the packet is
    /// EXEMPTED (deemed not-fully-encrypted, i.e. NOT blocked). A flow is
    /// flagged when this returns false for its packets.
    fn wu_exempt(pkt: &[u8]) -> bool {
        if pkt.is_empty() {
            return true;
        }
        // Ex1: popcount ratio near an extreme (few or many 1-bits). Real QUIC
        // Initials land here via zero-valued PADDING frames; uniform-random
        // Salamander output sits at ~0.5 and does not.
        let ones: usize = pkt.iter().map(|b| b.count_ones() as usize).sum();
        let ratio = ones as f64 / (pkt.len() * 8) as f64;
        if ratio <= 0.034 || ratio >= 0.966 {
            return true;
        }
        // Ex2: first six bytes all printable ASCII.
        if pkt.len() >= 6 && pkt[..6].iter().all(|b| (0x20..=0x7e).contains(b)) {
            return true;
        }
        // Ex3: more than half the bytes are printable ASCII.
        let printable = pkt.iter().filter(|&&b| (0x20..=0x7e).contains(&b)).count();
        if printable * 2 > pkt.len() {
            return true;
        }
        // Ex4: longest printable-ASCII run exceeds 20 bytes.
        longest_printable_run(pkt) > 20
    }

    #[test]
    fn preamble_flips_the_gfw_verdict_from_blocked_to_exempt() {
        // Headline measurement: run the reconstructed GFW classifier over many
        // datagrams of raw Salamander output vs the same output with the
        // preamble. Raw output looks fully-encrypted (blocked); the preamble
        // makes every datagram exempt.
        let key = crate::key_from_password(b"measure-obfs-key");
        let n: usize = 2000;
        let (mut plain_flagged, mut wu_flagged) = (0usize, 0usize);
        for i in 0..n {
            // A realistic ~1200-byte QUIC datagram of pseudo-random payload.
            let salt = i as u32;
            let body: Vec<u8> = (0..1200u32)
                .map(|j| (j.wrapping_mul(2654435761) ^ salt) as u8)
                .collect();
            let mut obf = Vec::new();
            crate::salamander_wrap(&key, &body, &mut obf);
            if !wu_exempt(&obf) {
                plain_flagged += 1;
            }
            let framed = add_preamble(&obf);
            if !wu_exempt(&framed) {
                wu_flagged += 1;
            }
        }
        // Raw Salamander: the vast majority read as fully-encrypted (blocked).
        assert!(
            plain_flagged * 100 > n * 95,
            "raw Salamander should be flagged by the GFW classifier: {plain_flagged}/{n}"
        );
        // With the preamble: not a single datagram is flagged.
        assert_eq!(
            wu_flagged, 0,
            "the preamble must exempt every datagram, {wu_flagged}/{n} still flagged"
        );
    }

    #[test]
    fn preamble_round_trips_and_strips_to_original() {
        for body_len in [0usize, 1, 8, 64, 1200] {
            let obf: Vec<u8> = (0..body_len).map(|i| (i * 31 % 256) as u8).collect();
            let wire = add_preamble(&obf);
            let start = strip_preamble(&wire).expect("valid preamble strips");
            assert_eq!(&wire[start..], &obf[..], "body recovered after strip");
        }
    }

    #[test]
    fn preamble_hits_the_gfw_printable_exemptions() {
        // Adversary view: the on-wire datagram must clear Ex2 (first 6 printable)
        // AND Ex4 (printable run > 20) on every draw, for a fully-random body
        // (the worst case - a de-facto uniform Salamander ciphertext).
        for trial in 0..256u32 {
            let obf: Vec<u8> = (0..1200u32).map(|i| (i ^ trial).to_le_bytes()[0]).collect();
            let wire = add_preamble(&obf);
            // Ex2: first six bytes all printable.
            assert!(
                wire[..6].iter().all(|b| (0x20..=0x7e).contains(b)),
                "first 6 bytes must be printable (Ex2)"
            );
            // Ex4: a printable run strictly longer than 20.
            assert!(
                longest_printable_run(&wire) > 20,
                "printable run must exceed 20 (Ex4)"
            );
        }
    }

    #[test]
    fn length_varies_across_draws() {
        // No constant-length signature: the leading length byte must not be
        // pinned to a single value across many packets.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..512 {
            let wire = add_preamble(b"x");
            seen.insert(wire[0]);
        }
        assert!(seen.len() > 1, "preamble length must vary per packet");
    }

    #[test]
    fn rejects_non_printable_or_truncated_leading_bytes() {
        // A non-printable length byte (e.g. a plain Salamander datagram whose
        // first salt byte is < 0x20) is not mistaken for a preamble.
        assert_eq!(strip_preamble(&[0x00, 0x41, 0x42]), None);
        // A printable length byte declaring more than we received is rejected.
        let mut buf = vec![0x20u8]; // declares L = MIN_PRE
        buf.extend(std::iter::repeat_n(b'A', 3)); // but only 3 bytes follow
        assert_eq!(strip_preamble(&buf), None);
        // A length byte in range but with a non-printable byte inside the run is
        // rejected (defends against a random datagram whose first byte happens
        // to be printable).
        let mut buf2 = vec![0x20]; // L = MIN_PRE
        buf2.resize(1 + MIN_PRE + 4, b'A');
        buf2[3] = 0x01; // corrupt one preamble byte
        assert_eq!(strip_preamble(&buf2), None);
    }
}
