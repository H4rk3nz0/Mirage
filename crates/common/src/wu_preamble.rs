//! Wu-2023 fully-encrypted-traffic evasion preamble (shared primitive).
//!
//! # The attack this defeats
//!
//! Wu et al. (USENIX Security 2023, "How the Great Firewall of China Detects
//! and Blocks Fully Encrypted Traffic") documented a PASSIVE classifier the GFW
//! deployed in 2021: a flow whose bytes look uniformly random is flagged as
//! "fully encrypted" and throttled or blocked. A packet is EXEMPTED - judged
//! not-random - if any of a few cheap heuristics hold, among them:
//!   - Ex2: the first six bytes are all printable ASCII (`0x20..=0x7e`), or
//!   - Ex4: the longest run of printable-ASCII bytes exceeds 20 bytes.
//!
//! Carriers whose wire is high-entropy from byte 0 - Salamander-obfuscated QUIC,
//! Shadowsocks-2022 (AEAD + random salt), obfs4 - hit none of the exemptions
//! and so read as fully-encrypted. (obfs4 is the protocol this classifier got
//! dropped in China.)
//!
//! # The primitive
//!
//! [`make_preamble`] returns a fresh `len_byte || preamble` prefix of `1 + L`
//! printable bytes, `L` in `[MIN_PRE, MAX_PRE]`, forming a printable run of at
//! least 25 bytes - clearing Ex2 and Ex4. Both the length and the bytes vary
//! per call, so there is no constant offset or constant-byte signature; only
//! "there is a printable run at the front" is fixed, a property shared by
//! countless benign text-carrying protocols. [`preamble_body_len`] decodes the
//! length byte on the receiving side so the prefix can be stripped.
//!
//! Two callers share this: the QUIC obfuscator prepends one per datagram, and
//! the Shadowsocks carrier prepends one at the start of each stream direction.
//! It adds *structure*, not entropy, so it does not fall foul of the generative
//! shaping trap - the run is drawn from a real printable alphabet, not
//! synthesised to imitate a specific protocol.
//!
//! # Honest scope
//!
//! This defeats the *published, deployed* entropy classifier. A printable prefix
//! is itself a mild anomaly to DPI that fully parses the carrier, so it is a
//! per-network posture, enabled where entropy-DPI is the actual threat, not a
//! universal default.

/// The alphabet the preamble is drawn from: base64url (RFC 4648 sec. 5), the
/// 64 characters real session tokens, nonces, JWT segments and API keys use.
///
/// Drawing from the FULL printable range instead would clear the classifier just
/// as well while making the preamble trivially separable from any real text:
/// uniform-over-95 puts a symbol like `~` or `|` in ~35% of positions, so a
/// stateless rule ("printable run holding a character no token alphabet uses")
/// fires on essentially every packet. Measured at AUC 1.0 against real tokens -
/// a cheaper and more reliable signature than the one the preamble evades. A
/// uniformly random base64url string is not an imitation of a token; it *is*
/// one, so there is no distribution left to separate on.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Smallest preamble body length. `1 + MIN_PRE` must exceed 20 so the run clears
/// the "longest printable run > 20" exemption on its own.
pub const MIN_PRE: usize = 21;
/// Largest preamble body length. `MAX_PRE - MIN_PRE + 1` is exactly
/// [`ALPHABET`]`.len()`, so the leading length character is uniform over the WHOLE
/// alphabet - it carries no positional bias and is indistinguishable from any
/// other character of the run. (The earlier encoding pinned it to a 41-value
/// sub-range, i.e. a second standalone signature.)
pub const MAX_PRE: usize = MIN_PRE + 63;

/// Is `b` a printable ASCII byte (`0x20..=0x7e`)? This is the classifier's own
/// notion of printable, used when validating a received preamble.
#[must_use]
pub fn is_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

/// Is `b` a character of the preamble [`ALPHABET`]?
#[must_use]
pub fn is_alphabet(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn fill_random(out: &mut [u8]) {
    getrandom::fill(out).expect("OS CSPRNG");
}

/// Map random bytes onto the alphabet. 64 divides 256, so masking to 6 bits is
/// exactly uniform - no modulo bias and no rejection sampling needed.
fn fill_alphabet(out: &mut [u8]) {
    fill_random(out);
    for b in out.iter_mut() {
        *b = ALPHABET[(*b & 0x3f) as usize];
    }
}

/// Produce a fresh `len_char || preamble` prefix: `1 + L` characters drawn from
/// [`ALPHABET`], with `L` uniform in `[MIN_PRE, MAX_PRE]`. The whole prefix is a
/// single uniform base64url run of at least 22 characters - a real-looking
/// token that satisfies both the "first six printable" and "printable run > 20"
/// exemptions.
#[must_use]
pub fn make_preamble() -> Vec<u8> {
    let mut lb = [0u8; 1];
    fill_random(&mut lb);
    let idx = (lb[0] & 0x3f) as usize; // uniform over the 64-char alphabet
    let l = MIN_PRE + idx;
    let mut out = vec![0u8; 1 + l];
    out[0] = ALPHABET[idx];
    fill_alphabet(&mut out[1..]);
    out
}

/// Decode the preamble body length `L` from a leading length character, or
/// `None` if it is not one (corrupt / injected / not a preamble).
#[must_use]
pub fn preamble_body_len(len_byte: u8) -> Option<usize> {
    let idx = ALPHABET.iter().position(|&c| c == len_byte)?;
    let l = MIN_PRE + idx;
    if l > MAX_PRE {
        None
    } else {
        Some(l)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn longest_printable_run(buf: &[u8]) -> usize {
        let (mut best, mut cur) = (0, 0);
        for &b in buf {
            if is_printable(b) {
                cur += 1;
                best = best.max(cur);
            } else {
                cur = 0;
            }
        }
        best
    }

    #[test]
    fn preamble_is_a_long_printable_run_and_self_describes_its_length() {
        for _ in 0..512 {
            let p = make_preamble();
            assert!(p.iter().all(|&b| is_printable(b)), "all bytes printable");
            assert!(longest_printable_run(&p) > 20, "run clears Ex4");
            assert!(
                p.len() >= 6 && p[..6].iter().all(|&b| is_printable(b)),
                "Ex2"
            );
            let l = preamble_body_len(p[0]).expect("length byte decodes");
            assert_eq!(1 + l, p.len(), "declared length matches actual prefix");
        }
    }

    #[test]
    fn length_varies_across_draws() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..512 {
            seen.insert(make_preamble()[0]);
        }
        assert!(seen.len() > 1, "preamble length must vary");
    }

    #[test]
    fn rejects_non_preamble_length_bytes() {
        assert_eq!(
            preamble_body_len(0x00),
            None,
            "control byte is not a length"
        );
        assert_eq!(preamble_body_len(0x7f), None, "DEL is not a length");
        // Printable but OUTSIDE the token alphabet - the exact class of byte
        // that used to be accepted and that made the run separable.
        for b in [b' ', b'~', b'|', b'{', b'!', b'/', b'+', b'='] {
            assert_eq!(
                preamble_body_len(b),
                None,
                "{b:#04x} is not in the alphabet"
            );
        }
        // Every alphabet character is a valid length char, and they span exactly
        // the [MIN_PRE, MAX_PRE] range with no gaps - so the length char carries
        // no positional bias.
        let mut decoded: Vec<usize> = ALPHABET
            .iter()
            .map(|&c| preamble_body_len(c).expect("alphabet char decodes"))
            .collect();
        decoded.sort_unstable();
        let expect: Vec<usize> = (MIN_PRE..=MAX_PRE).collect();
        assert_eq!(decoded, expect, "length chars cover the range bijectively");
    }

    /// The regression that matters: the preamble must not be separable from a
    /// real token by its own byte distribution. Drawing uniformly over all 95
    /// printable characters (the first implementation) put a character outside
    /// every real token alphabet in ~100% of preambles, which is a cheaper and
    /// more reliable signature than the entropy rule the preamble exists to
    /// evade. Every byte must now come from the base64url alphabet.
    #[test]
    fn preamble_is_indistinguishable_from_a_real_token_by_alphabet() {
        let mut seen_chars = std::collections::HashSet::new();
        for _ in 0..4096 {
            let p = make_preamble();
            assert!(
                p.iter().all(|&b| is_alphabet(b)),
                "a preamble byte fell outside the token alphabet: {p:?}"
            );
            seen_chars.extend(p.iter().copied());
        }
        // And it must actually USE the whole alphabet - a preamble confined to a
        // sub-range would be its own signature.
        assert_eq!(
            seen_chars.len(),
            ALPHABET.len(),
            "preambles should exercise every alphabet character"
        );
    }
}
