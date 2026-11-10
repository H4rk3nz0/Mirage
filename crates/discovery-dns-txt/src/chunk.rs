//! TXT-record chunk codec.
//!
//! A DNS TXT `RRset` can carry multiple "character strings," each
//! capped at 255 bytes on the wire (RFC 1035 §3.3.14). A Mirage
//! announcement after sealing is ~800 bytes; it must be split
//! across several strings.
//!
//! # Cover shape (finding #7)
//!
//! An earlier revision shaped the split as a **DKIM public-key record**
//! (`v=DKIM1; k=rsa; p=<base64>`). That was withdrawn: a real DKIM key lives
//! ONLY at `<selector>._domainkey.<domain>`, but Mirage publishes at
//! `<hex(info_hash)>.<apex>` with no `_domainkey` label. A censor can then
//! filter passive-DNS for "TXT contains `v=DKIM1` whose owner name is NOT under
//! `_domainkey`" - a near-zero-false-positive rule that enumerates every Mirage
//! rendezvous name. A second tell: a real DKIM `p=` value base64-decodes to a
//! DER `SubjectPublicKeyInfo` (leading `0x30 0x82`), whereas Mirage's decodes to a
//! sealed `nonce||ct||tag` whose first byte is random.
//!
//! We therefore claim NO schema. The whole sealed blob is emitted as plain
//! standard (padded) base64, spilled across concatenated <=255-byte TXT
//! character-strings:
//!
//! ```text
//!   string 1:  "<base64...>"
//!   string 2:  "<base64...>"   (continuation, in order)
//!   ...
//! ```
//!
//! With no schema assertion there is no owner-name/location rule to be
//! inconsistent with, and the decoded payload's leading bytes no longer have to
//! imitate DER. An opaque base64 TXT at a random-looking label is
//! indistinguishable from the large population of domain-verification /
//! challenge tokens. Reassembly relies on within-RRset string ORDER (which
//! resolvers preserve), so there is no `<idx>/<total>` header. The seal layer
//! above authenticates the reassembled blob, so a foreign TXT record that
//! happens to sit at the same name decodes to bytes the seal rejects.
//!
//! # Size math
//!
//! - 255 B TXT max per string; every string is pure base64 now (no prefix).
//! - `MAX_CHUNKS` (99) strings x ~255 B base64 = ~25 KB base64 -> the raw cap is
//!   `MAX_REASSEMBLED_BYTES`, comfortably above the ~800 B announcement.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// RFC 1035 §3.3.14 per-string cap.
pub const MAX_TXT_STRING_LEN: usize = 255;

/// Maximum chunks per announcement. 99 fits in two decimal digits;
/// trying to encode/decode past it is a wire-format error.
pub const MAX_CHUNKS: u16 = 99;

/// Hard cap on the reassembled blob length - 99 chunks x 180 B.
pub const MAX_REASSEMBLED_BYTES: usize = MAX_CHUNKS as usize * 180;

/// Errors from the chunk codec.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChunkError {
    /// Raw blob is larger than `MAX_CHUNKS` can hold.
    #[error("blob too large: {0} bytes exceeds cap {1}")]
    BlobTooLarge(usize, usize),
    /// A chunk TXT string couldn't be parsed (missing header, bad
    /// index, invalid base64, etc.).
    #[error("chunk parse: {0}")]
    Parse(&'static str),
    /// Chunks disagreed on `total`, had duplicate indices, or were
    /// missing a required index.
    #[error("chunk set inconsistent: {0}")]
    Inconsistent(&'static str),
    /// Reassembled blob exceeded the cap.
    #[error("reassembled blob over cap")]
    Oversize,
    /// The blob (to encode) or the decoded value was empty. Mirage never
    /// emits a 0-byte announcement, so an empty value is out of the codec's
    /// domain on both ends - this keeps the encode/decode roundtrip total.
    #[error("empty blob")]
    Empty,
}

/// Split `blob` into TXT-string chunks. Returns the ordered
/// sequence of strings an operator publishes as one TXT `RRset`.
pub fn blob_to_chunks(blob: &[u8]) -> Result<Vec<String>, ChunkError> {
    if blob.is_empty() {
        // A 0-byte announcement is never valid; reject it here so we never emit
        // an artifact `chunks_to_blob` would reject, keeping the roundtrip total.
        return Err(ChunkError::Empty);
    }
    if blob.len() > MAX_REASSEMBLED_BYTES {
        return Err(ChunkError::BlobTooLarge(blob.len(), MAX_REASSEMBLED_BYTES));
    }
    // Encode the WHOLE blob once as standard (padded) base64, then spill it
    // across <=255-byte TXT character-strings in order. No schema prefix and no
    // per-chunk header: the record claims nothing (finding #7) and reassembly is
    // by RRset string ORDER, which resolvers preserve.
    let b64 = STANDARD.encode(blob);
    let b64 = b64.as_bytes(); // ASCII, so byte slicing == char slicing
    let mut out = Vec::new();
    let mut rest = b64;
    while !rest.is_empty() {
        let take = rest.len().min(MAX_TXT_STRING_LEN);
        let (head, tail) = rest.split_at(take);
        // `head` is a slice of ASCII base64, always valid UTF-8.
        out.push(std::str::from_utf8(head).unwrap().to_string());
        rest = tail;
    }
    if out.len() > MAX_CHUNKS as usize {
        return Err(ChunkError::BlobTooLarge(blob.len(), MAX_REASSEMBLED_BYTES));
    }
    Ok(out)
}

/// Parse + reassemble a set of TXT strings into the original blob.
///
/// Input ORDER IS significant: the strings are concatenated in the order given,
/// matching how [`blob_to_chunks`] spills the base64 across the `RRset` (no
/// per-chunk index header is emitted - `RRset` string order is wire-significant
/// and preserved by resolvers). There is no schema prefix to check (finding #7);
/// a foreign TXT record that isn't our announcement either fails to base64-decode
/// here or decodes to bytes the seal layer above rejects.
pub fn chunks_to_blob(chunks: &[String]) -> Result<Vec<u8>, ChunkError> {
    if chunks.len() > MAX_CHUNKS as usize {
        return Err(ChunkError::Parse("too many TXT strings"));
    }
    // Concatenate ALL strings in order - order within a TXT RRset is
    // wire-significant and preserved by resolvers - then base64-decode.
    let mut joined = String::new();
    for s in chunks {
        if s.len() > MAX_TXT_STRING_LEN {
            return Err(ChunkError::Parse("chunk exceeds 255 B"));
        }
        joined.push_str(s);
    }
    // Tolerate folding whitespace a zone tool might insert (our own emit never
    // inserts any). STANDARD base64 with padding.
    let cleaned: String = joined.split_whitespace().collect();
    if cleaned.is_empty() {
        return Err(ChunkError::Empty);
    }
    let out = STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|_| ChunkError::Parse("base64 decode failed"))?;
    if out.len() > MAX_REASSEMBLED_BYTES {
        return Err(ChunkError::Oversize);
    }
    if out.is_empty() {
        return Err(ChunkError::Empty);
    }
    Ok(out)
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small() {
        let blob = b"hello mirage dns";
        let chunks = blob_to_chunks(blob).unwrap();
        assert_eq!(chunks.len(), 1, "small blob = single chunk");
        let back = chunks_to_blob(&chunks).unwrap();
        assert_eq!(back, blob);
    }

    #[test]
    fn roundtrip_multi_chunk() {
        let blob: Vec<u8> = (0..800).map(|i| (i % 251) as u8).collect();
        let chunks = blob_to_chunks(&blob).unwrap();
        assert!(chunks.len() > 1, "800 B = multi-chunk");
        // Order is wire-significant (base64 spill), preserved on reassembly.
        let back = chunks_to_blob(&chunks).unwrap();
        assert_eq!(back, blob);
    }

    #[test]
    fn chunks_are_opaque_base64_no_schema() {
        // finding #7: the split claims NO schema - every string is pure standard
        // base64, and none carries a `v=DKIM1` (or any) tag list.
        let chunks = blob_to_chunks(b"forty-two bytes of sealed announcement..").unwrap();
        for c in &chunks {
            assert!(!c.starts_with("v=DKIM1"), "must not claim a DKIM schema");
            assert!(
                c.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='),
                "chunk must be pure standard-base64: {c}"
            );
        }
    }

    #[test]
    fn reversed_order_does_not_roundtrip() {
        // Reassembly is order-dependent: a TXT RRset's string order is
        // wire-significant. Reversing the strings must not reproduce the blob
        // (it either fails to base64-decode or decodes to different bytes).
        let blob: Vec<u8> = (0..800).map(|i| (i % 251) as u8).collect();
        let mut chunks = blob_to_chunks(&blob).unwrap();
        chunks.reverse();
        match chunks_to_blob(&chunks) {
            Ok(back) => assert_ne!(back, blob, "reversed order must not reproduce the blob"),
            Err(_) => {} // also acceptable: reversed base64 is undecodable
        }
    }

    #[test]
    fn chunk_strings_fit_txt_cap() {
        let blob: Vec<u8> = (0..MAX_REASSEMBLED_BYTES / 2).map(|i| i as u8).collect();
        let chunks = blob_to_chunks(&blob).unwrap();
        for c in &chunks {
            assert!(c.len() <= MAX_TXT_STRING_LEN, "chunk too long: {}", c.len());
        }
    }

    #[test]
    fn rejects_blob_over_cap() {
        let big = vec![0u8; MAX_REASSEMBLED_BYTES + 1];
        let err = blob_to_chunks(&big).unwrap_err();
        assert!(matches!(err, ChunkError::BlobTooLarge(_, _)));
    }

    #[test]
    fn empty_set_returns_empty() {
        let err = chunks_to_blob(&[]).unwrap_err();
        assert!(matches!(err, ChunkError::Empty));
    }

    #[test]
    fn foreign_txt_record_rejected() {
        // A foreign TXT record (e.g. a real SPF) is not valid base64 (spaces,
        // colons, etc.), so it fails to decode rather than being mistaken for
        // ours. (Any that DID decode would still be rejected by the seal layer.)
        let chunks = vec!["v=spf1 include:_spf.example.com -all".to_string()];
        let err = chunks_to_blob(&chunks).unwrap_err();
        assert!(matches!(err, ChunkError::Parse(_)), "got: {err:?}");
    }

    #[test]
    fn bad_base64_rejected() {
        let chunks = vec!["not_valid_base64_!!".to_string()];
        let err = chunks_to_blob(&chunks).unwrap_err();
        assert!(matches!(err, ChunkError::Parse(_)), "got: {err:?}");
    }

    #[test]
    fn whitespace_only_returns_empty() {
        // A set of empty/whitespace-only strings has no base64 payload -> Empty.
        let chunks = vec!["   ".to_string(), String::new()];
        let err = chunks_to_blob(&chunks).unwrap_err();
        assert!(matches!(err, ChunkError::Empty), "got: {err:?}");
    }

    #[test]
    fn empty_blob_rejected_at_encode() {
        // The encode/decode roundtrip is total: we never PRODUCE an artifact the
        // decoder would choke on, because a 0-byte blob is refused up front.
        assert!(matches!(blob_to_chunks(&[]), Err(ChunkError::Empty)));
    }

    #[test]
    fn fuzz_chunk_parser_never_panics() {
        use proptest::prelude::*;
        proptest!(ProptestConfig::with_cases(256), |(
            strs in prop::collection::vec(".{0,255}", 0..16),
        )| {
            let _ = chunks_to_blob(&strs);
        });
    }

    #[test]
    fn fuzz_roundtrip_random_blobs() {
        use proptest::prelude::*;
        // Domain is NON-EMPTY blobs: a 0-byte announcement is out of the codec's
        // domain (blob_to_chunks rejects it with ChunkError::Empty to keep the
        // roundtrip total - see `empty_blob_rejected_at_encode`). Draw 1..2000 so
        // the empty case, which is asserted separately, doesn't panic the unwrap.
        proptest!(ProptestConfig::with_cases(64), |(
            blob in prop::collection::vec(any::<u8>(), 1..2000),
        )| {
            let chunks = blob_to_chunks(&blob).unwrap();
            let back = chunks_to_blob(&chunks).unwrap();
            prop_assert_eq!(back, blob);
        });
    }
}
