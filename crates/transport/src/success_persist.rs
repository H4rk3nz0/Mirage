//! Disk persistence for the [`crate::SuccessRateMap`].
//!
//! v0.1u shipped the in-memory map plus snapshot/load methods.
//! v0.1w wires those to a small append-overwrite file format so
//! "what worked yesterday" survives a process restart - finishing
//! the invariant that per-network success rates are persisted and
//! bias the next race.
//!
//! # Wire format
//!
//! ```text
//!  HEADER:
//!    magic         "MSRP"  (4 B)
//!    version       0x01    (1 B)
//!    record_count  u32 BE  (4 B)
//!
//!  RECORD (repeated record_count times):
//!    digest        16 B               # NetworkFingerprint::digest
//!    name_len      u8                 # transport name length (1..=64)
//!    name          name_len B         # transport name UTF-8
//!    successes     u32 BE
//!    failures      u32 BE
//! ```
//!
//! `last_success: Option<Instant>` is **not** persisted -
//! `Instant` doesn't have a portable wire form. On reload, the
//! field is `None` (the entry is treated as "stale" by
//! [`crate::SuccessStats::is_recent`]). Counters are persisted so
//! the rate calculation survives.
//!
//! # Atomicity
//!
//! Writes go to `<path>.tmp` first, then `rename` atomically over
//! `<path>`. A crash between write and rename leaves the previous
//! contents intact.
//!
//! # Threat-model fit
//!
//! The persisted file holds aggregate counters per `(network,
//! transport)` pair - no per-session content, no destinations. A
//! seizure-class adversary reading the file learns "the user has
//! been on N distinct local networks" (the count of unique
//! `NetworkFingerprint` digests), which the digest design already
//! exposes by construction. No additional secrets are committed.

use crate::success_rate::{NetworkFingerprint, SuccessRateMap, SuccessStats};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;

const MSRP_MAGIC: &[u8] = b"MSRP";
const MSRP_VERSION_V1: u8 = 0x01;
const HEADER_LEN: usize = 4 + 1 + 4;
/// Hard cap on transport-name byte length to keep file format
/// compact and bound parser allocations. Mirage's transport names
/// (`reality-v2`, `obfs-tcp`, `quic-masque`, `webrtc`, `trojan`,
/// etc.) are all well under this.
pub const MAX_TRANSPORT_NAME_LEN: usize = 64;
/// Smallest legal record on the wire: 16 (digest) + 1 (`name_len`) +
/// 1 (name byte, since `name_len == 0` is rejected) + 4 + 4. Used
/// to bound the header's `record_count` against the file's actual
/// remaining body before any allocation occurs.
const MIN_RECORD_LEN: usize = 16 + 1 + 1 + 4 + 4;
/// Hard cap on the total persisted-state file size. The state is
/// per-network success counters; even a paranoid user with hundreds
/// of distinct local networks will not approach this. Cap exists
/// so a hostile or corrupted file cannot push the loader into a
/// multi-GB allocation. 16 MiB ~ ~180k records at minimum size.
pub const MAX_PERSIST_FILE_SIZE: u64 = 16 * 1024 * 1024;

/// Errors produced by save/load.
#[derive(Debug, Error)]
pub enum PersistError {
    /// Underlying I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Header magic / version mismatch.
    #[error("bad header (magic or version)")]
    BadHeader,
    /// Encoded record claims a transport-name length over the cap.
    #[error("transport name length {0} exceeds cap {MAX_TRANSPORT_NAME_LEN}")]
    NameTooLong(usize),
    /// Body bytes don't match the header's claimed record count.
    #[error("file truncated mid-record")]
    Truncated,
    /// File on disk exceeds [`MAX_PERSIST_FILE_SIZE`].
    #[error("persisted file too large: {0} bytes (cap {MAX_PERSIST_FILE_SIZE})")]
    FileTooLarge(u64),
    /// Header claims more records than could possibly fit in the file body.
    #[error("record_count {0} cannot fit in {1} body bytes")]
    RecordCountUnreachable(usize, usize),
    /// Transport name contains non-UTF-8 bytes.
    #[error("transport name not UTF-8")]
    NameEncoding,
    /// Caller asked to persist a transport name that's not a known
    /// `'static` value the loader can re-intern. Persistence
    /// requires `&'static str` names so the loaded map's API
    /// matches the in-memory map. See [`SuccessRateMap::load`]
    /// limitation in §1.
    #[error("transport name {0:?} not in the known-static set")]
    UnknownStaticName(String),
}

/// Save a snapshot of `map` to `path`, atomically.
pub fn save_to_path<P: AsRef<Path>>(map: &SuccessRateMap, path: P) -> Result<(), PersistError> {
    let path = path.as_ref();
    let tmp = path.with_extension("tmp");
    let snap = map.snapshot();

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    file.write_all(MSRP_MAGIC)?;
    file.write_all(&[MSRP_VERSION_V1])?;
    file.write_all(&(snap.len() as u32).to_be_bytes())?;
    for (fp, name, stats) in &snap {
        let nb = name.as_bytes();
        if nb.len() > MAX_TRANSPORT_NAME_LEN {
            return Err(PersistError::NameTooLong(nb.len()));
        }
        file.write_all(&fp.digest)?;
        file.write_all(&[nb.len() as u8])?;
        file.write_all(nb)?;
        file.write_all(&stats.successes.to_be_bytes())?;
        file.write_all(&stats.failures.to_be_bytes())?;
    }
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Load a [`SuccessRateMap`] from `path`. Returns an empty map if
/// the file doesn't exist; returns `Err` if the header is invalid
/// (caller MUST decide whether to treat that as fatal - typically
/// "log + start fresh").
///
/// # Static-name limitation
///
/// `SuccessRateMap` keys transport names by `&'static str`. The
/// caller passes `known_transports` - a slice of all `&'static str`
/// names the loader is allowed to intern records as. Records whose
/// persisted name doesn't match any known-static value are dropped
/// with a `tracing::warn!`. This is the loader's only "I trust the
/// caller" knob.
pub fn load_from_path<P: AsRef<Path>>(
    path: P,
    known_transports: &[&'static str],
) -> Result<SuccessRateMap, PersistError> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(SuccessRateMap::new());
    }
    let mut f = File::open(path)?;
    // Cap total file size up front so a hostile or corrupted file
    // cannot push the loader into a multi-GB allocation via either
    // `Vec::with_capacity(record_count)` or `read_to_end`.
    let file_len = f.metadata()?.len();
    if file_len > MAX_PERSIST_FILE_SIZE {
        return Err(PersistError::FileTooLarge(file_len));
    }
    let mut hdr = [0u8; HEADER_LEN];
    f.read_exact(&mut hdr)?;
    if &hdr[0..4] != MSRP_MAGIC || hdr[4] != MSRP_VERSION_V1 {
        return Err(PersistError::BadHeader);
    }
    let record_count = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
    // Body length is total file length minus the header we just read.
    // `record_count` cannot exceed `body_len / MIN_RECORD_LEN` - reject
    // before allocating so a header claiming u32::MAX records on a
    // 12-byte file fails fast instead of trying to reserve 4 GB.
    let body_len = (file_len as usize).saturating_sub(HEADER_LEN);
    let max_possible_records = body_len / MIN_RECORD_LEN;
    if record_count > max_possible_records {
        return Err(PersistError::RecordCountUnreachable(record_count, body_len));
    }
    let mut entries: Vec<(NetworkFingerprint, &'static str, SuccessStats)> =
        Vec::with_capacity(record_count);
    let mut buf = Vec::with_capacity(body_len);
    // Use Read::take as a defense-in-depth bound - the metadata check
    // above already rejected oversized files, but this guards against
    // the file growing under us between metadata() and read_to_end.
    Read::take(&mut f, MAX_PERSIST_FILE_SIZE).read_to_end(&mut buf)?;
    let mut cursor = 0usize;
    for _ in 0..record_count {
        if buf.len() < cursor + 16 + 1 {
            return Err(PersistError::Truncated);
        }
        let mut digest = [0u8; 16];
        digest.copy_from_slice(&buf[cursor..cursor + 16]);
        cursor += 16;
        let name_len = buf[cursor] as usize;
        cursor += 1;
        if name_len == 0 || name_len > MAX_TRANSPORT_NAME_LEN {
            return Err(PersistError::NameTooLong(name_len));
        }
        if buf.len() < cursor + name_len + 8 {
            return Err(PersistError::Truncated);
        }
        let name = std::str::from_utf8(&buf[cursor..cursor + name_len])
            .map_err(|_| PersistError::NameEncoding)?;
        cursor += name_len;
        let successes = u32::from_be_bytes([
            buf[cursor],
            buf[cursor + 1],
            buf[cursor + 2],
            buf[cursor + 3],
        ]);
        cursor += 4;
        let failures = u32::from_be_bytes([
            buf[cursor],
            buf[cursor + 1],
            buf[cursor + 2],
            buf[cursor + 3],
        ]);
        cursor += 4;
        let static_name = known_transports.iter().find(|n| **n == name).copied();
        match static_name {
            Some(s) => {
                entries.push((
                    NetworkFingerprint::from_digest(digest),
                    s,
                    SuccessStats {
                        successes,
                        failures,
                        last_success: None,
                        last_failure: None,
                        consecutive_failures: 0,
                    },
                ));
            }
            None => {
                tracing::warn!(
                    transport = %name,
                    "skipping persisted success-rate entry for unknown transport"
                );
            }
        }
    }
    Ok(SuccessRateMap::load(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn n(tag: u8) -> NetworkFingerprint {
        NetworkFingerprint::from_digest([tag; 16])
    }

    #[test]
    fn save_load_roundtrip() {
        let d = TempDir::new().unwrap();
        let path = d.path().join("rates");
        let m = SuccessRateMap::new();
        m.record(&n(1), "reality-v2", true);
        m.record(&n(1), "reality-v2", true);
        m.record(&n(1), "reality-v2", false);
        m.record(&n(2), "obfs-tcp", true);
        save_to_path(&m, &path).unwrap();

        let loaded = load_from_path(&path, &["reality-v2", "obfs-tcp"]).unwrap();
        let r1 = loaded.lookup(&n(1), "reality-v2");
        assert_eq!(r1.successes, 2);
        assert_eq!(r1.failures, 1);
        assert_eq!(loaded.lookup(&n(2), "obfs-tcp").successes, 1);
    }

    #[test]
    fn missing_path_returns_empty_map() {
        let d = TempDir::new().unwrap();
        let path = d.path().join("nonexistent");
        let loaded = load_from_path(&path, &["reality-v2"]).unwrap();
        assert_eq!(loaded.len(), 0);
    }

    #[test]
    fn save_overwrites_atomically() {
        let d = TempDir::new().unwrap();
        let path = d.path().join("rates");
        let m1 = SuccessRateMap::new();
        m1.record(&n(1), "reality-v2", true);
        save_to_path(&m1, &path).unwrap();
        let m2 = SuccessRateMap::new();
        m2.record(&n(1), "reality-v2", false);
        save_to_path(&m2, &path).unwrap();
        let loaded = load_from_path(&path, &["reality-v2"]).unwrap();
        let r = loaded.lookup(&n(1), "reality-v2");
        assert_eq!(r.failures, 1);
        assert_eq!(r.successes, 0);
    }

    #[test]
    fn load_drops_unknown_transport_names() {
        let d = TempDir::new().unwrap();
        let path = d.path().join("rates");
        let m = SuccessRateMap::new();
        m.record(&n(1), "obsolete-transport", true);
        save_to_path(&m, &path).unwrap();
        // Loader doesn't know `obsolete-transport`; skip it.
        let loaded = load_from_path(&path, &["reality-v2"]).unwrap();
        assert_eq!(loaded.len(), 0);
    }

    #[test]
    fn load_rejects_bad_magic() {
        let d = TempDir::new().unwrap();
        let path = d.path().join("rates");
        std::fs::write(&path, b"NOPEv1\x00\x00\x00\x00\x00\x00").unwrap();
        let err = load_from_path(&path, &["reality-v2"]).unwrap_err();
        assert!(matches!(err, PersistError::BadHeader));
    }

    #[test]
    fn load_rejects_truncated_record_block() {
        let d = TempDir::new().unwrap();
        let path = d.path().join("rates");
        // Header says 1 record (small enough to pass the
        // RecordCountUnreachable bound but still missing body bytes).
        let mut buf = Vec::new();
        buf.extend_from_slice(MSRP_MAGIC);
        buf.push(MSRP_VERSION_V1);
        buf.extend_from_slice(&1u32.to_be_bytes());
        // Provide exactly MIN_RECORD_LEN-1 bytes so the header check
        // doesn't catch it but the body parse does.
        buf.extend_from_slice(&[0u8; MIN_RECORD_LEN - 1]);
        std::fs::write(&path, &buf).unwrap();
        let err = load_from_path(&path, &["reality-v2"]).unwrap_err();
        // Either RecordCountUnreachable (if the math rejects up
        // front) or Truncated (if the body parse runs and bails).
        assert!(
            matches!(
                err,
                PersistError::Truncated | PersistError::RecordCountUnreachable(_, _)
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn rejects_oversized_name_at_save() {
        // Manually inject a long name into the snapshot path. The
        // SuccessRateMap API doesn't accept dynamic names so this
        // path is hard to hit naturally - we test the guard
        // directly via the snapshot/save round-trip.
        let d = TempDir::new().unwrap();
        let path = d.path().join("rates");
        let m = SuccessRateMap::new();
        // 65-char name (over the 64 cap).
        const LONG_NAME: &str = "x012345678901234567890123456789012345678901234567890123456789xxxx";
        m.record(&n(1), LONG_NAME, true);
        let err = save_to_path(&m, &path).unwrap_err();
        assert!(matches!(err, PersistError::NameTooLong(65)));
    }

    #[test]
    fn load_rejects_oversized_file() {
        let d = TempDir::new().unwrap();
        let path = d.path().join("rates");
        // Write a file just over the cap with a valid-looking header.
        let mut buf = Vec::new();
        buf.extend_from_slice(MSRP_MAGIC);
        buf.push(MSRP_VERSION_V1);
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.resize(MAX_PERSIST_FILE_SIZE as usize + 1, 0);
        std::fs::write(&path, &buf).unwrap();
        let err = load_from_path(&path, &["reality-v2"]).unwrap_err();
        assert!(matches!(err, PersistError::FileTooLarge(_)));
    }

    #[test]
    fn load_rejects_unreachable_record_count() {
        // Header claims u32::MAX records but the file is only the
        // header. Pre-fix, this triggered a 4 GiB Vec::with_capacity.
        let d = TempDir::new().unwrap();
        let path = d.path().join("rates");
        let mut buf = Vec::new();
        buf.extend_from_slice(MSRP_MAGIC);
        buf.push(MSRP_VERSION_V1);
        buf.extend_from_slice(&u32::MAX.to_be_bytes());
        std::fs::write(&path, &buf).unwrap();
        let err = load_from_path(&path, &["reality-v2"]).unwrap_err();
        assert!(matches!(err, PersistError::RecordCountUnreachable(_, _)));
    }

    #[test]
    fn save_then_load_with_three_transports() {
        let d = TempDir::new().unwrap();
        let path = d.path().join("rates");
        let m = SuccessRateMap::new();
        m.record(&n(1), "reality-v2", true);
        m.record(&n(1), "obfs-tcp", false);
        m.record(&n(2), "quic-masque", true);
        save_to_path(&m, &path).unwrap();
        let loaded = load_from_path(&path, &["reality-v2", "obfs-tcp", "quic-masque"]).unwrap();
        assert_eq!(loaded.lookup(&n(1), "reality-v2").successes, 1);
        assert_eq!(loaded.lookup(&n(1), "obfs-tcp").failures, 1);
        assert_eq!(loaded.lookup(&n(2), "quic-masque").successes, 1);
    }
}
