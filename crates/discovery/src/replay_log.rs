//! Append-only on-disk log backing [`crate::replay::SyncReplaySet`].
//!
//! # Problem
//!
//! A bridge's [`crate::replay::ReplaySet`] is in-memory. On restart
//! (crash, deployment, host reboot) the set is empty and every
//! previously-accepted capability token whose expiry hasn't passed
//! becomes replayable again. For invite-bound tokens this reopens a
//! window proportional to the token's TTL (v0.1 default: 24 h).
//! AUDIT item A14b.
//!
//! # Solution
//!
//! Back the set with an append-only file. Each accepted
//! `check_and_insert` writes one 40-byte record:
//!
//! ```text
//!   [u8; 32] token_id
//!   u64 BE   expires_at
//! ```
//!
//! On bridge startup, [`PersistentReplayLog::load`] scans the file,
//! drops records whose `expires_at` is already past `now_unix`, and
//! returns the surviving set. Expired records on disk are dropped on
//! the next **compaction**: the log is rewritten with only unexpired
//! entries. Compaction is triggered manually by the caller (bridge
//! startup) - a background compaction loop can be added later.
//!
//! # Durability tradeoff
//!
//! The writer uses a `BufWriter` for throughput. Every successful
//! `append` **flushes** the buffer to the OS (so a userspace crash
//! loses nothing), and optionally `fsync`s the file handle (so a
//! kernel crash / power loss loses nothing). `fsync` costs ~1 ms per
//! handshake and is opt-in via config; default is "flush only" -
//! acceptable for v0.1 because a torn record at the tail simply
//! omits that one accept from the persistent set on reload, and the
//! token is still single-use by virtue of the client's session
//! having already consumed it on the wire.
//!
//! # Format
//!
//! 8-byte header: `"MRRL\x01\x00\x00\x00"` (magic `MRRL` + version 1 +
//! 3 reserved bytes). Then repeated 40-byte records as above.
//!
//! Torn-write handling: the loader stops at the first record whose
//! read returns fewer than 40 bytes. The partial tail is discarded
//! on the next compaction.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// File magic: `MRRL` = Mirage Replay Log.
pub const MRRL_MAGIC: &[u8; 4] = b"MRRL";
/// Current file-format version.
pub const MRRL_VERSION: u8 = 0x01;
/// Fixed header length (magic + version + 3 reserved).
pub const MRRL_HEADER_LEN: usize = 8;
/// Fixed record length: 32 B token_id + 8 B expires_at.
pub const MRRL_RECORD_LEN: usize = 40;

/// Error surface for log operations.
#[derive(Debug, thiserror::Error)]
pub enum ReplayLogError {
    /// Underlying I/O failure (open, read, write, seek, fsync, rename).
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// File begins with something other than the expected `MRRL` header.
    #[error("unrecognized header: expected MRRL magic + version 1")]
    BadHeader,
}

/// An append-only on-disk log of accepted replay-set entries.
///
/// One instance per bridge. The [`crate::replay::SyncReplaySet`] ties
/// to the log by calling [`Self::append`] on every accepted insert.
pub struct PersistentReplayLog {
    path: PathBuf,
    writer: BufWriter<File>,
    /// Whether to `fsync` after every append. False by default;
    /// True trades ~1 ms/handshake for kernel-crash durability.
    fsync_every_write: bool,
}

impl PersistentReplayLog {
    /// Open (creating if absent) the log at `path`. If the file
    /// exists, its header is validated - a mismatch yields
    /// `BadHeader` rather than silently overwriting, so an operator
    /// who points the bridge at the wrong file learns about it.
    pub fn open<P: AsRef<Path>>(path: P, fsync_every_write: bool) -> Result<Self, ReplayLogError> {
        let path = path.as_ref().to_path_buf();
        let already_exists = path.exists();
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Preserve an existing log: when the file is already there we read
            // and verify its header + replay its entries below, so we must NOT
            // truncate on open. (Explicit per clippy::suspicious_open_options.)
            .truncate(false)
            .open(&path)?;
        if already_exists {
            // Read and verify the header.
            let mut hdr = [0u8; MRRL_HEADER_LEN];
            let n = f.read(&mut hdr)?;
            if n == 0 {
                // Empty file: treat as freshly-created, write header.
                write_header(&mut f)?;
            } else if n < MRRL_HEADER_LEN || &hdr[0..4] != MRRL_MAGIC || hdr[4] != MRRL_VERSION {
                return Err(ReplayLogError::BadHeader);
            }
        } else {
            write_header(&mut f)?;
        }
        // Position at end for appends. If the file ended mid-record
        // (40-byte boundary not respected, e.g., ENOSPC during a
        // previous append's BufWriter flush), truncate to the last
        // whole-record boundary BEFORE appending. Without this, a
        // subsequent append would land after the torn tail and the
        // next loader would silently drop every record after the
        // torn boundary (loader's read-loop stops at first short
        // read). Closes the audit-flagged "hot-append torn tail"
        // window outside startup compaction.
        let end = f.seek(SeekFrom::End(0))?;
        if end > MRRL_HEADER_LEN as u64 {
            let body = end - MRRL_HEADER_LEN as u64;
            let remainder = body % MRRL_RECORD_LEN as u64;
            if remainder != 0 {
                let new_len = end - remainder;
                f.set_len(new_len)?;
                f.seek(SeekFrom::End(0))?;
            }
        }
        Ok(Self {
            path,
            writer: BufWriter::new(f),
            fsync_every_write,
        })
    }

    /// Append one record. Flushes the writer (userspace durability)
    /// and, if configured, `fsync`s the underlying handle (kernel /
    /// power-loss durability).
    pub fn append(&mut self, token_id: &[u8; 32], expires_at: u64) -> Result<(), ReplayLogError> {
        // RT #20: build the WHOLE record and write it in one `write_all`,
        // rather than two separate writes (token then expiry). A partial
        // flush between the two (e.g. ENOSPC) left a 32-byte torn tail that
        // mis-aligns the loader and silently drops that token's single-use
        // record after restart - reopening re-redemption. On ANY error, also
        // realign the file to the last whole-record boundary immediately so a
        // torn partial cannot desync subsequent appends; the caller treats
        // the Err as "refuse the operation" (it does not accept the token).
        let mut record = [0u8; MRRL_RECORD_LEN];
        record[0..32].copy_from_slice(token_id);
        record[32..MRRL_RECORD_LEN].copy_from_slice(&expires_at.to_be_bytes());
        if let Err(e) = self.write_record(&record) {
            self.realign_to_record_boundary();
            return Err(e);
        }
        Ok(())
    }

    fn write_record(&mut self, record: &[u8; MRRL_RECORD_LEN]) -> Result<(), ReplayLogError> {
        self.writer.write_all(record)?;
        self.writer.flush()?;
        if self.fsync_every_write {
            self.writer.get_ref().sync_data()?;
        }
        Ok(())
    }

    /// Best-effort: truncate any torn partial record at the tail back to the
    /// last whole-record boundary so the loader (and subsequent appends) stay
    /// aligned. Called after a failed append.
    fn realign_to_record_boundary(&mut self) {
        let _ = self.writer.flush();
        let f = self.writer.get_mut();
        if let Ok(end) = f.seek(SeekFrom::End(0)) {
            if end > MRRL_HEADER_LEN as u64 {
                let remainder = (end - MRRL_HEADER_LEN as u64) % MRRL_RECORD_LEN as u64;
                if remainder != 0 {
                    let _ = f.set_len(end - remainder);
                    let _ = f.seek(SeekFrom::End(0));
                }
            }
        }
    }

    /// Load every unexpired entry from the log into a `Vec<(token_id,
    /// expires_at)>`. Entries whose `expires_at < now_unix` are
    /// dropped. A torn tail record (fewer than 40 bytes) is also
    /// silently dropped; compaction will clean it on the next rewrite.
    pub fn load<P: AsRef<Path>>(
        path: P,
        now_unix: u64,
    ) -> Result<Vec<([u8; 32], u64)>, ReplayLogError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut f = File::open(path)?;
        let mut hdr = [0u8; MRRL_HEADER_LEN];
        let n = f.read(&mut hdr)?;
        if n == 0 {
            return Ok(Vec::new()); // empty file, no header yet
        }
        if n < MRRL_HEADER_LEN || &hdr[0..4] != MRRL_MAGIC || hdr[4] != MRRL_VERSION {
            return Err(ReplayLogError::BadHeader);
        }
        let mut out = Vec::new();
        let mut rec = [0u8; MRRL_RECORD_LEN];
        loop {
            match f.read(&mut rec) {
                Ok(0) => break,
                Ok(n) if n < MRRL_RECORD_LEN => {
                    // Torn tail; stop. Compaction will drop it.
                    break;
                }
                Ok(_) => {
                    let mut token_id = [0u8; 32];
                    token_id.copy_from_slice(&rec[0..32]);
                    let expires_at = u64::from_be_bytes(rec[32..40].try_into().unwrap());
                    if expires_at >= now_unix {
                        out.push((token_id, expires_at));
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(out)
    }

    /// Rewrite the log keeping only the provided `(token_id,
    /// expires_at)` entries. Atomic: writes to a sibling `.compact`
    /// file, `fsync`s it, then renames over the original.
    ///
    /// The caller typically invokes this at startup after
    /// [`Self::load`], so the persistent set stays bounded even if
    /// the bridge has been running for months.
    pub fn compact<P: AsRef<Path>>(
        path: P,
        entries: &[([u8; 32], u64)],
    ) -> Result<(), ReplayLogError> {
        let path = path.as_ref().to_path_buf();
        let mut compact_path = path.clone();
        let mut file_name = compact_path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        file_name.push(".compact");
        compact_path.set_file_name(file_name);

        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&compact_path)?;
            write_header(&mut f)?;
            let mut bw = BufWriter::new(&mut f);
            for (tid, exp) in entries {
                bw.write_all(tid)?;
                bw.write_all(&exp.to_be_bytes())?;
            }
            bw.flush()?;
            drop(bw);
            f.sync_all()?;
        }
        // Atomic on POSIX: replace the live file.
        std::fs::rename(&compact_path, &path)?;
        Ok(())
    }

    /// Absolute path this log writes to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether this log is configured to `fsync` after every append.
    pub fn fsync_every_write(&self) -> bool {
        self.fsync_every_write
    }
}

fn write_header(f: &mut File) -> io::Result<()> {
    let mut hdr = [0u8; MRRL_HEADER_LEN];
    hdr[0..4].copy_from_slice(MRRL_MAGIC);
    hdr[4] = MRRL_VERSION;
    f.write_all(&hdr)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tid(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn open_creates_new_file_with_header() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("rl");
        let log = PersistentReplayLog::open(&p, false).unwrap();
        drop(log);
        let bytes = std::fs::read(&p).unwrap();
        assert_eq!(bytes.len(), MRRL_HEADER_LEN);
        assert_eq!(&bytes[0..4], MRRL_MAGIC);
        assert_eq!(bytes[4], MRRL_VERSION);
    }

    #[test]
    fn append_and_load_roundtrip() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("rl");
        {
            let mut log = PersistentReplayLog::open(&p, false).unwrap();
            log.append(&tid(1), 2_000).unwrap();
            log.append(&tid(2), 3_000).unwrap();
            log.append(&tid(3), 100).unwrap(); // will be expired at load time
        }
        let loaded = PersistentReplayLog::load(&p, 1_000).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.iter().any(|(t, _)| t == &tid(1)));
        assert!(loaded.iter().any(|(t, _)| t == &tid(2)));
        assert!(!loaded.iter().any(|(t, _)| t == &tid(3)));
    }

    #[test]
    fn load_rejects_wrong_magic() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("rl");
        std::fs::write(&p, b"NOPE\x01\x00\x00\x00").unwrap();
        let err = PersistentReplayLog::load(&p, 0).unwrap_err();
        assert!(matches!(err, ReplayLogError::BadHeader));
    }

    #[test]
    fn load_rejects_wrong_version() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("rl");
        std::fs::write(&p, b"MRRL\xFF\x00\x00\x00").unwrap();
        let err = PersistentReplayLog::load(&p, 0).unwrap_err();
        assert!(matches!(err, ReplayLogError::BadHeader));
    }

    #[test]
    fn torn_tail_record_is_ignored_on_load() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("rl");
        {
            let mut log = PersistentReplayLog::open(&p, false).unwrap();
            log.append(&tid(1), 2_000).unwrap();
        }
        // Append a torn half-record by hand.
        use std::fs::OpenOptions;
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(&[0xABu8; 19]).unwrap(); // < 40 bytes
        drop(f);
        // Loader survives and returns the one complete record.
        let loaded = PersistentReplayLog::load(&p, 1_000).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, tid(1));
    }

    #[test]
    fn open_truncates_torn_tail_so_subsequent_appends_are_recoverable() {
        // Audit-flagged regression: prior to the fix, a torn tail
        // (e.g. ENOSPC mid-flush) on disk would survive across
        // open(), and the next append would land AFTER the torn
        // bytes, leaving them embedded in the middle of the file.
        // The next loader stops at the first short read, silently
        // dropping every record after the torn boundary. After the
        // fix: open() truncates to the last whole-record boundary.
        let d = TempDir::new().unwrap();
        let p = d.path().join("rl");
        {
            let mut log = PersistentReplayLog::open(&p, false).unwrap();
            log.append(&tid(1), 2_000).unwrap();
        }
        // Inject a torn half-record.
        use std::fs::OpenOptions;
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(&[0xCDu8; 19]).unwrap();
        drop(f);
        // Reopen: the open() path must truncate the torn tail.
        let len_before_reopen = std::fs::metadata(&p).unwrap().len();
        assert!(
            len_before_reopen > (MRRL_HEADER_LEN + MRRL_RECORD_LEN) as u64,
            "torn tail present before reopen"
        );
        {
            let mut log = PersistentReplayLog::open(&p, false).unwrap();
            log.append(&tid(2), 3_000).unwrap();
        }
        // Both records must now be loadable.
        let loaded = PersistentReplayLog::load(&p, 1_000).unwrap();
        assert_eq!(loaded.len(), 2);
        let ids: Vec<_> = loaded.iter().map(|(t, _)| *t).collect();
        assert!(ids.contains(&tid(1)));
        assert!(ids.contains(&tid(2)));
    }

    #[test]
    fn compact_drops_expired_and_preserves_live() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("rl");
        {
            let mut log = PersistentReplayLog::open(&p, false).unwrap();
            log.append(&tid(1), 2_000).unwrap();
            log.append(&tid(2), 100).unwrap();
            log.append(&tid(3), 2_500).unwrap();
        }
        // Compact with only the live entries the loader returned.
        let loaded = PersistentReplayLog::load(&p, 1_000).unwrap();
        assert_eq!(loaded.len(), 2);
        PersistentReplayLog::compact(&p, &loaded).unwrap();

        // After compaction, the on-disk file is minimal.
        let bytes = std::fs::read(&p).unwrap();
        assert_eq!(bytes.len(), MRRL_HEADER_LEN + 2 * MRRL_RECORD_LEN);

        // Re-loading sees only the live entries.
        let loaded2 = PersistentReplayLog::load(&p, 1_000).unwrap();
        assert_eq!(loaded2.len(), 2);
    }

    #[test]
    fn append_persists_across_reopen() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("rl");
        {
            let mut log = PersistentReplayLog::open(&p, false).unwrap();
            log.append(&tid(7), 9_999).unwrap();
        }
        // Reopen and append more; earlier entry must survive.
        {
            let mut log = PersistentReplayLog::open(&p, false).unwrap();
            log.append(&tid(8), 9_999).unwrap();
        }
        let loaded = PersistentReplayLog::load(&p, 0).unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn fsync_mode_still_appends_correctly() {
        // Smoke test: the fsync-per-write branch shouldn't corrupt
        // anything. We can't easily simulate a power-loss crash in
        // a unit test, but we can verify the happy path.
        let d = TempDir::new().unwrap();
        let p = d.path().join("rl");
        {
            let mut log = PersistentReplayLog::open(&p, true).unwrap();
            log.append(&tid(42), 5_000).unwrap();
        }
        let loaded = PersistentReplayLog::load(&p, 0).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, tid(42));
    }
}
