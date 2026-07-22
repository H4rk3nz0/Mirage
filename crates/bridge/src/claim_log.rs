//! Disk-backed persistence for the claim-redemption set.
//!
//! Mirrors [`mirage_discovery::replay_log::PersistentReplayLog`] but
//! holds claim records (claim_id || root_token_id, 64 bytes each)
//! rather than replay entries. Without this, a bridge restart
//! resets the claim set and an attacker holding a leaked invite
//! can re-redeem already-claimed ids - defeats the
//! one-claim-per-invite property.
//!
//! Wire format:
//!
//! ```text
//! HEADER:    "MCRL"  + version(1) + reserved(3)   = 8 bytes
//! RECORD:    claim_id(32) || root_token_id(32)    = 64 bytes (repeated)
//! ```
//!
//! Append-only; durability via `BufWriter::flush` plus optional
//! `fsync` per write (recommended in production). Torn tails on
//! the trailing record are truncated at next open.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

const MCRL_MAGIC: &[u8] = b"MCRL";
const MCRL_VERSION: u8 = 0x01;
const MCRL_HEADER_LEN: usize = 8;
/// Bytes per persisted claim record (claim_id || root_token_id).
pub const MCRL_RECORD_LEN: usize = 64;

/// Errors produced by the claim log.
#[derive(Debug, Error)]
pub enum ClaimLogError {
    /// I/O failure (open, read, seek, write, fsync).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Header magic or version mismatch.
    #[error("bad header")]
    BadHeader,
}

/// A loaded claim record: `(claim_id, root_token_id)`.
pub type ClaimRecord = ([u8; 32], [u8; 32]);

/// Append-only persistent claim log.
pub struct PersistentClaimLog {
    #[allow(dead_code)] // operator-diagnostics-only; surfaced via path()
    path: PathBuf,
    writer: BufWriter<File>,
    fsync_every_write: bool,
}

impl PersistentClaimLog {
    /// Open (creating if absent) the log at `path`. Truncates a
    /// torn-tail trailing record at open so subsequent appends don't
    /// land after corrupted bytes.
    pub fn open<P: AsRef<Path>>(path: P, fsync_every_write: bool) -> Result<Self, ClaimLogError> {
        let path = path.as_ref().to_path_buf();
        let already_exists = path.exists();
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Append-log: never truncate existing contents at open.
            .truncate(false)
            .open(&path)?;
        if already_exists {
            let mut hdr = [0u8; MCRL_HEADER_LEN];
            let n = f.read(&mut hdr)?;
            if n == 0 {
                Self::write_header(&mut f)?;
            } else if n < MCRL_HEADER_LEN || &hdr[0..4] != MCRL_MAGIC || hdr[4] != MCRL_VERSION {
                return Err(ClaimLogError::BadHeader);
            }
        } else {
            Self::write_header(&mut f)?;
        }
        // Truncate torn tail if present.
        let end = f.seek(SeekFrom::End(0))?;
        if end > MCRL_HEADER_LEN as u64 {
            let body = end - MCRL_HEADER_LEN as u64;
            let remainder = body % MCRL_RECORD_LEN as u64;
            if remainder != 0 {
                f.set_len(end - remainder)?;
                f.seek(SeekFrom::End(0))?;
            }
        }
        Ok(Self {
            path,
            writer: BufWriter::new(f),
            fsync_every_write,
        })
    }

    fn write_header(f: &mut File) -> Result<(), ClaimLogError> {
        let mut hdr = [0u8; MCRL_HEADER_LEN];
        hdr[0..4].copy_from_slice(MCRL_MAGIC);
        hdr[4] = MCRL_VERSION;
        f.write_all(&hdr)?;
        f.sync_all()?;
        Ok(())
    }

    /// Append one claim record. Caller MUST persist BEFORE
    /// returning success to the requesting client (so a crash
    /// doesn't admit replay).
    pub fn append(
        &mut self,
        claim_id: &[u8; 32],
        root_token_id: &[u8; 32],
    ) -> Result<(), ClaimLogError> {
        let mut rec = [0u8; MCRL_RECORD_LEN];
        rec[0..32].copy_from_slice(claim_id);
        rec[32..64].copy_from_slice(root_token_id);
        // RT #20: on ANY write error, realign the file to the last whole
        // record so a torn partial (e.g. ENOSPC mid-record) cannot desync the
        // loader and silently drop a claim's one-time-use record after
        // restart. The caller treats Err as "refuse the claim".
        if let Err(e) = self.write_record(&rec) {
            self.realign_to_record_boundary();
            return Err(e);
        }
        Ok(())
    }

    fn write_record(&mut self, rec: &[u8; MCRL_RECORD_LEN]) -> Result<(), ClaimLogError> {
        self.writer.write_all(rec)?;
        self.writer.flush()?;
        if self.fsync_every_write {
            self.writer.get_ref().sync_data()?;
        }
        Ok(())
    }

    /// Best-effort: truncate a torn partial tail back to the last whole-record
    /// boundary after a failed append, keeping the loader aligned.
    fn realign_to_record_boundary(&mut self) {
        let _ = self.writer.flush();
        let f = self.writer.get_mut();
        if let Ok(end) = f.seek(SeekFrom::End(0)) {
            if end > MCRL_HEADER_LEN as u64 {
                let remainder = (end - MCRL_HEADER_LEN as u64) % MCRL_RECORD_LEN as u64;
                if remainder != 0 {
                    let _ = f.set_len(end - remainder);
                    let _ = f.seek(SeekFrom::End(0));
                }
            }
        }
    }

    /// Load every record from `path`. Returns
    /// `Vec<(claim_id, root_token_id)>` in append order, with the
    /// caller responsible for materializing the in-memory set.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Vec<ClaimRecord>, ClaimLogError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut f = File::open(path)?;
        let mut hdr = [0u8; MCRL_HEADER_LEN];
        let n = f.read(&mut hdr)?;
        if n < MCRL_HEADER_LEN || &hdr[0..4] != MCRL_MAGIC || hdr[4] != MCRL_VERSION {
            return Err(ClaimLogError::BadHeader);
        }
        let mut out = Vec::new();
        loop {
            let mut rec = [0u8; MCRL_RECORD_LEN];
            match f.read(&mut rec) {
                Ok(0) => break,
                Ok(k) if k < MCRL_RECORD_LEN => break, // torn tail
                Ok(_) => {}
                Err(e) => return Err(e.into()),
            }
            let mut cid = [0u8; 32];
            cid.copy_from_slice(&rec[0..32]);
            let mut rid = [0u8; 32];
            rid.copy_from_slice(&rec[32..64]);
            out.push((cid, rid));
        }
        Ok(out)
    }

    /// Path the log writes to, for diagnostics.
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn cid(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn rid(n: u8) -> [u8; 32] {
        [n.wrapping_add(0x80); 32]
    }

    #[test]
    fn append_and_load_roundtrip() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("cl");
        {
            let mut log = PersistentClaimLog::open(&p, false).unwrap();
            log.append(&cid(1), &rid(1)).unwrap();
            log.append(&cid(2), &rid(2)).unwrap();
        }
        let loaded = PersistentClaimLog::load(&p).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0], (cid(1), rid(1)));
        assert_eq!(loaded[1], (cid(2), rid(2)));
    }

    #[test]
    fn rejects_wrong_magic() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("cl");
        std::fs::write(&p, b"NOPE\x01\x00\x00\x00").unwrap();
        let err = PersistentClaimLog::load(&p).unwrap_err();
        assert!(matches!(err, ClaimLogError::BadHeader));
    }

    #[test]
    fn torn_tail_is_truncated_on_open() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("cl");
        {
            let mut log = PersistentClaimLog::open(&p, false).unwrap();
            log.append(&cid(1), &rid(1)).unwrap();
        }
        // Inject a torn half-record.
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(&[0xCDu8; 17]).unwrap();
        drop(f);
        // Reopen + append + reload: only the two whole records survive.
        {
            let mut log = PersistentClaimLog::open(&p, false).unwrap();
            log.append(&cid(2), &rid(2)).unwrap();
        }
        let loaded = PersistentClaimLog::load(&p).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0], (cid(1), rid(1)));
        assert_eq!(loaded[1], (cid(2), rid(2)));
    }

    #[test]
    fn empty_existing_file_writes_header() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("cl");
        std::fs::write(&p, b"").unwrap(); // touch
        let _log = PersistentClaimLog::open(&p, false).unwrap();
        let bytes = std::fs::read(&p).unwrap();
        assert_eq!(&bytes[0..4], MCRL_MAGIC);
        assert_eq!(bytes[4], MCRL_VERSION);
    }
}
