//! Append-only on-disk backing for [`crate::cohort::RevealStore`].
//!
//! # Problem ([RT-CN-10])
//!
//! The per-token reveal cap defeats a single-token cohort
//! enumeration attack. But the in-memory counter resets on
//! bridge restart, so an attacker who exhausts the cap then
//! triggers a restart can re-exhaust it. The fix is to persist
//! `(token_id, bridge_pk)` reveal records on disk so the
//! counter survives restarts.
//!
//! # Solution
//!
//! Append-only file. Each `record_reveals` call writes one
//! 64-byte record per revealed bridge:
//!
//! ```text
//!   [u8; 32] token_id
//!   [u8; 32] bridge_pk
//! ```
//!
//! Total 64 bytes per reveal. With a 8-cap-per-token policy and
//! 10000 active tokens, the log size is ~5 MiB - small enough
//! for any bridge host.
//!
//! On startup, `FileRevealStore::open` scans the file and
//! populates an in-memory `HashMap<token_id, HashSet<bridge_pk>>`.
//! Subsequent `record_reveals` calls dual-write: append to file +
//! update the map. Reads are served from the map.
//!
//! # File format
//!
//! 8-byte header: `"MRRS\x01\x00\x00\x00"` (magic `MRRS` =
//! **M**irage **R**eveal **S**tore + version 1). Then repeated
//! 64-byte records as above.
//!
//! # Durability
//!
//! `record_reveals` flushes the buffer to the OS before
//! returning. Optional `fsync` (default off) for kernel-crash
//! durability - same pattern as `PersistentReplayLog`. Torn-tail
//! records on power-loss are discarded on next open; the
//! revealed bridges might be "forgotten" and re-revealable, but
//! this is the safe direction (under-count grants extra
//! reveals; over-count would under-serve legitimate clients).

use crate::cohort::RevealStore;
use fs2::FileExt;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

/// File magic: `MRRS` = Mirage Reveal Store.
pub const MRRS_MAGIC: &[u8; 4] = b"MRRS";
/// Current file-format version.
pub const MRRS_VERSION: u8 = 0x01;
/// Fixed header length (magic + version + 3 reserved).
pub const MRRS_HEADER_LEN: usize = 8;
/// Fixed record length: 32 B token_id + 32 B bridge_pk.
pub const MRRS_RECORD_LEN: usize = 64;

/// Error surface for FileRevealStore operations.
#[derive(Debug, thiserror::Error)]
pub enum FileRevealStoreError {
    /// Underlying I/O failure.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// File begins with something other than the expected magic.
    #[error("unrecognized header: expected MRRS magic + version 1")]
    BadHeader,
    /// Another process already holds the exclusive lock on this
    /// MRRS file. Closes RT-FR-1.
    #[error("file is locked by another process: {0}")]
    AlreadyLocked(PathBuf),
}

/// Persistent file-backed reveal-counter store. Closes [RT-CN-10]
/// when used by a bridge daemon.
pub struct FileRevealStore {
    inner: Arc<Mutex<FileRevealStoreInner>>,
}

impl std::fmt::Debug for FileRevealStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileRevealStore")
            .field("inner", &"<locked>")
            .finish()
    }
}

struct FileRevealStoreInner {
    map: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    writer: BufWriter<File>,
    /// Sidecar file holding the advisory exclusive flock. Held
    /// for the lifetime of the inner; released by `Drop`. The
    /// reason it's a sidecar `.lock` rather than the data file
    /// itself is that we want to detect lock-contention *before*
    /// we touch the data file's header, so the data file's
    /// content is never racy.
    _lock: File,
    fsync_every_write: bool,
    /// The path the store was opened at - exposed via `path()`
    /// for operator diagnostics. Closes RT-FR-4.
    path: PathBuf,
}

impl Drop for FileRevealStoreInner {
    fn drop(&mut self) {
        // Best-effort: try to flush + release the flock. If
        // either fails we can't do much about it - operator
        // should run with fsync_every_write for crash safety.
        let _ = self.writer.flush();
        let _ = FileExt::unlock(&self._lock);
    }
}

impl FileRevealStore {
    /// Open (creating if absent) the store at `path`. Loads any
    /// pre-existing records into memory. `fsync_every_write` =
    /// true trades ~1 ms per `record_reveals` for kernel-crash
    /// durability.
    ///
    /// Acquires an advisory exclusive lock (`flock(LOCK_EX | LOCK_NB)`)
    /// on a sidecar `<path>.lock` file. If another process
    /// already holds the lock, returns
    /// [`FileRevealStoreError::AlreadyLocked`]. The lock is
    /// released automatically when this `FileRevealStore` is
    /// dropped *or* when the process exits (POSIX `flock`
    /// semantics - no stale-lock-after-crash problem). Closes
    /// RT-FR-1.
    pub fn open<P: AsRef<Path>>(
        path: P,
        fsync_every_write: bool,
    ) -> Result<Self, FileRevealStoreError> {
        let path = path.as_ref().to_path_buf();
        // Sidecar lock file lives next to the data file.
        let lock_path = {
            let mut p = path.clone();
            let new_ext = match path.extension() {
                Some(ext) => {
                    let mut s = ext.to_os_string();
                    s.push(".lock");
                    s
                }
                None => std::ffi::OsString::from("lock"),
            };
            p.set_extension(new_ext);
            p
        };
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        match FileExt::try_lock_exclusive(&lock_file) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(FileRevealStoreError::AlreadyLocked(lock_path));
            }
            // fs2 on some platforms returns ErrorKind::Other for
            // EWOULDBLOCK - treat any error here as
            // already-locked rather than corrupting state.
            Err(_) => {
                return Err(FileRevealStoreError::AlreadyLocked(lock_path));
            }
        }

        let already_exists = path.exists();
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let map = if already_exists {
            // Validate header + load records.
            let mut hdr = [0u8; MRRS_HEADER_LEN];
            let n = f.read(&mut hdr)?;
            if n == 0 {
                // Empty file: treat as freshly-created.
                write_header(&mut f)?;
                HashMap::new()
            } else if n < MRRS_HEADER_LEN || &hdr[0..4] != MRRS_MAGIC || hdr[4] != MRRS_VERSION {
                // Release the flock before returning - Drop
                // wouldn't run because Self isn't constructed.
                let _ = FileExt::unlock(&lock_file);
                return Err(FileRevealStoreError::BadHeader);
            } else {
                load_records(&mut f)?
            }
        } else {
            write_header(&mut f)?;
            HashMap::new()
        };
        // Position at end for appends.
        use std::io::Seek;
        f.seek(std::io::SeekFrom::End(0))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(FileRevealStoreInner {
                map,
                writer: BufWriter::new(f),
                _lock: lock_file,
                fsync_every_write,
                path,
            })),
        })
    }

    /// Path the store was opened at. Closes RT-FR-4 (was a
    /// placeholder).
    pub async fn path(&self) -> PathBuf {
        self.inner.lock().await.path.clone()
    }
}

fn write_header(f: &mut File) -> io::Result<()> {
    let mut hdr = [0u8; MRRS_HEADER_LEN];
    hdr[0..4].copy_from_slice(MRRS_MAGIC);
    hdr[4] = MRRS_VERSION;
    f.write_all(&hdr)?;
    f.flush()?;
    Ok(())
}

fn load_records(
    f: &mut File,
) -> Result<HashMap<[u8; 32], HashSet<[u8; 32]>>, FileRevealStoreError> {
    let mut map: HashMap<[u8; 32], HashSet<[u8; 32]>> = HashMap::new();
    loop {
        let mut rec = [0u8; MRRS_RECORD_LEN];
        match f.read(&mut rec) {
            Ok(0) => break,
            Ok(n) if n < MRRS_RECORD_LEN => {
                // Torn write at the tail. Documented behaviour:
                // silently drop. Operator MAY compact / repair
                // later. We don't truncate here (truncation
                // requires a write lock the caller may not want).
                break;
            }
            Ok(_) => {
                let mut token_id = [0u8; 32];
                token_id.copy_from_slice(&rec[0..32]);
                let mut bridge_pk = [0u8; 32];
                bridge_pk.copy_from_slice(&rec[32..64]);
                map.entry(token_id).or_default().insert(bridge_pk);
            }
            Err(e) => return Err(FileRevealStoreError::Io(e)),
        }
    }
    Ok(map)
}

#[async_trait::async_trait]
impl RevealStore for FileRevealStore {
    async fn reveal_count(&self, token_id: &[u8; 32]) -> u8 {
        let g = self.inner.lock().await;
        g.map
            .get(token_id)
            .map(|set| u8::try_from(set.len()).unwrap_or(u8::MAX))
            .unwrap_or(0)
    }

    async fn has_revealed(&self, token_id: &[u8; 32], bridge_pk: &[u8; 32]) -> bool {
        let g = self.inner.lock().await;
        g.map
            .get(token_id)
            .is_some_and(|set| set.contains(bridge_pk))
    }

    async fn record_reveals(&self, token_id: &[u8; 32], bridge_pks: &[[u8; 32]]) {
        let mut g = self.inner.lock().await;
        // Append-first, update-second. If the file write fails
        // we don't pollute the in-memory map - the next caller
        // sees the previous state and gets a chance to retry.
        for pk in bridge_pks {
            // Skip records we already have (dedup, also
            // prevents file from growing under repeated calls).
            let already = g.map.get(token_id).is_some_and(|set| set.contains(pk));
            if already {
                continue;
            }
            let mut rec = [0u8; MRRS_RECORD_LEN];
            rec[0..32].copy_from_slice(token_id);
            rec[32..64].copy_from_slice(pk);
            if let Err(e) = g.writer.write_all(&rec) {
                tracing::warn!(error = %e, "FileRevealStore append failed; skipping");
                continue;
            }
            g.map.entry(*token_id).or_default().insert(*pk);
        }
        // Flush after the batch. fsync optional.
        if let Err(e) = g.writer.flush() {
            tracing::warn!(error = %e, "FileRevealStore flush failed");
        }
        if g.fsync_every_write {
            if let Err(e) = g.writer.get_ref().sync_data() {
                tracing::warn!(error = %e, "FileRevealStore fsync failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        // Unique-ish per test run.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("mirage-reveal-store-{name}-{nanos}.mrrs"));
        p
    }

    #[tokio::test]
    async fn file_store_records_persist_across_open() {
        let path = temp_path("persist");
        let token = [0x77u8; 32];
        let bridges = [[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];

        // Round 1: open, record, close.
        {
            let store = FileRevealStore::open(&path, false).unwrap();
            store.record_reveals(&token, &bridges).await;
            assert_eq!(store.reveal_count(&token).await, 3);
        }
        // Round 2: reopen, the records MUST still be there.
        {
            let store = FileRevealStore::open(&path, false).unwrap();
            assert_eq!(store.reveal_count(&token).await, 3);
            for pk in &bridges {
                assert!(store.has_revealed(&token, pk).await);
            }
        }
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn file_store_dedups_repeated_records() {
        let path = temp_path("dedup");
        let store = FileRevealStore::open(&path, false).unwrap();
        let token = [0x11u8; 32];
        let pk = [0xAAu8; 32];
        store.record_reveals(&token, &[pk]).await;
        store.record_reveals(&token, &[pk]).await;
        store.record_reveals(&token, &[pk]).await;
        assert_eq!(store.reveal_count(&token).await, 1);

        // File should also be small - header + 1 record.
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(
            metadata.len() as usize,
            MRRS_HEADER_LEN + MRRS_RECORD_LEN,
            "dedup must skip the file append, not double-write"
        );
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn file_store_rejects_bad_header() {
        let path = temp_path("badhdr");
        std::fs::write(&path, b"NOTHEADER-this-is-not-an-MRRS-file").unwrap();
        let err = FileRevealStore::open(&path, false).unwrap_err();
        assert!(matches!(err, FileRevealStoreError::BadHeader));
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn file_store_isolates_tokens() {
        let path = temp_path("isolate");
        let store = FileRevealStore::open(&path, false).unwrap();
        let token_a = [0x01u8; 32];
        let token_b = [0x02u8; 32];
        store
            .record_reveals(&token_a, &[[0xAA; 32], [0xBB; 32]])
            .await;
        store.record_reveals(&token_b, &[[0xCC; 32]]).await;
        assert_eq!(store.reveal_count(&token_a).await, 2);
        assert_eq!(store.reveal_count(&token_b).await, 1);
        assert!(!store.has_revealed(&token_a, &[0xCC; 32]).await);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn file_store_rejects_concurrent_open() {
        // Closes RT-FR-1: two processes (here, two FileRevealStore
        // instances in the same process - same effect on flock)
        // must not both open the same MRRS file. The second open
        // returns AlreadyLocked.
        let path = temp_path("concurrent");
        let _holder = FileRevealStore::open(&path, false).unwrap();
        let err = FileRevealStore::open(&path, false).unwrap_err();
        assert!(matches!(err, FileRevealStoreError::AlreadyLocked(_)));
        // Cleanup.
        drop(_holder);
        std::fs::remove_file(&path).ok();
        // Best-effort: remove the sidecar lock too.
        let mut lock_path = path.clone();
        let mut ext = lock_path
            .extension()
            .map(|e| e.to_os_string())
            .unwrap_or_default();
        ext.push(".lock");
        lock_path.set_extension(ext);
        std::fs::remove_file(&lock_path).ok();
    }

    #[tokio::test]
    async fn file_store_reopens_after_drop_releases_lock() {
        // The flock is released on Drop, so a subsequent
        // FileRevealStore::open on the same path should succeed.
        let path = temp_path("reopen");
        {
            let store = FileRevealStore::open(&path, false).unwrap();
            store.record_reveals(&[0xAB; 32], &[[0x01; 32]]).await;
        } // dropped here, flock released
        let store2 = FileRevealStore::open(&path, false).unwrap();
        assert_eq!(store2.reveal_count(&[0xAB; 32]).await, 1);
        drop(store2);
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn file_store_reports_path() {
        let path = temp_path("reportpath");
        let store = FileRevealStore::open(&path, false).unwrap();
        assert_eq!(store.path().await, path);
        drop(store);
        std::fs::remove_file(&path).ok();
    }
}
