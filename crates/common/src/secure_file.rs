//! Atomic secure writes for secret material (private keys, PSKs, bearer invites,
//! and the config files that embed them).
//!
//! Writing a secret with [`std::fs::write`] creates the file **world-readable**
//! under a typical `umask` (0644), and tightening it afterwards with a separate
//! `chmod`/`set_permissions` leaves a TOCTOU window in which another local user
//! can open the still-loose file. [`write_secret`] instead sets owner-only
//! (`0600`) permissions in the *same* `open(2)` call, so the bytes are never
//! exposed, and refuses to follow a symlink at the target so an attacker who can
//! pre-plant `path` as a symlink cannot redirect the secret write elsewhere.
//!
//! No `unsafe`: the platform flag is passed via the safe
//! [`OpenOptionsExt`](std::os::unix::fs::OpenOptionsExt) API.

use std::io;
use std::path::Path;

/// Write `contents` to `path` as a secret.
///
/// * **Unix:** created (or truncated) with mode `0600` in a single `open(2)`,
///   with `O_NOFOLLOW` so a symlink at `path` is rejected rather than followed.
///   If `path` already exists as a regular file we own, its mode is also
///   re-tightened to `0600` (in case it was created loosely by an older build).
/// * **Non-Unix (Windows):** a plain write. NTFS inherits the user profile's
///   restrictive ACL and has no `umask`-style world-read exposure.
///
/// Returns the underlying I/O error on failure (including `ELOOP` if `path` is a
/// symlink, or a permission error if `path` is a regular file owned by someone
/// else - in both cases the secret is *not* written to an attacker-chosen place).
pub fn write_secret(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref();
    let contents = contents.as_ref();

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        // Re-assert 0600 in case `path` pre-existed with looser bits (mode() only
        // applies to a freshly-created file). fchmod on the open descriptor, so
        // there is no separate path lookup to race.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(contents)?;
        f.sync_all()
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

/// Convenience wrapper: pretty-print a [`serde_json::Value`] and write it with
/// [`write_secret`]. Centralises the "config files are secret" policy so no call
/// site can accidentally reach for `fs::write` and leak keys.
pub fn write_secret_json(path: impl AsRef<Path>, value: &serde_json::Value) -> io::Result<()> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_secret(path, json.as_bytes())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn creates_file_0600() {
        let dir = std::env::temp_dir().join(format!("mirage-secfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("secret.json");
        write_secret(&p, b"top secret").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret must be created owner-only");
        assert_eq!(std::fs::read(&p).unwrap(), b"top secret");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tightens_preexisting_loose_file() {
        let dir = std::env::temp_dir().join(format!("mirage-secfile2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("loose.json");
        std::fs::write(&p, b"old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_secret(&p, b"new").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "overwrite must re-tighten a loosely-created file"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_symlink_target() {
        let dir = std::env::temp_dir().join(format!("mirage-secfile3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        let link = dir.join("link.json");
        std::fs::write(&victim, b"").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        // Writing through the symlink must fail (O_NOFOLLOW), leaving victim intact.
        assert!(write_secret(&link, b"redirected").is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"");
        std::fs::remove_dir_all(&dir).ok();
    }
}
