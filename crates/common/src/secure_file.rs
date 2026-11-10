//! Atomic replacement for files containing private keys, tokens, or invites.
//!
//! The new content is written to a randomly named file in the same directory,
//! then renamed into place. On Unix the temporary file has mode `0600` before
//! any bytes are written. Existing Unix readers continue to see the old file;
//! they cannot observe a partial or newly written secret.
//! The caller must choose a trusted parent directory.

use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

struct TempFile {
    path: PathBuf,
    armed: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn reject_unsafe_destination(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret destination must be a regular file",
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Write `contents` to `path` as a secret.
///
/// * **Unix:** a new file is created with mode `0600` and `O_NOFOLLOW`, written
///   and synced, then renamed over the old file. A symlink destination is
///   rejected. A hard-link destination is replaced without changing the other
///   link's content.
/// * **Windows:** the temporary file inherits its parent directory's ACL.
///   Store secrets only in a directory whose ACL restricts other users. An
///   existing destination may need to be closed before Windows can replace it.
///
/// If a write fails before rename, the old destination remains untouched.
/// The rename is atomic for readers on the same filesystem; this does not
/// promise durability across a power loss.
pub fn write_secret(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref();
    let contents = contents.as_ref();
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret destination has no parent",
        )
    })?;
    if path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret destination has no file name",
        ));
    }

    reject_unsafe_destination(path)?;

    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|err| io::Error::other(err.to_string()))?;
    let temp_path = parent.join(format!(
        ".mirage-secret-{}-{:032x}.tmp",
        std::process::id(),
        u128::from_le_bytes(random)
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temp_path)?;
    let mut temp = TempFile {
        path: temp_path,
        armed: true,
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // umask can only remove permissions. Set exactly 0600 before writing.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);

    // A race after this check is safe: rename replaces a link itself, never
    // follows it. The check preserves the public refusal of known symlinks.
    reject_unsafe_destination(path)?;
    std::fs::rename(&temp.path, path)?;
    temp.armed = false;
    Ok(())
}

/// Pretty-print a [`serde_json::Value`] and write it with [`write_secret`].
pub fn write_secret_json(path: impl AsRef<Path>, value: &serde_json::Value) -> io::Result<()> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_secret(path, json.as_bytes())
}

#[cfg(test)]
mod portable_tests {
    use super::write_secret;

    #[test]
    fn replaces_file_and_leaves_no_temporary_file() {
        let dir =
            std::env::temp_dir().join(format!("mirage-secfile-portable-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        write_secret(&path, b"old").unwrap();
        write_secret(&path, b"new").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }
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

    #[test]
    fn existing_reader_keeps_old_content() {
        use std::io::Read as _;

        let dir = std::env::temp_dir().join(format!("mirage-secfile4-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        write_secret(&path, b"old").unwrap();
        let mut reader = std::fs::File::open(&path).unwrap();

        write_secret(&path, b"new secret").unwrap();
        let mut old = String::new();
        reader.read_to_string(&mut old).unwrap();
        assert_eq!(old, "old");
        assert_eq!(std::fs::read(&path).unwrap(), b"new secret");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn hard_link_target_is_replaced_without_changing_other_link() {
        let dir = std::env::temp_dir().join(format!("mirage-secfile5-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let original = dir.join("original");
        let link = dir.join("link");
        std::fs::write(&original, b"old").unwrap();
        std::fs::hard_link(&original, &link).unwrap();

        write_secret(&link, b"new").unwrap();
        assert_eq!(std::fs::read(&original).unwrap(), b"old");
        assert_eq!(std::fs::read(&link).unwrap(), b"new");
        std::fs::remove_dir_all(&dir).ok();
    }
}
