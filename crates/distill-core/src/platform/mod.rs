//! OS primitives shared by private state consumers. Windows editor/IPC support
//! remains gated until the transport and host adapters have their own tests.
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[cfg(windows)]
mod windows;

pub fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    return windows::home_dir();
    #[cfg(not(windows))]
    std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

pub fn config_directory() -> Option<PathBuf> {
    #[cfg(windows)]
    return windows::data_directory().map(|path| path.join("config"));
    #[cfg(not(windows))]
    home_dir().map(|home| home.join(".config/distill"))
}

pub fn state_directory() -> Option<PathBuf> {
    #[cfg(windows)]
    return windows::data_directory().map(|path| path.join("state"));
    #[cfg(not(windows))]
    home_dir().map(|home| home.join(".local/state/distill"))
}

pub fn service_directory() -> Option<PathBuf> {
    #[cfg(windows)]
    return windows::data_directory().map(|path| path.join("service"));
    #[cfg(not(windows))]
    config_directory().map(|path| path.join("service"))
}

/// Fill from the OS CSPRNG. Never fall back to timestamps or process IDs.
pub fn random_bytes(bytes: &mut [u8]) -> Result<(), String> {
    getrandom::fill(bytes).map_err(|error| format!("OS randomness unavailable: {error}"))
}

#[derive(Clone, Copy, Debug)]
pub enum PrivateFileMode {
    Read,
    /// Open or create without truncating. Validate before reading or writing.
    ReadWrite,
    CreateNew,
}

pub fn private_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|error| error.to_string())?;
        validate_private_directory(path)
    }
    #[cfg(windows)]
    {
        windows::private_directory(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err("Private state is unsupported on this platform".into())
    }
}

/// Inspect an existing directory without creating or changing it.
pub fn validate_private_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err("State directory must be private and owned by the current user".into());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        windows::validate_private_directory(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err("Private state is unsupported on this platform".into())
    }
}

pub fn open_private(path: &Path, mode: PrivateFileMode) -> Result<File, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        match mode {
            PrivateFileMode::Read => {}
            PrivateFileMode::ReadWrite => {
                options.write(true).create(true).mode(0o600);
            }
            PrivateFileMode::CreateNew => {
                options.write(true).create_new(true).mode(0o600);
            }
        }
        let file = options.open(path).map_err(|error| error.to_string())?;
        validate_private_file(&file)?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        windows::open_private(path, mode)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, mode);
        Err("Private state is unsupported on this platform".into())
    }
}

pub fn validate_private_file(file: &File) -> Result<(), String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("Private state must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err("State file permissions are not private".into());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        windows::validate_private_handle(file, false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err("Private state is unsupported on this platform".into())
    }
}

/// std uses flock on Unix and LockFileEx on Windows. Read a locked file using
/// this same handle: Windows byte-range locks also apply to other read handles.
pub fn lock_exclusive(file: &File, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(fs::TryLockError::WouldBlock) => {}
            Err(fs::TryLockError::Error(error))
                if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(format!(
                    "Cannot lock session ledger: {error}; review is required"
                ));
            }
        }
        let remaining = timeout
            .checked_sub(started.elapsed())
            .ok_or("Session ledger is busy; review is required")?;
        std::thread::sleep(remaining.min(Duration::from_millis(2)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, Write};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(crate::new_id("distill-platform"));
            private_directory(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn private_files_are_bounded_and_create_new_never_replaces() {
        let root = Fixture::new();
        let path = root.0.join("key");
        let mut file = open_private(&path, PrivateFileMode::CreateNew).unwrap();
        file.write_all(b"private key").unwrap();
        drop(file);
        assert!(open_private(&path, PrivateFileMode::CreateNew).is_err());
        assert_eq!(
            crate::integrity::read_private(&path, 11).unwrap(),
            b"private key"
        );
        assert!(crate::integrity::read_private(&path, 10).is_err());
        assert!(open_private(&root.0, PrivateFileMode::Read).is_err());
    }

    #[test]
    fn exclusive_lock_bounds_contention_and_releases_on_close() {
        let root = Fixture::new();
        let path = root.0.join("ledger");
        let mut owner = open_private(&path, PrivateFileMode::ReadWrite).unwrap();
        let contender = open_private(&path, PrivateFileMode::ReadWrite).unwrap();
        lock_exclusive(&owner, Duration::ZERO).unwrap();
        owner.write_all(b"state").unwrap();
        owner.rewind().unwrap();
        let mut bytes = Vec::new();
        (&owner).read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"state");
        let started = Instant::now();
        assert!(
            lock_exclusive(&contender, Duration::from_millis(25))
                .unwrap_err()
                .contains("busy")
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(owner);
        lock_exclusive(&contender, Duration::ZERO).unwrap();
    }

    #[test]
    fn signing_key_creation_is_private_and_idempotent() {
        let root = Fixture::new();
        let path = root.0.join("label.key");
        crate::integrity::create_key(&path).unwrap();
        let key = crate::integrity::read_private(&path, 32).unwrap();
        assert_eq!(key.len(), 32);
        crate::integrity::create_key(&path).unwrap();
        assert_eq!(crate::integrity::read_private(&path, 32).unwrap(), key);
        assert!(crate::integrity::authentic(
            &key,
            "command",
            &crate::integrity::sign(&key, "command")
        ));
    }

    #[test]
    fn ledger_transactions_read_through_the_locked_handle() {
        let root = Fixture::new();
        let mut config = crate::Config::default();
        config.ledger.enabled = true;
        config.ledger.directory = Some(root.0.join("ledger"));
        for _ in 0..2 {
            assert_eq!(
                crate::session::shell_options(&config, "test", "session", &root.0).unwrap(),
                None
            );
        }
        crate::session::clear(&config, "test", "session", &root.0).unwrap();
        assert_eq!(
            crate::session::shell_options(&config, "test", "session", &root.0).unwrap(),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn public_permissions_and_symlinks_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = Fixture::new();
        let path = root.0.join("public");
        fs::write(&path, b"public").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(open_private(&path, PrivateFileMode::Read).is_err());
        let private = root.0.join("private");
        drop(open_private(&private, PrivateFileMode::CreateNew).unwrap());
        let link = root.0.join("link");
        symlink(&private, &link).unwrap();
        assert!(open_private(&link, PrivateFileMode::Read).is_err());
        let directory = root.0.join("directory");
        private_directory(&directory).unwrap();
        symlink(&directory, root.0.join("dir-link")).unwrap();
        assert!(private_directory(&root.0.join("dir-link")).is_err());
    }
}
