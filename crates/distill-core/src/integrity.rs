//! Content bindings and private local keys. No candidate code is executed here.
use crate::AnalysisBudget;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSnapshot {
    pub path: PathBuf,
    pub resolved_path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
}

pub fn read_snapshot(
    path: &Path,
    budget: &AnalysisBudget,
    cap: usize,
) -> Result<(String, FileSnapshot), String> {
    if budget.expired() {
        return Err(budget.stop_reason().into());
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "Inspected file cannot be opened")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Inspected metadata unavailable")?;
    if !metadata.is_file() || metadata.len() > cap as u64 {
        return Err("Inspected file is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    loop {
        if budget.expired() {
            return Err(budget.stop_reason().into());
        }
        let mut chunk = [0; 16384];
        let size = file
            .read(&mut chunk)
            .map_err(|_| "Inspected file cannot be read")?;
        if size == 0 {
            break;
        }
        if bytes.len() + size > cap {
            return Err("Inspected file exceeds limit".into());
        }
        bytes.extend_from_slice(&chunk[..size]);
    }
    let resolved_path = fs::canonicalize(path).map_err(|_| "Inspected path cannot be resolved")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current =
            fs::metadata(&resolved_path).map_err(|_| "Inspected file changed during read")?;
        let after = file
            .metadata()
            .map_err(|_| "Inspected file changed during read")?;
        if current.dev() != metadata.dev()
            || current.ino() != metadata.ino()
            || after.len() != metadata.len()
            || after.mtime() != metadata.mtime()
            || after.mtime_nsec() != metadata.mtime_nsec()
            || after.ctime() != metadata.ctime()
            || after.ctime_nsec() != metadata.ctime_nsec()
        {
            return Err("Inspected file changed during read".into());
        }
    }
    let snapshot = FileSnapshot {
        path: path.to_path_buf(),
        resolved_path,
        sha256: sha256(&bytes),
        bytes: bytes.len() as u64,
    };
    Ok((
        String::from_utf8(bytes).map_err(|_| "Inspected source is not UTF-8")?,
        snapshot,
    ))
}

impl FileSnapshot {
    pub fn verify(&self) -> Result<(), String> {
        let (_, current) = read_snapshot(&self.path, &AnalysisBudget::new(1000), 1024 * 1024)?;
        if &current != self {
            return Err(format!(
                "Inspected dependency changed: {}",
                self.path.display()
            ));
        }
        Ok(())
    }
}

pub fn private_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path).map_err(|e| e.to_string())?;
        let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err("State directory must be private and owned by the current user".into());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err("Private state requires Unix".into())
    }
}

pub fn read_private(path: &Path, cap: usize) -> Result<Vec<u8>, String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err("State file permissions are not private".into());
        }
    }
    if !metadata.is_file() || metadata.len() > cap as u64 {
        return Err("Invalid state file".into());
    }
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > cap {
        return Err("State file exceeds limit".into());
    }
    Ok(bytes)
}

pub fn key_path(config: &crate::Config) -> Option<PathBuf> {
    config.security.label_key_path.clone().or_else(|| {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/distill/label.key"))
    })
}
pub fn create_key(path: &Path) -> Result<(), String> {
    private_directory(path.parent().ok_or("Key requires a parent directory")?)?;
    if path.exists() {
        read_private(path, 32).and_then(|key| {
            if key.len() == 32 {
                Ok(())
            } else {
                Err("Invalid signing key".into())
            }
        })?;
        return Ok(());
    }
    let mut bytes = [0; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| e.to_string())?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut file| file.write_all(&bytes))
        .map_err(|e| e.to_string())
}
pub fn sign(key: &[u8], text: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(text.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn authentic(key: &[u8], text: &str, signature: &str) -> bool {
    if signature.len() != 64 || !signature.is_ascii() {
        return false;
    }
    let bytes = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&signature[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>();
    let Ok(bytes) = bytes else {
        return false;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(text.as_bytes());
    mac.verify_slice(&bytes).is_ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn snapshots_reject_changed_content_and_symlink_retargeting() {
        use super::*;
        let root = std::env::temp_dir().join(crate::new_id("distill-binding"));
        fs::create_dir(&root).unwrap();
        let path = root.join("source");
        fs::write(&path, "print(1)").unwrap();
        let (_, snapshot) = read_snapshot(&path, &AnalysisBudget::new(100), 1024).unwrap();
        snapshot.verify().unwrap();
        fs::write(&path, "print(2)").unwrap();
        assert!(snapshot.verify().is_err());
        #[cfg(unix)]
        {
            let link = root.join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            let (_, snapshot) = read_snapshot(&link, &AnalysisBudget::new(100), 1024).unwrap();
            let other = root.join("other");
            fs::write(&other, "print(2)").unwrap();
            fs::remove_file(&link).unwrap();
            std::os::unix::fs::symlink(&other, &link).unwrap();
            assert!(snapshot.verify().is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn hmac_authentication_rejects_all_modified_inputs() {
        let key = [7; 32];
        let signature = super::sign(&key, "hello");
        assert!(super::authentic(&key, "hello", &signature));
        assert!(!super::authentic(&key, "hello\nrm -rf /", &signature));
        assert!(!super::authentic(&[8; 32], "hello", &signature));
        assert!(!super::authentic(&key, "hello", "é"));
    }
}
