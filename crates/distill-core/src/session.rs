//! Bounded, user-owned policy state. Only hashes, effect labels and timestamps persist.
use crate::{
    Config, Decision, EffectKind, Evidence, Finding, FindingBasis, Report, Severity, TargetClass,
    integrity::{private_directory, read_private, sha256},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::{Seek, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

// Keep a ledger transaction's contention budget below the CLI's six-second
// watchdog. A hook burst can legitimately serialize dozens of small fsyncs on
// a shared CI disk, and two seconds is not enough for that queue to drain.
// The watchdog remains the aggregate fail-closed backstop for a whole hook.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(unix)]
fn lock(file: &fs::File, timeout: std::time::Duration) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let started = std::time::Instant::now();
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if !matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ) {
            return Err(format!(
                "Cannot lock session ledger: {error}; review is required"
            ));
        }
        let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
            return Err("Session ledger is busy; review is required".into());
        };
        std::thread::sleep(remaining.min(std::time::Duration::from_millis(2)));
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    entries: Vec<Entry>,
    secret_targets: BTreeSet<String>,
    remote_targets: BTreeSet<String>,
    secret_observed: bool,
    shell_options: Option<Vec<String>>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Entry {
    id: String,
    command: String,
    signature: String,
    time: u64,
    decision: Decision,
    secret_read: bool,
    remote_read: bool,
    writes: Vec<String>,
    completed: bool,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn directory(config: &Config) -> Result<PathBuf, String> {
    config
        .ledger
        .directory
        .clone()
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state/distill"))
        })
        .ok_or("HOME is unavailable".into())
}
fn transaction<T>(
    config: &Config,
    source: &str,
    session: &str,
    workspace: &Path,
    f: impl FnOnce(&mut State) -> Result<T, String>,
) -> Result<T, String> {
    let directory = directory(config)?;
    private_directory(&directory)?;
    let key = sha256(format!("{source}\0{session}\0{}", workspace.display()).as_bytes());
    let path = directory.join(format!("{key}.json"));
    let mut files = 0;
    let mut bytes = 0;
    for entry in fs::read_dir(&directory)
        .map_err(|e| e.to_string())?
        .take(258)
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("Unexpected entry in private ledger directory".into());
        }
        files += 1;
        bytes += metadata.len();
    }
    if files > 256 || bytes > 64 * 1024 * 1024 || files == 256 && !path.exists() {
        return Err("Global session ledger capacity reached; clear old session files".into());
    }
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(&path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    lock(&file, LOCK_WAIT)?;
    let original = read_private(&path, 2 * 1024 * 1024)?;
    let mut state: State = if original.is_empty() {
        State::default()
    } else {
        serde_json::from_slice(&original)
            .map_err(|_| "Session ledger is corrupt; review is required")?
    };
    let cutoff = now().saturating_sub(config.ledger.ttl_seconds);
    state.entries.retain(|entry| entry.time >= cutoff);
    if state.entries.is_empty() {
        state.shell_options = None;
    }
    // Labels are rebuilt exclusively from retained completion evidence.
    state.secret_targets.clear();
    state.remote_targets.clear();
    state.secret_observed = false;
    for entry in state.entries.iter().filter(|entry| entry.completed) {
        state.secret_observed |= entry.secret_read;
        if entry.secret_read {
            state.secret_targets.extend(entry.writes.iter().cloned());
        }
        if entry.remote_read {
            state.remote_targets.extend(entry.writes.iter().cloned());
        }
    }
    let result = f(&mut state)?;
    if state.entries.len() > config.ledger.max_entries {
        return Err("Session ledger capacity reached; clear the session before continuing".into());
    }
    let bytes = serde_json::to_vec(&state).map_err(|e| e.to_string())?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("Session ledger byte limit reached".into());
    }
    // Looking up shell options or retrying an unchanged completion must not
    // truncate and fsync the ledger while every competing hook waits for it.
    // Expiration cleanup and real mutations still persist under the same lock.
    if bytes == original {
        return Ok(result);
    }
    file.rewind().map_err(|e| e.to_string())?;
    file.set_len(0).map_err(|e| e.to_string())?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_data())
        .map_err(|e| e.to_string())?;
    Ok(result)
}

fn signal(report: &mut Report, severity: Severity, rule: &str, text: &str, deny: bool) {
    report.severity = report.severity.max(severity);
    report.impact_severity = Some(
        report
            .impact_severity
            .unwrap_or(Severity::Safe)
            .max(severity),
    );
    report.decision = if deny || report.decision == Decision::Deny {
        Decision::Deny
    } else {
        Decision::Ask
    };
    report.findings.push(Finding {
        rule_id: rule.into(),
        severity,
        impact: text.into(),
        evidence: vec![Evidence {
            source: "session_ledger",
            fact: text.into(),
        }],
        confidence: "conditional",
        basis: FindingBasis::Impact,
    });
    report.explanation = format!("distill {}: {text}", severity.as_str().to_ascii_uppercase());
}

pub fn assess(
    config: &Config,
    source: &str,
    session: &str,
    id: &str,
    workspace: &Path,
    retry_fingerprint: &str,
    report: &mut Report,
) -> Result<(), String> {
    if !config.ledger.enabled {
        return Ok(());
    }
    if report
        .analysis_context
        .shell_options
        .as_ref()
        .is_some_and(|options| {
            options.len() > 64
                || options.iter().any(|option| {
                    option.len() > 64
                        || !option
                            .bytes()
                            .all(|byte| byte.is_ascii_alphabetic() || byte == b'_')
                })
        })
    {
        return Err("Invalid shell option snapshot cannot be recorded".into());
    }
    transaction(config, source, session, workspace, |state| {
        let id = sha256(id.as_bytes());
        let mut signature = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        signature.sort();
        signature.dedup();
        let signature = sha256(format!("{retry_fingerprint}\0{}", signature.join("\0")).as_bytes());
        let reads = report
            .behaviors
            .iter()
            .filter(|b| b.kind == EffectKind::FileRead)
            .filter_map(|b| b.target.as_ref())
            .map(|path| sha256(path.as_bytes()))
            .collect::<Vec<_>>();
        let secret_read = report
            .behaviors
            .iter()
            .any(|b| b.kind == EffectKind::FileRead && b.target_class == TargetClass::Secret)
            || reads.iter().any(|hash| state.secret_targets.contains(hash));
        let remote_read = report
            .effects
            .iter()
            .any(|effect| effect.kind == EffectKind::NetworkReceive);
        let sends = report
            .effects
            .iter()
            .any(|effect| matches!(effect.kind, EffectKind::Connect | EffectKind::NetworkSend));
        if sends && secret_read {
            signal(
                report,
                Severity::Critical,
                "chain.secret-send",
                "Network operation consumes a credential-labeled file from this session",
                true,
            );
        } else if sends && state.secret_observed {
            signal(
                report,
                Severity::High,
                "chain.secret-network",
                "A network operation follows observed credential access in this session; data flow requires review",
                false,
            );
        }
        if report.inspected_files.iter().any(|file| {
            state
                .remote_targets
                .contains(&sha256(file.path.to_string_lossy().as_bytes()))
        }) {
            signal(
                report,
                Severity::Critical,
                "chain.remote-execute",
                "Execution inspects a file previously labeled as downloaded code",
                true,
            );
        }
        let repeats = state
            .entries
            .iter()
            .filter(|entry| {
                entry.signature == signature && entry.id != id && entry.decision != Decision::Allow
            })
            .count();
        if config.ledger.repeat_limit > 0 && repeats >= config.ledger.repeat_limit {
            signal(
                report,
                Severity::High,
                "retry.escalation",
                "Repeated equivalent review-level attempts exceeded the session retry limit",
                true,
            );
        }
        state.shell_options = if report
            .unknowns
            .iter()
            .any(|reason| reason.contains("Shell options or modules"))
        {
            None
        } else {
            report
                .analysis_context
                .shell_options
                .clone()
                .or_else(|| state.shell_options.clone())
        };
        let entry = Entry {
            id: id.clone(),
            command: report.command_digest.clone(),
            signature,
            time: now(),
            decision: report.decision,
            secret_read,
            remote_read,
            writes: report
                .behaviors
                .iter()
                .filter(|b| b.kind == EffectKind::FileWrite)
                .filter_map(|b| b.target.as_ref())
                .map(|path| sha256(path.as_bytes()))
                .collect(),
            completed: false,
        };
        if let Some(existing) = state.entries.iter_mut().find(|existing| existing.id == id) {
            let completed = existing.completed;
            *existing = entry;
            existing.completed = completed;
        } else {
            state.entries.push(entry);
        }
        Ok(())
    })
}
pub fn complete(
    config: &Config,
    source: &str,
    session: &str,
    id: &str,
    workspace: &Path,
) -> Result<(), String> {
    if !config.ledger.enabled {
        return Ok(());
    }
    transaction(config, source, session, workspace, |state| {
        let id = sha256(id.as_bytes());
        if let Some(entry) = state.entries.iter_mut().find(|entry| entry.id == id) {
            entry.completed = true;
        }
        Ok(())
    })
}
pub fn clear(config: &Config, source: &str, session: &str, workspace: &Path) -> Result<(), String> {
    // Recovery must work even when the stored JSON is corrupt or over capacity.
    let directory = directory(config)?;
    private_directory(&directory)?;
    let key = sha256(format!("{source}\0{session}\0{}", workspace.display()).as_bytes());
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(directory.join(format!("{key}.json")))
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::{os::fd::AsRawFd, os::unix::fs::MetadataExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || !metadata.is_file()
        {
            return Err("Ledger must be a private regular file".into());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("Session ledger is busy; retry clearing it".into());
        }
    }
    file.set_len(0)
        .and_then(|_| file.sync_data())
        .map_err(|e| e.to_string())
}
pub fn shell_options(
    config: &Config,
    source: &str,
    session: &str,
    workspace: &Path,
) -> Result<Option<Vec<String>>, String> {
    if !config.ledger.enabled {
        return Ok(None);
    }
    transaction(config, source, session, workspace, |state| {
        Ok(state.shell_options.clone())
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{os::fd::AsRawFd, os::unix::fs::OpenOptionsExt, time::Duration};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(crate::new_id("ledger-test"));
            private_directory(&path).unwrap();
            Self(path)
        }
        fn file(&self) -> fs::File {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(self.0.join("lock"))
                .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn unchanged_reads_preserve_the_ledger_file() {
        let f = Fixture::new();
        let mut config = Config::default();
        config.ledger.enabled = true;
        config.ledger.directory = Some(f.0.clone());
        let workspace = Path::new("/tmp");
        assert_eq!(
            shell_options(&config, "test", "session", workspace).unwrap(),
            None
        );
        let path = fs::read_dir(&f.0).unwrap().next().unwrap().unwrap().path();
        let before = fs::metadata(&path).unwrap().modified().unwrap();
        let bytes = fs::read(&path).unwrap();
        std::thread::sleep(Duration::from_millis(25));
        for _ in 0..8 {
            assert_eq!(
                shell_options(&config, "test", "session", workspace).unwrap(),
                None
            );
        }
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn contended_lock_survives_a_slow_flush_beyond_the_old_deadline() {
        let f = Fixture::new();
        let held = f.file();
        assert_eq!(
            unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let waiting = f.file();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            tx.send(()).unwrap();
            lock(&waiting, LOCK_WAIT)
        });
        rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(650));
        drop(held);
        worker.join().unwrap().unwrap();
    }

    #[test]
    fn a_stuck_lock_still_fails_closed_with_a_bounded_wait() {
        let f = Fixture::new();
        let held = f.file();
        lock(&held, LOCK_WAIT).unwrap();
        let error = lock(&f.file(), Duration::from_millis(25)).unwrap_err();
        assert!(error.contains("busy") && error.contains("review is required"));
    }
}
