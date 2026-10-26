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
    {
        use std::os::fd::AsRawFd;
        let started = std::time::Instant::now();
        while unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock
                || started.elapsed().as_millis() >= 500
            {
                return Err("Session ledger is busy; review is required".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
    let bytes = read_private(&path, 2 * 1024 * 1024)?;
    let mut state: State = if bytes.is_empty() {
        State::default()
    } else {
        serde_json::from_slice(&bytes)
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
