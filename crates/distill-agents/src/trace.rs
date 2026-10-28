//! Best-effort delivery to an editor-owned, memory-only trace broker.
//! This bridge never writes commands, reports, or output to disk.
use distill_core::{Integration, Report};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const MAX_EVENT_BYTES: usize = 32 * 1024 * 1024;

pub fn directory() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("DISTILL_TRACE_DIR") {
        return Some(PathBuf::from(path));
    }
    let home = std::env::var("HOME").ok()?;
    let hash = home.bytes().fold(0xcbf29ce484222325u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    });
    Some(std::env::temp_dir().join(format!("distill-vscode-{hash:016x}")))
}

pub fn is_completion(input: &str) -> bool {
    serde_json::from_str::<Value>(input).is_ok_and(|event| {
        matches!(
            event["hook_event_name"].as_str(),
            Some("PostToolUse" | "PostToolUseFailure")
        )
    })
}

pub fn assessment(
    host: Integration,
    input: &str,
    report: &Report,
    response: &Value,
    config: &distill_core::Config,
) -> Result<(), String> {
    assessment_value(
        host,
        input,
        &serde_json::to_value(report).map_err(|e| e.to_string())?,
        response,
        config,
    )
}

/// Record the final human decision after the supervised CLI's approval dialog.
pub fn assessment_value(
    host: Integration,
    input: &str,
    report: &Value,
    response: &Value,
    config: &distill_core::Config,
) -> Result<(), String> {
    if !has_endpoints() {
        return Ok(());
    }
    let event: Value = serde_json::from_str(input).map_err(|e| e.to_string())?;
    let blocked = response.pointer("/hookSpecificOutput/permissionDecision")
        == Some(&json!("deny"))
        || response.pointer("/hookSpecificOutput/decision/behavior") == Some(&json!("deny"))
        || response.get("decision") == Some(&json!("block"));
    let mut trace = envelope(host, &event, config)?;
    trace["kind"] = json!("assessment");
    trace["report"] = report.clone();
    trace["blocked"] = json!(blocked);
    deliver(trace)
}

pub fn completion(host: Integration, input: &str) -> Result<(), String> {
    completion_with_config(host, input, &distill_core::Config::default())
}

pub fn completion_with_config(
    host: Integration,
    input: &str,
    config: &distill_core::Config,
) -> Result<(), String> {
    let event: Value = serde_json::from_str(input).map_err(|e| e.to_string())?;
    if event["tool_name"] != "Bash" || !is_completion(input) {
        return Err("Expected a Bash completion event".into());
    }
    if let (Some(session), Some(id), Some(cwd)) = (
        event["session_id"].as_str(),
        event["tool_use_id"].as_str(),
        event["cwd"].as_str(),
    ) {
        distill_core::session::complete(
            config,
            if host == Integration::Codex {
                "codex"
            } else {
                "claude"
            },
            session,
            id,
            Path::new(cwd),
        )?;
    }
    if !config.editor_trace.enabled {
        return Ok(());
    }
    if !has_endpoints() {
        return Ok(());
    }
    let event: Value = serde_json::from_str(input).map_err(|e| e.to_string())?;
    if event["tool_name"] != "Bash" || !is_completion(input) {
        return Err("expected a Bash PostToolUse or PostToolUseFailure event".into());
    }
    let mut trace = envelope(host, &event, config)?;
    trace["kind"] = json!("completion");
    // Preserve the complete response, including structured stdout/stderr.
    trace["tool_response"] = if config.capture_editor_output() {
        event.get("tool_response").cloned().unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    trace["error"] = if config.capture_editor_output() {
        event.get("error").cloned().unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    trace["output_capture_disabled"] = json!(!config.capture_editor_output());
    let code = ["exit_code", "exitCode", "code"]
        .iter()
        .find_map(|key| event["tool_response"][key].as_i64());
    trace["exit_code"] = json!(code);
    trace["cancelled"] = json!(event["is_interrupt"].as_bool().unwrap_or(false));
    trace["failed"] = json!(
        event["hook_event_name"] == "PostToolUseFailure"
            || code.is_some_and(|code| code != 0)
            || event["tool_response"]["is_error"]
                .as_bool()
                .unwrap_or(false)
            || event["tool_response"]["isError"].as_bool().unwrap_or(false)
            || event.get("error").is_some_and(|error| !error.is_null())
    );
    distill_core::privacy::redact_value(&mut trace["tool_response"]);
    distill_core::privacy::redact_value(&mut trace["error"]);
    deliver(trace)
}

pub fn failure(
    host: Integration,
    input: &str,
    error: &str,
    response: &Value,
    config: &distill_core::Config,
) -> Result<(), String> {
    if !has_endpoints() {
        return Ok(());
    }
    let event: Value = serde_json::from_str(input).map_err(|e| e.to_string())?;
    let mut trace = envelope(host, &event, config)?;
    trace["kind"] = json!("assessment");
    trace["report"] = json!({"impact_severity": null, "severity": null, "decision": "unavailable", "explanation": error});
    trace["blocked"] = json!(
        response.pointer("/hookSpecificOutput/permissionDecision") == Some(&json!("deny"))
            || response.get("decision") == Some(&json!("block"))
    );
    deliver(trace)
}

fn has_endpoints() -> bool {
    directory()
        .and_then(|path| std::fs::read_dir(path).ok())
        .is_some_and(|files| {
            files
                .flatten()
                .take(128)
                .any(|file| file.path().extension().and_then(|s| s.to_str()) == Some("json"))
        })
}

#[cfg(unix)]
fn private_metadata(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let owner = std::env::var_os("HOME")
        .and_then(|home| std::fs::metadata(home).ok())
        .map(|m| m.uid());
    metadata.mode() & 0o077 == 0 && owner == Some(metadata.uid())
}

#[cfg(not(unix))]
fn private_metadata(_: &std::fs::Metadata) -> bool {
    false
}

fn envelope(
    host: Integration,
    event: &Value,
    config: &distill_core::Config,
) -> Result<Value, String> {
    let required = |key: &str| {
        event[key]
            .as_str()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| format!("trace requires {key}; chats are never grouped by cwd alone"))
    };
    let command = event
        .pointer("/tool_input/command")
        .and_then(Value::as_str)
        .ok_or("trace requires tool_input.command")?;
    let cwd = event["cwd"].as_str().ok_or("trace requires cwd")?;
    let cwd = std::fs::canonicalize(cwd).unwrap_or_else(|_| PathBuf::from(cwd));
    let execution_cwd = event
        .pointer("/tool_input/workdir")
        .or_else(|| event.pointer("/tool_input/cwd"))
        .and_then(Value::as_str)
        .map(|path| cwd.join(path))
        .unwrap_or_else(|| cwd.clone());
    Ok(json!({
        "protocol": 1,
        "event_id": distill_core::new_id("evt"),
        "editor_pid": std::env::var("VSCODE_PID").ok().and_then(|pid| pid.parse::<u64>().ok()),
        "source": host,
        "session_title": event.get("session_title").or_else(|| event.get("thread_name")).and_then(Value::as_str),
        "session_id": required("session_id")?,
        "tool_use_id": required("tool_use_id")?,
        "hook_event_name": required("hook_event_name")?,
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
        "command": distill_core::privacy::redact(super::authenticated_command(command, config)),
        "cwd": execution_cwd,
        "session_cwd": cwd,
    }))
}

fn deliver(trace: Value) -> Result<(), String> {
    let started = Instant::now();
    let Some(directory) = directory() else {
        return Ok(());
    };
    let metadata = std::fs::symlink_metadata(&directory).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || !private_metadata(&metadata) {
        return Err("trace directory must be private and owned by the current user".into());
    }
    let files = match std::fs::read_dir(directory) {
        Ok(files) => files,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    let Some(cwd) = trace["session_cwd"].as_str() else {
        return Err("trace requires cwd".into());
    };
    let editor_pid = std::env::var("VSCODE_PID")
        .ok()
        .and_then(|pid| pid.parse::<u64>().ok());
    let mut candidates = Vec::new();
    for file in files.flatten().take(128) {
        remaining(started)?;
        let path = file.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.is_file() || metadata.len() > 16 * 1024 || !private_metadata(&metadata) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(endpoint) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if endpoint["protocol"] != 1 {
            continue;
        }
        let specificity = endpoint["roots"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|root| Path::new(cwd).starts_with(root))
            .map(str::len)
            .max();
        if let Some(specificity) = specificity {
            candidates.push((specificity, endpoint));
        }
    }
    if let Some(editor_pid) = editor_pid {
        candidates.retain(|(_, endpoint)| endpoint["editor_pid"].as_u64() == Some(editor_pid));
    }
    if candidates.iter().any(|(_, endpoint)| {
        endpoint["broker_version"]
            .as_u64()
            .is_some_and(|version| version >= 2)
    }) {
        candidates.retain(|(_, endpoint)| {
            endpoint["broker_version"]
                .as_u64()
                .is_some_and(|version| version >= 2)
        });
    }
    candidates.sort_by_key(|(specificity, _)| std::cmp::Reverse(*specificity));
    let Some((specificity, endpoint)) = candidates.first() else {
        return Ok(());
    };
    if candidates
        .iter()
        .skip(1)
        .any(|(score, _)| score == specificity)
    {
        return Err(
            "Ambiguous editor routing; trace was not sent to another editor instance".into(),
        );
    }
    send(endpoint, &trace, started)
}

/// The recorder has its own small deadline and cannot consume the analysis budget.
fn remaining(started: Instant) -> Result<Duration, String> {
    Duration::from_millis(100)
        .checked_sub(started.elapsed())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| "Trace delivery deadline exhausted".into())
}

fn send(endpoint: &Value, trace: &Value, started: Instant) -> Result<(), String> {
    exchange(
        endpoint,
        json!({"action": "record", "event": trace}),
        started,
    )
    .map(|_| ())
}
fn exchange(endpoint: &Value, mut message: Value, started: Instant) -> Result<Value, String> {
    let socket = endpoint["socket"].as_str().ok_or("Trace broker requires the authenticated Unix-socket transport; restart the editor after upgrading")?;
    let directory = directory().ok_or("Trace directory unavailable")?;
    let path = Path::new(socket);
    if path.parent() != Some(directory.as_path()) {
        return Err("Trace socket is outside its private directory".into());
    }
    let token = endpoint["token"].as_str().ok_or("missing trace token")?;
    message["token"] = json!(token);
    let mut bytes = serde_json::to_vec(&message).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_EVENT_BYTES {
        return Err("trace event exceeds 32 MiB; output was not recorded".into());
    }
    bytes.push(b'\n');
    remaining(started)?;
    #[cfg(unix)]
    let mut stream = connect_socket(path, remaining(started)?)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        verify_peer(stream.as_raw_fd())?;
    }
    let mut offset = 0;
    while offset < bytes.len() {
        stream
            .set_write_timeout(Some(remaining(started)?))
            .map_err(|e| e.to_string())?;
        let end = (offset + 64 * 1024).min(bytes.len());
        let written = stream
            .write(&bytes[offset..end])
            .map_err(|e| e.to_string())?;
        if written == 0 {
            return Err("Trace connection closed during delivery".into());
        }
        offset += written;
    }
    let mut ack = Vec::new();
    loop {
        stream
            .set_read_timeout(Some(remaining(started)?))
            .map_err(|e| e.to_string())?;
        let mut chunk = [0; 512];
        let size = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if size == 0 {
            break;
        }
        ack.extend_from_slice(&chunk[..size]);
        if ack.len() > 4096 {
            return Err("Trace acknowledgement is too large".into());
        }
        if ack.contains(&b'\n') {
            break;
        }
    }
    let ack = String::from_utf8(ack).map_err(|e| e.to_string())?;
    let ack: Value = serde_json::from_str(ack.trim()).map_err(|e| e.to_string())?;
    if ack["ok"] != true {
        return Err("trace broker rejected event".into());
    }
    Ok(ack)
}

#[cfg(unix)]
fn connect_socket(
    path: &Path,
    timeout: Duration,
) -> Result<std::os::unix::net::UnixStream, String> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    };
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() {
        return Err("Trace socket path is too long".into());
    }
    address.sun_family = libc::AF_UNIX as _;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as _;
    }
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(raw) };
    stream.set_nonblocking(true).map_err(|e| e.to_string())?;
    let result = unsafe {
        libc::connect(
            stream.as_raw_fd(),
            &address as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as _,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EINPROGRESS | libc::EAGAIN)) {
            return Err(error.to_string());
        }
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        if unsafe { libc::poll(&mut descriptor, 1, timeout.as_millis().max(1) as i32) } <= 0 {
            return Err("Trace connection deadline exhausted".into());
        }
        if let Some(error) = stream.take_error().map_err(|e| e.to_string())? {
            return Err(error.to_string());
        }
    }
    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
    Ok(stream)
}

pub fn coverage() -> Result<Value, String> {
    let directory = directory().ok_or("Trace directory unavailable")?;
    let mut endpoints = Vec::new();
    for entry in std::fs::read_dir(&directory)
        .map_err(|e| e.to_string())?
        .flatten()
        .take(128)
    {
        if entry.path().extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = distill_core::integrity::read_private(&entry.path(), 16384) else {
            continue;
        };
        let Ok(endpoint) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if std::env::var("VSCODE_PID")
            .ok()
            .and_then(|pid| pid.parse::<u64>().ok())
            .is_none_or(|pid| endpoint["editor_pid"] == pid)
        {
            endpoints.push(endpoint);
        }
    }
    if endpoints.len() != 1 {
        return Err("Coverage requires one unambiguous editor broker; supply report JSON with --input instead".into());
    }
    exchange(&endpoints[0], json!({"action": "coverage"}), Instant::now())
}

#[cfg(unix)]
pub fn verify_peer(fd: i32) -> Result<(), String> {
    let uid = unsafe { libc::geteuid() };
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let mut peer_uid = 0;
        let mut peer_gid = 0;
        if unsafe { libc::getpeereid(fd, &mut peer_uid, &mut peer_gid) } != 0 || peer_uid != uid {
            return Err("Unix peer credentials do not match the current user".into());
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut credentials as *mut _ as *mut _,
                &mut length,
            )
        } != 0
            || credentials.uid != uid
        {
            return Err("Unix peer credentials do not match the current user".into());
        }
    }
    Ok(())
}
#[cfg(not(unix))]
pub fn verify_peer(_: i32) -> Result<(), String> {
    Err("Unix peer verification unavailable".into())
}
