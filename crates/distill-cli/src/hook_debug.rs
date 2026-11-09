//! Opt-in, bounded hook diagnostics. Never record command text, output, or environment.
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;

pub fn record(args: &[String], input: &[u8], stage: &str, output: Option<&[u8]>) {
    if args.first().map(String::as_str) != Some("hook") {
        return;
    }
    let path = args.iter().enumerate().find_map(|(index, arg)| {
        if arg == "--debug-log" {
            args.get(index + 1).map(PathBuf::from)
        } else {
            arg.strip_prefix("--debug-log=").map(PathBuf::from)
        }
    });
    let Some(path) = path else { return };
    if let Err(error) = append(&path, &entry(args, input, stage, output)) {
        // Diagnostics must never change the policy response on stdout.
        eprintln!("distill hook debug: {error}");
    }
}

fn string(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(|value| value.chars().take(1024).collect())
}

fn keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .into_iter()
        .flat_map(|object| object.keys())
        .take(64)
        .map(|key| key.chars().take(128).collect())
        .collect()
}

fn entry(args: &[String], input: &[u8], stage: &str, output: Option<&[u8]>) -> Value {
    let event = serde_json::from_slice::<Value>(input).ok();
    let empty = Value::Null;
    let event_value = event.as_ref().unwrap_or(&empty);
    let tool = &event_value["tool_input"];
    let output = output.and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok());
    let output = output.as_ref().unwrap_or(&empty);
    let report = &output["report"];
    let response = output.get("distill_hook_response").unwrap_or(output);
    json!({
        "schema_version": 1,
        "timestamp_ms": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),
        "pid": std::process::id(),
        "stage": stage,
        "host": args.get(1),
        "input_bytes": input.len(),
        "input_digest": distill_core::sha256(input),
        "valid_json": event.is_some(),
        "input_keys": keys(event_value),
        "tool_input_keys": keys(tool),
        "hook_event_name": string(&event_value["hook_event_name"]),
        "session_id": string(&event_value["session_id"]),
        "turn_id": string(&event_value["turn_id"]),
        "tool_use_id": string(&event_value["tool_use_id"]),
        "tool_name": string(&event_value["tool_name"]),
        "session_cwd": string(&event_value["cwd"]),
        "execution_cwd": tool.get("workdir").or_else(|| tool.get("cwd")).and_then(string),
        "shell": string(&tool["shell"]),
        "shell_options": tool["shell_options"].as_array().map(|options| options.iter().take(64).map(string).collect::<Vec<_>>()),
        "analysis": report.is_object().then(|| json!({
            "shell": report["analysis_context"]["shell"],
            "shell_dialect": report["shell_dialect"],
            "impact_severity": report["impact_severity"],
            "approval_risk": report["severity"],
            "decision": report["decision"],
            "coverage": report["coverage"]["summary"],
            "unknown_count": report["unknowns"].as_array().map(Vec::len),
        })),
        "permission_decision": response.pointer("/hookSpecificOutput/permissionDecision")
            .or_else(|| response.pointer("/hookSpecificOutput/decision/behavior")).and_then(string),
    })
}

fn append(path: &Path, entry: &Value) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("log path must be absolute".into());
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("log must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(
                "log must be private, owned by the current user, and not hard-linked".into(),
            );
        }
    }
    let mut bytes = serde_json::to_vec(entry).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if metadata.len().saturating_add(bytes.len() as u64) > MAX_LOG_BYTES {
        return Err("log reached its 8 MiB limit; choose a new path".into());
    }
    file.write_all(&bytes).map_err(|error| error.to_string())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    #[test]
    fn rejects_unsafe_destinations_and_bounds_log_growth() {
        let root = std::env::temp_dir().join(distill_core::new_id("hook-debug-test"));
        fs::create_dir(&root).unwrap();
        let target = root.join("target.jsonl");
        fs::write(&target, "untouched").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.join("link.jsonl");
        symlink(&target, &link).unwrap();
        assert!(append(&link, &json!({"stage": "received"})).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(append(&target, &json!({})).is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let hard = root.join("hard.jsonl");
        fs::hard_link(&target, &hard).unwrap();
        assert!(append(&hard, &json!({})).is_err());
        let full = root.join("full.jsonl");
        append(&full, &json!({})).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&full)
            .unwrap()
            .set_len(MAX_LOG_BYTES)
            .unwrap();
        assert!(append(&full, &json!({})).is_err());
        assert_eq!(fs::metadata(&full).unwrap().len(), MAX_LOG_BYTES);
        assert!(append(Path::new("relative.jsonl"), &json!({})).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
