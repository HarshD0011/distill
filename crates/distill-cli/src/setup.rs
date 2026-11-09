//! User-level installation. Workspace files are inspected and never modified here.
use distill_core::{
    Config,
    integrity::{create_key, key_path, private_directory, sha256},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};
// Older, still-running host sessions cache their hook command and policy path.
// Never rewrite that policy using fields their pinned executable cannot parse.
pub fn policy_path(home: &Path, host: &str) -> PathBuf {
    home.join(format!(".config/distill/hook-policy-v3-{host}.toml"))
}

pub fn load_config(host: &str, explicit: Option<&Path>) -> Result<Config, String> {
    if explicit.is_some() {
        return Config::load(explicit);
    }
    let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME unavailable")?);
    for stored in [
        policy_path(&home, host),
        home.join(format!(".config/distill/hook-policy-v2-{host}.toml")),
        home.join(format!(".config/distill/hook-policy-{host}.toml")),
    ] {
        if let Some(bytes) = read_user_file(&stored)? {
            let config: Config =
                toml::from_str(std::str::from_utf8(&bytes).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            config.validate()?;
            return Ok(config);
        }
    }
    Config::load(None)
}

pub fn configure_router(
    host: &str,
    judge: distill_core::JudgeConfig,
    memory_only: bool,
) -> Result<Value, String> {
    let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME unavailable")?);
    let path = policy_path(&home, host);
    let original = read_user_file(&path)?;
    let mut config = load_config(host, None)?;
    let before = toml::to_string(&config).map_err(|e| e.to_string())?;
    config.judge = judge;
    if memory_only {
        config.service.history_enabled = false;
        config.history.enabled = false;
        config.ledger.enabled = false;
    }
    config.validate()?;
    let updated = toml::to_string(&config).map_err(|e| e.to_string())?;
    let changed = original.is_none() || before != updated;
    if changed {
        private_directory(path.parent().ok_or("Policy directory unavailable")?)?;
        if read_user_file(&path)? != original {
            return Err("User policy changed while applying router settings; retry".into());
        }
        atomic_private(&path, updated.as_bytes())?;
    }
    Ok(
        json!({"policy_path":path,"policy_digest":config.digest(),"changed":changed,"history_enabled":config.service.history_enabled,"router":config.judge}),
    )
}
pub fn configure(
    host: &str,
    config: &Config,
    roots: &[PathBuf],
    check: bool,
    labels: bool,
    node_runtime: Option<&Path>,
    debug_log: Option<&Path>,
) -> Result<Value, String> {
    if debug_log.is_some_and(|path| !path.is_absolute()) {
        return Err("Hook debug log path must be absolute".into());
    }
    let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME unavailable")?);
    let directory = if host == "codex" {
        std::env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".codex"))
    } else {
        home.join(".claude")
    };
    if !directory.is_absolute() || roots.iter().any(|root| directory.starts_with(root)) {
        return Err("Hook installation requires a user directory outside the workspace".into());
    }
    let file = directory.join(if host == "codex" {
        "hooks.json"
    } else {
        "settings.json"
    });
    let original_bytes = read_user_file(&file)?;
    let mut existing: Value = match &original_bytes {
        Some(bytes) => serde_json::from_slice(bytes).map_err(|e| e.to_string())?,
        None => json!({}),
    };
    let binary = fs::canonicalize(std::env::current_exe().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let digest = sha256(&fs::read(&binary).map_err(|e| e.to_string())?);
    let state = home.join(".config/distill");
    let (launcher, launcher_source, launcher_command) = if let Some(runtime) = node_runtime {
        if !runtime.is_absolute() {
            return Err("Node runtime must be an absolute executable path".into());
        }
        let runtime = fs::canonicalize(runtime).map_err(|e| e.to_string())?;
        if !runtime.is_file() || roots.iter().any(|root| runtime.starts_with(root)) {
            return Err("Node runtime must be installed outside the workspace".into());
        }
        let launcher = state.join("hook-launcher.js");
        let command = format!(
            "/usr/bin/env -u NODE_OPTIONS -u NODE_PATH -u LD_PRELOAD -u LD_LIBRARY_PATH -u DYLD_INSERT_LIBRARIES -u DYLD_LIBRARY_PATH ELECTRON_RUN_AS_NODE=1 {} {}",
            quote(&runtime),
            quote(&launcher)
        );
        (launcher, NODE_LAUNCHER, command)
    } else {
        let launcher = state.join("hook-launcher.py");
        let command = format!("/usr/bin/python3 -I {}", quote(&launcher));
        (launcher, LAUNCHER, command)
    };
    let policy = policy_path(&home, host);
    let mut pinned_config = config.clone();
    pinned_config.security.label_key_path = key_path(config);
    let events = if host == "codex" {
        vec!["PreToolUse", "PermissionRequest", "PostToolUse"]
    } else {
        vec!["PreToolUse", "PostToolUse", "PostToolUseFailure"]
    };
    if !existing.is_object() {
        return Err("User hook source must be an object".into());
    }
    if existing.get("hooks").is_none() {
        existing["hooks"] = json!({});
    }
    let hooks = existing["hooks"]
        .as_object_mut()
        .ok_or("User hooks must be an object")?;
    let mut needs_key = labels;
    for event in &events {
        let groups = hooks
            .entry(event.to_string())
            .or_insert(json!([]))
            .as_array_mut()
            .ok_or("Hook groups must be arrays")?;
        let mut mode = match if host == "codex" {
            config.agents.codex.mode
        } else {
            config.agents.claude.mode
        } {
            distill_core::AgentMode::Strict => "strict",
            _ => "advisory",
        };
        let mut preserve_labels = false;
        for group in groups.iter_mut() {
            let handlers = group["hooks"]
                .as_array_mut()
                .ok_or("Hook handlers must be arrays")?;
            handlers.retain(|handler| {
                let command = handler["command"].as_str().unwrap_or("");
                let ours = crate::hook_sources::distill_handler(command, host).is_some();
                if ours && command.contains("--mode strict") {
                    mode = "strict";
                }
                preserve_labels |= ours && command.contains("--label-command");
                !ours
            });
        }
        groups.retain(|group| {
            group["hooks"]
                .as_array()
                .is_some_and(|handlers| !handlers.is_empty())
        });
        let label = if (labels || preserve_labels)
            && host == "codex"
            && *event == "PreToolUse"
            && mode == "advisory"
        {
            " --label-command"
        } else {
            ""
        };
        // -I prevents repository modules and PYTHON* injection into the pin-checking launcher.
        needs_key |= !label.is_empty();
        let debug = debug_log
            .map(|path| format!(" --debug-log {}", quote(path)))
            .unwrap_or_default();
        let command = format!(
            "{launcher_command} --binary {} --sha256 {} hook {host} --config {} --mode {mode}{label}{debug}",
            quote(&binary),
            digest,
            quote(&policy)
        );
        let timeout = if *event == "PostToolUse" || *event == "PostToolUseFailure" {
            10
        } else {
            150
        };
        groups.push(json!({"matcher": "^(Bash|Write|Edit|MultiEdit)$", "hooks": [{"type": "command", "command": command, "timeout": timeout}]}));
    }
    let inventory = crate::hook_sources::inspect(host, roots)?;
    if inventory["handlers"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|handler| {
            handler["scope"] == "user"
                && handler["path"]
                    .as_str()
                    .is_some_and(|path| Path::new(path) != file)
        })
    {
        return Err("Another user hook source already defines Distill handlers; consolidate those definitions before installing additional handlers".into());
    }
    if !check {
        user_directory(&directory)?;
        private_directory(&state)?;
        if needs_key {
            create_key(
                pinned_config
                    .security
                    .label_key_path
                    .as_deref()
                    .ok_or("Key path unavailable")?,
            )?;
        }
        atomic_private(&launcher, launcher_source.as_bytes())?;
        if read_user_file(&file)?.as_deref() != original_bytes.as_deref() {
            return Err(
                "User hook configuration changed during setup; retry after reviewing it".into(),
            );
        }
        atomic_private(
            &policy,
            toml::to_string(&pinned_config)
                .map_err(|e| e.to_string())?
                .as_bytes(),
        )?;
        atomic_private(
            &file,
            serde_json::to_string_pretty(&existing)
                .map_err(|e| e.to_string())?
                .as_bytes(),
        )?;
    }
    Ok(
        json!({"path": file, "policy_path": policy, "configuration": existing, "binary": binary, "binary_sha256": digest, "changed": !check, "workspace_warnings": inventory["warnings"],
        "project_handlers": inventory["handlers"].as_array().into_iter().flatten().filter(|h| h["scope"] == "project").collect::<Vec<_>>(),
        "next_step": if host == "codex" { "Review and trust the changed user hooks in /hooks" } else { "Restart or resume Claude Code to load user hooks" }}),
    )
}
fn quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\"'\"'"))
}
fn user_directory(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return private_directory(path);
    }
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err("User hook directory must be owned by the current user and not writable by other users".into());
        }
    }
    Ok(())
}
fn read_user_file(path: &Path) -> Result<Option<Vec<u8>>, String> {
    use std::io::Read;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(
                "User hooks must be owned by the current user and not writable by others".into(),
            );
        }
    }
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err("User hooks must be a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("User hook source exceeds its size limit".into());
    }
    Ok(Some(bytes))
}
fn atomic_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let temporary = path.with_extension(distill_core::new_id("tmp"));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(temporary, path).map_err(|e| e.to_string())
}
const LAUNCHER: &str = r#"import hashlib, os, stat, sys
def deny(message):
    import json
    try: event = json.loads(sys.stdin.buffer.read(32 * 1024 * 1024 + 1)).get('hook_event_name', 'PreToolUse')
    except (ValueError, AttributeError): event = 'PreToolUse'
    if event == 'PermissionRequest':
        details = {'hookEventName': event, 'decision': {'behavior': 'deny', 'message': message}}
    else:
        details = {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny', 'permissionDecisionReason': message}
    print(json.dumps({'systemMessage': message, 'hookSpecificOutput': details}))
    raise SystemExit(2)
if len(sys.argv) < 7 or sys.argv[1] != '--binary' or sys.argv[3] != '--sha256':
    deny('Distill: invalid pinned launcher arguments')
binary, expected = sys.argv[2], sys.argv[4]
if not os.path.isabs(binary): deny('Distill: executable must be absolute')
try:
    fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as executable:
        if not stat.S_ISREG(os.fstat(executable.fileno()).st_mode): deny('Distill: executable is not a regular file')
        digest = hashlib.sha256()
        for chunk in iter(lambda: executable.read(65536), b''): digest.update(chunk)
    if digest.hexdigest() != expected: deny('Distill: pinned executable changed; reinstall trusted user hooks')
except OSError: deny('Distill: pinned executable unavailable')
environment = {key: value for key, value in os.environ.items() if key not in {'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'PYTHONPATH', 'PYTHONHOME', 'DISTILL_ANALYSIS_WORKER', 'DISTILL_WATCHDOG_MS'}}
os.execve(binary, [binary, *sys.argv[5:]], environment)
"#;
const NODE_LAUNCHER: &str = include_str!("../../../integrations/node/hook-launcher.js");
