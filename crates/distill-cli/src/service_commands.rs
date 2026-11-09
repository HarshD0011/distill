use clap::ValueEnum;
use distill_core::{Config, service_ipc};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, ValueEnum)]
pub enum Action {
    Start,
    Stop,
    Status,
}

pub fn configuration(path: Option<PathBuf>) -> Result<Config, String> {
    // Editor-installed hooks have a dedicated user policy; use it when the
    // service is invoked without an explicit configuration or global config.
    if let Some(path) = path.as_ref()
        && (!path.is_absolute() || !path.is_file())
    {
        return Err("Explicit service configuration must be an existing absolute file".into());
    }
    let path = selected_config(path);
    Config::load(path.as_deref())
}
pub fn call(path: Option<PathBuf>, method: &str, params: Value) -> Result<Value, String> {
    service_ipc::request(
        &configuration(path)?,
        method,
        params,
        Duration::from_millis(1500),
    )
}

pub fn export_data(path: Option<PathBuf>, mut params: Value) -> Result<Value, String> {
    let config = configuration(path)?;
    let mut events = std::collections::BTreeMap::new();
    let mut feedback = std::collections::BTreeMap::new();
    let mut offset = 0;
    let mut bytes = 0;
    let mut truncated = false;
    while offset < config.service.max_events {
        params["offset"] = json!(offset);
        params["limit"] = json!(1000);
        let page = service_ipc::request(
            &config,
            "export",
            params.clone(),
            Duration::from_millis(1500),
        )?;
        let rows = page["events"].as_array().ok_or("Invalid export page")?;
        for row in rows {
            bytes += row.to_string().len();
            if bytes > 32 * 1024 * 1024 {
                truncated = true;
                break;
            }
            events.insert(
                row["event_id"]
                    .as_str()
                    .ok_or("Missing event identity")?
                    .to_owned(),
                row.clone(),
            );
        }
        for row in page["feedback"].as_array().into_iter().flatten() {
            bytes += row.to_string().len();
            if bytes > 32 * 1024 * 1024 {
                truncated = true;
                break;
            }
            feedback.insert(row.to_string(), row.clone());
        }
        offset += rows.len();
        if truncated || page["has_more"] != true {
            break;
        }
        if rows.is_empty() {
            truncated = true;
            break;
        }
    }
    let mut events: Vec<_> = events.into_values().collect();
    events.sort_by_key(|v| v["timestamp"].as_i64().unwrap_or(0));
    Ok(
        json!({"schema_version":1,"events":events,"feedback":feedback.into_values().collect::<Vec<_>>(),"truncated":truncated,"scope":"Paged retained observations; concurrent additions can change pagination. Missing completion does not establish rejection."}),
    )
}
pub fn manage(
    action: Action,
    path: Option<PathBuf>,
    binary: Option<PathBuf>,
    credential_stdin: bool,
) -> Result<Value, String> {
    let config = configuration(path.clone())?;
    if credential_stdin && !matches!(action, Action::Start) {
        return Err("Credential handoff is only accepted on service start".into());
    }
    let credential = if !matches!(action, Action::Start) {
        None
    } else if credential_stdin {
        Some(distill_core::credentials::ServiceCredential::read(
            std::io::stdin().lock(),
            &config.judge,
        )?)
    } else {
        Some(distill_core::credentials::ServiceCredential::from_environment(&config.judge)?)
    };
    match action {
        Action::Status => Ok(
            match service_ipc::request(&config, "hello", json!({}), Duration::from_millis(100)) {
                Ok(mut v) => {
                    v["running"] = json!(true);
                    v
                }
                Err(_) => {
                    json!({"running":false,"history_enabled":config.service.history_enabled,"judge_enabled":config.judge.enabled})
                }
            },
        ),
        Action::Stop => {
            service_ipc::request(&config, "stop", json!({}), Duration::from_millis(200))
        }
        Action::Start => {
            let credential = credential.ok_or("Service credential handoff unavailable")?;
            if !config.service.history_enabled && !config.judge.enabled {
                return Err("Enable service.history_enabled or judge.enabled in your user policy before starting optional services".into());
            }
            if let Ok(mut value) =
                service_ipc::request(&config, "hello", json!({}), Duration::from_millis(100))
            {
                if value["policy_digest"] != config.digest() {
                    return Err("Optional service has a different policy; stop and start it to apply the current configuration".into());
                }
                value["running"] = json!(true);
                return Ok(value);
            }
            let binary = binary.unwrap_or(
                std::env::current_exe()
                    .map_err(|e| e.to_string())?
                    .with_file_name("distill-service"),
            );
            if !binary.is_absolute() {
                return Err("Service binary must be absolute".into());
            }
            let meta = std::fs::symlink_metadata(&binary).map_err(
                |_| "Install the service binary from the current platform extension package",
            )?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if !meta.is_file()
                    || meta.file_type().is_symlink()
                    || meta.mode() & 0o022 != 0
                    || ![0, unsafe { libc::geteuid() }].contains(&meta.uid())
                {
                    return Err("Service binary must be a trusted user/system file".into());
                }
            }
            let mut command = Command::new(binary);
            command.arg("--credential-stdin");
            let selected = selected_config(path);
            if let Some(path) = selected {
                command.arg("--config").arg(path);
            }
            if let Some(owner) = std::env::var("DISTILL_SERVICE_OWNER_PID")
                .ok()
                .and_then(|v| v.parse::<i32>().ok())
                .filter(|v| *v > 1)
            {
                command.arg("--owner-pid").arg(owner.to_string());
            }
            command
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            for name in ["HOME"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                command.process_group(0);
            }
            let mut child = command.spawn().map_err(|e| e.to_string())?;
            if credential
                .write(child.stdin.take().ok_or("Credential pipe unavailable")?)
                .is_err()
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Service credential handoff failed".into());
            }
            drop(credential);
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(3) {
                if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                    return Err(format!(
                        "Optional service exited ({status}); run distill-service --config /absolute/policy.toml in a terminal to inspect configuration"
                    ));
                }
                if let Ok(mut value) =
                    service_ipc::request(&config, "hello", json!({}), Duration::from_millis(100))
                {
                    value["running"] = json!(true);
                    return Ok(value);
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            let _ = child.kill();
            let _ = child.wait();
            Err("Optional service startup deadline exceeded".into())
        }
    }
}

pub fn markdown(result: &Value) -> String {
    let mut output = String::from(
        "# Distill session audit\n\nRetained observations. Missing completion does not establish rejection.\n\n",
    );
    for event in result["events"].as_array().into_iter().flatten() {
        let command = event["command"].as_str().unwrap_or("");
        let fence = "`".repeat(
            command
                .split(|c| c != '`')
                .map(str::len)
                .max()
                .unwrap_or(0)
                .max(3)
                + 1,
        );
        output.push_str(&format!(
            "## {} · {}\n\n{fence}sh\n{command}\n{fence}\n\n",
            event["kind"].as_str().unwrap_or("event"),
            event["report"]["impact_severity"]
                .as_str()
                .unwrap_or("unknown")
        ));
    }
    output
}

fn selected_config(path: Option<PathBuf>) -> Option<PathBuf> {
    path.or_else(|| {
        std::env::var_os("HOME").and_then(|home| {
            let home = PathBuf::from(home);
            [
                crate::setup::policy_path(&home, "codex"),
                home.join(".config/distill/hook-policy-v2-codex.toml"),
                home.join(".config/distill/hook-policy-codex.toml"),
            ]
            .into_iter()
            .find(|path| path.is_file())
        })
    })
    .or_else(distill_core::default_config_path)
    .filter(|v| v.is_file())
}
