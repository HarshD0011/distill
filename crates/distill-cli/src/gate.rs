//! Explicit execution gate. Analysis remains non-executing; only `run` reaches this module.
use distill_core::{
    Config, FileSnapshot,
    integrity::{private_directory, sha256},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
mod linux;

pub struct Options {
    pub command: String,
    pub cwd: Option<PathBuf>,
    pub config: Config,
    pub shell: String,
    pub workspace_roots: Vec<PathBuf>,
    pub writable: Vec<PathBuf>,
    pub approve: Option<String>,
    pub check: bool,
    pub session: Option<String>,
}
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn canonical(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path).map_err(|error| format!("Cannot resolve {}: {error}", path.display()))
}
pub fn backend(config: &Config) -> Result<&'static str, String> {
    match config.sandbox.backend.as_str() {
        "auto" | "seatbelt"
            if cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").is_file() =>
        {
            Ok("seatbelt")
        }
        "auto" | "landlock" if cfg!(target_os = "linux") => Ok("landlock+seccomp"),
        _ => Err(
            "Requested containment backend is unavailable; unsandboxed fallback is forbidden"
                .into(),
        ),
    }
}
pub fn run(mut options: Options) -> Result<i32, String> {
    let cwd = canonical(
        &options
            .cwd
            .take()
            .unwrap_or(std::env::current_dir().map_err(|e| e.to_string())?),
    )?;
    let shell = canonical(Path::new(&options.shell))?;
    if ![
        "/bin/bash",
        "/bin/sh",
        "/bin/zsh",
        "/usr/bin/bash",
        "/usr/bin/dash",
    ]
    .iter()
    .any(|path| canonical(Path::new(path)).ok().as_ref() == Some(&shell))
    {
        return Err("Execution gate requires a trusted system bash, sh, dash, or zsh".into());
    }
    let mut roots = options
        .workspace_roots
        .iter()
        .map(|root| canonical(root))
        .collect::<Result<Vec<_>, _>>()?;
    if roots.is_empty() {
        roots.push(cwd.clone());
    }
    if !roots.iter().any(|root| cwd.starts_with(root)) {
        return Err("Execution directory must belong to a declared workspace".into());
    }
    let writable = options
        .writable
        .iter()
        .map(|path| canonical(path))
        .collect::<Result<Vec<_>, _>>()?;
    if writable.iter().any(|path| {
        !roots.iter().any(|root| path.starts_with(root))
            || options
                .config
                .policy
                .protected_paths
                .iter()
                .any(|root| path.starts_with(root))
    }) {
        return Err(
            "Writable grants must remain inside the workspace and outside protected paths".into(),
        );
    }
    let scratch = Scratch(std::env::temp_dir().join(distill_core::new_id("distill-run")));
    private_directory(&scratch.0)?;
    let config_file = scratch.0.join("policy.toml");
    fs::write(
        &config_file,
        toml::to_string(&options.config).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let mut analyzer = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    analyzer
        .args(["analyze", "--command", &options.command, "--shell"])
        .arg(&shell)
        .arg("--cwd")
        .arg(&cwd)
        .arg("--config")
        .arg(&config_file);
    for root in &roots {
        analyzer.arg("--workspace-root").arg(root);
    }
    let zsh = shell.file_name().is_some_and(|name| name == "zsh");
    let zsh_options = [
        "noaliases",
        "norcs",
        "noglobalrcs",
        "noequals",
        "nomultios",
        "nobanghist",
        "noextendedglob",
        "noglobsubst",
        "noshwordsplit",
        "interactivecomments",
    ];
    if zsh {
        for option in zsh_options {
            analyzer.arg("--shell-option").arg(option);
        }
    }
    if let Some(session) = &options.session {
        analyzer.arg("--session").arg(session);
    }
    // The execution gate owns its deadline; never inherit an opt-out for its analyzer.
    analyzer
        .env_remove("DISTILL_ANALYSIS_WORKER")
        .env_remove("DISTILL_WATCHDOG_MS");
    let output = analyzer.output().map_err(|e| e.to_string())?;
    let report: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "Gate analyzer did not return a valid report")?;
    if !output.status.success() || report["command_digest"] != sha256(options.command.as_bytes()) {
        return Err("Gate analysis failed or command binding is missing".into());
    }
    let request_id = report["request_id"].as_str().unwrap_or("").to_string();
    let snapshots: Vec<FileSnapshot> = serde_json::from_value(report["inspected_files"].clone())
        .map_err(|_| "Dependency bindings are unavailable")?;
    let shell_hash = sha256(&fs::read(&shell).map_err(|e| e.to_string())?);
    let selected_backend = backend(&options.config)?;
    let binding = sha256(serde_json::to_string(&json!({"command": report["command_digest"], "files": snapshots, "policy": report["policy_digest"], "cwd": cwd,
        "shell": shell, "shell_sha256": shell_hash, "backend": selected_backend, "read": roots, "write": writable, "timeout_ms": options.config.sandbox.timeout_ms})).map_err(|e| e.to_string())?.as_bytes());
    if options.check {
        println!(
            "{}",
            json!({"report": report, "execution_binding": binding, "sandbox": {"backend": selected_backend, "network": "deny", "workspace": "read_only", "write_grants": writable, "environment": "cleared", "timeout_ms": options.config.sandbox.timeout_ms}, "dependency_recheck": "immediately before spawn; not an atomic filesystem snapshot"})
        );
        return Ok(0);
    }
    if report["decision"] == "deny" {
        return Err("Execution denied by policy; approval cannot override a denial".into());
    }
    if options
        .approve
        .as_deref()
        .is_some_and(|approval| approval != binding)
    {
        return Err("Execution binding is stale or does not match this command, policy, dependencies, or grants".into());
    }
    if report["decision"] != "allow" && options.approve.as_deref() != Some(&binding) {
        return Err(format!(
            "Review required. Inspect `run --check`, then use --approve {binding} for the same command, policy, dependencies, and grants"
        ));
    }
    let mut command = if selected_backend == "seatbelt" {
        let profile = seatbelt(&roots, &writable, &scratch.0, &options.config)?;
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.args(["-p", &profile]).arg(&shell);
        command
    } else {
        Command::new(&shell)
    };
    command
        .current_dir(&cwd)
        .env_clear()
        .env("HOME", &scratch.0)
        .env("TMPDIR", &scratch.0)
        .env("PATH", "/usr/bin:/bin:/opt/homebrew/bin")
        .env("LANG", "C.UTF-8");
    if zsh {
        command.args(["-f", "-d"]);
        for option in zsh_options {
            command.args(["-o", option]);
        }
    } else if shell.file_name().is_some_and(|name| name == "bash") {
        command.args(["--noprofile", "--norc"]);
    }
    command
        .args(["-c", &options.command])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        unsafe {
            command.pre_exec(|| {
                for (resource, value) in [
                    (libc::RLIMIT_CORE, 0),
                    (libc::RLIMIT_NOFILE, 256),
                    (libc::RLIMIT_CPU, 60),
                ] {
                    let limit = libc::rlimit {
                        rlim_cur: value,
                        rlim_max: value,
                    };
                    if libc::setrlimit(resource, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    if selected_backend == "landlock+seccomp" {
        linux::apply(&mut command, &roots, &writable, &scratch.0)?;
    }
    for snapshot in &snapshots {
        snapshot.verify()?;
    }
    if sha256(&fs::read(&shell).map_err(|e| e.to_string())?) != shell_hash {
        return Err("Shell changed after analysis".into());
    }
    let mut child = command.spawn().map_err(|error| {
        format!("Sandbox launch failed; command was not retried outside containment: {error}")
    })?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            if let Some(session) = &options.session {
                distill_core::session::complete(
                    &options.config,
                    "cli",
                    session,
                    &request_id,
                    &cwd,
                )?;
            }
            return Ok(status.code().unwrap_or(128));
        }
        if started.elapsed() >= Duration::from_millis(options.config.sandbox.timeout_ms) {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err("Sandbox execution deadline exceeded".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn seatbelt(
    roots: &[PathBuf],
    writable: &[PathBuf],
    scratch: &Path,
    config: &Config,
) -> Result<String, String> {
    let quote = |path: &Path| -> Result<String, String> {
        let value = path.to_str().ok_or("Sandbox paths must be UTF-8")?;
        if value.chars().any(char::is_control) {
            return Err("Sandbox paths cannot contain control characters".into());
        }
        Ok(format!(
            "\"{}\"",
            value.replace('\\', "\\\\").replace('"', "\\\"")
        ))
    };
    let mut profile =
        "(version 1)\n(deny default)\n(allow process-exec process-fork sysctl-read)\n(allow file-read-metadata)\n(import \"dyld-support.sb\")\n".to_string();
    let system = [
        "/bin",
        "/usr/bin",
        "/usr/lib",
        "/usr/share",
        "/System/Library",
        "/Library/Apple/System/Library",
        "/opt/homebrew",
        "/dev/null",
        "/dev/urandom",
        "/private/etc",
        "/etc",
    ];
    for path in system
        .iter()
        .map(PathBuf::from)
        .chain(roots.iter().cloned())
        .chain([scratch.to_path_buf()])
    {
        profile.push_str(&format!(
            "(allow file-read* file-map-executable (subpath {}))\n",
            quote(&path)?
        ));
    }
    for path in writable.iter().cloned().chain([scratch.to_path_buf()]) {
        profile.push_str(&format!(
            "(allow file-write* (subpath {}))\n",
            quote(&path)?
        ));
    }
    for root in roots {
        for name in [
            ".git", ".codex", ".claude", ".ssh", ".aws", ".config", ".env", ".envrc", ".vscode",
            ".github",
        ] {
            profile.push_str(&format!(
                "(deny file-write* (subpath {}))\n",
                quote(&root.join(name))?
            ));
            if [".ssh", ".aws", ".env"].contains(&name) {
                profile.push_str(&format!(
                    "(deny file-read* (subpath {}))\n",
                    quote(&root.join(name))?
                ));
            }
        }
    }
    for root in &config.policy.protected_paths {
        profile.push_str(&format!("(deny file-write* (subpath {}))\n", quote(root)?));
    }
    profile.push_str(r#"(deny file-read* (regex #"(^|/)([.]env($|[./])|[.]ssh(/|$)|[.]aws(/|$)|[.]gnupg(/|$)|[.]kube(/|$)|[.]npmrc$|[.]netrc$|id_rsa$|id_ed25519$)"))
(deny file-write* (regex #"(^|/)([.]git(/|$)|[.]codex(/|$)|[.]claude(/|$)|[.]vscode(/|$)|[.]github(/|$)|[.]envrc$|package[.]json$)"))
"#);
    // No network, IPC, Mach lookup, process signalling, or task inspection grants.
    Ok(profile)
}
