//! Real execution tests use only harmless commands and disposable fixture paths.
use serde_json::Value;
use std::{fs, path::PathBuf, process::Command};
fn fixture() -> PathBuf {
    let root = std::env::temp_dir().join(distill_core::new_id("distill-runtime-test"));
    fs::create_dir(&root).unwrap();
    root
}
fn cli(root: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_distill"));
    command
        .env("HOME", root.join("home"))
        .env("DISTILL_TRACE_DIR", root.join("no-recorder"));
    command
}
fn check(root: &std::path::Path, source: &str, grants: &[&std::path::Path]) -> Value {
    let mut command = cli(root);
    command
        .args(["run", "--command", source, "--check", "--cwd"])
        .arg(root);
    for grant in grants {
        command.arg("--write").arg(grant);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "status={:?}; stderr={}; stdout={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn execution_bindings_change_with_dependencies_and_grants() {
    let root = fixture();
    fs::write(root.join("script.py"), "print(1)").unwrap();
    let first = check(&root, "python3 script.py", &[]);
    assert_eq!(
        first["report"]["inspected_files"].as_array().unwrap().len(),
        1
    );
    fs::write(root.join("script.py"), "print(2)").unwrap();
    let second = check(&root, "python3 script.py", &[]);
    assert_ne!(first["execution_binding"], second["execution_binding"]);
    let grant = check(&root, "python3 script.py", &[&root]);
    assert_ne!(grant["execution_binding"], second["execution_binding"]);
    let output = cli(&root)
        .args(["run", "--command", "python3 script.py", "--cwd"])
        .arg(&root)
        .arg("--approve")
        .arg(first["execution_binding"].as_str().unwrap())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("stale"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn user_setup_is_pinned_idempotent_and_never_edits_project_hooks() {
    let root = fixture();
    let home = root.join("home");
    fs::create_dir_all(root.join("workspace/.codex")).unwrap();
    fs::write(root.join("workspace/.codex/hooks.json"), "{\"hooks\":{}}\n").unwrap();
    fs::create_dir_all(home.join(".config/distill")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            home.join(".config/distill"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let legacy = home.join(".config/distill/hook-policy-v2-codex.toml");
    let legacy_bytes =
        "# An active older hook still reads these exact bytes.\n[policy]\nhigh = 'deny'\n";
    fs::write(&legacy, legacy_bytes).unwrap();
    let mut command = cli(&root);
    command
        .args(["setup", "codex", "--workspace-root"])
        .arg(root.join("workspace"))
        .arg("--debug-log")
        .arg(root.join("debug with spaces.jsonl"));
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let first = fs::read(home.join(".codex/hooks.json")).unwrap();
    let value: Value = serde_json::from_slice(&first).unwrap();
    let hook = value["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(hook.contains("--sha256"));
    assert!(!hook.contains("--label-command"));
    assert!(!hook.contains("--workspace-root"));
    assert!(hook.contains("--debug-log"));
    assert!(hook.contains("debug with spaces.jsonl'"));
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(first, fs::read(home.join(".codex/hooks.json")).unwrap());
    assert_eq!(fs::read_to_string(&legacy).unwrap(), legacy_bytes);
    let policy_file = home.join(".config/distill/hook-policy-v3-codex.toml");
    assert!(hook.contains("hook-policy-v3-codex.toml"));
    let mut policy: toml::Value =
        toml::from_str(&fs::read_to_string(&policy_file).unwrap()).unwrap();
    assert_eq!(policy["policy"]["high"].as_str(), Some("deny"));
    policy["policy"]["high"] = toml::Value::String("deny".into());
    fs::write(&policy_file, toml::to_string(&policy).unwrap()).unwrap();
    assert!(command.output().unwrap().status.success());
    let retained: toml::Value = toml::from_str(&fs::read_to_string(&policy_file).unwrap()).unwrap();
    assert_eq!(retained["policy"]["high"].as_str(), Some("deny"));
    assert_eq!(fs::read_to_string(&legacy).unwrap(), legacy_bytes);
    use std::{io::Write, process::Stdio};
    let mut launcher = Command::new("/usr/bin/python3")
        .arg("-I")
        .arg(home.join(".config/distill/hook-launcher.py"))
        .args([
            "--binary",
            env!("CARGO_BIN_EXE_distill"),
            "--sha256",
            "invalid",
            "hook",
            "codex",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    launcher
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"hook_event_name":"PermissionRequest"}"#)
        .unwrap();
    let rejected = launcher.wait_with_output().unwrap();
    assert_eq!(rejected.status.code(), Some(2));
    let rejected: Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(
        rejected["hookSpecificOutput"]["decision"]["behavior"],
        "deny"
    );
    assert_eq!(
        fs::read_to_string(root.join("workspace/.codex/hooks.json")).unwrap(),
        "{\"hooks\":{}}\n"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn watchdog_returns_high_denial_in_the_correct_hook_schema() {
    use std::{io::Write, process::Stdio};
    let root = fixture();
    let mut child = cli(&root)
        .args(["hook", "codex", "--mode", "advisory"])
        .arg("--debug-log")
        .arg(root.join("debug.jsonl"))
        .env("DISTILL_WATCHDOG_MS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(serde_json::json!({"hook_event_name":"PermissionRequest", "tool_name":"Bash", "cwd":"/tmp", "tool_input":{"command":"echo hello;".repeat(4000)}}).to_string().as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["hookSpecificOutput"]["hookEventName"],
        "PermissionRequest"
    );
    assert_eq!(value["hookSpecificOutput"]["decision"]["behavior"], "deny");
    let records = fs::read_to_string(root.join("debug.jsonl")).unwrap();
    let records = records
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.first().unwrap()["stage"], "received");
    assert_eq!(records.last().unwrap()["stage"], "failed");
    assert_eq!(records.last().unwrap()["permission_decision"], "deny");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn router_settings_preserve_other_policy_and_reject_invalid_updates_atomically() {
    use std::{io::Write, process::Stdio};
    let root = fixture();
    let home = root.join("home");
    fs::create_dir_all(home.join(".config/distill")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            home.join(".config/distill"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let legacy = home.join(".config/distill/hook-policy-codex.toml");
    let legacy_bytes = "[policy]\nhigh='deny'\n[service]\nhistory_enabled=true\n";
    fs::write(&legacy, legacy_bytes).unwrap();
    let update = |settings: Value, memory_only: bool| {
        let mut command = cli(&root);
        command.args(["configure-router", "codex"]);
        if memory_only {
            command.arg("--memory-only");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(settings.to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let settings = serde_json::json!({"enabled":true,"provider":"llama_cpp","endpoint":"http://127.0.0.1:8080/v1/chat/completions","model":"served-model","api_key_env":""});
    let result = update(settings.clone(), false);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["router"]["model"], "served-model");
    assert_eq!(result["history_enabled"], true);
    let policy = home.join(".config/distill/hook-policy-v3-codex.toml");
    let before = fs::read(&policy).unwrap();
    let config = distill_core::Config::load(Some(&policy)).unwrap();
    assert_eq!(config.policy.high, distill_core::PolicyAction::Deny);
    assert!(config.service.history_enabled);
    assert_eq!(fs::read_to_string(&legacy).unwrap(), legacy_bytes);
    assert_eq!(
        serde_json::from_slice::<Value>(&update(settings, false).stdout).unwrap()["changed"],
        false
    );
    assert!(
        !update(serde_json::json!({"enabled":true,"model":""}), false)
            .status
            .success()
    );
    assert_eq!(fs::read(&policy).unwrap(), before);
    assert!(
        update(serde_json::json!({"enabled":false}), false)
            .status
            .success()
    );
    assert!(
        !distill_core::Config::load(Some(&policy))
            .unwrap()
            .judge
            .enabled
    );
    let memory = update(serde_json::json!({"enabled":false}), true);
    assert!(memory.status.success());
    let config = distill_core::Config::load(Some(&policy)).unwrap();
    assert!(!config.service.history_enabled);
    assert!(!config.history.enabled);
    assert!(!config.ledger.enabled);
    assert_eq!(fs::read_to_string(&legacy).unwrap(), legacy_bytes);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn hook_debug_records_metadata_and_verdicts_without_command_or_output() {
    use std::{io::Write, process::Stdio};
    let root = fixture();
    let log = root.join("debug.jsonl");
    let secret = "debug-private-payload-must-not-be-recorded";
    let mut event = serde_json::json!({
        "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": root,
        "session_id": "debug-session", "tool_use_id": "debug-tool",
        "tool_input": {"command": format!("echo {secret}"), "workdir": root, "extra": secret},
    });
    for stage in ["PreToolUse", "PostToolUse"] {
        event["hook_event_name"] = serde_json::json!(stage);
        if stage == "PostToolUse" {
            event["tool_response"] = serde_json::json!({"stdout": secret, "exit_code": 0});
        }
        let mut child = cli(&root)
            .args(["hook", "codex", "--mode", "advisory", "--no-prompt"])
            .arg(format!("--debug-log={}", log.display()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(event.to_string().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        if stage == "PreToolUse" {
            let message = response["systemMessage"].as_str().unwrap();
            assert!(message.contains("Severity: SAFE"));
            assert!(message.contains("Approval risk: HIGH"));
        } else {
            assert_eq!(response, serde_json::json!({}));
        }
    }
    let text = fs::read_to_string(&log).unwrap();
    assert!(!text.contains(secret));
    let records = text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 6);
    assert_eq!(records[0]["stage"], "received");
    assert_eq!(records[0]["shell"], Value::Null);
    assert_eq!(records[0]["tool_use_id"], "debug-tool");
    assert_eq!(records[0]["input_digest"], records[1]["input_digest"]);
    assert_eq!(records[1]["stage"], "assessed");
    assert_eq!(records[1]["analysis"]["impact_severity"], "safe");
    assert_eq!(records[1]["analysis"]["approval_risk"], "high");
    assert_eq!(records[1]["analysis"]["decision"], "ask");
    assert_eq!(records[1]["analysis"]["coverage"], "partial");
    assert_eq!(records[2]["stage"], "completed");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&log).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn coverage_ranks_unknown_options_without_revealing_argument_values() {
    use std::{io::Write, process::Stdio};
    let root = fixture();
    let mut child = cli(&root)
        .arg("coverage")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(br#"[{"command_redacted":"mystery --token=private-value", "decision":"ask", "coverage":{"summary":"opaque"}, "unknowns":["Unknown command definition"]}]"#).unwrap();
    let output = child.wait_with_output().unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["commands"][0]["name"], "mystery");
    assert_eq!(value["flags"][0]["name"], "mystery --token");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-value"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires a host containment backend"]
fn sandbox_enforces_writes_and_clears_inherited_secrets() {
    if std::env::var_os("DISTILL_SANDBOX_TESTS").is_none() {
        return;
    }
    let root = fixture();
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    let output = cli(&root)
        .args([
            "run",
            "--command",
            "printf '%s' \"$DISTILL_TEST_SECRET\"",
            "--cwd",
        ])
        .arg(&workspace)
        .env("DISTILL_TEST_SECRET", "must-not-leak")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("must-not-leak"));
    let outside = root.join("outside");
    fs::write(&outside, "original").unwrap();
    let source = format!("printf changed > '{}'", outside.display());
    let review = check(&workspace, &source, &[]);
    let output = cli(&root)
        .args(["run", "--command", &source, "--cwd"])
        .arg(&workspace)
        .arg("--approve")
        .arg(review["execution_binding"].as_str().unwrap())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&outside).unwrap(), "original");
    let source = "printf granted > result";
    let review = check(&workspace, source, &[&workspace]);
    let output = cli(&root)
        .args(["run", "--command", source, "--cwd"])
        .arg(&workspace)
        .arg("--write")
        .arg(&workspace)
        .arg("--approve")
        .arg(review["execution_binding"].as_str().unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(workspace.join("result")).unwrap(),
        "granted"
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let source = format!(
        "/usr/bin/curl --connect-timeout 1 --max-time 1 --noproxy '*' http://{}",
        listener.local_addr().unwrap()
    );
    let review = check(&workspace, &source, &[]);
    let output = cli(&root)
        .args(["run", "--command", &source, "--cwd"])
        .arg(&workspace)
        .arg("--approve")
        .arg(review["execution_binding"].as_str().unwrap())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    fs::write(workspace.join(".env"), "DISTILL_SECRET=must-not-leak").unwrap();
    let source = "cat .env";
    let review = check(&workspace, source, &[]);
    let output = cli(&root)
        .args(["run", "--command", source, "--cwd"])
        .arg(&workspace)
        .arg("--approve")
        .arg(review["execution_binding"].as_str().unwrap())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("must-not-leak"));
    fs::remove_dir_all(root).unwrap();
}
