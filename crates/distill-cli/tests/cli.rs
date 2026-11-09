use std::{
    io::Write,
    process::{Command, Stdio},
};

fn distill() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_distill"));
    let home = std::env::temp_dir().join(distill_core::new_id("distill-test-home"));
    std::fs::create_dir(&home).unwrap();
    command.env("HOME", home);
    command.env(
        "DISTILL_TRACE_DIR",
        std::env::temp_dir().join(format!(
            "distill-cli-tests-no-recorder-{}",
            std::process::id()
        )),
    );
    command
}

#[test]
fn analyze_echo_is_allow() {
    let output = distill()
        .args(["analyze", "--command", "echo hello"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["decision"], "allow");
    assert_eq!(json["severity"], "safe");
    assert_eq!(json["mode"], "embedded_static");
}

#[test]
fn cli_context_and_health_are_explicit() {
    let health = distill().args(["doctor", "--json"]).output().unwrap();
    assert!(health.status.success());
    let json: serde_json::Value = serde_json::from_slice(&health.stdout).unwrap();
    assert_eq!(json["trace_protocol"], 1);
    assert!(
        json["capabilities"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("workspace-context"))
    );
    let output = distill()
        .args([
            "analyze",
            "--shell",
            "/bin/fish",
            "--workspace-root",
            "/workspace",
            "--command",
            "echo hi",
        ])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["shell_dialect"], "unsupported");
    assert_eq!(json["analysis_context"]["shell"], "/bin/fish");
    assert_eq!(json["analysis_context"]["workspace_roots"][0], "/workspace");
    assert_ne!(json["decision"], "allow");
}

#[test]
fn analyze_rm_root_is_deny() {
    let output = distill()
        .args(["analyze", "--command", "rm -rf /", "--cwd", "/tmp"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["decision"], "deny");
    assert_eq!(json["severity"], "critical");
}

#[test]
fn impact_and_uncertainty_are_separate_without_auto_allowing_partial_programs() {
    for (command, impact) in [
        (
            "python3 -c 'print(1); import unmodeled_dependency'",
            serde_json::Value::Null,
        ),
        (
            "python3 -c 'path = \"/etc/passwd\"; print(open(path).read()); unresolved()'",
            serde_json::json!("low"),
        ),
        (
            "python3 -c 'path = \".env\"; open(path); unresolved()'",
            serde_json::json!("high"),
        ),
    ] {
        let output = distill()
            .args(["analyze", "--cwd", "/tmp", "--command", command])
            .output()
            .unwrap();
        assert!(output.status.success());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["impact_severity"], impact, "{command}");
        assert_eq!(report["severity"], "high");
        assert_eq!(report["decision"], "ask");
        assert_ne!(report["coverage"]["summary"], "static_accounted");
        assert_eq!(
            report["behavior_policy_version"],
            distill_core::BEHAVIOR_POLICY_VERSION
        );
    }
}

#[test]
fn compiler_output_protection_does_not_depend_on_source_recognition() {
    let root = std::env::temp_dir().join(distill_core::new_id("distill-output-policy"));
    std::fs::create_dir(&root).unwrap();
    let source = root.join("unresolved.cpp");
    std::fs::write(&source, "int main(){ unknown(); }").unwrap();
    let command = format!("clang++ {} -o /", source.display());
    let output = distill()
        .args(["analyze", "--command", &command, "--cwd", "/tmp"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["impact_severity"], "critical");
    assert_eq!(report["decision"], "deny");
    assert!(
        report["behaviors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|behavior| behavior["kind"] == "file_write" && behavior["target"] == "/")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn configured_effect_policy_applies_to_shell_and_source_writes() {
    let root = std::env::temp_dir().join(distill_core::new_id("distill-effect-policy"));
    std::fs::create_dir(&root).unwrap();
    let config = root.join("config.toml");
    std::fs::write(&config, "[policy.effects]\nwrite = 'high'\n").unwrap();
    for command in [
        "printf text > ordinary.txt",
        "python3 -c 'open(\"ordinary.txt\", \"w\")'",
    ] {
        let output = distill()
            .args(["analyze", "--command", command, "--cwd"])
            .arg(&root)
            .arg("--config")
            .arg(&config)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["impact_severity"], "high", "{command}");
        assert_eq!(report["decision"], "ask");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn hook_claude_unknown_asks() {
    let mut child = distill()
        .args(["hook", "claude"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(include_bytes!(
            "../../../corpus/hooks/pretooluse-unknown.json"
        ))
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn doctor_reports_embedded_mode() {
    let output = distill().arg("doctor").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("embedded static analyzer"));
}

#[test]
fn config_validate_example() {
    let output = distill()
        .args(["config", "validate", "--path", "config.example.toml"])
        .current_dir(env!("CARGO_MANIFEST_DIR").to_string() + "/../..")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_hook(host: &str, args: &[&str], input: &[u8]) -> serde_json::Value {
    let directory = std::env::temp_dir().join(distill_core::new_id("distill-hook-test"));
    let key = directory.join("key");
    distill_core::integrity::create_key(&key).unwrap();
    let config = directory.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[ledger]\nenabled=false\n[security]\nlabel_key_path={:?}\n",
            key.to_str().unwrap()
        ),
    )
    .unwrap();
    let mut child = distill()
        .args(["hook", host, "--no-prompt"])
        .arg("--config")
        .arg(&config)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn codex_permission_hook_emits_severity_without_auto_approval() {
    let output = run_hook(
        "codex",
        &["--mode", "advisory"],
        include_bytes!("../../../corpus/hooks/permissionrequest-high.json"),
    );
    let message = output["systemMessage"].as_str().unwrap();
    assert!(message.contains("Severity: UNKNOWN"));
    assert!(message.contains("Approval risk: HIGH"));
    assert!(message.contains("Reason:"));
    assert!(output.get("hookSpecificOutput").is_none());
}

#[test]
fn advisory_critical_is_blocked_on_both_hosts() {
    for host in ["codex", "claude"] {
        let output = run_hook(
            host,
            &["--mode", "advisory"],
            include_bytes!("../../../corpus/hooks/pretooluse-rm-root.json"),
        );
        assert!(
            output["systemMessage"]
                .as_str()
                .unwrap()
                .contains("Severity: CRITICAL")
        );
        assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(output["hookSpecificOutput"].get("updatedInput").is_none());
    }
}

#[test]
fn advisory_failure_emits_unknown_without_a_permission_decision() {
    let output = run_hook(
        "codex",
        &["--mode", "advisory"],
        br#"{"hook_event_name":"PermissionRequest","tool_name":"Bash","cwd":"/tmp","tool_input":{}}"#,
    );
    assert!(
        output["systemMessage"]
            .as_str()
            .unwrap()
            .contains("Severity: UNKNOWN")
    );
    assert!(output.get("hookSpecificOutput").is_none());
}

#[test]
fn strict_failure_denies_the_correct_event() {
    let output = run_hook(
        "codex",
        &["--mode", "strict"],
        br#"{"hook_event_name":"PermissionRequest","tool_name":"Bash","cwd":"/tmp","tool_input":{}}"#,
    );
    assert_eq!(
        output["hookSpecificOutput"]["hookEventName"],
        "PermissionRequest"
    );
    assert_eq!(output["hookSpecificOutput"]["decision"]["behavior"], "deny");
}

#[test]
fn codex_command_label_flag_produces_an_advisory_pretool_rewrite() {
    let output = run_hook(
        "codex",
        &["--mode", "advisory", "--label-command"],
        include_bytes!("../../../corpus/hooks/pretooluse-echo.json"),
    );
    let hook = &output["hookSpecificOutput"];
    assert_eq!(hook["hookEventName"], "PreToolUse");
    assert_eq!(hook["permissionDecision"], "allow");
    let command = hook["updatedInput"]["command"].as_str().unwrap();
    assert!(command.starts_with("# Distill severity: SAFE 🟢 | Analysis: modeled"));
    assert!(command.contains(" | HMAC-SHA256: "));
    assert_eq!(command.split_once('\n').unwrap().1, "echo hello");
    assert!(hook.get("decision").is_none());
}

#[test]
fn codex_command_label_failure_is_unknown_and_preserves_escalation() {
    let output = run_hook(
        "codex",
        &["--mode", "advisory", "--label-command"],
        br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hello","shell":"/bin/sh","sandbox_permissions":"require_escalated"}}"#,
    );
    let input = &output["hookSpecificOutput"]["updatedInput"];
    let command = input["command"].as_str().unwrap();
    assert!(command.starts_with("# Distill severity: UNKNOWN"));
    assert_eq!(command.split_once('\n').unwrap().1, "echo hello");
    assert_eq!(input["sandbox_permissions"], "require_escalated");
}

#[test]
fn codex_command_label_preserves_shell_output_and_exit_status() {
    let command = "printf '%s\\n' 'literal # text' 'literal $text'\ncat <<'DISTILL_EOF'\nliteral $text and `text`\nDISTILL_EOF\nprintf '%s\\n' 'error text' >&2\nexit 7";
    let input = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": "/tmp",
        "tool_input": {"command": command, "shell": "/bin/sh"}
    });
    let output = run_hook(
        "codex",
        &["--mode", "advisory", "--label-command"],
        input.to_string().as_bytes(),
    );
    let labeled = output["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .unwrap();
    assert_eq!(labeled.split_once('\n').unwrap().1, command);
    // Only these literal, harmless test commands are executed. Hazard fixtures are never run.
    let original_output = Command::new("/bin/sh")
        .args(["-c", command])
        .output()
        .unwrap();
    let labeled_output = Command::new("/bin/sh")
        .args(["-c", labeled])
        .output()
        .unwrap();
    assert_eq!(original_output.status.code(), Some(7));
    assert_eq!(labeled_output.status, original_output.status);
    assert_eq!(labeled_output.stdout, original_output.stdout);
    assert_eq!(labeled_output.stderr, original_output.stderr);
}

#[test]
fn independently_labeled_verdict_audit_has_no_wrong_impacts_or_unsafe_allows() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("../../../corpus/verdict-audit.json")).unwrap();
    let root = std::env::temp_dir().join(distill_core::new_id("distill-verdict-audit"));
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("input.txt"), "needle\nsecond\nthird\n").unwrap();
    std::fs::write(root.join(".env"), "needle=fake-credential-fixture\n").unwrap();
    let severity = |value: &str| {
        ["safe", "low", "medium", "high", "critical"]
            .iter()
            .position(|candidate| *candidate == value)
            .unwrap()
    };
    for case in cases.as_array().unwrap() {
        let output = distill()
            .args([
                "analyze",
                "--command",
                case["command"].as_str().unwrap(),
                "--cwd",
            ])
            .arg(&root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["impact_severity"], case["impact"],
            "{}: {}",
            case["name"], report
        );
        assert_eq!(
            report["decision"] != "allow",
            case["review"].as_bool().unwrap(),
            "{}: {}",
            case["name"],
            report
        );
        if let Some(minimum) = case["risk_min"].as_str() {
            assert!(
                severity(report["severity"].as_str().unwrap()) >= severity(minimum),
                "{}: {}",
                case["name"],
                report
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
