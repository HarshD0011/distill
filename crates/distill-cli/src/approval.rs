//! Human decisions run in the supervisor, outside the parser's six-second budget.
//! No approval flag, environment variable, cache, or model response can grant consent.
use crate::{Cli, Commands};
use clap::Parser;
use distill_core::{AnalysisBudget, Config, FileSnapshot, Integration, integrity::sha256};
use serde_json::{Value, json};
use std::path::Path;

pub fn finish(args: &[String], input: &[u8], bytes: &[u8]) -> Result<Vec<u8>, String> {
    let envelope: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let Some(response) = envelope.get("distill_hook_response") else {
        // Completion and failure responses have no analysis envelope.
        return Ok(bytes.to_vec());
    };
    let mut response = response.clone();
    let mut report = envelope["report"].clone();
    if report["severity"] == "critical" {
        let event: Value = serde_json::from_slice(input).map_err(|e| e.to_string())?;
        let (host, config, no_prompt) = configuration(args)?;
        response = decide(
            &event,
            &mut report,
            &response,
            &config,
            no_prompt,
            native_dialog,
            || {
                let (_, current, _) = configuration(args)?;
                if current.digest() != config.digest() {
                    return Err(
                        "Policy changed while the dialog was open; review a new request".into(),
                    );
                }
                Ok(())
            },
        );
        if config.editor_trace.enabled
            && let Err(error) = distill_agents::trace::assessment_value(
                host,
                std::str::from_utf8(input).map_err(|e| e.to_string())?,
                &report,
                &response,
                &config,
            )
        {
            eprintln!("distill trace: {error}");
        }
    }
    serde_json::to_vec(&response).map_err(|e| e.to_string())
}

fn configuration(args: &[String]) -> Result<(Integration, Config, bool), String> {
    let cli =
        Cli::try_parse_from(std::iter::once("distill".to_string()).chain(args.iter().cloned()))
            .map_err(|e| e.to_string())?;
    let Commands::Hook {
        host,
        config,
        mode,
        no_prompt,
        ..
    } = cli.command
    else {
        return Err("Expected a hook invocation".into());
    };
    let mut config = Config::load(config.as_deref())?;
    if let Some(mode) = mode {
        match host {
            crate::Host::Codex => config.agents.codex.mode = mode.into(),
            crate::Host::Claude => config.agents.claude.mode = mode.into(),
        }
    }
    Ok((host.into(), config, no_prompt))
}

fn verify_bindings(event: &Value, report: &Value, config: &Config) -> Result<(), String> {
    if event["tool_name"] != "Bash"
        || !matches!(
            event["hook_event_name"].as_str(),
            Some("PreToolUse" | "PermissionRequest")
        )
    {
        return Err("Approval event is not a supported command invocation".into());
    }
    let command = event
        .pointer("/tool_input/command")
        .and_then(Value::as_str)
        .ok_or("Approval command is missing")?;
    let command = distill_agents::authenticated_command(command, config);
    if report["command_digest"] != sha256(command.as_bytes())
        || report["policy_digest"] != config.digest()
    {
        return Err("Command or policy no longer matches the assessment".into());
    }
    if !report["cwd"]
        .as_str()
        .is_some_and(|cwd| Path::new(cwd).is_absolute())
    {
        return Err("Approval working directory is unavailable".into());
    }
    let snapshots: Vec<FileSnapshot> = serde_json::from_value(report["inspected_files"].clone())
        .map_err(|_| "Approval source bindings are unavailable")?;
    let budget = AnalysisBudget::new(1000);
    for snapshot in snapshots {
        let (_, current) =
            distill_core::integrity::read_snapshot(&snapshot.path, &budget, 1024 * 1024)?;
        if current != snapshot {
            return Err(
                "An inspected file changed while approval was pending; review a new request".into(),
            );
        }
    }
    Ok(())
}

fn decide(
    event: &Value,
    report: &mut Value,
    response: &Value,
    config: &Config,
    no_prompt: bool,
    ask: impl FnOnce(&str) -> Result<bool, String>,
    policy_current: impl FnOnce() -> Result<(), String>,
) -> Value {
    let result: Result<(), String> = (|| {
        if no_prompt {
            return Err(
                "Human dialog disabled by --no-prompt; CRITICAL commands cannot be auto-approved"
                    .into(),
            );
        }
        if response.pointer("/hookSpecificOutput/permissionDecision") != Some(&json!("deny"))
            && response.pointer("/hookSpecificOutput/decision/behavior") != Some(&json!("deny"))
        {
            return Err("Critical assessment did not contain a valid pending denial".into());
        }
        verify_bindings(event, report, config)?;
        let command = distill_agents::authenticated_command(
            event["tool_input"]["command"].as_str().unwrap(),
            config,
        );
        let prompt = prompt(command, report, response)?;
        if !ask(&prompt)? {
            return Err("User denied or dismissed the Distill approval dialog".into());
        }
        policy_current()?;
        verify_bindings(event, report, config)?;
        Ok(())
    })();
    let summary = response["systemMessage"]
        .as_str()
        .unwrap_or("Distill | Severity: CRITICAL")
        .split("\nExplicit human approval required.")
        .next()
        .unwrap();
    let event_name = if event["hook_event_name"] == "PermissionRequest" {
        "PermissionRequest"
    } else {
        "PreToolUse"
    };
    match result {
        Ok(()) => {
            let message = format!(
                "{summary}\nHuman approved this exact invocation once in the Distill dialog. Other host permissions still apply."
            );
            report["policy_decision"] = report["decision"].clone();
            report["decision"] = json!("allow");
            report["human_approval"] = json!({"status":"approved_once", "method":"native_dialog"});
            if event_name == "PermissionRequest" {
                json!({"systemMessage": message, "hookSpecificOutput": {"hookEventName": event_name, "decision": {"behavior": "allow"}}})
            } else {
                json!({"systemMessage": message, "hookSpecificOutput": {"hookEventName": event_name, "permissionDecision": "allow", "permissionDecisionReason": message, "additionalContext": message}})
            }
        }
        Err(reason) => {
            let message =
                format!("{summary}\nHuman approval not granted: {reason}. Command not executed.");
            report["human_approval"] = json!({"status":"not_granted", "reason":reason});
            if event_name == "PermissionRequest" {
                json!({"systemMessage": message, "hookSpecificOutput": {"hookEventName": event_name, "decision": {"behavior": "deny", "message": message}}})
            } else {
                distill_agents::deny(Integration::Codex, &message)
            }
        }
    }
}

fn visible(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                c.escape_debug().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn prompt(command: &str, report: &Value, response: &Value) -> Result<String, String> {
    let message = format!(
        "CRITICAL command — explicit approval required\n\nWorking directory:\n{}\n\nExact command (control characters escaped):\n{}\n\n{}\n\nApprove once permits only this invocation. Automatic/model approval does not count. This dialog expires in 120 seconds.",
        visible(report["cwd"].as_str().unwrap_or("")),
        visible(command),
        response["systemMessage"]
            .as_str()
            .unwrap_or("")
            .split("\nExplicit human approval required.")
            .next()
            .unwrap()
            .lines()
            .map(visible)
            .collect::<Vec<_>>()
            .join("\n")
    );
    if message.len() > 8192 {
        return Err("Command is too long to display completely in the approval dialog".into());
    }
    Ok(message)
}

#[cfg(target_os = "macos")]
const DIALOG: &str = r#"ObjC.import('AppKit');
function run(argv) {
    var app = $.NSApplication.sharedApplication;
    app.setActivationPolicy(0);
    app.finishLaunching;
    var alert = $.NSAlert.alloc.init;
    alert.messageText = 'Distill — CRITICAL command';
    alert.informativeText = argv[0];
    alert.alertStyle = 2;
    alert.addButtonWithTitle('Deny');
    alert.addButtonWithTitle('Approve once');
    var window = alert.window;
    window.level = 8;
    window.collectionBehavior = 1 | 256;
    window.hidesOnDeactivate = false;
    window.center;
    app.activateIgnoringOtherApps(true);
    window.makeKeyAndOrderFront(null);
    window.orderFrontRegardless;
    return Number(alert.runModal) === 1001 ? 'DISTILL_APPROVED_ONCE' : 'DISTILL_DENIED';
}"#;

#[cfg(target_os = "macos")]
fn dialog_result(success: bool, output: &str) -> Result<bool, String> {
    match (success, output.trim()) {
        (true, "DISTILL_APPROVED_ONCE") => Ok(true),
        (true, "DISTILL_DENIED") => Ok(false),
        _ => Err("Native approval UI failed or returned no valid human decision".into()),
    }
}

#[cfg(target_os = "macos")]
fn native_dialog(message: &str) -> Result<bool, String> {
    use std::{
        io::Read,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let mut child = Command::new("/usr/bin/osascript")
        .args(["-l", "JavaScript", "-e", DIALOG, "--", message])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "The macOS approval dialog could not start")?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut output = String::new();
                if let Some(stdout) = child.stdout.take() {
                    stdout
                        .take(256)
                        .read_to_string(&mut output)
                        .map_err(|e| e.to_string())?;
                }
                return dialog_result(status.success(), &output);
            }
            Ok(None) if started.elapsed() < Duration::from_secs(120) => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("The approval dialog expired or became unavailable".into());
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn native_dialog(_message: &str) -> Result<bool, String> {
    Err(
        "Native critical approval dialogs currently require macOS; this command remains denied"
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value, Value, Config) {
        let config = Config::default();
        let event = json!({"hook_event_name":"PreToolUse", "tool_name":"Bash", "permission_mode":"bypassPermissions", "cwd":"/tmp", "tool_input":{"command":"touch /tmp/probe.app", "approved":true}});
        let report = json!({"severity":"critical", "decision":"deny", "cwd":"/tmp", "command_digest":sha256(b"touch /tmp/probe.app"), "policy_digest":config.digest(), "inspected_files":[]});
        let response = distill_agents::deny(
            Integration::Codex,
            "Distill | Severity: CRITICAL\nExplicit human approval required.",
        );
        (event, report, response, config)
    }
    #[test]
    fn only_an_explicit_dialog_acceptance_releases_one_invocation() {
        for accepted in [false, true] {
            let (event, mut report, response, config) = fixture();
            let result = decide(
                &event,
                &mut report,
                &response,
                &config,
                false,
                |text| {
                    assert!(text.contains("touch /tmp/probe.app"));
                    assert!(text.contains("/tmp"));
                    Ok(accepted)
                },
                || Ok(()),
            );
            assert_eq!(
                result["hookSpecificOutput"]["permissionDecision"],
                if accepted { "allow" } else { "deny" }
            );
            assert!(result["hookSpecificOutput"].get("updatedInput").is_none());
        }
    }
    #[test]
    #[cfg(target_os = "macos")]
    fn ui_errors_timeouts_and_unexpected_output_never_count_as_a_click() {
        assert_eq!(dialog_result(true, "DISTILL_APPROVED_ONCE\n"), Ok(true));
        assert_eq!(dialog_result(true, "DISTILL_DENIED\n"), Ok(false));
        assert!(dialog_result(false, "DISTILL_APPROVED_ONCE").is_err());
        assert!(dialog_result(true, "").is_err());
        assert!(dialog_result(true, "prefix DISTILL_APPROVED_ONCE").is_err());
    }
    #[test]
    fn cancellation_unavailable_ui_headless_and_changed_policy_deny() {
        for mode in 0..3 {
            let (event, mut report, response, config) = fixture();
            let result = decide(
                &event,
                &mut report,
                &response,
                &config,
                mode == 0,
                |_| {
                    if mode == 1 {
                        Err("No GUI".into())
                    } else {
                        Ok(true)
                    }
                },
                || {
                    if mode == 2 {
                        Err("Changed policy".into())
                    } else {
                        Ok(())
                    }
                },
            );
            if mode < 3 {
                assert_eq!(result["hookSpecificOutput"]["permissionDecision"], "deny");
            }
        }
    }
    #[test]
    fn source_changes_and_forged_command_bindings_cannot_reuse_approval() {
        let (event, mut report, response, config) = fixture();
        report["command_digest"] = json!(sha256(b"another command"));
        let result = decide(
            &event,
            &mut report,
            &response,
            &config,
            false,
            |_| panic!("must not prompt for stale input"),
            || Ok(()),
        );
        assert_eq!(result["hookSpecificOutput"]["permissionDecision"], "deny");
        let (event, mut report, response, config) = fixture();
        let path = std::env::temp_dir().join(distill_core::new_id("distill-approval-source"));
        std::fs::write(&path, "original").unwrap();
        let (_, snapshot) =
            distill_core::integrity::read_snapshot(&path, &AnalysisBudget::new(1000), 1024)
                .unwrap();
        report["inspected_files"] = json!([snapshot]);
        let result = decide(
            &event,
            &mut report,
            &response,
            &config,
            false,
            |_| {
                std::fs::write(&path, "changed").unwrap();
                Ok(true)
            },
            || Ok(()),
        );
        assert_eq!(result["hookSpecificOutput"]["permissionDecision"], "deny");
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn permission_request_uses_its_supported_allow_schema_after_click() {
        let (mut event, mut report, response, config) = fixture();
        event["hook_event_name"] = json!("PermissionRequest");
        let result = decide(
            &event,
            &mut report,
            &response,
            &config,
            false,
            |_| Ok(true),
            || Ok(()),
        );
        assert_eq!(
            result["hookSpecificOutput"]["decision"]["behavior"],
            "allow"
        );
        assert!(result["hookSpecificOutput"].get("updatedInput").is_none());
        assert_eq!(report["human_approval"]["status"], "approved_once");
    }
    #[test]
    fn actual_critical_assessment_requires_dialog_even_when_policy_and_host_auto_approve() {
        let (mut event, _, _, mut config) = fixture();
        config.ledger.enabled = false;
        config.editor_trace.enabled = false;
        config.policy.critical = distill_core::PolicyAction::Allow;
        config.agents.codex.mode = distill_core::AgentMode::Advisory;
        event["cwd"] = json!(std::env::temp_dir());
        event["tool_input"]["command"] = json!("touch /private/tmp/distill-approval-fixture.app");
        let (response, report) = distill_agents::assess_hook(
            Integration::Codex,
            &event.to_string(),
            &config,
            distill_agents::HookOptions::default(),
        )
        .unwrap();
        let mut report = serde_json::to_value(report).unwrap();
        assert_eq!(report["severity"], "critical");
        let result = decide(
            &event,
            &mut report,
            &response,
            &config,
            false,
            |text| {
                assert!(text.contains("distill-approval-fixture.app"));
                Ok(true)
            },
            || Ok(()),
        );
        assert_eq!(result["hookSpecificOutput"]["permissionDecision"], "allow");
    }
    #[test]
    fn display_cannot_inject_script_source_or_hide_control_characters() {
        let (_, report, response, _) = fixture();
        let text = prompt("echo \"a\"; $(anything)\nnext\u{202e}", &report, &response).unwrap();
        assert!(text.contains("$(anything)\\nnext\\u{202e}"));
        assert!(prompt(&"x".repeat(8192), &report, &response).is_err());
    }
}
