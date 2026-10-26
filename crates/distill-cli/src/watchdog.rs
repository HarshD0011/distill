//! Process isolation around untrusted parser inputs. Worker failures always tighten policy.
use serde_json::json;
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn supervise() -> bool {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if !matches!(
        args.first().map(String::as_str),
        Some("analyze" | "assess" | "hook" | "inspect")
    ) || std::env::var_os("DISTILL_ANALYSIS_WORKER").is_some()
    {
        return false;
    }
    let needs_input = args[0] == "hook" || args.iter().any(|arg| arg == "--stdin");
    let mut input = Vec::new();
    if needs_input
        && std::io::stdin()
            .take(32 * 1024 * 1024 + 1)
            .read_to_end(&mut input)
            .is_err()
    {
        failure(&args, &input, "Analysis input unavailable");
        return true;
    }
    if input.len() > 32 * 1024 * 1024 {
        failure(&args, &input, "Analysis input limit exceeded");
        return true;
    }
    let Ok(binary) = std::env::current_exe() else {
        failure(&args, &input, "Analyzer executable unavailable");
        return true;
    };
    let mut command = Command::new(binary);
    command
        .args(&args)
        .env("DISTILL_ANALYSIS_WORKER", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let Ok(mut child) = command.spawn() else {
        failure(&args, &input, "Analyzer worker could not start");
        return true;
    };
    let stdin = child.stdin.take();
    let supplied = input.clone();
    std::thread::spawn(move || {
        if let Some(mut stdin) = stdin {
            let _ = stdin.write_all(&supplied);
        }
    });
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes);
        let _ = tx.send((result.is_ok(), bytes));
    });
    let started = Instant::now();
    let deadline = std::env::var("DISTILL_WATCHDOG_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(6000)
        .clamp(1, 6000);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if let Ok((true, bytes)) = rx.recv_timeout(Duration::from_millis(100))
                    && status.success()
                    && !bytes.is_empty()
                    && bytes.len() <= 16 * 1024 * 1024
                {
                    let _ = std::io::stdout().write_all(&bytes);
                    return true;
                }
                failure(
                    &args,
                    &input,
                    "Analyzer worker failed or exceeded its output limit",
                );
                return true;
            }
            Err(_) => {
                failure(&args, &input, "Analyzer worker status unavailable");
                return true;
            }
            Ok(None) if started.elapsed() >= Duration::from_millis(deadline) => {
                #[cfg(unix)]
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                failure(&args, &input, "Hard analysis watchdog expired");
                return true;
            }
            _ => std::thread::sleep(Duration::from_millis(2)),
        }
    }
}
fn failure(args: &[String], input: &[u8], reason: &str) {
    let report = if args[0] == "hook" {
        let event = serde_json::from_slice::<serde_json::Value>(input).unwrap_or_default();
        if event["hook_event_name"] == "PermissionRequest" {
            json!({"systemMessage": format!("Distill | Approval risk: HIGH | {reason}"), "hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "deny", "message": reason}}})
        } else if matches!(
            event["hook_event_name"].as_str(),
            Some("PostToolUse" | "PostToolUseFailure")
        ) {
            json!({"systemMessage": "Distill completion recorder unavailable"})
        } else {
            json!({"systemMessage": format!("Distill | Approval risk: HIGH | {reason}"), "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}})
        }
    } else {
        json!({"mode": "embedded_static", "severity": "high", "impact_severity": null, "decision": "deny", "coverage": {"summary": "stopped", "stop_reasons": [reason]}, "trace_status": "stopped", "unknowns": [reason], "findings": [], "behaviors": [], "inspected_files": [], "explanation": reason})
    };
    println!("{report}");
}
