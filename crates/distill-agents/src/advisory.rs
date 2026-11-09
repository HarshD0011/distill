//! Advisory proposals never discharge static uncertainty or authorization checks.
use distill_core::{AnalyzeRequest, Config, CoverageGap, Decision, GapCode, Report, Severity};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

pub fn fallback_severity(report: &Report) -> Option<Severity> {
    let judge = report.judge.as_ref()?;
    if report.impact_severity.is_some() || judge["status"] != "advisory" {
        return None;
    }
    serde_json::from_value(judge["severity"].clone()).ok()
}

pub fn enrich(request: &AnalyzeRequest, report: &mut Report, config: &Config, started: Instant) {
    if !config.judge.enabled || report.unknowns.is_empty() {
        return;
    }
    // Model advice cannot establish omitted host execution facts. Do not spend
    // the network deadline on metadata-only gaps or let advice suggest those
    // facts were recovered. Static coverage and review requirements stay intact.
    if report
        .unknowns
        .iter()
        .all(|reason| CoverageGap::from_reason(reason).code == GapCode::HostMetadata)
    {
        report.judge = Some(json!({
            "status": "skipped",
            "reason": "Only host execution metadata is missing; model advice cannot establish it. Static review requirements are retained."
        }));
        return;
    }
    let mut remaining = request
        .budget_ms
        .saturating_sub(started.elapsed().as_millis() as u64)
        .min(config.judge.deadline_ms);
    if remaining < 20 {
        report.judge =
            Some(json!({"status":"skipped","reason":"Insufficient remaining analysis budget"}));
        return;
    }
    let mut payload = json!({"command":distill_core::privacy::redact(&request.command.text),"command_digest":report.command_digest,"cwd":request.cwd,"shell":request.command.dialect,"shell_context":request.context,"policy_digest":report.policy_digest,"analyzer_version":distill_core::PRODUCT_VERSION,"behavior_policy_version":report.behavior_policy_version,"dependencies":report.inspected_files,"graph":report.graph,"coverage_gaps":report.coverage_gaps,"context_evidence":report.context_evidence,"effects":report.behaviors,"remaining_ms":remaining});
    let code_files: Vec<_> = report
        .inspected_files
        .iter()
        .filter(|dependency| {
            dependency
                .path
                .extension()
                .and_then(|v| v.to_str())
                .is_some_and(|v| {
                    matches!(
                        v,
                        "js" | "mjs"
                            | "cjs"
                            | "ts"
                            | "mts"
                            | "cts"
                            | "jsx"
                            | "tsx"
                            | "py"
                            | "sh"
                            | "rs"
                            | "go"
                            | "c"
                            | "cpp"
                            | "java"
                    )
                })
        })
        .collect();
    let mut scripts = Vec::new();
    if config.judge.send_script_contents {
        let budget = distill_core::AnalysisBudget::new(remaining.min(20));
        let mut used = 0;
        for dependency in &code_files {
            let cap = config.judge.max_script_bytes.saturating_sub(used);
            if cap == 0 {
                break;
            }
            if let Ok((source, snapshot)) =
                distill_core::read_snapshot(&dependency.path, &budget, cap)
                && snapshot.sha256 == dependency.sha256
            {
                let source = distill_core::privacy::redact(&source);
                if source.len() > cap {
                    continue;
                }
                used += source.len();
                scripts
                    .push(json!({"path":snapshot.path,"sha256":snapshot.sha256,"source":source}));
            }
        }
    }
    let missing_source = report.unknowns.iter().any(|reason| {
        reason.contains("Source is unavailable")
            || reason.contains("source is unavailable")
            || reason.contains("source is dynamic")
    });
    payload["source_review"] = json!({"sharing_enabled":config.judge.send_script_contents,"inspected_files":code_files.len(),"shared_files":scripts.len(),"omitted_files":code_files.len().saturating_sub(scripts.len()),"missing_source":missing_source});
    if config.judge.send_script_contents {
        payload["scripts"] = json!(scripts);
    }
    if config.judge.review_format == distill_core::ReviewFormat::Severity {
        // Preserve full analysis provenance in the cache binding without sending
        // a large static graph over IPC or into the compact model prompt.
        payload["analysis_digest"] = json!(distill_core::sha256(
            json!([
                payload["graph"],
                payload["context_evidence"],
                payload["effects"],
                payload["coverage_gaps"]
            ])
            .to_string()
            .as_bytes()
        ));
        for field in ["graph", "context_evidence", "effects"] {
            payload.as_object_mut().unwrap().remove(field);
        }
        if let Some(gaps) = payload["coverage_gaps"].as_array() {
            let total = gaps.len();
            let kept: Vec<_> = gaps.iter().take(16).cloned().collect();
            payload["coverage_gaps"] = json!(kept);
            payload["coverage_gaps_omitted"] = json!(total.saturating_sub(16));
        }
    }
    distill_core::privacy::redact_value(&mut payload);
    payload["model_policy_digest"] = json!(config.model_digest());
    remaining = request
        .budget_ms
        .saturating_sub(started.elapsed().as_millis() as u64)
        .min(config.judge.deadline_ms);
    if remaining < 20 {
        report.judge = Some(
            json!({"status":"skipped","reason":"Payload preparation exhausted the remaining analysis budget"}),
        );
        return;
    }
    payload["remaining_ms"] = json!(remaining);
    let model_started = Instant::now();
    match distill_core::service_ipc::request(
        config,
        "judge_enqueue",
        payload,
        Duration::from_millis(remaining.min(40)),
    ) {
        Ok(value) => {
            let previous_risk = report.severity;
            if let Ok(severity) = serde_json::from_value::<Severity>(value["severity"].clone()) {
                report.severity = report.severity.max(severity);
                if severity == Severity::Critical {
                    report.decision = Decision::Deny;
                } else if severity >= Severity::Medium && report.decision == Decision::Allow {
                    report.decision = Decision::Ask;
                }
            }
            if let Some(severity) = value
                .pointer("/classifier/severity")
                .and_then(Value::as_str)
                .and_then(|v| serde_json::from_value::<Severity>(json!(v)).ok())
            {
                report.severity = report.severity.max(severity);
                if severity == Severity::Critical {
                    report.decision = Decision::Deny;
                }
            }
            if let Some(effects) = value.pointer("/proposal/effects").and_then(Value::as_array) {
                let proposed = distill_interp::proposed_effects(request, effects, config);
                let floor = proposed.max_severity.unwrap_or(Severity::Safe);
                report.severity = report.severity.max(floor);
                if floor == Severity::Critical {
                    report.decision = Decision::Deny;
                } else if floor >= Severity::Medium && report.decision == Decision::Allow {
                    report.decision = Decision::Ask;
                }
            }
            if report.severity > previous_risk {
                report.findings.push(distill_core::Finding {rule_id:"judge.proposed-risk".into(),severity:report.severity,impact:"Optional model proposes additional risk; this is advisory evidence, not established static impact".into(),evidence:vec![],confidence:"advisory",basis:distill_core::FindingBasis::Uncertainty});
                report.explanation.push_str(
                    "; optional model proposed additional approval risk (advisory evidence)",
                );
            }
            report.judge = Some(value);
        }
        Err(error) => {
            report.judge = Some(
                json!({"status":"unavailable","reason":"Local model service could not queue the review","detail":error}),
            )
        }
    }
    let elapsed = model_started.elapsed().as_millis();
    report.timings_ms.total += elapsed;
    report.timings_ms.stages.insert("judge".into(), elapsed);
}

#[cfg(test)]
mod tests {
    fn metadata_gap_report(command: &str, config: &distill_core::Config) -> distill_core::Report {
        let event = serde_json::json!({
            "hook_event_name":"PreToolUse", "tool_name":"Bash", "cwd":"/tmp",
            "tool_input":{"command":command}
        })
        .to_string();
        crate::assess_hook(
            distill_core::Integration::Codex,
            &event,
            config,
            Default::default(),
        )
        .unwrap()
        .1
    }

    #[test]
    fn metadata_only_gaps_skip_enabled_judge_and_preserve_static_review() {
        let mut config = distill_core::Config::default();
        config.ledger.enabled = false;
        let service =
            std::path::PathBuf::from("/tmp").join(distill_core::new_id("metadata-no-service"));
        config.service.directory = Some(service.clone());
        for command in [
            "pwd",
            "python3 -c 'import json; print(json.dumps({\"ok\":True}))'",
            "touch ordinary.txt",
            "rm -rf /",
        ] {
            config.judge.enabled = false;
            let baseline = metadata_gap_report(command, &config);
            config.judge.enabled = true;
            let report = metadata_gap_report(command, &config);
            let judge = report.judge.as_ref().unwrap();
            assert_eq!(judge["status"], "skipped", "{command}");
            assert!(
                judge["reason"]
                    .as_str()
                    .unwrap()
                    .contains("host execution metadata")
            );
            assert!(!report.timings_ms.stages.contains_key("judge"), "{command}");
            assert_eq!(report.impact_severity, baseline.impact_severity);
            assert_eq!(report.severity, baseline.severity);
            assert_eq!(report.decision, baseline.decision);
            assert_eq!(report.coverage.summary, baseline.coverage.summary);
            assert_eq!(report.unknowns, baseline.unknowns);
            assert!(report.severity >= distill_core::Severity::High);
            assert_ne!(report.decision, distill_core::Decision::Allow);
            assert!(
                report
                    .unknowns
                    .iter()
                    .all(|reason| distill_core::CoverageGap::from_reason(reason).code
                        == distill_core::GapCode::HostMetadata)
            );
        }
        assert!(!service.exists());
    }

    #[test]
    fn metadata_plus_unresolved_code_still_attempts_enabled_judge() {
        let mut config = distill_core::Config::default();
        config.ledger.enabled = false;
        config.judge.enabled = true;
        config.service.directory = Some(
            std::path::PathBuf::from("/tmp").join(distill_core::new_id("mixed-gap-no-service")),
        );
        for command in [
            "python3 -c 'import distill_unknown_package'",
            "node -e 'import(\"distill_unknown_package\")'",
        ] {
            let report = metadata_gap_report(command, &config);
            assert_eq!(
                report.judge.as_ref().unwrap()["status"],
                "unavailable",
                "{command}"
            );
            assert!(report.timings_ms.stages.contains_key("judge"), "{command}");
            assert!(
                report
                    .unknowns
                    .iter()
                    .any(|reason| distill_core::CoverageGap::from_reason(reason).code
                        == distill_core::GapCode::HostMetadata)
            );
            assert!(
                report
                    .unknowns
                    .iter()
                    .any(|reason| distill_core::CoverageGap::from_reason(reason).code
                        != distill_core::GapCode::HostMetadata)
            );
            assert!(report.severity >= distill_core::Severity::High);
            assert_ne!(report.decision, distill_core::Decision::Allow);
        }
    }

    #[test]
    fn accounted_python_low_impact_survives_missing_host_shell_metadata() {
        let mut config = distill_core::Config::default();
        config.ledger.enabled = false;
        for source in [
            "import json; values=[1,2,3]; print(json.dumps({'sum':sum(values)}))",
            "import subprocess; p=subprocess.run(['printf','ok'],capture_output=True,text=True); print(p.stdout)",
        ] {
            let command = format!("python3 - <<'PY'\n{source}\nPY");
            let event = serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/tmp","tool_input":{"command":command}}).to_string();
            let (_, report) = crate::assess_hook(
                distill_core::Integration::Codex,
                &event,
                &config,
                Default::default(),
            )
            .unwrap();
            assert_eq!(
                report.impact_severity,
                Some(distill_core::Severity::Low),
                "{source}"
            );
            assert_eq!(report.severity, distill_core::Severity::High);
            assert_eq!(report.decision, distill_core::Decision::Ask);
            assert_eq!(
                report.coverage.summary,
                distill_core::CoverageSummary::Partial
            );
            assert!(
                report
                    .unknowns
                    .iter()
                    .all(|v| v.contains("shell metadata is missing")),
                "{source}: {:?}",
                report.unknowns
            );
            assert!(
                report
                    .findings
                    .iter()
                    .any(|v| v.rule_id == "shell.conditional-low"
                        && v.basis == distill_core::FindingBasis::Impact)
            );
        }
        let event=serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/tmp","tool_input":{"command":"python3 -c 'import unmodeled_package'"}}).to_string();
        let (_, report) = crate::assess_hook(
            distill_core::Integration::Codex,
            &event,
            &config,
            Default::default(),
        )
        .unwrap();
        assert_eq!(report.impact_severity, None);
        assert!(
            !report
                .findings
                .iter()
                .any(|v| v.rule_id == "shell.conditional-low")
        );
    }

    #[test]
    fn accounted_python_testing_commands_skip_an_enabled_model_router() {
        let mut config = distill_core::Config::default();
        config.ledger.enabled = false;
        config.judge.enabled = true;
        let service =
            std::path::PathBuf::from("/tmp").join(distill_core::new_id("python-static-no-service"));
        config.service.directory = Some(service.clone());
        for source in [
            "import json; print(json.dumps({'ok':True}))",
            "values=[1,2,3]; assert sum(values)==6; print(len(values))",
            "from pathlib import Path; print(Path('fixture.json').read_text())",
        ] {
            let command = format!("python3 - <<'PY'\n{source}\nPY");
            let event = serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/tmp","tool_input":{"command":command,"shell":"/bin/bash"}}).to_string();
            let (_, report) = crate::assess_hook(
                distill_core::Integration::Codex,
                &event,
                &config,
                Default::default(),
            )
            .unwrap();
            assert!(
                report.unknowns.is_empty(),
                "{source}: {:?}",
                report.unknowns
            );
            assert!(report.judge.is_none(), "{source}");
            assert!(!report.timings_ms.stages.contains_key("judge"));
        }
        assert!(!service.exists());
    }

    #[test]
    fn disabled_router_is_static_only_even_with_a_classifier_configured() {
        let mut config = distill_core::Config::default();
        config.ledger.enabled = false;
        config.service.classifier_path = Some("/tmp/nonexistent-adviser.json".into());
        let event=serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/tmp","tool_input":{"command":"node -e 'import(\"unknown-package\")'","shell":"/bin/bash"}}).to_string();
        let (_, report) = crate::assess_hook(
            distill_core::Integration::Codex,
            &event,
            &config,
            Default::default(),
        )
        .unwrap();
        assert!(report.judge.is_none());
        assert!(!report.timings_ms.stages.contains_key("judge"));
        assert_eq!(report.decision, distill_core::Decision::Ask);
    }

    #[test]
    fn unavailable_judge_keeps_static_unknown_and_its_policy_floor() {
        let mut config = distill_core::Config::default();
        config.ledger.enabled = false;
        config.judge.enabled = true;
        config.judge.model = "fixture".into();
        config.service.directory =
            Some(std::path::PathBuf::from("/tmp").join(distill_core::new_id("no-service")));
        let event=serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/tmp","tool_input":{"command":"node -e 'import(\"unknown-package\")'","shell":"/bin/bash"}}).to_string();
        let (_, report) = crate::assess_hook(
            distill_core::Integration::Codex,
            &event,
            &config,
            Default::default(),
        )
        .unwrap();
        assert_eq!(report.decision, distill_core::Decision::Ask);
        assert_eq!(report.impact_severity, None);
        assert_eq!(
            report.coverage.summary,
            distill_core::CoverageSummary::Partial
        );
        assert_eq!(report.judge.unwrap()["status"], "unavailable");
        assert!(!config.service.directory.unwrap().exists());
    }
}
