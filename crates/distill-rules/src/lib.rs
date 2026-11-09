use distill_core::{
    AnalysisDraft, AnalyzeRequest, Config, CoverageSummary, Decision, FindingBasis, PolicyAction,
    Report, Severity, Timings, TraceStatus, redact_command,
};

mod behavior;
pub mod catalog;
mod token_trie;
pub use behavior::{BehaviorVerdict, evaluate_behavior};

pub fn score(
    request: &AnalyzeRequest,
    mut draft: AnalysisDraft,
    config: &Config,
    elapsed_ms: u128,
) -> Report {
    let scoring_started = std::time::Instant::now();
    let mut incomplete = draft.coverage.summary != CoverageSummary::StaticAccounted;
    let modeled_impact = draft
        .findings
        .iter()
        .filter(|finding| finding.basis == FindingBasis::Impact)
        .map(|finding| finding.severity)
        .max();
    let impact_severity = if incomplete {
        modeled_impact
    } else {
        Some(
            modeled_impact
                .unwrap_or(Severity::Safe)
                .max(draft.max_severity.unwrap_or(Severity::Safe)),
        )
    };
    let raw_severity = match draft.max_severity {
        Some(value) => value,
        None if incomplete => Severity::Medium,
        None => Severity::Safe,
    };
    let mut severity = if incomplete {
        raw_severity.max(Severity::Medium)
    } else {
        raw_severity
    };
    for rule in &config.overrides {
        if regex::Regex::new(&format!("^(?:{})$", rule.pattern))
            .is_ok_and(|v| v.is_match(&request.command.text))
        {
            severity = if !incomplete && severity < Severity::Critical {
                rule.severity
            } else {
                severity.max(rule.severity)
            };
        }
    }
    // Workspace-owned rules may only raise risk. Bind their contents just like
    // other dependencies so an execution receipt cannot outlive a policy change.
    let project = request.cwd.join(".distill-policy.toml");
    let mut invalid_project = false;
    if project.exists() {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Project {
            #[serde(default)]
            raise: Vec<distill_core::PolicyOverride>,
        }
        let budget = distill_core::AnalysisBudget::new(20);
        match distill_core::read_snapshot(&project, &budget, 16384).and_then(
            |(source, snapshot)| {
                toml::from_str::<Project>(&source)
                    .map(|v| (v, snapshot))
                    .map_err(|e| e.to_string())
            },
        ) {
            Ok((policy, snapshot)) if policy.raise.len() <= 128 => {
                draft.inspected_files.push(snapshot);
                for rule in policy.raise {
                    if rule.pattern.len() > 1024 {
                        severity = severity.max(Severity::High);
                        invalid_project = true;
                        continue;
                    }
                    match regex::Regex::new(&format!("^(?:{})$", rule.pattern)) {
                        Ok(pattern) if pattern.is_match(&request.command.text) => {
                            severity = severity.max(rule.severity)
                        }
                        Err(_) => {
                            severity = severity.max(Severity::High);
                            invalid_project = true;
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                severity = severity.max(Severity::High);
                invalid_project = true;
            }
        }
    }
    if invalid_project {
        let reason = "Workspace policy could not be validated; review required";
        draft.unknowns.push(reason.into());
        draft.coverage.stop_reasons.push(reason.into());
        if draft.coverage.summary == CoverageSummary::StaticAccounted {
            draft.coverage.summary = CoverageSummary::Partial;
        }
        incomplete = true;
    }
    let from_severity = match severity {
        Severity::Safe | Severity::Low => Decision::Allow,
        Severity::Medium => map_action(config.policy.medium),
        Severity::High => map_action(config.policy.high),
        Severity::Critical => map_action(config.policy.critical),
    };
    let decision = if invalid_project {
        stronger(from_severity, Decision::Ask)
    } else if draft.coverage.summary == CoverageSummary::Stopped {
        Decision::Deny
    } else if incomplete {
        stronger(from_severity, map_action(config.policy.incomplete))
    } else {
        from_severity
    };
    let explanation = explanation(impact_severity, severity, elapsed_ms, &draft);
    let trace_status = match draft.coverage.summary {
        CoverageSummary::StaticAccounted => TraceStatus::StaticOnly,
        CoverageSummary::Partial => TraceStatus::Partial,
        CoverageSummary::Stopped => TraceStatus::Stopped,
        CoverageSummary::Opaque => TraceStatus::Opaque,
    };
    Report {
        protocol_version: request.protocol_version,
        report_id: distill_core::new_id("rpt"),
        request_id: request.request_id.clone(),
        mode: "embedded_static",
        command_redacted: redact_command(&request.command.text),
        command_digest: distill_core::sha256(request.command.text.as_bytes()),
        inspected_files: draft.inspected_files,
        severity,
        impact_severity,
        decision,
        explanation,
        findings: draft.findings,
        effects: draft.effects,
        behaviors: draft.behaviors,
        coverage: draft.coverage,
        trace_status,
        coverage_gaps: draft
            .unknowns
            .iter()
            .map(|v| distill_core::CoverageGap::from_reason(v))
            .collect(),
        unknowns: draft.unknowns,
        graph: draft.graph,
        context_evidence: draft.context_evidence,
        judge: None,
        policy_digest: config.digest(),
        behavior_policy_version: distill_core::BEHAVIOR_POLICY_VERSION,
        analysis_context: request.context.clone(),
        shell_dialect: request.command.dialect,
        cwd: request.cwd.clone(),
        timings_ms: Timings {
            total: elapsed_ms + scoring_started.elapsed().as_millis(),
            stages: [
                ("static".into(), elapsed_ms),
                ("scoring".into(), scoring_started.elapsed().as_millis()),
            ]
            .into_iter()
            .collect(),
        },
    }
}

fn map_action(action: PolicyAction) -> Decision {
    match action {
        PolicyAction::Allow => Decision::Allow,
        PolicyAction::Ask => Decision::Ask,
        PolicyAction::ForceAsk => Decision::ForceAsk,
        PolicyAction::Deny | PolicyAction::Hold => Decision::Deny,
    }
}

fn stronger(left: Decision, right: Decision) -> Decision {
    fn rank(decision: Decision) -> u8 {
        match decision {
            Decision::Allow => 0,
            Decision::Ask => 1,
            Decision::ForceAsk => 2,
            Decision::Deny => 3,
        }
    }
    if rank(right) > rank(left) {
        right
    } else {
        left
    }
}

fn explanation(
    known: Option<Severity>,
    severity: Severity,
    elapsed_ms: u128,
    draft: &AnalysisDraft,
) -> String {
    let impact = draft
        .findings
        .iter()
        .filter(|finding| finding.basis == FindingBasis::Impact)
        .max_by_key(|f| f.severity)
        .map(|f| f.impact.as_str())
        .or_else(|| draft.unknowns.first().map(String::as_str))
        .unwrap_or("No modeled hazardous effect was found in the supported static semantics");
    format!(
        "distill {} ({elapsed_ms} ms; approval risk {}): {}",
        known
            .map_or("unknown", Severity::as_str)
            .to_ascii_uppercase(),
        severity.as_str().to_ascii_uppercase(),
        impact.trim_end_matches('.')
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use distill_core::{
        AnalysisDraft, CommandForm, CommandKind, Coverage, CoverageLevel, Integration, ShellDialect,
    };

    fn request() -> AnalyzeRequest {
        AnalyzeRequest {
            protocol_version: 1,
            request_id: "req-test".into(),
            command: CommandForm {
                kind: CommandKind::Shell,
                text: "echo hi".into(),
                dialect: ShellDialect::Bash,
            },
            cwd: "/tmp".into(),
            session_id: None,
            source: Integration::Cli,
            budget_ms: 900,
            context: Default::default(),
        }
    }

    fn empty_draft(summary: CoverageSummary, severity: Option<Severity>) -> AnalysisDraft {
        AnalysisDraft {
            graph: Default::default(),
            context_evidence: Vec::new(),
            inspected_files: Vec::new(),
            findings: Vec::new(),
            effects: Vec::new(),
            behaviors: Vec::new(),
            unknowns: if summary == CoverageSummary::StaticAccounted {
                Vec::new()
            } else {
                vec!["unknown".into()]
            },
            coverage: Coverage {
                summary,
                parse: CoverageLevel::Accounted,
                options: CoverageLevel::Accounted,
                targets: CoverageLevel::Accounted,
                expansion: CoverageLevel::Accounted,
                stop_reasons: Vec::new(),
            },
            max_severity: severity,
        }
    }

    #[test]
    fn safe_accounted_is_allow() {
        let report = score(
            &request(),
            empty_draft(CoverageSummary::StaticAccounted, Some(Severity::Safe)),
            &Config::default(),
            1,
        );
        assert_eq!(report.decision, Decision::Allow);
    }

    #[test]
    fn incomplete_raises_to_ask() {
        let report = score(
            &request(),
            empty_draft(CoverageSummary::Opaque, Some(Severity::Safe)),
            &Config::default(),
            12,
        );
        assert_eq!(report.decision, Decision::Ask);
        assert_eq!(report.severity, Severity::Medium);
        assert_eq!(report.trace_status, TraceStatus::Opaque);
        assert_eq!(report.impact_severity, None);
        assert!(
            report
                .explanation
                .starts_with("distill UNKNOWN (12 ms; approval risk MEDIUM):")
        );
    }

    #[test]
    fn critical_is_deny() {
        let report = score(
            &request(),
            empty_draft(CoverageSummary::StaticAccounted, Some(Severity::Critical)),
            &Config::default(),
            1,
        );
        assert_eq!(report.decision, Decision::Deny);
    }

    #[test]
    fn known_impact_does_not_discharge_unresolved_execution() {
        let mut draft = empty_draft(CoverageSummary::Partial, Some(Severity::High));
        draft.findings.push(distill_core::Finding {
            rule_id: "source.file-read".into(),
            severity: Severity::Low,
            impact: "Reads an ordinary file".into(),
            evidence: Vec::new(),
            confidence: "conditional",
            basis: FindingBasis::Impact,
        });
        let report = score(&request(), draft, &Config::default(), 1);
        assert_eq!(report.impact_severity, Some(Severity::Low));
        assert_eq!(report.severity, Severity::High);
        assert_eq!(report.decision, Decision::Ask);
        assert_eq!(report.severity_label(), "low");
    }

    #[test]
    fn uncertainty_findings_cannot_masquerade_as_known_impact() {
        let mut draft = empty_draft(CoverageSummary::Partial, Some(Severity::High));
        draft.findings.push(distill_core::Finding {
            rule_id: "exec.command".into(),
            severity: Severity::High,
            impact: "Unresolved execution".into(),
            evidence: Vec::new(),
            confidence: "conditional",
            basis: FindingBasis::Uncertainty,
        });
        let report = score(&request(), draft, &Config::default(), 1);
        assert_eq!(report.impact_severity, None);
        assert_eq!(report.severity_label(), "unknown");
        assert_eq!(report.decision, Decision::Ask);
    }
}
