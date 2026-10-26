#![no_main]
use libfuzzer_sys::fuzz_target;
use distill_core::{AnalyzeRequest, CommandForm, CommandKind, Config, CoverageSummary, Decision, Integration, Severity, ShellDialect};
fuzz_target!(|data: &[u8]| {
    let Ok(source) = std::str::from_utf8(data) else { return; };
    if source.len() > 8192 { return; }
    let mut config = Config::default(); config.analysis.command_bytes_max = 4096; config.analysis.graph_nodes_max = 256;
    let request = AnalyzeRequest { protocol_version: 1, request_id: "fuzz".into(), command: CommandForm { kind: CommandKind::Shell, text: source.into(), dialect: ShellDialect::Bash }, cwd: "/tmp".into(), session_id: None, source: Integration::Cli, budget_ms: 20, context: Default::default() };
    let report = distill_rules::score(&request, distill_interp::interpret(&request, &config), &config, 0);
    if report.coverage.summary == CoverageSummary::Stopped { assert!(report.severity >= Severity::High); assert_eq!(report.decision, Decision::Deny); }
});
