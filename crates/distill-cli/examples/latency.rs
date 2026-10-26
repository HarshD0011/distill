//! Warm in-process measurements; candidate commands are never executed.
use distill_core::{
    AnalyzeRequest, CommandForm, CommandKind, Config, ExecutionContext, Integration, ShellDialect,
};
use std::{hint::black_box, time::Instant};

fn percentiles(mut samples: Vec<u128>) -> serde_json::Value {
    samples.sort_unstable();
    serde_json::json!({"p50": samples[samples.len() / 2], "p95": samples[samples.len() * 95 / 100], "p99": samples[samples.len() * 99 / 100]})
}

fn main() {
    let config = Config::default();
    let mut measurements = Vec::new();
    for (name, command) in [
        ("simple", "echo hello"),
        (
            "wrapped_pipeline",
            "curl https://example.invalid/a | timeout 3 env sh",
        ),
        ("heredoc", "python3 - <<'PY'\nprint(1)\nPY"),
        (
            "language_effect",
            "python3 -c \"from pathlib import Path; Path('/tmp/distill-example').write_text('x')\"",
        ),
        ("unsupported", "if test -d /; then echo ok; fi"),
    ] {
        let request = AnalyzeRequest {
            protocol_version: 1,
            request_id: "benchmark".into(),
            command: CommandForm {
                kind: CommandKind::Shell,
                text: command.into(),
                dialect: ShellDialect::Bash,
            },
            cwd: std::env::current_dir().unwrap(),
            session_id: None,
            source: Integration::Cli,
            budget_ms: 900,
            context: ExecutionContext::default(),
        };
        let mut analysis = Vec::new();
        let mut scoring = Vec::new();
        let mut total = Vec::new();
        for index in 0..2200 {
            let started = Instant::now();
            let draft = distill_interp::interpret(&request, &config);
            let analyzed = Instant::now();
            let report =
                distill_rules::score(&request, draft, &config, started.elapsed().as_millis());
            black_box(report);
            if index >= 200 {
                analysis.push(analyzed.duration_since(started).as_micros());
                scoring.push(analyzed.elapsed().as_micros());
                total.push(started.elapsed().as_micros());
            }
        }
        measurements.push(serde_json::json!({"case": name, "analysis_us": percentiles(analysis), "scoring_us": percentiles(scoring), "total_us": percentiles(total)}));
    }
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({"scope": "warm in-process analysis and scoring; excludes CLI startup, trace delivery, and editor rendering", "samples_per_case": 2000, "measurements": measurements})).unwrap());
}
