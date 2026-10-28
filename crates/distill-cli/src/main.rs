use clap::{Parser, Subcommand, ValueEnum};
use distill_agents::{HookOptions, assess_hook, failure_with_options, trace};
use distill_core::{
    AgentMode, AnalyzeRequest, CommandForm, CommandKind, Config, Integration, PRODUCT_VERSION,
    PROTOCOL_VERSION, ShellDialect, default_config_path, new_id,
};
use distill_interp::interpret;
use distill_rules::score;
use std::{
    io::{self, Read},
    path::PathBuf,
    time::Instant,
};

mod approval;
mod coverage;
mod gate;
mod hook_sources;
mod setup;
mod watchdog;

#[derive(Parser)]
#[command(
    name = "distill",
    version = PRODUCT_VERSION,
    about = "Pre-execution severity analysis for shell commands"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Statically inspect literal Dockerfile/CI recipes or SQL/awk/sed source.
    Inspect {
        #[arg(long)]
        format: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Verify an inherited Unix socket belongs to the current user.
    PeerCheck {
        #[arg(long)]
        fd: i32,
    },
    /// Analyze, bind dependencies, and execute only within a restrictive sandbox.
    Run {
        #[arg(short, long)]
        command: String,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = "/bin/bash")]
        shell: String,
        #[arg(long = "workspace-root")]
        workspace_roots: Vec<PathBuf>,
        #[arg(long = "write")]
        writable: Vec<PathBuf>,
        #[arg(long)]
        approve: Option<String>,
        #[arg(long)]
        check: bool,
        #[arg(long)]
        session: Option<String>,
    },
    /// Configure user-owned hooks with an absolute executable and SHA-256 pin.
    Setup {
        host: Host,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        check: bool,
        #[arg(long)]
        labels: bool,
        /// Use the editor's Node/Electron runtime for hooks, without requiring Python.
        #[arg(long)]
        node_runtime: Option<PathBuf>,
        #[arg(long = "workspace-root")]
        workspace_roots: Vec<PathBuf>,
    },
    /// Aggregate coverage gaps from JSON reports on stdin, a file, or the editor broker.
    Coverage {
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        editor: bool,
    },
    /// Clear hashed policy state for one session and workspace.
    LedgerClear {
        #[arg(long)]
        session: String,
        #[arg(long, default_value = "cli")]
        source: String,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Inspect Distill hook sources without changing host configuration.
    HookSources {
        host: Host,
        #[arg(long = "workspace-root")]
        workspace_roots: Vec<PathBuf>,
    },
    /// Analyze a shell command without executing it.
    Analyze {
        #[arg(short, long, conflicts_with = "stdin")]
        command: Option<String>,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        human: bool,
        #[arg(long, default_value = "bash")]
        shell: String,
        #[arg(long = "workspace-root")]
        workspace_roots: Vec<PathBuf>,
        #[arg(long = "shell-option")]
        shell_options: Vec<String>,
        #[arg(long)]
        session: Option<String>,
    },
    /// Alias for analyze, kept for earlier local workflows.
    Assess {
        #[arg(short, long, conflicts_with = "stdin")]
        command: Option<String>,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        human: bool,
        #[arg(long, default_value = "bash")]
        shell: String,
        #[arg(long = "workspace-root")]
        workspace_roots: Vec<PathBuf>,
        #[arg(long = "shell-option")]
        shell_options: Vec<String>,
        #[arg(long)]
        session: Option<String>,
    },
    /// Analyze pre-tool events or record completed tool output for the editor extension.
    Hook {
        host: Host,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Advisory emits severity data and leaves approval to the host; strict enforces policy.
        #[arg(long, value_enum)]
        mode: Option<HookMode>,
        /// Add a severity comment to Codex advisory PreToolUse commands for approval display.
        #[arg(long)]
        label_command: bool,
        #[arg(long = "workspace-root")]
        workspace_roots: Vec<PathBuf>,
        /// Deny critical commands without displaying a dialog (for headless checks).
        #[arg(long)]
        no_prompt: bool,
        #[arg(long, hide = true)]
        internal_report: bool,
    },
    /// Report embedded-analyzer health and integration translation.
    Doctor {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        #[arg(long = "workspace-root")]
        workspace_roots: Vec<PathBuf>,
    },
    /// Configuration helpers.
    Config {
        #[command(subcommand)]
        command: ConfigCmd,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    Validate {
        #[arg(long)]
        path: Option<PathBuf>,
    },
    Show {
        #[arg(long)]
        path: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Host {
    Codex,
    Claude,
}

#[derive(Clone, Copy, ValueEnum)]
enum HookMode {
    Strict,
    Advisory,
}

impl From<HookMode> for AgentMode {
    fn from(value: HookMode) -> Self {
        match value {
            HookMode::Strict => Self::Strict,
            HookMode::Advisory => Self::Advisory,
        }
    }
}

impl From<Host> for Integration {
    fn from(value: Host) -> Self {
        match value {
            Host::Codex => Integration::Codex,
            Host::Claude => Integration::Claude,
        }
    }
}

fn main() {
    if watchdog::supervise() {
        return;
    }
    if let Err(error) = run() {
        eprintln!("distill: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Inspect {
            format,
            file,
            cwd,
            config,
        } => {
            if !["dockerfile", "ci", "sql", "awk", "sed"].contains(&format.as_str()) {
                return Err("Supported formats: dockerfile, ci, sql, awk, sed".into());
            }
            let command = format!(
                "distill inspect --format {format} --file '{}'",
                file.to_string_lossy().replace('\'', "'\"'\"'")
            );
            print_json(&analyze_command(
                &command,
                cwd,
                &load_config(config)?,
                Integration::Cli,
                "bash",
                vec![],
                vec![],
            )?)?;
        }
        Commands::PeerCheck { fd } => {
            distill_agents::trace::verify_peer(fd)?;
            println!("same-user");
        }
        Commands::Run {
            command,
            cwd,
            config,
            shell,
            workspace_roots,
            writable,
            approve,
            check,
            session,
        } => {
            let config = load_config(config)?;
            let code = gate::run(gate::Options {
                command,
                cwd,
                config,
                shell,
                workspace_roots,
                writable,
                approve,
                check,
                session,
            })?;
            if code != 0 {
                std::process::exit(code);
            }
        }
        Commands::Setup {
            host,
            config,
            check,
            labels,
            node_runtime,
            workspace_roots,
        } => {
            let host = match host {
                Host::Codex => "codex",
                Host::Claude => "claude",
            };
            print_json(&setup::configure(
                host,
                &setup::load_config(host, config.as_deref())?,
                &workspace_roots,
                check,
                labels,
                node_runtime.as_deref(),
            )?)?;
        }
        Commands::Coverage { input, editor } => {
            print_json(&coverage::run(input.as_deref(), editor)?)?;
        }
        Commands::LedgerClear {
            session,
            source,
            cwd,
            config,
        } => {
            let cwd = cwd.unwrap_or(std::env::current_dir().map_err(|e| e.to_string())?);
            distill_core::session::clear(&load_config(config)?, &source, &session, &cwd)?;
            println!("Session policy state cleared");
        }
        Commands::HookSources {
            host,
            workspace_roots,
        } => {
            print_json(&hook_sources::inspect(
                match host {
                    Host::Codex => "codex",
                    Host::Claude => "claude",
                },
                &workspace_roots,
            )?)?;
        }
        Commands::Analyze {
            command,
            stdin,
            cwd,
            config,
            human,
            shell,
            workspace_roots,
            shell_options,
            session,
        }
        | Commands::Assess {
            command,
            stdin,
            cwd,
            config,
            human,
            shell,
            workspace_roots,
            shell_options,
            session,
        } => {
            let config = load_config(config)?;
            let command = match (command, stdin) {
                (Some(text), _) => text,
                (None, true) => read_bounded_stdin(config.analysis.command_bytes_max)?,
                _ => return Err("provide --command or --stdin".into()),
            };
            let mut report = analyze_command(
                &command,
                cwd,
                &config,
                Integration::Cli,
                &shell,
                workspace_roots,
                shell_options,
            )?;
            if let Some(session) = session {
                distill_core::session::assess(
                    &config,
                    "cli",
                    &session,
                    &report.request_id.clone(),
                    &report.cwd.clone(),
                    &distill_parse::retry_fingerprint(&command),
                    &mut report,
                )?;
            }
            if human {
                print_human(&report);
            } else {
                print_json(&report)?;
            }
        }
        Commands::Hook {
            host,
            config,
            mode,
            label_command,
            workspace_roots,
            no_prompt: _,
            internal_report,
        } => {
            let mut input = read_bounded_stdin(trace::MAX_EVENT_BYTES);
            if !workspace_roots.is_empty() {
                if workspace_roots.iter().any(|root| !root.is_absolute()) {
                    return Err("workspace roots must be absolute".into());
                }
                if let Ok(raw) = &input
                    && let Ok(mut event) = serde_json::from_str::<serde_json::Value>(raw)
                {
                    event["workspace_roots"] = serde_json::json!(workspace_roots);
                    input = Ok(serde_json::to_string(&event).map_err(|e| e.to_string())?);
                }
            }
            if let Ok(input) = &input
                && trace::is_completion(input)
            {
                let trace_result = load_config(config)
                    .and_then(|config| trace::completion_with_config(host.into(), input, &config));
                if let Err(error) = trace_result {
                    eprintln!("distill trace: {error}");
                }
                print_json(&serde_json::json!({}))?;
                return Ok(());
            }
            let mut config = load_config(config)?;
            if let Some(mode) = mode {
                match host {
                    Host::Codex => config.agents.codex.mode = mode.into(),
                    Host::Claude => config.agents.claude.mode = mode.into(),
                }
            }
            let options = HookOptions { label_command };
            let result = input
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|input| assess_hook(host.into(), input, &config, options));
            match result {
                Ok((output, report)) => {
                    if internal_report {
                        print_json(
                            &serde_json::json!({"distill_hook_response": output, "report": report}),
                        )?;
                    } else {
                        print_json(&output)?;
                    }
                    if config.editor_trace.enabled
                        && (!internal_report || report.severity != distill_core::Severity::Critical)
                        && let Err(error) = trace::assessment(
                            host.into(),
                            input.as_deref().unwrap_or(""),
                            &report,
                            &output,
                            &config,
                        )
                    {
                        eprintln!("distill trace: {error}");
                    }
                }
                Err(error) => {
                    let output = failure_with_options(
                        host.into(),
                        input.as_deref().unwrap_or(""),
                        &config,
                        &error,
                        options,
                    );
                    print_json(&output)?;
                    if config.editor_trace.enabled
                        && let Ok(input) = &input
                        && let Err(error) =
                            trace::failure(host.into(), input, &error, &output, &config)
                    {
                        eprintln!("distill trace: {error}");
                    }
                }
            }
        }
        Commands::Doctor {
            config,
            json,
            mut workspace_roots,
        } => {
            let config = load_config(config)?;
            if workspace_roots.is_empty() {
                workspace_roots.push(std::env::current_dir().map_err(|e| e.to_string())?);
            }
            let codex_hooks = hook_sources::inspect("codex", &workspace_roots)
                .unwrap_or_else(|error| serde_json::json!({"warnings": [error]}));
            let claude_hooks = hook_sources::inspect("claude", &workspace_roots)
                .unwrap_or_else(|error| serde_json::json!({"warnings": [error]}));
            if json {
                print_json(&serde_json::json!({
                    "product_version": PRODUCT_VERSION, "protocol": PROTOCOL_VERSION,
                    "executable": std::env::current_exe().ok(),
                    "executable_sha256": std::env::current_exe().ok().and_then(|p| std::fs::read(p).ok()).map(|b| distill_core::sha256(&b)),
                    "trace_protocol": 1, "output_capture": config.capture_editor_output(), "behavior_policy_version": distill_core::BEHAVIOR_POLICY_VERSION,
                    "sandbox": gate::backend(&config).ok(), "session_ledger": config.ledger.enabled, "hooks": {"codex": codex_hooks, "claude": claude_hooks},
                    "capabilities": ["assessments", "completion", "memory-only", "analysis-context", "shared-deadline", "workspace-context", "hook-source-inspection", "user-hook-setup", "unix-peer-credentials", "execution-gate", "file-bindings", "session-ledger", "coverage-report", "signed-labels", "hard-watchdog", "critical-hook-block", "shell-context-coverage", "node-hook-launcher", "coding-workflows", "native-critical-approval", "foreground-critical-approval"]
                }))?;
                return Ok(());
            }
            println!("distill {PRODUCT_VERSION}");
            println!("protocol {PROTOCOL_VERSION}");
            println!("mode: embedded static analyzer (daemon not required for local CLI testing)");
            println!("trace: disabled / not requested");
            println!("deadline_ms: {}", config.analysis.deadline_ms);
            println!(
                "config: {}",
                default_config_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "defaults".into())
            );
            println!("policy_digest: {}", config.digest());
            for (host, mode, strict_behavior) in [
                (
                    "codex",
                    config.agents.codex.mode,
                    "PreToolUse Ask/ForceAsk map to deny",
                ),
                (
                    "claude",
                    config.agents.claude.mode,
                    "PreToolUse Ask/ForceAsk map to native ask",
                ),
            ] {
                let behavior = match mode {
                    AgentMode::Strict => strict_behavior,
                    AgentMode::Advisory => {
                        "severity warnings; CRITICAL requires a human dialog even with automatic approval"
                    }
                };
                println!("agents.{host}.mode: {mode:?} ({behavior})");
            }
            println!(
                "Codex PermissionRequest: CRITICAL requires a human dialog; other verdicts preserve native approval"
            );
            println!("history: optional editor-owned memory trace; no command history on disk");
            println!("extension: install extensions/vscode for per-chat command traces");
            println!(
                "execution gate: {:?}; environment cleared, network denied",
                gate::backend(&config)
            );
            for source in [&codex_hooks, &claude_hooks] {
                for warning in source["warnings"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(serde_json::Value::as_str)
                {
                    println!("warning: {warning}");
                }
            }
        }
        Commands::Config { command } => match command {
            ConfigCmd::Validate { path } => {
                let config = Config::load(path.as_deref())?;
                println!(
                    "valid schema_version={} digest={}",
                    config.schema_version,
                    config.digest()
                );
            }
            ConfigCmd::Show { path } => {
                let config = Config::load(path.as_deref())?;
                print_json(&config)?;
            }
        },
    }
    Ok(())
}

fn load_config(path: Option<PathBuf>) -> Result<Config, String> {
    Config::load(path.as_deref())
}

fn analyze_command(
    command: &str,
    cwd: Option<PathBuf>,
    config: &Config,
    source: Integration,
    shell: &str,
    workspace_roots: Vec<PathBuf>,
    shell_options: Vec<String>,
) -> Result<distill_core::Report, String> {
    let started = Instant::now();
    let current = std::env::current_dir().map_err(|e| e.to_string())?;
    let cwd = match cwd {
        Some(path) if path.is_absolute() => path,
        Some(path) => current.join(path),
        None => current,
    };
    let request = AnalyzeRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: new_id("req"),
        command: CommandForm {
            kind: CommandKind::Shell,
            text: command.to_string(),
            dialect: ShellDialect::from_shell(shell),
        },
        cwd,
        session_id: None,
        source,
        budget_ms: config.analysis.deadline_ms.saturating_sub(50),
        context: distill_core::ExecutionContext {
            shell: Some(shell.into()),
            workspace_roots,
            shell_options: (!shell_options.is_empty()).then_some(shell_options),
            sandbox_escalation: false,
        },
    };
    let draft = interpret(&request, config);
    Ok(score(
        &request,
        draft,
        config,
        started.elapsed().as_millis(),
    ))
}

fn colored_severity(severity: &str) -> String {
    let mark = match severity {
        "safe" => "\u{1b}[32m",
        "low" => "\u{1b}[34m",
        "medium" => "\u{1b}[33m",
        "high" => "\u{1b}[31m",
        "critical" => "\u{1b}[35m",
        _ => "\u{1b}[0m",
    };
    if std::io::IsTerminal::is_terminal(&io::stdout()) {
        format!("{mark}{severity}\u{1b}[0m")
    } else {
        severity.to_string()
    }
}

fn print_human(report: &distill_core::Report) {
    println!("report:    {}", report.report_id);
    println!("severity:  {}", colored_severity(report.severity_label()));
    println!(
        "policy:    {} (conservative approval rating)",
        colored_severity(report.severity.as_str())
    );
    println!("analysis:  {}", report.analysis_label());
    println!("decision:  {}", report.decision.as_str());
    println!("coverage:  {:?}", report.coverage.summary);
    println!("trace:     {:?}", report.trace_status);
    println!("mode:      {}", report.mode);
    println!();
    println!("{}", report.explanation);
    if !report.findings.is_empty() {
        println!("\nfindings:");
        for finding in &report.findings {
            println!(
                "  - {} [{}] {}",
                finding.rule_id,
                finding.severity.as_str(),
                finding.impact
            );
        }
    }
    if !report.unknowns.is_empty() {
        println!("\nunknowns:");
        for unknown in &report.unknowns {
            println!("  - {unknown}");
        }
    }
}

fn read_bounded_stdin(max: usize) -> Result<String, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > max {
        return Err(format!("input exceeds {max} bytes"));
    }
    String::from_utf8(bytes).map_err(|_| "input must be UTF-8".into())
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|e| e.to_string())?
    );
    Ok(())
}
