use serde::{Deserialize, Serialize};
pub mod credentials;
pub mod diagnostics;
pub mod integrity;
pub use diagnostics::{CommandGraph, CommandNode, ContextEvidence, CoverageGap, GapCode, Span};
pub mod privacy;
pub mod recoverability;
pub mod service_ipc;
pub mod session;
pub use integrity::{FileSnapshot, read_snapshot, sha256};
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const PROTOCOL_VERSION: u32 = 1;
pub const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Included in report provenance and the policy digest when built-in semantics change.
pub const BEHAVIOR_POLICY_VERSION: &str = "10";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn bump(self, steps: i8) -> Self {
        let order = [
            Self::Safe,
            Self::Low,
            Self::Medium,
            Self::High,
            Self::Critical,
        ];
        let index = order.iter().position(|item| *item == self).unwrap_or(0) as i8;
        order[(index + steps).clamp(0, 4) as usize]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Ask,
    ForceAsk,
    Deny,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::ForceAsk => "force_ask",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Ask,
    ForceAsk,
    Deny,
    Hold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageSummary {
    StaticAccounted,
    Partial,
    Stopped,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLevel {
    Accounted,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceStatus {
    StaticOnly,
    Complete,
    Partial,
    Stopped,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    Shell,
    Argv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellDialect {
    Bash,
    Posix,
    Zsh,
    Unsupported,
}

impl ShellDialect {
    pub fn from_shell(shell: &str) -> Self {
        match Path::new(shell).file_name().and_then(|name| name.to_str()) {
            Some("bash") => Self::Bash,
            Some("sh" | "dash") => Self::Posix,
            Some("zsh") => Self::Zsh,
            _ => Self::Unsupported,
        }
    }
}

/// Context supplied by the host; absent values are never inferred from the hook process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecutionContext {
    pub shell: Option<String>,
    pub workspace_roots: Vec<PathBuf>,
    /// Host-provided enabled options, never inferred from the analyzer process.
    pub shell_options: Option<Vec<String>>,
    pub sandbox_escalation: bool,
}

/// One deadline shared by shell parsing, recursive analysis, and language handoffs.
pub struct AnalysisBudget {
    started: std::time::Instant,
    duration: std::time::Duration,
    nodes: std::cell::Cell<usize>,
    node_limit: usize,
}

impl AnalysisBudget {
    pub fn new(milliseconds: u64) -> Self {
        Self {
            started: std::time::Instant::now(),
            duration: std::time::Duration::from_millis(milliseconds),
            nodes: std::cell::Cell::new(0),
            node_limit: 4096,
        }
    }

    pub fn expired(&self) -> bool {
        self.started.elapsed() >= self.duration || self.nodes.get() > self.node_limit
    }

    pub fn with_node_limit(mut self, limit: usize) -> Self {
        self.node_limit = limit;
        self
    }

    pub fn visit_node(&self) -> bool {
        self.nodes.set(self.nodes.get().saturating_add(1));
        !self.expired()
    }

    pub fn remaining_nodes(&self) -> usize {
        self.node_limit.saturating_sub(self.nodes.get())
    }

    pub fn stop_reason(&self) -> &'static str {
        if self.nodes.get() > self.node_limit {
            "Shared analysis node budget exhausted"
        } else {
            "Shared analysis deadline exhausted"
        }
    }
}

/// Bounded regular-file reads. Nonblocking open prevents a raced FIFO from hanging a hook.
pub fn read_analysis_file(
    path: &Path,
    budget: &AnalysisBudget,
    cap: usize,
) -> Result<String, String> {
    use std::io::Read;
    if budget.expired() {
        return Err(budget.stop_reason().into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "Source file could not be opened")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Source metadata is unavailable")?;
    if !metadata.is_file() || metadata.len() > cap as u64 {
        return Err("Source is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    loop {
        if budget.expired() {
            return Err(budget.stop_reason().into());
        }
        let mut chunk = [0; 16384];
        let count = file
            .read(&mut chunk)
            .map_err(|_| "Source could not be read")?;
        if count == 0 {
            break;
        }
        if bytes.len() + count > cap {
            return Err("Source size exceeds the analysis limit".into());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    String::from_utf8(bytes).map_err(|_| "Source is not UTF-8".into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Integration {
    Cli,
    Codex,
    Claude,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMode {
    /// Enforce the analyzer's policy using the host's supported hook decisions.
    Strict,
    /// Report severity while retaining the host's native approval policy.
    Advisory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    FileRead,
    FileWrite,
    FileDelete,
    PermissionChange,
    Execute,
    Connect,
    NetworkSend,
    NetworkReceive,
    Persistence,
    Privilege,
    UnknownEffect,
    Database,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseAction {
    Query,
    Delete,
    Update,
    SchemaDelete,
    SchemaModify,
}

/// Selection scope is independent of the number of rows actually in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseScope {
    AllRows,
    NoRows,
    ConditionalRows,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DatabaseEffect {
    pub action: DatabaseAction,
    pub scope: DatabaseScope,
}

/// Context about a target, independently of the language used to access it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetClass {
    Ordinary,
    Protected,
    Secret,
    Startup,
    Regenerable,
    Source,
    BuildArtifact,
    Null,
    Unresolved,
    OutsideWorkspace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceLocation {
    pub file: Option<String>,
    pub line: usize,
    /// One-based byte column, matching Tree-sitter positions.
    pub column: usize,
}

/// A semantic fact. Language adapters supply context, never a severity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Behavior {
    pub kind: EffectKind,
    pub operation: String,
    pub target: Option<String>,
    pub target_class: TargetClass,
    pub recursive: bool,
    pub append: bool,
    pub location: Option<SourceLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<DatabaseEffect>,
}

impl Behavior {
    pub fn database(
        action: DatabaseAction,
        scope: DatabaseScope,
        target: Option<String>,
        location: Option<SourceLocation>,
    ) -> Self {
        Self {
            kind: EffectKind::Database,
            operation: "sql".into(),
            target,
            target_class: TargetClass::Ordinary,
            recursive: false,
            append: false,
            location,
            database: Some(DatabaseEffect { action, scope }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingBasis {
    Impact,
    Uncertainty,
}

#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub summary: CoverageSummary,
    pub parse: CoverageLevel,
    pub options: CoverageLevel,
    pub targets: CoverageLevel,
    pub expansion: CoverageLevel,
    pub stop_reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub source: &'static str,
    pub fact: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub impact: String,
    pub evidence: Vec<Evidence>,
    pub confidence: &'static str,
    pub basis: FindingBasis,
}

#[derive(Debug, Clone, Serialize)]
pub struct Effect {
    pub kind: EffectKind,
    pub stage: &'static str,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeRequest {
    pub protocol_version: u32,
    pub request_id: String,
    pub command: CommandForm,
    pub cwd: PathBuf,
    pub session_id: Option<String>,
    pub source: Integration,
    pub budget_ms: u64,
    #[serde(default)]
    pub context: ExecutionContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandForm {
    pub kind: CommandKind,
    pub text: String,
    pub dialect: ShellDialect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEdit {
    pub path: PathBuf,
    pub content: Option<String>,
    pub full_write: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub protocol_version: u32,
    pub report_id: String,
    pub request_id: String,
    pub mode: &'static str,
    pub command_redacted: String,
    pub command_digest: String,
    pub inspected_files: Vec<FileSnapshot>,
    pub severity: Severity,
    /// Highest modeled impact; None means the impact could not be established.
    /// `severity` remains the conservative policy rating for existing clients.
    pub impact_severity: Option<Severity>,
    pub decision: Decision,
    pub explanation: String,
    pub findings: Vec<Finding>,
    pub effects: Vec<Effect>,
    pub behaviors: Vec<Behavior>,
    pub coverage: Coverage,
    pub trace_status: TraceStatus,
    pub unknowns: Vec<String>,
    pub coverage_gaps: Vec<CoverageGap>,
    pub graph: CommandGraph,
    pub context_evidence: Vec<ContextEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub judge: Option<serde_json::Value>,
    pub policy_digest: String,
    pub behavior_policy_version: &'static str,
    pub analysis_context: ExecutionContext,
    pub shell_dialect: ShellDialect,
    pub cwd: PathBuf,
    pub timings_ms: Timings,
}

impl Report {
    pub fn severity_label(&self) -> &'static str {
        self.impact_severity.map_or("unknown", Severity::as_str)
    }

    pub fn analysis_label(&self) -> &'static str {
        match self.coverage.summary {
            CoverageSummary::StaticAccounted => "modeled",
            CoverageSummary::Partial => "partial",
            CoverageSummary::Stopped => "stopped",
            CoverageSummary::Opaque => "opaque",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Timings {
    pub total: u128,
    pub stages: std::collections::BTreeMap<String, u128>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisDraft {
    pub findings: Vec<Finding>,
    pub effects: Vec<Effect>,
    pub behaviors: Vec<Behavior>,
    pub unknowns: Vec<String>,
    pub graph: CommandGraph,
    pub context_evidence: Vec<ContextEvidence>,
    pub coverage: Coverage,
    pub max_severity: Option<Severity>,
    pub inspected_files: Vec<FileSnapshot>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub analysis: AnalysisConfig,
    pub trace: TraceConfig,
    pub policy: PolicyConfig,
    pub history: HistoryConfig,
    pub privacy: PrivacyConfig,
    pub agents: AgentsConfig,
    pub editor_trace: EditorTraceConfig,
    pub security: SecurityConfig,
    pub ledger: LedgerConfig,
    pub sandbox: SandboxConfig,
    pub service: ServiceConfig,
    pub judge: JudgeConfig,
    #[serde(rename = "override")]
    pub overrides: Vec<PolicyOverride>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            analysis: AnalysisConfig::default(),
            trace: TraceConfig::default(),
            policy: PolicyConfig::default(),
            history: HistoryConfig::default(),
            privacy: PrivacyConfig::default(),
            agents: AgentsConfig::default(),
            editor_trace: EditorTraceConfig::default(),
            security: SecurityConfig::default(),
            ledger: LedgerConfig::default(),
            sandbox: SandboxConfig::default(),
            service: ServiceConfig::default(),
            judge: JudgeConfig::default(),
            overrides: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnalysisConfig {
    pub deadline_ms: u64,
    pub command_bytes_max: usize,
    pub expansion_depth_max: usize,
    pub graph_nodes_max: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceConfig {
    /// Separate from the legacy reserved history.enabled setting: no implicit migration.
    pub history_enabled: bool,
    pub directory: Option<PathBuf>,
    pub max_events: usize,
    pub max_bytes: u64,
    pub classifier_path: Option<PathBuf>,
    pub classifier_min_support: usize,
    pub classifier_min_probability: f64,
}
impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            history_enabled: false,
            directory: None,
            max_events: 10000,
            max_bytes: 64 * 1024 * 1024,
            classifier_path: None,
            classifier_min_support: 20,
            classifier_min_probability: 0.99,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(from = "JudgeOptions")]
pub struct JudgeConfig {
    pub enabled: bool,
    pub provider: JudgeProvider,
    pub endpoint: String,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<ReasoningEffort>,
    pub api_key_env: String,
    pub max_output_tokens: u32,
    pub deadline_ms: u64,
    pub send_script_contents: bool,
    pub max_script_bytes: usize,
    pub background_deadline_ms: u64,
    pub review_format: ReviewFormat,
    pub batch_window_ms: u64,
}
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewFormat {
    #[default]
    Effects,
    Severity,
}
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JudgeProvider {
    #[default]
    OpenaiCompatible,
    Gemini,
    #[serde(alias = "anthropic")]
    Claude,
    LlamaCpp,
    Vllm,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    None,
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}
impl Default for JudgeConfig {
    fn default() -> Self {
        Self::for_provider(JudgeProvider::OpenaiCompatible)
    }
}
impl JudgeConfig {
    pub fn for_provider(provider: JudgeProvider) -> Self {
        let (endpoint, model, api_key_env) = match provider {
            JudgeProvider::OpenaiCompatible => (
                "https://api.openai.com/v1/chat/completions",
                "gpt-6-luna",
                "OPENAI_API_KEY",
            ),
            JudgeProvider::Gemini => (
                "https://generativelanguage.googleapis.com/v1beta",
                "gemini-3.1-flash-lite",
                "GEMINI_API_KEY",
            ),
            JudgeProvider::Claude => (
                "https://api.anthropic.com/v1/messages",
                "claude-haiku-5-5",
                "ANTHROPIC_API_KEY",
            ),
            JudgeProvider::LlamaCpp => ("http://127.0.0.1:8080/v1/chat/completions", "", ""),
            JudgeProvider::Vllm => ("http://127.0.0.1:8000/v1/chat/completions", "", ""),
        };
        Self {
            enabled: false,
            provider,
            endpoint: endpoint.into(),
            model: model.into(),
            reasoning_effort: None,
            api_key_env: api_key_env.into(),
            max_output_tokens: 512,
            deadline_ms: 800,
            send_script_contents: false,
            max_script_bytes: 8192,
            background_deadline_ms: 5000,
            review_format: ReviewFormat::Effects,
            batch_window_ms: 0,
        }
    }
}

// Provider-specific defaults prevent a partial Gemini/Claude configuration from
// accidentally reusing OpenAI's model, endpoint, or credential variable.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct JudgeOptions {
    enabled: Option<bool>,
    provider: Option<JudgeProvider>,
    endpoint: Option<String>,
    model: Option<String>,
    reasoning_effort: Option<ReasoningEffort>,
    api_key_env: Option<String>,
    max_output_tokens: Option<u32>,
    deadline_ms: Option<u64>,
    send_script_contents: Option<bool>,
    max_script_bytes: Option<usize>,
    background_deadline_ms: Option<u64>,
    review_format: Option<ReviewFormat>,
    batch_window_ms: Option<u64>,
}
impl From<JudgeOptions> for JudgeConfig {
    fn from(options: JudgeOptions) -> Self {
        let mut result = Self::for_provider(options.provider.unwrap_or_default());
        if let Some(v) = options.enabled {
            result.enabled = v;
        }
        if let Some(v) = options.endpoint {
            result.endpoint = v;
        }
        if let Some(v) = options.model {
            result.model = v;
        }
        result.reasoning_effort = options.reasoning_effort;
        if let Some(v) = options.api_key_env {
            result.api_key_env = v;
        }
        if let Some(v) = options.max_output_tokens {
            result.max_output_tokens = v;
        }
        if let Some(v) = options.deadline_ms {
            result.deadline_ms = v;
        }
        if let Some(v) = options.send_script_contents {
            result.send_script_contents = v;
        }
        if let Some(v) = options.max_script_bytes {
            result.max_script_bytes = v;
        }
        if let Some(v) = options.background_deadline_ms {
            result.background_deadline_ms = v;
        }
        if let Some(v) = options.review_format {
            result.review_format = v;
        }
        if let Some(v) = options.batch_window_ms {
            result.batch_window_ms = v;
        }
        result
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyOverride {
    pub pattern: String,
    pub severity: Severity,
    #[serde(default)]
    pub note: String,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            deadline_ms: 900,
            command_bytes_max: 64 * 1024,
            expansion_depth_max: 8,
            graph_nodes_max: 4096,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TraceConfig {
    pub enabled: bool,
    pub network: String,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            network: "deny".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    pub medium: PolicyAction,
    pub high: PolicyAction,
    pub critical: PolicyAction,
    pub incomplete: PolicyAction,
    pub unavailable: PolicyAction,
    pub protected_paths: Vec<PathBuf>,
    pub protected_packages: Vec<String>,
    pub effects: EffectPolicy,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            medium: PolicyAction::Ask,
            high: PolicyAction::Ask,
            critical: PolicyAction::Deny,
            incomplete: PolicyAction::Ask,
            unavailable: PolicyAction::Hold,
            protected_paths: Vec::new(),
            protected_packages: Vec::new(),
            effects: EffectPolicy::default(),
        }
    }
}

/// Versioned, validated policy input shared by shell and language semantics.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EffectPolicy {
    pub read: Severity,
    pub write: Severity,
    pub build_artifact: Severity,
    pub delete: Severity,
    pub recursive_delete: Severity,
    pub sensitive: Severity,
    pub startup: Severity,
    pub protected_modify: Severity,
    pub execute: Severity,
    pub network: Severity,
    pub unresolved_target: Severity,
    pub outside_workspace_read: Severity,
    pub outside_workspace_modify: Severity,
    pub database_query: Severity,
    pub database_modify: Severity,
    pub database_all_rows: Severity,
    pub database_unknown_scope: Severity,
}

impl Default for EffectPolicy {
    fn default() -> Self {
        Self {
            read: Severity::Low,
            write: Severity::Medium,
            build_artifact: Severity::Low,
            delete: Severity::Medium,
            recursive_delete: Severity::Medium,
            sensitive: Severity::High,
            startup: Severity::High,
            protected_modify: Severity::Critical,
            execute: Severity::High,
            network: Severity::Low,
            unresolved_target: Severity::High,
            outside_workspace_read: Severity::Medium,
            outside_workspace_modify: Severity::High,
            database_query: Severity::Medium,
            database_modify: Severity::High,
            database_all_rows: Severity::Critical,
            database_unknown_scope: Severity::High,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryConfig {
    pub enabled: bool,
    pub retention_days: u32,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 7,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivacyConfig {
    /// None preserves existing temporary-capture defaults. Explicit false always wins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_output: Option<bool>,
    pub telemetry: bool,
}

/// Explicitly scoped to the temporary editor-owned broker; never persisted history.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EditorTraceConfig {
    pub enabled: bool,
    /// Backward-compatible disable switch. New configurations use privacy.capture_output.
    pub capture_output: bool,
}

impl Default for EditorTraceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            capture_output: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentsConfig {
    pub codex: AgentSettings,
    pub claude: AgentSettings,
}

impl Default for AgentsConfig {
    fn default() -> Self {
        Self {
            codex: AgentSettings {
                mode: AgentMode::Strict,
            },
            claude: AgentSettings {
                mode: AgentMode::Strict,
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentSettings {
    pub mode: AgentMode,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            mode: AgentMode::Strict,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    pub label_key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LedgerConfig {
    pub enabled: bool,
    pub directory: Option<PathBuf>,
    pub ttl_seconds: u64,
    pub max_entries: usize,
    pub repeat_limit: usize,
}
impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directory: None,
            ttl_seconds: 7200,
            max_entries: 1000,
            repeat_limit: 3,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    pub backend: String,
    pub timeout_ms: u64,
}
impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            backend: "auto".into(),
            timeout_ms: 30000,
        }
    }
}

impl Config {
    pub fn model_digest(&self) -> String {
        sha256(
            serde_json::json!([
                self.judge,
                self.service.classifier_path,
                self.service.classifier_min_support,
                self.service.classifier_min_probability
            ])
            .to_string()
            .as_bytes(),
        )
    }
    pub fn recording_enabled(&self) -> bool {
        self.editor_trace.enabled || self.service.history_enabled
    }
    pub fn capture_editor_output(&self) -> bool {
        self.privacy.capture_output.unwrap_or(false) && self.editor_trace.capture_output
    }

    pub fn load(path: Option<&Path>) -> Result<Self, String> {
        let config = match path {
            Some(path) => Self::from_toml_bytes(&std::fs::read(path).map_err(|e| e.to_string())?)?,
            None => match default_config_path() {
                Some(path) if path.is_file() => {
                    Self::from_toml_bytes(&std::fs::read(&path).map_err(|e| e.to_string())?)?
                }
                _ => Self::default(),
            },
        };
        config.validate()?;
        Ok(config)
    }

    pub fn from_toml_bytes(bytes: &[u8]) -> Result<Self, String> {
        toml::from_str(std::str::from_utf8(bytes).map_err(|_| "config must be UTF-8")?)
            .map_err(|e| format!("invalid config: {e}"))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self
            .service
            .classifier_path
            .as_ref()
            .is_some_and(|v| !v.is_absolute())
            || self.service.classifier_min_support == 0
            || !self.service.classifier_min_probability.is_finite()
            || !(0.5..=1.0).contains(&self.service.classifier_min_probability)
        {
            return Err("Invalid local classifier path or abstention thresholds".into());
        }
        if self
            .service
            .directory
            .as_ref()
            .is_some_and(|v| !v.is_absolute() || v.as_os_str().len() > 80)
            || self.service.max_events == 0
            || self.service.max_events > 100000
            || !(1024 * 1024..=1024 * 1024 * 1024).contains(&self.service.max_bytes)
        {
            return Err("Service directory or retention limits are invalid".into());
        }
        if self.history.retention_days == 0 || self.history.retention_days > 3650 {
            return Err("History retention must be 1..3650 days".into());
        }
        if !(100..=15000).contains(&self.judge.background_deadline_ms) {
            return Err("judge.background_deadline_ms must be between 100 and 15000".into());
        }
        if self.judge.batch_window_ms > 500
            || self.judge.batch_window_ms >= self.judge.background_deadline_ms
        {
            return Err(
                "judge.batch_window_ms must be 0..500 and shorter than the background deadline"
                    .into(),
            );
        }
        if self.judge.batch_window_ms > 0 && self.judge.review_format != ReviewFormat::Severity {
            return Err("Batching requires judge.review_format = severity".into());
        }
        if self.judge.reasoning_effort.is_some()
            && matches!(
                self.judge.provider,
                JudgeProvider::Gemini | JudgeProvider::Claude
            )
        {
            return Err("judge.reasoning_effort requires an OpenAI-compatible provider; omit it for Gemini or Claude".into());
        }
        if self.judge.deadline_ms == 0
            || self.judge.deadline_ms > 800
            || self.judge.max_script_bytes > 8192
            || !(64..=2048).contains(&self.judge.max_output_tokens)
            || self.judge.model.len() > 256
            || self.judge.endpoint.len() > 2048
            || !self
                .judge
                .api_key_env
                .bytes()
                .all(|v| v.is_ascii_uppercase() || v.is_ascii_digit() || v == b'_')
        {
            return Err(
                "Judge deadline, payload, endpoint or key-variable limits are invalid".into(),
            );
        }
        if self.judge.enabled && self.judge.model.trim().is_empty() {
            return Err("An enabled judge requires an explicit model".into());
        }
        if self.judge.enabled
            && matches!(
                self.judge.provider,
                JudgeProvider::Gemini | JudgeProvider::Claude
            )
            && self.judge.api_key_env.is_empty()
        {
            return Err("Gemini and Claude require an API key environment-variable name".into());
        }
        if self.overrides.len() > 128 {
            return Err("Too many policy overrides".into());
        }
        for rule in &self.overrides {
            if rule.pattern.len() > 1024
                || rule.note.len() > 1024
                || regex::Regex::new(&format!("^(?:{})$", rule.pattern)).is_err()
            {
                return Err("Invalid policy override regex or note".into());
            }
        }
        if self.schema_version != 1 {
            return Err(format!(
                "unsupported config schema_version {}",
                self.schema_version
            ));
        }
        if !(100..=5000).contains(&self.analysis.deadline_ms) {
            return Err("analysis.deadline_ms must be between 100 and 5000".into());
        }
        if self.analysis.command_bytes_max == 0 || self.analysis.command_bytes_max > 1024 * 1024 {
            return Err("analysis.command_bytes_max is out of range".into());
        }
        if self.trace.enabled {
            return Err("trace.enabled is not supported in the embedded static CLI".into());
        }
        if self.trace.network != "deny" {
            return Err("trace.network must be \"deny\" in this release".into());
        }
        if self.privacy.telemetry {
            return Err("privacy.telemetry cannot be enabled in this release".into());
        }
        if self.policy.protected_paths.iter().any(|p| !p.is_absolute()) {
            return Err("policy.protected_paths must be absolute".into());
        }
        if self
            .security
            .label_key_path
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
            || self
                .ledger
                .directory
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
        {
            return Err("Security key and ledger paths must be absolute".into());
        }
        if self.ledger.max_entries == 0
            || self.ledger.max_entries > 10000
            || self.ledger.ttl_seconds == 0
            || self.ledger.ttl_seconds > 86400
            || self.sandbox.timeout_ms == 0
            || self.sandbox.timeout_ms > 3600000
        {
            return Err("Ledger or execution limits are out of range".into());
        }
        if !["auto", "seatbelt", "landlock"].contains(&self.sandbox.backend.as_str()) {
            return Err("sandbox.backend must be auto, seatbelt, or landlock".into());
        }
        if self.policy.effects.recursive_delete < self.policy.effects.delete {
            return Err("policy.effects.recursive_delete must be at least delete".into());
        }
        let effects = &self.policy.effects;
        if effects.database_modify < effects.database_query
            || effects.database_all_rows < effects.database_modify
            || effects.database_unknown_scope < effects.database_modify
        {
            return Err("Database policy must cover query, modification, all-row and unknown scope consistently".into());
        }
        if self.policy.effects.protected_modify
            < self
                .policy
                .effects
                .write
                .max(self.policy.effects.recursive_delete)
        {
            return Err(
                "policy.effects.protected_modify must cover write and recursive_delete".into(),
            );
        }
        if self.policy.effects.sensitive
            < self
                .policy
                .effects
                .read
                .max(self.policy.effects.write)
                .max(self.policy.effects.delete)
        {
            return Err("policy.effects.sensitive must cover ordinary file operations".into());
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        let encoded = toml::to_string(self).unwrap_or_default();
        sha256(format!("{BEHAVIOR_POLICY_VERSION}\0{encoded}").as_bytes())
    }
}

pub fn default_config_path() -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    let xdg = home.join(".config/distill/config.toml");
    if xdg.is_file() {
        return Some(xdg);
    }
    let mac = home.join("Library/Application Support/distill/config.toml");
    if mac.is_file() {
        return Some(mac);
    }
    Some(xdg)
}

pub fn new_id(prefix: &str) -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{prefix}-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

pub fn redact_command(text: &str) -> String {
    let text = privacy::redact(text);
    const MAX: usize = 512;
    if text.len() <= MAX {
        text
    } else {
        let mut end = MAX;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &text[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_truncation_preserves_utf8_boundaries() {
        let command = format!("{}🟢{}", "a".repeat(511), "b".repeat(10));
        assert_eq!(redact_command(&command), format!("{}…", "a".repeat(511)));
    }

    #[test]
    fn default_config_validates() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn reasoning_effort_is_explicit_and_changes_model_cache_policy() {
        let default = Config::default();
        assert!(default.judge.reasoning_effort.is_none());
        assert!(
            !toml::to_string(&default)
                .unwrap()
                .contains("reasoning_effort")
        );
        for provider in ["openai_compatible", "llama_cpp", "vllm"] {
            for effort in ["none", "minimal", "low", "medium", "high", "xhigh", "max"] {
                let input = format!(
                    "[judge]\nprovider='{provider}'\nmodel='custom-model'\nreasoning_effort='{effort}'\n"
                );
                let config = Config::from_toml_bytes(input.as_bytes()).unwrap();
                config.validate().unwrap();
                let mut without = config.clone();
                without.judge.reasoning_effort = None;
                assert_ne!(config.model_digest(), without.model_digest());
                let roundtrip: Config = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
                assert_eq!(roundtrip.model_digest(), config.model_digest());
            }
        }
        assert!(Config::from_toml_bytes(b"[judge]\nreasoning_effort='invented'\n").is_err());
        for provider in ["gemini", "claude"] {
            let input = format!("[judge]\nprovider='{provider}'\nreasoning_effort='none'\n");
            assert!(
                Config::from_toml_bytes(input.as_bytes())
                    .unwrap()
                    .validate()
                    .unwrap_err()
                    .contains("OpenAI-compatible")
            );
        }
    }

    #[test]
    fn partial_provider_config_uses_its_own_model_endpoint_and_key_variable() {
        for (provider, model, key) in [
            ("gemini", "gemini-3.1-flash-lite", "GEMINI_API_KEY"),
            ("claude", "claude-haiku-5-5", "ANTHROPIC_API_KEY"),
        ] {
            let input = format!("[judge]\nprovider='{provider}'\nenabled=true\n");
            let config = Config::from_toml_bytes(input.as_bytes()).unwrap();
            config.validate().unwrap();
            assert_eq!(config.judge.model, model);
            assert_eq!(config.judge.api_key_env, key);
            assert!(!config.judge.endpoint.contains("openai.com"));
            let roundtrip: Config = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
            assert_eq!(roundtrip.model_digest(), config.model_digest());
        }
        assert!(
            Config::from_toml_bytes(b"[judge]\nprovider='gemini'\nunrecognized=true\n").is_err()
        );
    }

    #[test]
    fn explicit_privacy_capture_opt_out_wins_over_legacy_trace_defaults() {
        assert!(!Config::default().capture_editor_output());
        let config = Config::from_toml_bytes(
            b"[privacy]\ncapture_output = false\n[editor_trace]\ncapture_output = true\n",
        )
        .unwrap();
        assert!(!config.capture_editor_output());
        let config = Config::from_toml_bytes(b"[editor_trace]\ncapture_output = false\n").unwrap();
        assert!(!config.capture_editor_output());
        let config = Config::from_toml_bytes(b"[privacy]\ncapture_output = true\n").unwrap();
        assert!(config.capture_editor_output());
    }

    #[cfg(unix)]
    #[test]
    fn analysis_file_reads_reject_fifos_without_waiting_for_a_writer() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let fifo = std::env::temp_dir().join(new_id("distill-fifo"));
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: name is a valid NUL-terminated path owned by this test.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let result = read_analysis_file(&fifo, &AnalysisBudget::new(100), 1024);
        std::fs::remove_file(fifo).unwrap();
        assert!(result.unwrap_err().contains("regular file"));
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = Config::from_toml_bytes(b"schema_version = 1\nunexpected = true\n").unwrap_err();
        assert!(err.contains("invalid config"));
    }

    #[test]
    fn severity_order() {
        assert!(Severity::Safe < Severity::Low);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn effect_policy_is_validated_and_changes_provenance() {
        let original = Config::default();
        let mut adjusted = original.clone();
        adjusted.policy.effects.read = Severity::Medium;
        adjusted.validate().unwrap();
        assert_ne!(original.digest(), adjusted.digest());
        adjusted.policy.effects.recursive_delete = Severity::Safe;
        assert!(adjusted.validate().is_err());
        assert!(
            Config::from_toml_bytes(b"[policy.effects]\nread = 'low'\nunknown = 'high'\n").is_err()
        );
    }

    #[test]
    fn database_policy_cannot_understate_unknown_or_all_row_scope() {
        for invalid in [
            "database_all_rows = 'medium'",
            "database_unknown_scope = 'low'",
            "database_modify = 'low'",
        ] {
            assert!(
                Config::from_toml_bytes(format!("[policy.effects]\n{invalid}\n").as_bytes())
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        let defaults = Config::default();
        let changed =
            Config::from_toml_bytes(b"[policy.effects]\ndatabase_all_rows='high'\n").unwrap();
        assert_ne!(defaults.digest(), changed.digest());
    }
}
