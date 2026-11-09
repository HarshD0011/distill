//! Additive analysis evidence. Gaps describe limitations, not hazard ratings.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GapCode {
    HostMetadata,
    Invocation,
    Dependency,
    Language,
    Budget,
    ShellSemantics,
    Context,
    RuntimeEnvironment,
    Unmodeled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageGap {
    pub code: GapCode,
    pub message: String,
}
impl CoverageGap {
    pub fn from_reason(reason: &str) -> Self {
        let lower = reason.to_ascii_lowercase();
        let code = if lower.contains("metadata is missing") {
            GapCode::HostMetadata
        } else if lower.contains("budget")
            || lower.contains("limit reached")
            || lower.contains("deadline")
            || lower.contains("watchdog")
        {
            GapCode::Budget
        } else if lower.contains("preload")
            || lower.contains("runtime environment")
            || lower.contains("runtime configuration")
            || lower.contains("startup")
        {
            GapCode::RuntimeEnvironment
        } else if lower.contains("import")
            || lower.contains("dependency")
            || lower.contains("dependencies")
            || lower.contains("module resolution")
        {
            GapCode::Dependency
        } else if lower.contains("option")
            || lower.contains("invocation")
            || lower.contains("source selection")
        {
            GapCode::Invocation
        } else if lower.contains("source includes")
            || lower.contains("program behavior")
            || lower.contains("source format")
        {
            GapCode::Language
        } else if lower.contains("shell") || lower.contains("expansion") || lower.contains("syntax")
        {
            GapCode::ShellSemantics
        } else if lower.contains("directory")
            || lower.contains("context")
            || lower.contains("target")
        {
            GapCode::Context
        } else {
            GapCode::Unmodeled
        };
        Self {
            code,
            message: reason.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Span {
    pub start_byte: usize,
    pub end_byte: usize,
    pub line: usize,
    pub column: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandNode {
    pub id: usize,
    pub parent: Option<usize>,
    pub kind: String,
    pub span: Span,
    pub program: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CommandGraph {
    pub nodes: Vec<CommandNode>,
    pub parse_complete: bool,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContextEvidence {
    pub source: String,
    pub value: Option<String>,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stable_gap_categories_separate_host_and_source_limits() {
        assert_eq!(
            CoverageGap::from_reason("Execution shell metadata is missing").code,
            GapCode::HostMetadata
        );
        assert_eq!(
            CoverageGap::from_reason("Node interpreter option is unsupported").code,
            GapCode::Invocation
        );
        assert_eq!(
            CoverageGap::from_reason("Node package imports are unresolved").code,
            GapCode::Dependency
        );
        assert_eq!(
            CoverageGap::from_reason("Shared analysis deadline exhausted").code,
            GapCode::Budget
        );
    }
}
