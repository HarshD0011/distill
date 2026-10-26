use std::path::Path;

/// Argument classes from the architecture knowledge base.
/// Classification order: root/home, secret, startup file, regenerable, source, hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgClass {
    RootOrHome,
    Secret,
    StartupFile,
    Regenerable,
    Source,
    Hidden,
    #[allow(dead_code)]
    None,
    Other,
}

pub fn classify(raw: &str, path: Option<&Path>, root_or_home: bool) -> ArgClass {
    if root_or_home || is_root_text(raw) {
        return ArgClass::RootOrHome;
    }
    if crate::is_sensitive(raw) || path.is_some_and(path_sensitive) {
        return ArgClass::Secret;
    }
    if is_startup(raw) || path.is_some_and(path_startup) {
        return ArgClass::StartupFile;
    }
    if is_regenerable(raw) || path.is_some_and(path_regenerable) {
        return ArgClass::Regenerable;
    }
    if is_source(raw) || path.is_some_and(path_source) {
        return ArgClass::Source;
    }
    if is_hidden(raw) {
        return ArgClass::Hidden;
    }
    ArgClass::Other
}

fn is_root_text(raw: &str) -> bool {
    matches!(
        raw,
        "/" | "/*" | "~" | "~/" | "~/*" | "$HOME" | "${HOME}" | "$HOME/" | "$HOME/*"
    )
}

fn is_hidden(raw: &str) -> bool {
    let name = raw.rsplit('/').next().unwrap_or(raw);
    name.starts_with('.') && name != "." && name != ".."
}

fn is_startup(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    [
        ".zshrc",
        ".zprofile",
        ".bashrc",
        ".bash_profile",
        ".profile",
        "/.git/hooks/",
        "launchagents",
        "launchdaemons",
        "/.vscode/tasks.json",
        "/.vscode/settings.json",
        "/.github/workflows/",
        "/.gitlab-ci.yml",
        "/.envrc",
        "/package.json",
        "/.codex/",
        "/.claude/",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_regenerable(raw: &str) -> bool {
    let name = raw
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(raw)
        .trim_start_matches('.');
    let base = name.split('*').next_back().unwrap_or(name);
    [
        "__pycache__",
        "pytest_cache",
        "mypy_cache",
        "ruff_cache",
        "node_modules",
        "next",
        "target",
        "ds_store",
    ]
    .contains(&base.to_ascii_lowercase().as_str())
        || matches!(ext(raw), Some("pyc" | "pyo" | "o" | "class" | "log"))
}

fn is_source(raw: &str) -> bool {
    matches!(
        ext(raw),
        Some(
            "py" | "rs"
                | "go"
                | "js"
                | "ts"
                | "tsx"
                | "c"
                | "cpp"
                | "h"
                | "java"
                | "rb"
                | "sh"
                | "md"
        )
    )
}

fn ext(raw: &str) -> Option<&str> {
    let name = raw.trim_end_matches('/').rsplit('/').next().unwrap_or(raw);
    let name = name.trim_start_matches('*');
    name.rsplit_once('.')
        .map(|(_, ext)| ext)
        .filter(|ext| !ext.is_empty() && !ext.contains('*'))
}

fn path_sensitive(path: &Path) -> bool {
    crate::is_sensitive(&path.to_string_lossy())
}

fn path_startup(path: &Path) -> bool {
    is_startup(&path.to_string_lossy())
}

fn path_regenerable(path: &Path) -> bool {
    is_regenerable(&path.to_string_lossy())
}

fn path_source(path: &Path) -> bool {
    is_source(&path.to_string_lossy())
}
