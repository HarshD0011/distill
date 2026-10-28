//! Read-only inventory for safe hook migration. Never executes a configured handler.
use distill_core::{AnalysisBudget, read_analysis_file};
use distill_parse::{Token, lex};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub fn inspect(host: &str, workspaces: &[PathBuf]) -> Result<Value, String> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is unavailable")?;
    let user = if host == "codex" {
        std::env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".codex"))
    } else {
        home.join(".claude")
    };
    let mut directories = vec![(user, "user")];
    let mut seen = BTreeSet::new();
    for workspace in workspaces {
        if !workspace.is_absolute() {
            return Err("Workspace roots must be absolute".into());
        }
        for ancestor in workspace.ancestors() {
            let directory = ancestor.join(if host == "codex" { ".codex" } else { ".claude" });
            if seen.insert(directory.clone()) {
                directories.push((directory, "project"));
            }
            if ancestor.join(".git").exists() {
                break;
            }
        }
    }
    let mut seen_files = BTreeSet::new();
    let mut handlers = Vec::new();
    let mut warnings = Vec::new();
    let mut binary_hashes = BTreeMap::new();
    for (directory, scope) in directories {
        for name in if host == "codex" {
            vec!["hooks.json", "config.toml"]
        } else {
            vec!["settings.json"]
        } {
            let file = directory.join(name);
            if !seen_files.insert(file.clone()) {
                continue;
            }
            match std::fs::symlink_metadata(&file) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("Cannot inspect {}: {error}", file.display())),
            }
            let budget = AnalysisBudget::new(5000);
            let contents = read_analysis_file(&file, &budget, 1024 * 1024)
                .map_err(|error| format!("Cannot inspect {}: {error}", file.display()))?;
            let config: Value = if name.ends_with("toml") {
                let value: toml::Value = toml::from_str(&contents)
                    .map_err(|error| format!("Invalid hook source {}: {error}", file.display()))?;
                serde_json::to_value(value).map_err(|error| error.to_string())?
            } else {
                serde_json::from_str(&contents)
                    .map_err(|error| format!("Invalid hook source {}: {error}", file.display()))?
            };
            if config.pointer("/features/hooks") == Some(&json!(false)) {
                warnings.push(format!("Hooks are disabled in {}", file.display()));
            }
            if config.get("disableAllHooks") == Some(&json!(true)) {
                warnings.push(format!("All hooks are disabled in {}", file.display()));
            }
            if scope == "project"
                && (config.get("hooks").is_some() || config.get("permissions").is_some())
            {
                warnings.push(format!("Project-controlled hook or permission configuration in {}; user hooks do not establish managed-policy enforcement", file.display()));
            }
            for (event, groups) in config
                .get("hooks")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
            {
                let Some(groups) = groups.as_array() else {
                    continue;
                };
                for group in groups {
                    let matcher = group.get("matcher").and_then(Value::as_str).unwrap_or("");
                    for handler in group
                        .get("hooks")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let Some(command) = handler.get("command").and_then(Value::as_str) else {
                            continue;
                        };
                        if let Some((executable, args)) = distill_handler(command, host) {
                            if scope == "project" {
                                warnings.push(format!(
                                    "Project-controlled Distill handler in {}",
                                    file.display()
                                ));
                            }
                            if !Path::new(&executable).is_absolute() {
                                warnings.push(format!(
                                    "Distill handler uses PATH lookup in {}",
                                    file.display()
                                ));
                            }
                            if !command.contains("--sha256 ") {
                                warnings.push(format!(
                                    "Distill handler has no executable hash pin in {}",
                                    file.display()
                                ));
                            } else {
                                let words = lex(command).unwrap_or_default();
                                let expected =
                                    words
                                        .windows(2)
                                        .find_map(|pair| match (&pair[0], &pair[1]) {
                                            (Token::Word(flag), Token::Word(value))
                                                if flag.text == "--sha256" && !value.dynamic =>
                                            {
                                                Some(value.text.as_str())
                                            }
                                            _ => None,
                                        });
                                let actual =
                                    binary_hashes.entry(executable.clone()).or_insert_with(|| {
                                        std::fs::metadata(&executable)
                                            .ok()
                                            .filter(|m| m.is_file() && m.len() <= 128 * 1024 * 1024)
                                            .and_then(|_| std::fs::read(&executable).ok())
                                            .map(|bytes| distill_core::sha256(&bytes))
                                    });
                                if expected.is_none() || actual.as_deref() != expected {
                                    warnings.push(format!("Distill executable hash pin is invalid or stale in {}; rerun setup after reviewing the installed binary", file.display()));
                                }
                            }
                            handlers.push(json!({"scope": scope, "path": file, "event": event, "matcher": matcher, "command": command, "executable": executable, "args": args}));
                        }
                    }
                }
            }
        }
    }
    Ok(
        json!({"handlers": handlers, "warnings": warnings, "trust": "Review changed definitions in the host hook browser"}),
    )
}

pub(crate) fn distill_handler(command: &str, host: &str) -> Option<(String, Vec<String>)> {
    let words: Vec<_> = lex(command)
        .ok()?
        .into_iter()
        .map(|token| match token {
            Token::Word(word) if !word.dynamic => Some(word.text),
            _ => None,
        })
        .collect::<Option<_>>()?;
    let node_prefix = [
        "/usr/bin/env",
        "-u",
        "NODE_OPTIONS",
        "-u",
        "NODE_PATH",
        "-u",
        "LD_PRELOAD",
        "-u",
        "LD_LIBRARY_PATH",
        "-u",
        "DYLD_INSERT_LIBRARIES",
        "-u",
        "DYLD_LIBRARY_PATH",
        "ELECTRON_RUN_AS_NODE=1",
    ];
    let node_launcher = words
        .iter()
        .take(node_prefix.len())
        .map(String::as_str)
        .eq(node_prefix)
        && words
            .get(14)
            .is_some_and(|word| Path::new(word).is_absolute())
        && words.get(15).is_some_and(|word| {
            Path::new(word)
                .file_name()
                .is_some_and(|name| name == "hook-launcher.js")
        })
        && words.get(16).is_some_and(|word| word == "--binary");
    let words = if node_launcher || words.first().is_some_and(|word| word.ends_with("python3")) {
        let index = words.iter().position(|word| word == "--binary")?;
        let binary = words.get(index + 1)?.clone();
        let hook = words.iter().position(|word| word == "hook")?;
        [vec![binary], words[hook..].to_vec()].concat()
    } else {
        words
    };
    let [binary, hook, integration, args @ ..] = words.as_slice() else {
        return None;
    };
    if Path::new(binary).file_name()?.to_str()? != "distill"
        || hook != "hook"
        || integration != host
    {
        return None;
    }
    Some((binary.clone(), args.to_vec()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_standalone_distill_handlers_are_inventory_candidates() {
        for command in [
            "distill hook codex --mode advisory",
            "'/a path/distill' hook codex --mode strict",
        ] {
            assert!(super::distill_handler(command, "codex").is_some());
        }
        for command in [
            "echo 'distill hook codex'",
            "distill hook claude",
            "distill hook codex; echo done",
            "$BIN hook codex",
        ] {
            assert!(super::distill_handler(command, "codex").is_none());
        }
    }
}
