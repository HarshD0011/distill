//! Reviewed capability adapters. Unknown argv shapes remain unresolved.
use crate::Analyzer;
use distill_core::{EffectKind, Severity};
use distill_parse::Word;
use serde::Deserialize;
use std::{collections::BTreeMap, sync::OnceLock};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    version: u32,
    reviewed: bool,
    provenance: String,
    commands: BTreeMap<String, Vec<Capability>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capability {
    flag: String,
    kind: String,
    #[serde(default)]
    prefix: Option<String>,
}
fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let catalog: Catalog = serde_json::from_str(include_str!("../rules/capabilities.json"))
            .expect("validated embedded capability catalog");
        assert!(catalog.version == 1 && catalog.reviewed && !catalog.provenance.is_empty());
        catalog
    })
}

impl Analyzer<'_> {
    pub(super) fn capability_command(&mut self, name: &str, args: &[Word], depth: usize) -> bool {
        if matches!(name, "sed" | "nl") && self.literal_text_read(name, args) {
            return true;
        }
        if name == "distill" && args.first().is_some_and(|word| word.text == "inspect") {
            let format = args
                .windows(2)
                .find(|pair| pair[0].text == "--format")
                .map(|pair| pair[1].text.clone());
            let file = args
                .windows(2)
                .find(|pair| pair[0].text == "--file")
                .map(|pair| pair[1].clone());
            if let (Some(format), Some(file)) = (format, file) {
                self.artifact_file(&format, &file, depth);
            } else {
                self.unresolved_program("Artifact invocation is incomplete");
            }
            return true;
        }
        if matches!(name, "docker" | "podman")
            && args.first().is_some_and(|word| word.text == "build")
        {
            let file = args
                .windows(2)
                .find(|pair| matches!(pair[0].text.as_str(), "-f" | "--file"))
                .map(|pair| pair[1].clone())
                .unwrap_or(Word {
                    text: "Dockerfile".into(),
                    dynamic: false,
                    tilde_expansion: false,
                    substitutions: vec![],
                });
            self.artifact_file("dockerfile", &file, depth);
            return true;
        }
        if let Some(capabilities) = catalog().commands.get(name).filter(|_| name != "rg") {
            for capability in capabilities {
                for (index, word) in args.iter().enumerate() {
                    let payload = if word.text == capability.flag {
                        args.get(index + 1)
                    } else {
                        None
                    };
                    let inline = word.text.strip_prefix(&format!("{}=", capability.flag));
                    let Some(text) = payload.map(|w| w.text.as_str()).or(inline) else {
                        continue;
                    };
                    let text = if let Some(prefix) = &capability.prefix {
                        let Some(text) = text.strip_prefix(prefix) else {
                            continue;
                        };
                        text
                    } else {
                        text
                    };
                    self.unresolved_program("Reviewed capability catalog identifies executable or unresolved option behavior");
                    let target = Word {
                        text: text.into(),
                        dynamic: word.dynamic || payload.is_some_and(|word| word.dynamic),
                        tilde_expansion: payload.is_some_and(|word| word.tilde_expansion),
                        substitutions: vec![],
                    };
                    match capability.kind.as_str() {
                        "exec" if !target.dynamic => self.analyze(text, depth + 1),
                        "file-read" => self.read_destination(&target),
                        "file-write" => self.write_destination(&target, true),
                        "net-send" => self.finding(
                            Severity::High,
                            EffectKind::NetworkSend,
                            "capability.net-send",
                            "Reviewed command capability may send data to a network peer",
                        ),
                        "net-fetch" => self.finding(
                            Severity::Low,
                            EffectKind::NetworkReceive,
                            "capability.net-fetch",
                            "Reviewed command capability may receive remote data",
                        ),
                        "priv" => self.finding(
                            Severity::High,
                            EffectKind::Privilege,
                            "capability.privilege",
                            "Reviewed command capability may elevate privileges",
                        ),
                        "persist" => self.finding(
                            Severity::High,
                            EffectKind::Persistence,
                            "capability.persistence",
                            "Reviewed command capability may configure persistent execution",
                        ),
                        _ => {}
                    }
                }
            }
        }
        let texts = args
            .iter()
            .map(|word| word.text.as_str())
            .collect::<Vec<_>>();
        let nested = match name {
            "watch" => Some(
                texts
                    .iter()
                    .position(|arg| !arg.starts_with('-') && arg.parse::<f64>().is_err())
                    .unwrap_or(texts.len()),
            ),
            "xargs" => Some(xargs_command(&texts)),
            "parallel" => Some(0),
            "docker" | "podman" if texts.first() == Some(&"exec") => Some(2),
            "kubectl" if texts.contains(&"exec") => {
                texts.iter().position(|arg| *arg == "--").map(|i| i + 1)
            }
            _ => None,
        };
        if let Some(index) = nested {
            self.unresolved_program(
                "Capability invokes additional commands with unresolved execution context",
            );
            if let Some(words) = args
                .get(index..)
                .filter(|words| !words.is_empty() && words.iter().all(|word| !word.dynamic))
            {
                let source = words
                    .iter()
                    .map(|word| format!("'{}'", word.text.replace('\'', "'\"'\"'")))
                    .collect::<Vec<_>>()
                    .join(" ");
                self.analyze(&source, depth + 1);
            }
            return true;
        }
        if matches!(
            name,
            "tar" | "ssh" | "rsync" | "git" | "vim" | "vi" | "nvim" | "less" | "find"
        ) {
            for (index, word) in args.iter().enumerate() {
                let embedded = word
                    .text
                    .split_once('=')
                    .and_then(|(key, value)| {
                        [
                            "--to-command",
                            "--checkpoint-action",
                            "core.fsmonitor",
                            "core.sshCommand",
                            "core.editor",
                            "core.pager",
                            "ProxyCommand",
                            "LocalCommand",
                            "--rsh",
                        ]
                        .contains(&key)
                        .then_some(value.strip_prefix("exec=").unwrap_or(value))
                    })
                    .or_else(|| {
                        let previous = index
                            .checked_sub(1)
                            .and_then(|i| args.get(i))?
                            .text
                            .as_str();
                        matches!(
                            (name, previous),
                            ("tar", "--to-command" | "--checkpoint-action")
                                | ("rsync", "-e" | "--rsh")
                                | ("vim" | "vi" | "nvim", "-c" | "--cmd")
                                | ("ssh", "-o")
                        )
                        .then_some(word.text.as_str())
                    });
                if let Some(payload) = embedded {
                    self.unresolved_program("Command option can execute a nested program");
                    if !word.dynamic {
                        let payload = payload
                            .strip_prefix("ProxyCommand=")
                            .or_else(|| payload.strip_prefix("LocalCommand="))
                            .unwrap_or(payload);
                        self.analyze(payload, depth + 1);
                    }
                }
            }
        }
        match name {
            "npx" | "uvx" | "pipx" => {
                self.finding(
                    Severity::High,
                    EffectKind::Execute,
                    "exec.fetch-launcher",
                    "Launcher may download and execute package code",
                );
                self.context_partial = true;
                self.unknown("Fetched package contents and lifecycle behavior are unresolved");
                true
            }
            "awk" | "gawk" | "mawk" | "sed" => {
                self.unresolved_program(
                    "Embedded awk or sed program requires capability inspection",
                );
                for word in args.iter().filter(|word| !word.dynamic) {
                    if name != "sed"
                        && (word.text.contains("system(")
                            || word.text.contains("system (")
                            || word.text.contains("| getline"))
                        || name == "sed"
                            && (word.text.contains("/e")
                                || word.text.starts_with("e ")
                                || word.text.contains(";e "))
                    {
                        self.finding(
                            Severity::High,
                            EffectKind::Execute,
                            "exec.text-program",
                            "Text-processing program may execute a shell command",
                        );
                    }
                    if name == "sed"
                        && (word.text.contains("/w ")
                            || word.text.starts_with("w ")
                            || word.text.contains(";w "))
                    {
                        self.finding(
                            Severity::High,
                            EffectKind::FileWrite,
                            "write.sed-program",
                            "Sed program may write a file selected by its script",
                        );
                    }
                }
                true
            }
            "scp" | "rsync" | "nc" | "ncat" | "netcat" | "ssh" => {
                self.finding(
                    Severity::High,
                    EffectKind::NetworkSend,
                    "net.transfer",
                    "Transfer or remote shell may send local data to a network peer",
                );
                for word in args.iter().filter(|word| !word.text.starts_with('-')) {
                    if crate::is_sensitive(&word.text) {
                        self.finding(
                            Severity::Critical,
                            EffectKind::NetworkSend,
                            "net.secret-transfer",
                            "Transfer includes a credential-like path",
                        );
                    }
                }
                self.context_partial = true;
                self.unknown(
                    "Remote command, transfer direction, or stream contents are unresolved",
                );
                true
            }
            "psql" | "mysql" | "sqlite3" => {
                self.database_client(name, args, depth);
                true
            }
            "aws" | "gcloud" | "az" | "kubectl" | "terraform" | "pulumi" => {
                self.semantic_verbs(name, args);
                true
            }
            _ => false,
        }
    }
    fn semantic_verbs(&mut self, name: &str, args: &[Word]) {
        let database = matches!(name, "psql" | "mysql" | "sqlite3");
        let mut destructive = false;
        if !database {
            for word in args
                .iter()
                .take_while(|word| !word.text.starts_with('-') && !word.dynamic)
            {
                let lower = word.text.to_ascii_lowercase();
                if ["get", "list", "describe", "show", "status"]
                    .iter()
                    .any(|query| lower == *query || lower.starts_with(&format!("{query}-")))
                {
                    break;
                }
                if [
                    "delete",
                    "terminate",
                    "destroy",
                    "purge",
                    "rm",
                    "drop",
                    "truncate",
                    "remove",
                    "revoke",
                ]
                .iter()
                .any(|verb| lower == *verb || lower.starts_with(&format!("{verb}-")))
                {
                    destructive = true;
                    break;
                }
            }
        }
        self.finding(
            if destructive {
                Severity::High
            } else {
                Severity::Medium
            },
            EffectKind::UnknownEffect,
            "semantic.remote-verb",
            if destructive {
                "Semantic CLI may delete resources or execute destructive database statements"
            } else {
                "Semantic CLI effects depend on remote state and configuration"
            },
        );
        self.context_partial = true;
        self.unknown("Semantic CLI scope and embedded-language behavior are unresolved");
    }

    // Deliberately narrow: unsupported scripts/options fall back to unresolved analysis.
    fn literal_text_read(&mut self, name: &str, args: &[Word]) -> bool {
        if args.iter().any(|word| word.dynamic) {
            return false;
        }
        let mut files = Vec::new();
        let mut options = true;
        let mut scripts = 0;
        let mut index = 0;
        while let Some(word) = args.get(index) {
            let text = word.text.as_str();
            if options && text == "--" {
                options = false;
            } else if options && name == "sed" && text == "-n" {
            } else if options && name == "sed" && text == "-e" {
                index += 1;
                if !args.get(index).is_some_and(|word| readonly_sed(&word.text)) {
                    return false;
                }
                scripts += 1;
            } else if options && name == "nl" && matches!(text, "-ba" | "-bt" | "-bn") {
            } else if options && name == "nl" && text == "-b" {
                index += 1;
                if !args
                    .get(index)
                    .is_some_and(|word| matches!(word.text.as_str(), "a" | "t" | "n"))
                {
                    return false;
                }
            } else if options && text.starts_with('-') && text != "-" {
                return false;
            } else if name == "sed" && scripts == 0 {
                if !readonly_sed(text) {
                    return false;
                }
                scripts += 1;
            } else if text != "-" {
                files.push(word);
            }
            index += 1;
        }
        if name == "sed" && scripts == 0 {
            return false;
        }
        for file in files {
            self.read_destination(file);
        }
        true
    }
}
fn readonly_sed(program: &str) -> bool {
    let Some(operation) = program.chars().last() else {
        return false;
    };
    if !matches!(operation, 'p' | '=' | 'q') {
        return false;
    }
    let addresses = &program[..program.len() - 1];
    addresses.is_empty() || {
        let parts = addresses.split(',').collect::<Vec<_>>();
        parts.len() <= 2
            && parts.iter().all(|part| {
                *part == "$" || !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
            })
    }
}
fn xargs_command(args: &[&str]) -> usize {
    let mut index = 0;
    while let Some(argument) = args.get(index) {
        if *argument == "--" {
            return index + 1;
        }
        if !argument.starts_with('-') {
            return index;
        }
        if [
            "-I",
            "-n",
            "-P",
            "-s",
            "-d",
            "-E",
            "-a",
            "--arg-file",
            "--delimiter",
            "--replace",
            "--max-args",
            "--max-procs",
        ]
        .contains(argument)
        {
            index += 2;
        } else {
            index += 1;
        }
    }
    args.len()
}
