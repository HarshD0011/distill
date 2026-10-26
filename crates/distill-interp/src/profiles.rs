//! Bundled wrapper grammar. Unknown options stop peeling rather than guessing argv.
use crate::Analyzer;
use distill_core::{EffectKind, Severity};
use distill_parse::{Word, is_assignment};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::OnceLock};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u32,
    wrappers: BTreeMap<String, Wrapper>,
    commands: BTreeMap<String, Command>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    flags: Vec<String>,
    values: Vec<String>,
    targets: Targets,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Targets {
    WriteAll,
    Copy,
    Move,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Wrapper {
    flags: Vec<String>,
    values: Vec<String>,
    query: Vec<String>,
    assignments: bool,
    privilege: bool,
    operand: bool,
}

fn registry() -> Result<&'static Registry, &'static str> {
    static REGISTRY: OnceLock<Result<Registry, &'static str>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| {
            let registry: Registry = serde_json::from_str(include_str!("../rules/wrappers.json"))
                .map_err(|_| "Invalid bundled wrapper profiles")?;
            if registry.version != 1
                || registry.wrappers.iter().any(|(name, spec)| {
                    name.is_empty()
                        || spec
                            .flags
                            .iter()
                            .any(|flag| spec.values.contains(flag) || spec.query.contains(flag))
                        || spec.values.iter().any(|flag| spec.query.contains(flag))
                })
            {
                return Err("Conflicting bundled wrapper profiles");
            }
            Ok(registry)
        })
        .as_ref()
        .map_err(|error| *error)
}

impl Analyzer<'_> {
    pub(super) fn apply_profile(&mut self, name: &str, args: &[Word]) -> bool {
        let profiles = match registry() {
            Ok(profiles) => profiles,
            Err(reason) => {
                self.unknown(reason);
                return true;
            }
        };
        let Some(spec) = profiles.commands.get(name) else {
            return false;
        };
        let mut operands = Vec::new();
        let mut options = true;
        let mut index = 0;
        while let Some(arg) = args.get(index) {
            if !self.within_budget() {
                return true;
            }
            index += 1;
            if options && arg.text == "--" {
                options = false;
                continue;
            }
            if options && arg.text.starts_with('-') {
                let (flag, value) = arg
                    .text
                    .split_once('=')
                    .map_or((arg.text.as_str(), None), |(flag, value)| {
                        (flag, Some(value))
                    });
                if spec.values.iter().any(|known| known == flag) && !arg.dynamic {
                    if value.is_none() {
                        if index >= args.len() {
                            self.unknown("Command option value is missing");
                            return true;
                        }
                        index += 1;
                    }
                    continue;
                }
                let short_flags = arg
                    .text
                    .strip_prefix('-')
                    .filter(|flags| !flags.is_empty() && !flags.starts_with('-'));
                let known = !arg.dynamic
                    && value.is_none()
                    && (spec.flags.contains(&arg.text)
                        || short_flags.is_some_and(|flags| {
                            flags
                                .chars()
                                .all(|flag| spec.flags.contains(&format!("-{flag}")))
                        }));
                if known {
                    continue;
                }
                self.context_partial = true;
                self.unknown("Command profile has an unknown or dynamic option");
                self.record_behavior(
                    distill_core::Behavior {
                        database: None,
                        kind: EffectKind::FileWrite,
                        operation: name.into(),
                        target: None,
                        target_class: distill_core::TargetClass::Unresolved,
                        recursive: false,
                        append: false,
                        location: None,
                    },
                    None,
                );
                return true;
            }
            operands.push(arg);
        }
        if operands.is_empty() {
            self.unknown("Command profile requires path operands");
            return true;
        }
        match spec.targets {
            Targets::WriteAll => {
                for target in operands {
                    self.write_destination(target, true);
                }
            }
            Targets::Copy | Targets::Move => {
                let Some((destination, sources)) = operands
                    .split_last()
                    .filter(|(_, sources)| !sources.is_empty())
                else {
                    self.unknown("Copy or move requires source and destination paths");
                    return true;
                };
                self.write_destination(destination, true);
                for source in sources {
                    let path = self.resolve(source);
                    self.record_behavior(
                        distill_core::Behavior {
                            database: None,
                            kind: if matches!(spec.targets, Targets::Move) {
                                EffectKind::FileDelete
                            } else {
                                EffectKind::FileRead
                            },
                            operation: name.into(),
                            target: path
                                .as_ref()
                                .map(|path| path.to_string_lossy().into_owned()),
                            target_class: self.target_class(path.as_deref()),
                            recursive: false,
                            append: false,
                            location: None,
                        },
                        None,
                    );
                }
                // Contents and directory expansion remain conditional for recursive transfers.
                self.context_partial = true;
                self.unknown(
                    "Copy/move directory contents and destination expansion are unresolved",
                );
            }
        }
        true
    }

    /// Returns the effective executable and whether the wrapper creates a cwd scope.
    pub(super) fn peel_wrappers(&mut self, words: &[Word]) -> Option<(usize, bool)> {
        let profiles = match registry() {
            Ok(registry) => registry,
            Err(reason) => {
                self.unknown(reason);
                return None;
            }
        };
        let mut index = 0;
        let mut scoped = false;
        while index < words.len() && is_assignment(&words[index]) {
            self.program_environment(&words[index]);
            index += 1;
        }
        for _ in 0..=self.config.analysis.expansion_depth_max {
            if !self.within_budget() {
                return None;
            }
            let Some(word) = words.get(index) else {
                self.raise(Severity::Safe);
                return None;
            };
            if word.dynamic {
                return Some((index, scoped));
            }
            let name = word.text.rsplit('/').next().unwrap_or(&word.text);
            let Some(spec) = profiles.wrappers.get(name) else {
                return Some((index, scoped));
            };
            if !crate::trusted_system_path(&word.text) {
                self.context_partial = true;
                self.unknown("Wrapper executable identity is unresolved");
            }
            if spec.privilege {
                self.finding(
                    Severity::High,
                    EffectKind::Privilege,
                    "privilege.wrapper",
                    "Command requests an elevated privilege transition",
                );
                self.context_partial = true;
                self.unknown("Elevated privilege or executable resolution is conditional");
            }
            index += 1;
            while let Some(arg) = words.get(index) {
                if spec.assignments && is_assignment(arg) {
                    self.program_environment(arg);
                    index += 1;
                    continue;
                }
                if arg.text == "--" {
                    index += 1;
                    break;
                }
                if !arg.text.starts_with('-') {
                    break;
                }
                let (flag, attached) = arg
                    .text
                    .split_once('=')
                    .map_or((arg.text.as_str(), None), |(flag, value)| {
                        (flag, Some(value))
                    });
                if !arg.dynamic && spec.query.iter().any(|query| query == flag) {
                    self.raise(Severity::Safe);
                    return None;
                }
                if spec.flags.iter().any(|known| known == flag)
                    && attached.is_none()
                    && !arg.dynamic
                {
                    if matches!(flag, "-i" | "--ignore-environment") {
                        self.context_partial = true;
                        self.unknown("Environment override may change executable identity");
                    }
                    index += 1;
                    continue;
                }
                if spec.values.iter().any(|known| known == flag) {
                    index += 1;
                    let value = if let Some(value) = attached {
                        Some(Word {
                            text: value.into(),
                            dynamic: arg.dynamic,
                            tilde_expansion: false,
                            substitutions: vec![],
                        })
                    } else {
                        let value = words.get(index).cloned();
                        index += 1;
                        value
                    };
                    let Some(value) = value else {
                        self.context_partial = true;
                        self.unknown("Wrapper option value is missing");
                        return None;
                    };
                    if matches!(
                        (name, flag),
                        ("env", "-C" | "--chdir") | ("sudo", "-D" | "--chdir")
                    ) {
                        self.cwd = self.resolve(&value);
                        scoped = true;
                        if self.cwd.is_none() {
                            self.context_partial = true;
                            self.unknown("Wrapper working directory is unresolved");
                        }
                    } else if matches!(flag, "-R" | "--chroot") {
                        self.cwd = None;
                        scoped = true;
                        self.context_partial = true;
                        self.unknown("Wrapper filesystem root is unresolved");
                    } else if matches!((name, flag), ("time", "-o" | "--output")) {
                        self.write_destination(&value, true);
                    }
                    continue;
                }
                self.context_partial = true;
                self.unknown("Wrapper has an unknown or dynamic option");
                return None;
            }
            if spec.operand {
                let Some(duration) = words.get(index) else {
                    self.unknown("Wrapper duration is missing");
                    return None;
                };
                if duration.dynamic
                    || !duration
                        .text
                        .chars()
                        .all(|c| c.is_ascii_digit() || ".smhd".contains(c))
                {
                    self.unknown("Wrapper duration is unresolved");
                    return None;
                }
                index += 1;
            }
            if index >= words.len() {
                if name == "env" {
                    self.finding(
                        Severity::High,
                        EffectKind::FileRead,
                        "read.environment",
                        "Prints environment variables that may contain credentials",
                    );
                    self.read_secret = true;
                }
                self.context_partial = true;
                self.unknown("Wrapper has no resolved executable");
                return None;
            }
        }
        self.stop_analysis("Wrapper nesting limit reached");
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn bundled_profiles_are_valid() {
        assert!(super::registry().is_ok());
    }
}
