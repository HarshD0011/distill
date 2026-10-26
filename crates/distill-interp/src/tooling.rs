//! Shared, bounded argv decoding for tool adapters. Unknown syntax never proves safety.
use distill_core::{EffectKind, Severity};
use distill_parse::Word;

use crate::Analyzer;

#[derive(Default)]
pub(super) struct Options {
    pub values: Vec<(String, Option<Word>)>,
    pub operands: Vec<Word>,
    pub incomplete: bool,
}

impl Options {
    pub fn has(&self, names: &[&str]) -> bool {
        self.values
            .iter()
            .any(|(name, _)| names.contains(&name.as_str()))
    }
    pub fn all<'a>(&'a self, names: &'a [&str]) -> impl Iterator<Item = &'a Word> {
        self.values.iter().filter_map(move |(name, value)| {
            names
                .contains(&name.as_str())
                .then_some(value.as_ref())
                .flatten()
        })
    }
}

pub(super) fn literal(text: impl Into<String>) -> Word {
    Word {
        text: text.into(),
        dynamic: false,
        tilde_expansion: false,
        substitutions: vec![],
    }
}

/// `stop_at_operand` preserves program arguments after an image, script or subcommand.
pub(super) fn decode(
    args: &[Word],
    valued: &[&str],
    switches: &[&str],
    stop_at_operand: bool,
) -> Options {
    let mut out = Options::default();
    let mut index = 0;
    let mut options = true;
    while let Some(word) = args.get(index) {
        index += 1;
        if word.dynamic {
            out.incomplete = true;
        }
        if options && word.text == "--" {
            options = false;
            continue;
        }
        if !options || !word.text.starts_with('-') || word.text == "-" {
            out.operands.push(word.clone());
            if stop_at_operand {
                options = false;
            }
            continue;
        }
        let (name, inline) = word
            .text
            .split_once('=')
            .map_or((word.text.as_str(), None), |(a, b)| (a, Some(b)));
        if valued.contains(&name) {
            let value = if let Some(text) = inline {
                let mut value = word.clone();
                value.text = text.into();
                Some(value)
            } else {
                let value = args.get(index).cloned();
                if value.is_some() {
                    index += 1;
                }
                value
            };
            if value
                .as_ref()
                .is_none_or(|v| v.dynamic || v.text.is_empty())
            {
                out.incomplete = true;
            }
            out.values.push((name.into(), value));
        } else if switches.contains(&name)
            && (inline.is_none() || matches!(inline, Some("true" | "false")))
        {
            out.values.push((name.into(), inline.map(literal)));
        } else if !word.text.starts_with("--") && word.text.len() > 2 && word.text.is_ascii() {
            let mut chars = word.text[1..].char_indices().peekable();
            while let Some((offset, flag)) = chars.next() {
                let name = format!("-{flag}");
                if valued.contains(&name.as_str()) {
                    let value = if chars.peek().is_some() {
                        let mut value = word.clone();
                        value.text = word.text[offset + 2..].into();
                        Some(value)
                    } else {
                        let value = args.get(index).cloned();
                        if value.is_some() {
                            index += 1;
                        }
                        value
                    };
                    if value
                        .as_ref()
                        .is_none_or(|v| v.dynamic || v.text.is_empty())
                    {
                        out.incomplete = true;
                    }
                    out.values.push((name, value));
                    break;
                } else if switches.contains(&name.as_str()) {
                    out.values.push((name, None));
                } else {
                    out.incomplete = true;
                }
            }
        } else {
            out.incomplete = true;
        }
    }
    out
}

impl Analyzer<'_> {
    pub(super) fn tool_options(
        &mut self,
        args: &[Word],
        valued: &[&str],
        switches: &[&str],
        stop: bool,
    ) -> Options {
        let options = decode(args, valued, switches, stop);
        if options.incomplete {
            self.context_partial = true;
            self.unknown("Tool has unsupported, dynamic, or missing option arguments");
        }
        options
    }

    pub(super) fn package_change(&mut self, tool: &str, args: &[Word], removing: bool) {
        self.finding(
            Severity::High,
            if removing {
                EffectKind::FileDelete
            } else {
                EffectKind::FileWrite
            },
            if removing {
                "package.remove"
            } else {
                "package.install"
            },
            if removing {
                "Removes installed software or its dependencies"
            } else {
                "Installs, replaces, or upgrades executable software"
            },
        );
        self.context_partial = true;
        self.unknown("Package contents, install locations, hooks, and dependent applications are not fully resolved");
        if !removing {
            self.unresolved_program(
                "Package installation or build hooks may execute additional code",
            );
        }
        if args.iter().filter(|arg| !arg.dynamic).any(|arg| {
            let name = arg.text.split(['@', '=']).next().unwrap_or(&arg.text);
            self.config
                .policy
                .protected_packages
                .iter()
                .any(|p| p == name || p == &arg.text)
        }) {
            self.finding(
                Severity::Critical,
                EffectKind::FileWrite,
                "package.protected",
                "Package operation can replace or remove a protected application",
            );
        }
        if matches!(
            tool,
            "apt" | "apt-get" | "dpkg" | "dnf" | "yum" | "rpm" | "pacman" | "apk" | "installer"
        ) {
            self.unresolved_program(
                "System package maintainer scripts may run during installation or removal",
            );
        }
    }
}
