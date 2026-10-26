//! Reviewed argv grammars bind values to semantic roles, never to severity.
use distill_parse::Word;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Role {
    Flag,
    Value,
    Read,
    Write,
    Program,
    Script,
}

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Form {
    Separate,
    Equals,
    Attached,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OptionSpec {
    names: Vec<String>,
    role: Role,
    #[serde(default)]
    forms: Vec<Form>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    last_wins: bool,
    #[serde(default)]
    before_program: bool,
    #[serde(default)]
    append: bool,
    #[serde(default)]
    pipe: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grammar {
    options: Vec<OptionSpec>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    version: u32,
    commands: BTreeMap<String, Grammar>,
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let registry: Registry = serde_json::from_str(include_str!("../rules/arguments.json"))
            .expect("valid bundled argument grammars");
        assert_eq!(registry.version, 1);
        for grammar in registry.commands.values() {
            let mut names = BTreeSet::new();
            for spec in &grammar.options {
                assert!(!spec.names.is_empty());
                assert_eq!(spec.role == Role::Flag, spec.forms.is_empty());
                for name in &spec.names {
                    assert!(name.starts_with('-') && names.insert(name));
                }
            }
        }
        registry
    })
}

#[derive(Debug)]
pub(super) struct Argument {
    pub role: Role,
    pub value: Option<Word>,
    pub mode: Option<String>,
    pub before_program: bool,
    /// Position in the original argv, retained for ordered client programs.
    pub index: usize,
    pub append: bool,
    pub pipe: bool,
    canonical: String,
}
#[derive(Default, Debug)]
pub(super) struct Decoded {
    pub arguments: Vec<Argument>,
    pub operands: Vec<Word>,
    pub unknown: Option<&'static str>,
}

fn suffix(word: &Word, text: &str) -> Word {
    Word {
        text: text.into(),
        dynamic: word.dynamic,
        tilde_expansion: false,
        substitutions: word.substitutions.clone(),
    }
}

/// Unknown option arity stops binding; already established arguments survive.
pub(super) fn decode(name: &str, words: &[Word], budget: &distill_core::AnalysisBudget) -> Decoded {
    let grammar = &registry().commands[name];
    let mut result = Decoded::default();
    let mut options = true;
    let mut index = 0;
    while let Some(word) = words.get(index) {
        if !budget.visit_node() {
            result.unknown = Some(budget.stop_reason());
            break;
        }
        let original_index = index;
        index += 1;
        if options && word.text == "--" && !word.dynamic {
            options = false;
            continue;
        }
        if !options || !word.text.starts_with('-') || word.text == "-" {
            result.operands.push(word.clone());
            continue;
        }
        if word.dynamic {
            result.unknown = Some("Dynamic option prevents argument binding");
            break;
        }
        let long = word.text.starts_with("--")
            || grammar.options.iter().any(|s| s.names.contains(&word.text));
        let mut remainder = word.text.clone();
        loop {
            if !budget.visit_node() {
                result.unknown = Some(budget.stop_reason());
                return result;
            }
            let (key, inline) = if long {
                remainder
                    .split_once('=')
                    .map_or((remainder.as_str(), None), |(k, v)| {
                        (k, Some((v, Form::Equals)))
                    })
            } else {
                // A short cluster consists of zero-arity flags, followed by at most one value option.
                let end = remainder
                    .char_indices()
                    .nth(2)
                    .map_or(remainder.len(), |(i, _)| i);
                (
                    &remainder[..end],
                    if end < remainder.len() {
                        Some((&remainder[end..], Form::Attached))
                    } else {
                        None
                    },
                )
            };
            let Some(spec) = grammar
                .options
                .iter()
                .find(|s| s.names.iter().any(|n| n == key))
            else {
                result.unknown = Some("Unknown option prevents argument binding");
                return result;
            };
            let value = if spec.role == Role::Flag {
                None
            } else if let Some((value, form)) = inline {
                if !spec.forms.contains(&form) {
                    result.unknown = Some("Unsupported option value spelling");
                    return result;
                }
                Some(suffix(word, value))
            } else if spec.forms.contains(&Form::Separate) {
                let Some(value) = words.get(index) else {
                    result.unknown = Some("Option value is missing");
                    return result;
                };
                index += 1;
                Some(value.clone())
            } else {
                result.unknown = Some("Option requires an attached value");
                return result;
            };
            if spec.last_wins {
                result
                    .arguments
                    .retain(|arg| arg.canonical != spec.names[0]);
            }
            result.arguments.push(Argument {
                role: spec.role,
                value,
                mode: spec.mode.clone(),
                before_program: spec.before_program,
                index: original_index,
                append: spec.append,
                pipe: spec.pipe,
                canonical: spec.names[0].clone(),
            });
            if spec.role == Role::Flag
                && let Some((tail, Form::Attached)) = inline
                && !long
            {
                remainder = format!("-{tail}");
                continue;
            }
            if spec.role == Role::Flag && inline.is_some() {
                result.unknown = Some("Flag does not accept a value");
            }
            break;
        }
        if result.unknown.is_some() {
            break;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn words(items: &[&str]) -> Vec<Word> {
        items
            .iter()
            .map(|s| Word {
                text: (*s).into(),
                dynamic: false,
                tilde_expansion: false,
                substitutions: vec![],
            })
            .collect()
    }
    #[test]
    fn value_roles_and_unknown_arity_preserve_boundaries() {
        for spelling in [vec!["--output=.env"], vec!["--output", ".env"]] {
            let d = decode(
                "git-diff",
                &words(&spelling),
                &distill_core::AnalysisBudget::new(900),
            );
            assert!(d.unknown.is_none());
            assert_eq!(d.arguments[0].role, Role::Write);
            assert_eq!(d.arguments[0].value.as_ref().unwrap().text, ".env");
        }
        let d = decode(
            "psql",
            &words(&["-AtcSELECT 1", "-f", "next.sql"]),
            &distill_core::AnalysisBudget::new(900),
        );
        assert!(d.unknown.is_none());
        assert_eq!(
            d.arguments
                .iter()
                .filter(|a| a.role == Role::Program)
                .count(),
            1
        );
        assert_eq!(d.arguments.last().unwrap().role, Role::Script);
        let d = decode(
            "psql",
            &words(&["--unknown", "-f", ".env"]),
            &distill_core::AnalysisBudget::new(900),
        );
        assert!(d.unknown.is_some());
        assert!(d.arguments.is_empty());
        assert!(d.operands.is_empty());
    }
}
