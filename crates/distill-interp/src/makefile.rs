//! Bounded GNU-style literal rule inspection. Never launches Make, even for dry runs.
use crate::Analyzer;
use distill_core::{AnalysisBudget, Severity};
use distill_parse::Word;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

#[derive(Default)]
struct Rule {
    prerequisites: Vec<String>,
    recipes: Vec<String>,
}
struct Invocation {
    cwd: PathBuf,
    files: Vec<PathBuf>,
    targets: Vec<String>,
}

impl Invocation {
    fn parse(args: &[Word], mut cwd: PathBuf) -> Result<Self, &'static str> {
        let mut files = Vec::new();
        let mut targets = Vec::new();
        let mut index = 0;
        let mut options = true;
        while let Some(arg) = args.get(index) {
            if arg.dynamic || arg.text.contains('$') {
                return Err("Make arguments contain unresolved expansions");
            }
            let text = arg.text.as_str();
            index += 1;
            if options && text == "--" {
                options = false;
                continue;
            }
            let path_option = if options {
                if matches!(text, "-f" | "--file" | "--makefile" | "-C" | "--directory") {
                    let value = args
                        .get(index)
                        .ok_or("Make path option is missing its value")?;
                    if value.dynamic || value.text.contains('$') {
                        return Err("Make path is unresolved");
                    }
                    index += 1;
                    Some((matches!(text, "-C" | "--directory"), value.text.as_str()))
                } else if let Some(value) = text
                    .strip_prefix("--directory=")
                    .or_else(|| text.strip_prefix("-C"))
                {
                    Some((true, value))
                } else {
                    text.strip_prefix("--file=")
                        .or_else(|| text.strip_prefix("--makefile="))
                        .or_else(|| text.strip_prefix("-f"))
                        .map(|value| (false, value))
                }
            } else {
                None
            };
            if let Some((directory, value)) = path_option {
                if value.is_empty() || value == "-" {
                    return Err("Make stdin or empty paths are unresolved");
                }
                if directory {
                    cwd = cwd.join(value);
                } else {
                    files.push(PathBuf::from(value));
                }
            } else if options
                && matches!(
                    text,
                    "-j" | "--jobs" | "-l" | "--load-average" | "--max-load"
                )
            {
                if args
                    .get(index)
                    .is_some_and(|value| !value.dynamic && value.text.parse::<f64>().is_ok())
                {
                    index += 1;
                }
            } else if options
                && (matches!(
                    text,
                    "--silent"
                        | "--quiet"
                        | "--always-make"
                        | "--keep-going"
                        | "--ignore-errors"
                        | "--no-builtin-rules"
                        | "--no-builtin-variables"
                        | "--no-print-directory"
                        | "--print-directory"
                        | "--trace"
                        | "--warn-undefined-variables"
                        | "--dry-run"
                        | "--just-print"
                        | "--recon"
                        | "--touch"
                        | "--question"
                ) || (text.starts_with('-')
                    && text.len() > 1
                    && text[1..].chars().all(|c| "sBkirRnntq".contains(c)))
                    || text
                        .strip_prefix("-j")
                        .or_else(|| text.strip_prefix("--jobs="))
                        .is_some_and(|v| v.parse::<u32>().is_ok()))
            {
                // These flags do not establish safety. Recipe effects remain a conservative superset.
            } else if text.starts_with('-') && options {
                return Err("Unmodeled Make option; recipe selection is unresolved");
            } else if text.contains('=') {
                // Variable overrides can change paths, recipes, SHELL, or included files.
                return Err("Make variable overrides are unresolved");
            } else {
                targets.push(text.to_owned());
            }
        }
        if files.is_empty() {
            files.push(
                ["GNUmakefile", "makefile", "Makefile"]
                    .into_iter()
                    .map(|name| cwd.join(name))
                    .find(|file| file.exists())
                    .ok_or("No Makefile found in the Make working directory")?,
            );
        } else {
            files = files.into_iter().map(|file| cwd.join(file)).collect();
        }
        Ok(Self {
            cwd,
            files,
            targets,
        })
    }
}

impl Analyzer<'_> {
    pub(super) fn expand_make(&mut self, args: &[Word], depth: usize) -> bool {
        self.context_partial = true;
        self.unknown("Makefile analysis is partial: variables, includes, implicit rules, and functions are unresolved");
        self.raise(Severity::Medium);
        let Some(cwd) = self.cwd.clone() else {
            self.unknown("Make requires a working directory");
            return true;
        };
        let invocation = match Invocation::parse(args, cwd) {
            Ok(value) => value,
            Err(reason) => {
                self.unknown(reason);
                return true;
            }
        };
        let mut rules = BTreeMap::<String, Rule>::new();
        let mut default_target = None;
        let mut retained_bytes = 0;
        for file in &invocation.files {
            match self.inspect_read(file, 256 * 1024) {
                Ok(text) => {
                    if let Err(reason) = parse_rules(
                        &text,
                        &self.budget,
                        &mut rules,
                        &mut default_target,
                        &mut retained_bytes,
                    ) {
                        self.unknown(reason);
                        self.within_budget();
                        return true;
                    }
                }
                Err(error) => {
                    self.unknown(&format!("Makefile {}: {error}", file.display()));
                    self.within_budget();
                    return true;
                }
            }
        }
        let one_shell = rules.contains_key(".ONESHELL");
        let targets = if invocation.targets.is_empty() {
            default_target.into_iter().collect()
        } else {
            invocation.targets
        };
        if targets.is_empty() {
            self.unknown("No literal Make target could be selected");
            return true;
        }
        let mut stack: Vec<_> = targets
            .into_iter()
            .rev()
            .map(|target| (target, false, 0usize))
            .collect();
        let mut active = BTreeSet::new();
        let mut visited = BTreeSet::new();
        while let Some((target, finish, level)) = stack.pop() {
            if !self.budget.visit_node() || !self.within_budget() {
                self.within_budget();
                break;
            }
            if level > self.config.analysis.expansion_depth_max {
                self.unknown("Makefile prerequisite depth limit reached");
                continue;
            }
            let Some(rule) = rules.get(&target) else {
                if !invocation.cwd.join(&target).is_file() {
                    self.unknown(
                        "Make target or prerequisite has no literal rule or existing file",
                    );
                }
                continue;
            };
            if finish {
                active.remove(&target);
                visited.insert(target);
                let mut shell_recipes = Vec::new();
                for recipe in &rule.recipes {
                    let Some(recipe) = recipe_shell(recipe) else {
                        self.unknown("Makefile recipe contains an unresolved Make expansion");
                        continue;
                    };
                    shell_recipes.push(recipe);
                }
                if one_shell {
                    shell_recipes = vec![shell_recipes.join("\n")];
                }
                for recipe in shell_recipes {
                    // Each ordinary recipe runs in its own shell. Never leak recipe cd state.
                    let previous = self.cwd.replace(invocation.cwd.clone());
                    self.analyze(&recipe, depth + 1);
                    self.cwd = previous;
                }
            } else if !visited.contains(&target) {
                if !active.insert(target.clone()) {
                    self.unknown("Makefile prerequisite cycle is unresolved");
                    continue;
                }
                stack.push((target, true, level));
                stack.extend(
                    rule.prerequisites
                        .iter()
                        .rev()
                        .cloned()
                        .map(|target| (target, false, level + 1)),
                );
            }
        }
        true
    }
}

fn literal_name(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(|c| "$%\\*?[]=;|".contains(c))
}

fn parse_rules(
    text: &str,
    budget: &AnalysisBudget,
    rules: &mut BTreeMap<String, Rule>,
    default_target: &mut Option<String>,
    retained_bytes: &mut usize,
) -> Result<(), &'static str> {
    let lines: Vec<_> = text.lines().collect();
    let mut index = 0;
    let mut capturing: Vec<String> = Vec::new();
    while let Some(line) = lines.get(index) {
        if !budget.visit_node() {
            return Err("Makefile inspection budget exhausted");
        }
        index += 1;
        if let Some(recipe) = line.strip_prefix('\t') {
            let mut recipe = recipe.to_owned();
            while recipe.ends_with('\\') && index < lines.len() {
                if !budget.visit_node() {
                    return Err("Makefile inspection budget exhausted");
                }
                recipe.push('\n');
                recipe.push_str(lines[index].strip_prefix('\t').unwrap_or(lines[index]));
                index += 1;
            }
            for target in &capturing {
                if !budget.visit_node() {
                    return Err("Makefile inspection budget exhausted");
                }
                *retained_bytes += recipe.len();
                if *retained_bytes > 1024 * 1024 {
                    return Err("Makefile rule storage limit reached");
                }
                rules
                    .entry(target.clone())
                    .or_default()
                    .recipes
                    .push(recipe.clone());
            }
            continue;
        }
        let mut line = line.to_string();
        while line.ends_with('\\') && index < lines.len() {
            if !budget.visit_node() {
                return Err("Makefile inspection budget exhausted");
            }
            line.pop();
            line.push(' ');
            line.push_str(lines[index].trim());
            index += 1;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        capturing.clear();
        let Some((names, rest)) = line.split_once(':') else {
            continue;
        };
        if names.contains('=') {
            continue;
        }
        let names: Vec<_> = names.split_whitespace().collect();
        if names.is_empty() || !names.iter().all(|name| literal_name(name)) {
            continue;
        }
        let rest = rest.strip_prefix(':').unwrap_or(rest);
        if rest.starts_with('=') {
            continue;
        } // := and ::= variable assignments are not rules
        let (prerequisites, inline) = rest
            .split_once(';')
            .map_or((rest, None), |(deps, recipe)| (deps, Some(recipe)));
        let prerequisites: Vec<_> = prerequisites
            .split('#')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .filter(|name| *name != "|")
            .filter(|name| literal_name(name))
            .map(str::to_owned)
            .collect();
        for name in names {
            if !budget.visit_node() {
                return Err("Makefile inspection budget exhausted");
            }
            *retained_bytes += name.len()
                + prerequisites.iter().map(String::len).sum::<usize>()
                + inline.map_or(0, str::len);
            if *retained_bytes > 1024 * 1024 {
                return Err("Makefile rule storage limit reached");
            }
            if default_target.is_none() && !name.starts_with('.') {
                *default_target = Some(name.to_owned());
            }
            let rule = rules.entry(name.to_owned()).or_default();
            rule.prerequisites.extend(prerequisites.clone());
            if let Some(recipe) = inline {
                rule.recipes.push(recipe.trim().to_owned());
            }
            capturing.push(name.to_owned());
        }
    }
    Ok(())
}

fn recipe_shell(recipe: &str) -> Option<String> {
    let mut chars = recipe
        .trim_start()
        .trim_start_matches(['@', '-', '+'])
        .chars();
    let mut shell = String::new();
    while let Some(character) = chars.next() {
        if character == '$' && chars.next() != Some('$') {
            return None;
        }
        shell.push(character);
    }
    Some(shell)
}

#[cfg(test)]
mod tests {
    use super::*;
    use distill_core::{
        AnalyzeRequest, CommandForm, CommandKind, Config, CoverageSummary, ExecutionContext,
        Integration, ShellDialect,
    };

    fn fixture(files: &[(&str, &str)], command: &str) -> distill_core::Report {
        let root = std::env::temp_dir().join(distill_core::new_id("distill-make-test"));
        std::fs::create_dir_all(&root).unwrap();
        for (file, text) in files {
            let file = root.join(file);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, text).unwrap();
        }
        let request = AnalyzeRequest {
            protocol_version: 1,
            request_id: "make-test".into(),
            command: CommandForm {
                kind: CommandKind::Shell,
                text: command.into(),
                dialect: ShellDialect::Bash,
            },
            cwd: root.clone(),
            session_id: None,
            source: Integration::Cli,
            budget_ms: 900,
            context: ExecutionContext::default(),
        };
        let config = Config::default();
        let report =
            distill_rules::score(&request, crate::interpret(&request, &config), &config, 0);
        assert!(
            !root.join("must-not-execute").exists(),
            "Make functions and recipes must never run"
        );
        std::fs::remove_dir_all(root).unwrap();
        assert_ne!(report.coverage.summary, CoverageSummary::StaticAccounted);
        assert_ne!(report.decision, distill_core::Decision::Allow);
        report
    }

    #[test]
    fn prerequisites_multiple_goals_and_recipe_prefixes_keep_hazardous_effects() {
        let files = [(
            "Makefile",
            ".PHONY: all\nall: prepare\n\t@echo done\nprepare:\n\t@-+rm -rf /\nsafe:\n\techo safe\n",
        )];
        for command in [
            "make",
            "make all",
            "make safe prepare",
            "make -n all",
            "make -j2 all",
        ] {
            let report = fixture(&files, command);
            assert_eq!(
                report.impact_severity,
                Some(Severity::Critical),
                "{command}: {:?} {:?}",
                report.unknowns,
                report.findings
            );
        }
    }

    #[test]
    fn explicit_files_and_directories_are_resolved_after_all_directory_options() {
        let files = [("sub/build.mk", "all: clean\nclean:; rm -rf /\n")];
        for command in [
            "make -f build.mk -C sub all",
            "make -Csub -fbuild.mk",
            "make --directory=sub --file=build.mk",
            "make --directory sub --makefile build.mk",
        ] {
            assert_eq!(
                fixture(&files, command).impact_severity,
                Some(Severity::Critical),
                "{command}"
            );
        }
        assert_eq!(
            fixture(
                &[
                    ("first.mk", "all: clean\n"),
                    ("second.mk", "clean:; rm -rf /\n")
                ],
                "make -f first.mk -f second.mk all"
            )
            .impact_severity,
            Some(Severity::Critical)
        );
    }

    #[test]
    fn default_file_priority_and_assignments_do_not_hide_real_default_target() {
        assert_eq!(
            fixture(
                &[
                    ("GNUmakefile", "all:; rm -rf /\n"),
                    ("Makefile", "all:; echo safe\n")
                ],
                "make"
            )
            .impact_severity,
            Some(Severity::Critical)
        );
        assert_ne!(
            fixture(
                &[(
                    "Makefile",
                    "BUILD := output\nall:; echo safe\nclean:; rm -rf /\n"
                )],
                "make"
            )
            .impact_severity,
            Some(Severity::Critical)
        );
    }

    #[test]
    fn continuations_and_escaped_shell_substitutions_are_inspected() {
        for text in [
            "all: \\\n cleanup\ncleanup:\n\trm \\\n\t-rf /\n",
            "all:\n\techo $$(rm -rf /)\n",
            "all:\n\techo `rm -rf /`\n",
        ] {
            assert_eq!(
                fixture(&[("Makefile", text)], "make all").impact_severity,
                Some(Severity::Critical),
                "{text}"
            );
        }
    }

    #[test]
    fn recipe_working_directories_are_isolated_unless_oneshell_is_present() {
        let recipes = "all:\n\tcd /\n\trm -rf .\n";
        assert_ne!(
            fixture(&[("Makefile", recipes)], "make all").impact_severity,
            Some(Severity::Critical)
        );
        assert_eq!(
            fixture(
                &[("Makefile", &format!(".ONESHELL:\n{recipes}"))],
                "make all"
            )
            .impact_severity,
            Some(Severity::Critical)
        );
        assert_ne!(
            fixture(
                &[("sub/Makefile", "all:; cd /\n")],
                "make -C sub all; rm -rf build"
            )
            .impact_severity,
            Some(Severity::Critical)
        );
    }

    #[test]
    fn unsupported_constructs_and_cycles_remain_bounded_and_never_execute() {
        let text = "PAYLOAD := $(shell touch must-not-execute)\ninclude absent.mk\nall: second\n\t$(PAYLOAD)\nsecond: all\n\techo safe\n";
        let report = fixture(&[("Makefile", text)], "make all");
        assert!(
            report
                .unknowns
                .iter()
                .any(|reason| reason.contains("cycle"))
        );
        for command in [
            "make --eval=anything all",
            "make -f -",
            "make SHELL=evil all",
            "make missing",
        ] {
            fixture(&[("Makefile", text)], command);
        }
        let deep = (0..30)
            .map(|i| format!("target{i}: target{}\n", i + 1))
            .collect::<String>();
        assert!(
            fixture(&[("Makefile", &deep)], "make target0")
                .unknowns
                .iter()
                .any(|reason| reason.contains("depth limit"))
        );
    }

    #[test]
    fn multi_target_recipe_amplification_is_capped_before_copying() {
        let names = (0..100)
            .map(|index| format!("target{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        let text = format!("{names}:\n\techo {}\n", "a".repeat(20000));
        assert!(
            fixture(&[("Makefile", &text)], "make target0")
                .unknowns
                .iter()
                .any(|reason| reason.contains("storage limit"))
        );
    }
}
