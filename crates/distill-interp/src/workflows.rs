//! Bounded source discovery for build and test workflows. No candidate code runs.
use crate::{Analyzer, syntax::Language, tooling::literal};
use distill_core::{Behavior, EffectKind, Severity};
use distill_parse::Word;
use std::path::{Path, PathBuf};

impl Analyzer<'_> {
    pub(super) fn discover_sources(
        &mut self,
        root: &Path,
        extension: &str,
        tests_only: bool,
    ) -> Vec<PathBuf> {
        let mut pending = vec![(root.to_path_buf(), 0)];
        let mut result = Vec::new();
        let mut entries = 0;
        while let Some((path, depth)) = pending.pop() {
            if !self.within_budget() {
                break;
            }
            entries += 1;
            if entries > 256 || result.len() >= 64 || depth > 12 {
                self.context_partial = true;
                self.unknown("Build/test source discovery reached its bounded file or depth limit");
                break;
            }
            let Ok(metadata) = path.symlink_metadata() else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                self.context_partial = true;
                self.unknown("Build/test source discovery does not follow directory symlinks");
                continue;
            }
            if metadata.is_file() {
                let name = path
                    .file_name()
                    .and_then(|p| p.to_str())
                    .unwrap_or_default();
                if path.extension().is_some_and(|ext| ext == extension)
                    && (!tests_only
                        || name.starts_with("test")
                        || name.ends_with("_test.py")
                        || name == "conftest.py"
                        || name == "__init__.py")
                {
                    result.push(path);
                }
            } else if metadata.is_dir()
                && let Ok(children) = path.read_dir()
            {
                let mut children: Vec<_> = children
                    .take(257)
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .collect();
                children.sort();
                for child in children.into_iter().rev() {
                    if child
                        .file_name()
                        .and_then(|p| p.to_str())
                        .is_some_and(|name| {
                            matches!(
                                name,
                                ".git"
                                    | ".venv"
                                    | "venv"
                                    | ".tox"
                                    | "node_modules"
                                    | "target"
                                    | "__pycache__"
                            )
                        })
                    {
                        continue;
                    }
                    pending.push((child, depth + 1));
                }
            }
        }
        result.sort();
        result
    }

    pub(super) fn workflow_execution(&mut self, operation: &str) {
        self.record_behavior(
            Behavior {
                database: None,
                kind: EffectKind::Execute,
                operation: operation.into(),
                target: None,
                target_class: distill_core::TargetClass::Unresolved,
                recursive: false,
                append: false,
                location: None,
            },
            None,
        );
    }

    pub(super) fn python_tests(&mut self, runner: &str, args: &[Word]) {
        if args.len() == 1
            && !args[0].dynamic
            && matches!(args[0].text.as_str(), "--version" | "--help" | "-h" | "-V")
        {
            self.finding(
                Severity::Low,
                EffectKind::FileRead,
                "python.test-query",
                "Queries Python test-runner help or version information",
            );
            self.unresolved_program("Test-runner help/version can load framework and plugin code");
            return;
        }
        self.workflow_execution(if runner == "pytest" {
            "pytest test discovery and execution"
        } else {
            "unittest test discovery and execution"
        });
        self.unresolved_program("Python test discovery imports project code; fixtures, plugins, decorators, and installed dependencies remain conditional");
        let mut values = vec![
            "-k",
            "-m",
            "-c",
            "-o",
            "--override-ini",
            "--rootdir",
            "--confcutdir",
            "--basetemp",
            "--junitxml",
            "--junit-xml",
            "--tb",
            "--color",
            "--capture",
            "--maxfail",
            "--durations",
            "--durations-min",
            "--import-mode",
            "--ignore",
            "--ignore-glob",
            "--deselect",
            "-p",
            "--cov",
            "--cov-report",
            "--cov-config",
            "-n",
            "--dist",
            "--timeout",
            "--log-file",
            "--log-level",
            "--verbosity",
            "--assert",
            "--start-directory",
            "--pattern",
            "--top-level-directory",
            "-t",
        ];
        let mut switches = vec![
            "-q",
            "--quiet",
            "-v",
            "--verbose",
            "-x",
            "--exitfirst",
            "--disable-warnings",
            "--no-header",
            "--no-summary",
            "--collect-only",
            "--co",
            "--lf",
            "--last-failed",
            "--ff",
            "--failed-first",
            "--cache-clear",
            "--strict-markers",
            "--strict-config",
            "--disable-plugin-autoload",
            "--noconftest",
            "-b",
            "--buffer",
            "-f",
            "--failfast",
            "--locals",
            "-l",
        ];
        if runner == "pytest" {
            switches.push("-s");
        } else {
            values.push("-s");
        }
        let opts = self.tool_options(args, &values, &switches, false);
        for output in opts.all(&["--junitxml", "--junit-xml", "--basetemp", "--log-file"]) {
            self.write_destination(output, true);
        }
        for report in opts.all(&["--cov-report"]) {
            if let Some((format, output)) = report.text.split_once(':')
                && matches!(format, "xml" | "json" | "html" | "lcov" | "annotate")
                && !report.dynamic
            {
                self.write_destination(&literal(output), true);
            }
        }
        for file in opts.all(&["-c", "--cov-config"]) {
            self.read_destination(file);
        }
        // pytest -s is a switch, whereas unittest discover -s takes a directory.
        // Normalize that distinction before binding below rather than treating a
        // subsequent test path as interpreter or shell source.
        let mut targets: Vec<Word> = opts
            .operands
            .iter()
            .filter(|word| word.text != "discover")
            .cloned()
            .collect();
        if runner == "unittest" {
            targets.extend(opts.all(&["-s", "--start-directory"]).cloned());
        } else {
            self.write_destination(&literal(".pytest_cache"), true);
        }
        if targets.is_empty() {
            targets.push(literal("."));
        }
        let ignored: Vec<_> = opts
            .all(&["--ignore"])
            .filter_map(|word| self.resolve(word))
            .collect();
        let confcut = opts
            .all(&["--confcutdir"])
            .last()
            .and_then(|word| self.resolve(word));
        let mut files = std::collections::BTreeSet::new();
        for target in targets {
            let mut target = target;
            if runner == "pytest" {
                target.text = target.text.split("::").next().unwrap_or_default().into();
            }
            if runner == "unittest"
                && !target.text.contains('/')
                && !target.text.ends_with(".py")
                && target.text != "."
            {
                let components: Vec<_> = target.text.split('.').collect();
                for end in (1..=components.len()).rev() {
                    let candidate = format!("{}.py", components[..end].join("/"));
                    let word = literal(&candidate);
                    if self.resolve(&word).is_some_and(|path| path.is_file()) {
                        target.text = candidate;
                        break;
                    }
                }
            }
            let Some(path) = self.resolve(&target) else {
                self.unknown("Python test selection is dynamic or unresolved");
                continue;
            };
            if ignored.iter().any(|ignored| path.starts_with(ignored)) {
                continue;
            }
            if path.is_file() {
                files.insert(path.clone());
            } else {
                let discovered = self.discover_sources(
                    &path,
                    "py",
                    !(runner == "unittest" && opts.has(&["-p", "--pattern"])),
                );
                files.extend(discovered.into_iter().filter(|file| {
                    !ignored.iter().any(|ignored| file.starts_with(ignored))
                        && (file.file_name().is_none_or(|name| name != "conftest.py")
                            || !opts.has(&["--noconftest"])
                                && confcut.as_ref().is_none_or(|cut| file.starts_with(cut)))
                }));
            }
            if runner == "pytest" && !opts.has(&["--noconftest"]) {
                let mut parent = if path.is_dir() {
                    Some(path.as_path())
                } else {
                    path.parent()
                };
                for _ in 0..16 {
                    let Some(directory) = parent else {
                        break;
                    };
                    if confcut
                        .as_ref()
                        .is_some_and(|cut| !directory.starts_with(cut))
                    {
                        break;
                    }
                    let conftest = directory.join("conftest.py");
                    if conftest.is_file() {
                        files.insert(conftest);
                    }
                    if self.cwd.as_deref() == Some(directory) {
                        break;
                    }
                    parent = directory.parent();
                }
            }
        }
        // A local shadow module can replace the installed runner itself.
        if let Some(cwd) = &self.cwd {
            for relative in [
                format!("{runner}.py"),
                format!("{runner}/__init__.py"),
                format!("{runner}/__main__.py"),
            ] {
                let file = cwd.join(relative);
                if file.is_file() {
                    files.insert(file);
                }
            }
        }
        for file in files.into_iter().take(64) {
            if !self.within_budget() {
                break;
            }
            self.inspect_workflow_file(Language::Python, &literal(file.to_string_lossy()));
        }
    }
}
