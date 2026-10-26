use std::path::PathBuf;

use distill_core::{Behavior, EffectKind, Severity, SourceLocation, TargetClass};
use distill_parse::Word;

use crate::{
    Analyzer,
    syntax::{self, Language, Observation},
};

impl Analyzer<'_> {
    pub(super) fn program_environment(&mut self, word: &Word) {
        let Some((name, _)) = word.text.split_once('=') else {
            return;
        };
        if matches!(
            name,
            "PATH"
                | "PYTHONPATH"
                | "PYTHONHOME"
                | "PYTHONSTARTUP"
                | "PYTHONINSPECT"
                | "NODE_OPTIONS"
                | "NODE_PATH"
                | "LD_PRELOAD"
                | "LD_AUDIT"
                | "LD_DEBUG_OUTPUT"
                | "LD_LIBRARY_PATH"
                | "DYLD_INSERT_LIBRARIES"
                | "DYLD_LIBRARY_PATH"
                | "DYLD_FRAMEWORK_PATH"
                | "GOROOT"
                | "GOFLAGS"
                | "RUSTC_WRAPPER"
                | "RUSTC_WORKSPACE_WRAPPER"
                | "GCC_EXEC_PREFIX"
                | "COMPILER_PATH"
                | "CPATH"
                | "C_INCLUDE_PATH"
                | "CPLUS_INCLUDE_PATH"
                | "OBJC_INCLUDE_PATH"
                | "LIBRARY_PATH"
                | "SDKROOT"
                | "RUSTFLAGS"
                | "CARGO_ENCODED_RUSTFLAGS"
                | "CARGO_HOME"
                | "CARGO_TARGET_DIR"
                | "RUSTUP_TOOLCHAIN"
                | "GOTOOLCHAIN"
                | "GOWORK"
                | "GOMOD"
                | "GOPATH"
                | "GOBIN"
                | "CGO_CFLAGS"
                | "CGO_LDFLAGS"
                | "CC"
                | "CXX"
                | "JAVA_TOOL_OPTIONS"
                | "JDK_JAVA_OPTIONS"
                | "JDK_JAVAC_OPTIONS"
                | "_JAVA_OPTIONS"
                | "CLASSPATH"
                | "JAVA_HOME"
                | "BASH_ENV"
                | "ENV"
                | "RUBYOPT"
                | "PERL5OPT"
                | "ZDOTDIR"
                | "GIT_SSH_COMMAND"
                | "GIT_SSH"
                | "GIT_CONFIG_COUNT"
                | "GIT_CONFIG_GLOBAL"
                | "GIT_CONFIG_SYSTEM"
                | "GIT_EXTERNAL_DIFF"
                | "GIT_PAGER"
                | "RIPGREP_CONFIG_PATH"
                | "IFS"
                | "SHELLOPTS"
                | "BASHOPTS"
                | "MAKEFLAGS"
                | "SHELL"
        ) {
            self.finding(
                Severity::High,
                EffectKind::Execute,
                "exec.runtime-environment",
                "Environment override may load or execute additional code",
            );
            self.context_partial = true;
            self.unknown("Runtime environment override is not modeled");
        }
    }

    pub(super) fn python(&mut self, args: &[Word]) {
        if info_only(args, &["--version", "-V"]) {
            self.raise(Severity::Safe);
            return;
        }
        let prefix = crate::tooling::decode(
            args,
            &["-W", "-X"],
            &[
                "-I", "-E", "-s", "-S", "-B", "-u", "-O", "-OO", "-q", "-v", "-b",
            ],
            true,
        );
        // Locate -m using Python's option boundary, not an arbitrary occurrence in program data.
        let mut at = 0;
        while let Some(arg) = args.get(at) {
            if arg.dynamic {
                break;
            }
            if arg.text == "-m" {
                if let Some(module) = args.get(at + 1).filter(|w| !w.dynamic) {
                    if matches!(module.text.as_str(), "pip" | "pip3" | "pipx" | "uv") {
                        self.package_tool(&module.text, &args[at + 2..], 0);
                    } else {
                        self.python_module(module, &args[at + 2..]);
                    }
                    self.unresolved_program("Python module resolution and interpreter startup code are not fully resolved");
                    return;
                }
                break;
            }
            if matches!(arg.text.as_str(), "-c" | "--") || !arg.text.starts_with('-') {
                break;
            }
            if matches!(arg.text.as_str(), "-W" | "-X") {
                at += 2;
            } else {
                at += 1;
            }
        }
        if prefix.incomplete && !args.iter().any(|w| w.text == "-c") {
            // Existing narrow parsing still examines supported files, but never clears this gap.
            self.context_partial = true;
        }
        if let Some(script) = python_script(args) {
            if !script.dynamic {
                self.inspect_program(Language::Python, &script.text, None);
                return;
            }
        } else if let Some(file) = python_file(args) {
            self.inspect_file(Language::Python, file);
            return;
        }
        self.unresolved_program("Python invocation or source is unresolved");
    }

    pub(super) fn node(&mut self, args: &[Word]) {
        if info_only(args, &["--version", "-v"]) {
            self.raise(Severity::Safe);
            return;
        }
        // A narrow argv grammar avoids mistaking application arguments for Node
        // options or overlooking preload modules and repeated eval options.
        if args.len() == 2
            && !args.iter().any(|arg| arg.dynamic)
            && matches!(args[0].text.as_str(), "-e" | "--eval")
        {
            self.inspect_program(Language::JavaScript, &args[1].text, None);
        } else if args.len() == 1 && args[0].text.ends_with(".js") && !args[0].text.starts_with('-')
        {
            self.inspect_file(Language::JavaScript, &args[0]);
        } else {
            self.unresolved_program("Node invocation or source is unresolved");
        }
    }

    pub(super) fn go_tool(&mut self, args: &[Word]) {
        if info_only(args, &["version"]) {
            self.raise(Severity::Safe);
            return;
        }
        let files = match args {
            [run, file] if run.text == "run" => Some(file),
            [run, flag, file] if run.text == "run" && flag.text == "-mod=readonly" => Some(file),
            _ => None,
        };
        if let Some(file) = files.filter(|file| file.text.ends_with(".go"))
            && !args.iter().any(|arg| arg.dynamic)
        {
            self.inspect_file(Language::Go, file);
        } else {
            self.go_extended(args);
        }
    }

    pub(super) fn rustc(&mut self, args: &[Word]) {
        self.compiler(args, true);
    }

    pub(super) fn cxx(&mut self, args: &[Word]) {
        self.compiler(args, false);
    }

    fn compiler(&mut self, args: &[Word], rust: bool) {
        if info_only(args, &["--version"]) {
            self.raise(Severity::Safe);
            return;
        }
        let Some((source, output)) = compiler_arguments(args, rust) else {
            self.compiler_extended(args, rust);
            return;
        };
        let language = if rust {
            Language::Rust
        } else if source.text.ends_with(".c") {
            Language::C
        } else {
            Language::Cpp
        };
        let print_only = self.inspect_file(language, source);
        let default_output = Word {
            text: if rust {
                std::path::Path::new(&source.text)
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or("unknown-output")
                    .to_owned()
            } else {
                "a.out".into()
            },
            dynamic: false,
            tilde_expansion: false,
            substitutions: Vec::new(),
        };
        let output = output.unwrap_or(&default_output);
        let Some(path) = self.resolve(output) else {
            self.unresolved_program("Compiler output is unresolved");
            return;
        };
        // Compiler output is an effect even when source behavior is unknown.
        let mut target_class = self.target_class(Some(&path));
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if target_class == TargetClass::Ordinary {
                    target_class = TargetClass::BuildArtifact;
                }
            }
            Err(_) => {
                target_class = TargetClass::Unresolved;
                self.context_partial = true;
                self.unknown("Compiler output metadata is unavailable");
            }
            Ok(_) => {}
        }
        self.record_behavior(
            Behavior {
                database: None,
                kind: EffectKind::FileWrite,
                operation: "compiler.output".into(),
                target: Some(path.to_string_lossy().into_owned()),
                target_class,
                recursive: false,
                append: false,
                location: None,
            },
            None,
        );
        if let Ok(metadata) = std::fs::symlink_metadata(&path)
            && metadata.file_type().is_symlink()
        {
            self.context_partial = true;
            self.unknown("Compiler output is a symlink and may target another file");
            if let Ok(target) = std::fs::canonicalize(&path) {
                self.write_destination(
                    &Word {
                        text: target.to_string_lossy().into_owned(),
                        dynamic: false,
                        tilde_expansion: false,
                        substitutions: Vec::new(),
                    },
                    true,
                );
            }
        }
        if print_only {
            self.print_outputs.push(path);
        }
    }

    pub(super) fn inspect_file(&mut self, language: Language, file: &Word) -> bool {
        if !self.within_budget() {
            return false;
        }
        match source_text(self, file) {
            Ok(source) => self.inspect_program(language, &source, Some(&file.text)),
            Err(reason) => {
                self.unresolved_program(reason);
                false
            }
        }
    }

    pub(super) fn inspect_program(
        &mut self,
        language: Language,
        source: &str,
        origin: Option<&str>,
    ) -> bool {
        if !self.within_budget() {
            return false;
        }
        match syntax::analyze_with_budget(language, source, &self.budget) {
            Ok(analysis) if analysis.print_only => {
                if matches!(language, Language::Python) {
                    self.emit_path(&["python", "-c", "@print"]);
                } else {
                    self.emit_path(&["lang", "@print"]);
                }
                true
            }
            Ok(analysis) => {
                self.unresolved_program(
                    "Source includes behavior outside the supported static semantics",
                );
                for observation in analysis.observations {
                    self.source_observation(observation, origin);
                }
                false
            }
            Err(reason) => {
                self.unresolved_program(reason);
                false
            }
        }
    }

    pub(super) fn unresolved_program(&mut self, reason: &str) {
        self.unknown(reason);
        self.emit_path(&["cmd", "execute"]);
    }

    fn source_observation(&mut self, observation: Observation, origin: Option<&str>) {
        // Language string literals are paths, without shell glob or tilde expansion.
        let path = observation.path.as_ref().and_then(|raw| {
            let path = std::path::Path::new(raw);
            if path.is_absolute() {
                Some(crate::normalize_path(path))
            } else {
                self.cwd
                    .as_ref()
                    .map(|cwd| crate::normalize_path(&cwd.join(path)))
            }
        });
        let id = match observation.kind {
            EffectKind::FileRead => "source.file-read",
            EffectKind::FileWrite => "source.file-write",
            EffectKind::FileDelete => "source.file-delete",
            EffectKind::Execute => "source.execute",
            _ => "source.network",
        };
        self.record_behavior(
            Behavior {
                database: None,
                kind: observation.kind,
                operation: observation.call,
                target: path
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned()),
                target_class: self.target_class(path.as_deref()),
                recursive: observation.recursive,
                append: observation.append,
                location: Some(SourceLocation {
                    file: origin.map(str::to_owned),
                    line: observation.line,
                    column: observation.column,
                }),
            },
            Some(id),
        );
    }
}

fn info_only(args: &[Word], options: &[&str]) -> bool {
    args.len() == 1 && !args[0].dynamic && options.contains(&args[0].text.as_str())
}

fn python_script(args: &[Word]) -> Option<&Word> {
    for (index, arg) in args.iter().enumerate() {
        if arg.dynamic {
            return None;
        }
        if arg.text == "-c" {
            return args.get(index + 1);
        }
        if !python_flag(&arg.text) {
            return None;
        }
    }
    None
}

fn python_file(args: &[Word]) -> Option<&Word> {
    for arg in args {
        if arg.dynamic {
            return None;
        }
        if python_flag(&arg.text) {
            continue;
        }
        return (!arg.text.starts_with('-') && arg.text.ends_with(".py")).then_some(arg);
    }
    None
}

fn python_flag(text: &str) -> bool {
    matches!(text, "-u" | "-E" | "-B" | "-s" | "-q" | "-O" | "-OO")
}

fn compiler_arguments(args: &[Word], rust: bool) -> Option<(&Word, Option<&Word>)> {
    let mut source = None;
    let mut output = None;
    let mut index = 0;
    if args.iter().any(|arg| arg.dynamic) {
        return None;
    }
    while index < args.len() {
        let arg = &args[index];
        if arg.text == "-o" {
            if output.is_some() {
                return None;
            }
            output = Some(args.get(index + 1)?);
            index += 2;
            continue;
        }
        if rust && arg.text == "--edition" {
            if !matches!(
                args.get(index + 1)?.text.as_str(),
                "2015" | "2018" | "2021" | "2024"
            ) {
                return None;
            }
            index += 2;
            continue;
        }
        let flag = matches!(
            arg.text.as_str(),
            "-g" | "-O" | "-O0" | "-O1" | "-O2" | "-O3" | "-Os"
        ) || rust
            && matches!(
                arg.text.as_str(),
                "--edition=2015" | "--edition=2018" | "--edition=2021" | "--edition=2024"
            )
            || !rust
                && arg.text.strip_prefix("-std=").is_some_and(|std| {
                    matches!(
                        std,
                        "c99"
                            | "c11"
                            | "c17"
                            | "c23"
                            | "c++11"
                            | "c++14"
                            | "c++17"
                            | "c++20"
                            | "c++23"
                    )
                });
        if !flag {
            let extensions: &[&str] = if rust {
                &[".rs"]
            } else {
                &[".c", ".cc", ".cpp", ".cxx"]
            };
            if arg.text.starts_with('-')
                || source.is_some()
                || !extensions.iter().any(|ext| arg.text.ends_with(ext))
            {
                return None;
            }
            source = Some(arg);
        }
        index += 1;
    }
    Some((source?, output))
}

fn source_text(analyzer: &mut Analyzer<'_>, word: &Word) -> Result<String, &'static str> {
    let path: PathBuf = analyzer
        .lexical_path(word)
        .ok_or("Source path is dynamic or unresolved")?;
    analyzer
        .inspect_read(&path, 64 * 1024)
        .map_err(|_| "Source is unavailable, oversized, non-regular, or analysis budget exhausted")
}
