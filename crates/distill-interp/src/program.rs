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
                | "PYTHONWARNINGS"
                | "PYTEST_ADDOPTS"
                | "PYTEST_PLUGINS"
                | "UV_PROJECT_ENVIRONMENT"
                | "UV_CACHE_DIR"
                | "UV_WORKING_DIR"
                | "UV_PROJECT"
                | "UV_PYTHON"
                | "UV_PYTHON_INSTALL_DIR"
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

    pub(super) fn python(
        &mut self,
        args: &[Word],
        depth: usize,
        input: Option<&crate::shell::ShellInput>,
    ) {
        use crate::python_cli::Target;
        let invocation = match crate::python_cli::parse(args) {
            Ok(invocation) => invocation,
            Err(reason) => {
                self.unresolved_program(reason);
                return;
            }
        };
        self.python_startup(&invocation);
        match invocation.target {
            Target::Info => self.raise(Severity::Safe),
            Target::Code(source) if !source.dynamic => {
                self.inspect_program(Language::Python, &source.text, None);
            }
            Target::File(mut file) if !file.dynamic => {
                if self.resolve(&file).is_some_and(|path| path.is_dir()) {
                    file.text = format!("{}/__main__.py", file.text);
                }
                self.inspect_file(Language::Python, &file);
            }
            Target::Module(module) if !module.dynamic => {
                if self.python_standard_module(&module, &invocation.arguments) {
                    return;
                }
                match module.text.as_str() {
                    "pytest" | "unittest" => self.python_tests(&module.text, &invocation.arguments),
                    "uv" => self.uv("uv", &invocation.arguments, depth + 1, input),
                    "pip" | "pip3" | "pipx" => {
                        self.package_tool(&module.text, &invocation.arguments, 0);
                    }
                    _ => self.python_module(&module, &invocation.arguments),
                }
                self.unresolved_program(
                    "Python module resolution and interpreter startup code are not fully resolved",
                );
            }
            _ => {
                self.unresolved_program("Python invocation or standard-input source is unresolved")
            }
        }
    }

    fn python_standard_module(&mut self, module: &Word, args: &[Word]) -> bool {
        if !matches!(
            module.text.as_str(),
            "py_compile" | "compileall" | "json.tool"
        ) {
            return false;
        }
        let base = self.cwd.clone();
        if let Some(base) = base {
            for prefix in module.text.split('.').scan(String::new(), |prefix, part| {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(part);
                Some(prefix.clone())
            }) {
                for file in [
                    base.join(format!("{prefix}.py")),
                    base.join(prefix).join("__init__.py"),
                ] {
                    if file.exists() {
                        self.unresolved_program(
                            "Python standard-library module is shadowed by project source",
                        );
                        self.inspect_file(Language::Python, &literal_word(&file.to_string_lossy()));
                        return true;
                    }
                }
            }
        }
        self.raise(Severity::Low);
        let (valued, switches): (&[&str], &[&str]) = match module.text.as_str() {
            "py_compile" => (&[], &["-q", "--quiet", "-h", "--help"]),
            "compileall" => (
                &[
                    "-r",
                    "-d",
                    "-s",
                    "-p",
                    "-x",
                    "-j",
                    "--workers",
                    "-o",
                    "-e",
                    "--invalidation-mode",
                ],
                &["-l", "-q", "-f", "-b", "-h", "--help", "--hardlink-dupes"],
            ),
            _ => (
                &["--indent"],
                &[
                    "--sort-keys",
                    "--no-ensure-ascii",
                    "--json-lines",
                    "--tab",
                    "--no-indent",
                    "--compact",
                    "-h",
                    "--help",
                ],
            ),
        };
        let options = self.tool_options(args, valued, switches, false);
        if options.incomplete {
            return true;
        }
        if options.has(&["-h", "--help"]) {
            return true;
        }
        if module.text == "json.tool" {
            if options.operands.len() > 2 {
                self.unresolved_program("Python JSON tool operands are unsupported");
                return true;
            }
            if let Some(file) = options.operands.first().filter(|file| file.text != "-") {
                self.read_destination(file);
            }
            if let Some(file) = options.operands.get(1).filter(|file| file.text != "-") {
                self.write_destination(file, false);
            }
        } else {
            let mut files = options.operands;
            if module.text == "compileall" && files.is_empty() {
                self.unresolved_program("Python compileall without explicit targets traverses the interpreter search path");
            }
            for file in files.drain(..) {
                self.read_destination(&file);
                // Bytecode compilation parses source; it never executes the
                // compiled module. Preserve explicit output scope and policy.
                if let Some(path) = self.lexical_path(&file) {
                    let target = if path.is_dir() {
                        path
                    } else {
                        path.parent().unwrap_or(&path).to_path_buf()
                    };
                    self.write_destination(&literal_word(&target.to_string_lossy()), true);
                }
            }
        }
        true
    }

    pub(super) fn python_startup(&mut self, invocation: &crate::python_cli::Invocation) {
        if invocation.interactive {
            self.unresolved_program(
                "Python interactive mode can execute additional input and startup code",
            );
        }
        for option in &invocation.woptions {
            if option.dynamic
                || option
                    .text
                    .split(':')
                    .nth(2)
                    .is_some_and(|category| category.contains('.'))
            {
                self.unresolved_program(
                    "Python warning category resolution may import additional code",
                );
            }
        }
        for option in &invocation.xoptions {
            let key = option.text.split('=').next().unwrap_or_default();
            if key == "pycache_prefix" && !option.dynamic {
                if let Some((_, path)) = option.text.split_once('=') {
                    self.write_destination(&crate::tooling::literal(path), true);
                }
            } else if option.dynamic
                || !matches!(
                    key,
                    "dev"
                        | "utf8"
                        | "faulthandler"
                        | "tracemalloc"
                        | "warn_default_encoding"
                        | "int_max_str_digits"
                        | "frozen_modules"
                )
            {
                self.unresolved_program(
                    "Python -X option may load startup code or change execution semantics",
                );
            }
        }
    }

    pub(super) fn node(&mut self, args: &[Word], input: Option<&crate::shell::ShellInput>) {
        use crate::node_cli::Target;
        let invocation = match crate::node_cli::parse(args) {
            Ok(invocation) => invocation,
            Err(reason) => {
                self.unresolved_program(reason);
                return;
            }
        };
        let language = if invocation.typescript {
            Language::TypeScript
        } else {
            Language::JavaScript
        };
        for reason in invocation.gaps {
            self.unresolved_program(reason);
        }
        for file in invocation.configuration {
            self.read_destination(&file);
            self.unresolved_program(
                "Node runtime configuration or environment files can load additional code",
            );
        }
        for file in invocation.preloads {
            self.unresolved_program("Node preload modules or loaders can execute additional code");
            if !file.dynamic
                && (file.text.starts_with('.') || std::path::Path::new(&file.text).is_absolute())
            {
                self.node_file(&file);
            }
        }
        match invocation.target {
            Target::Info => self.raise(Severity::Safe),
            Target::Code(source) if !source.dynamic => {
                self.inspect_program(language, &source.text, None);
            }
            Target::File(file) => {
                self.node_file(&file);
            }
            Target::Stdin => match input {
                Some(input) if !input.dynamic => {
                    self.inspect_program(language, &input.text, None);
                }
                Some(_) => {
                    self.unresolved_program("Node stdin contains unresolved shell expansions")
                }
                None => self.unresolved_program("Node standard-input source is unavailable"),
            },
            _ => self.unresolved_program("Node eval source is dynamic"),
        }
    }

    fn node_file(&mut self, file: &Word) {
        if !file.dynamic
            && [".ts", ".mts", ".cts"]
                .iter()
                .any(|extension| file.text.ends_with(extension))
        {
            self.unresolved_program(
                "TypeScript runtime transformation and dependency behavior are unresolved",
            );
            self.inspect_file(Language::TypeScript, file);
            return;
        }
        if !file.dynamic
            && [".js", ".mjs", ".cjs"]
                .iter()
                .any(|extension| file.text.ends_with(extension))
        {
            self.inspect_file(Language::JavaScript, file);
        } else {
            self.unresolved_program("Node source format or module resolution is unsupported");
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
        self.inspect_program_limited(language, source, origin, None)
    }

    pub(super) fn inspect_workflow_file(&mut self, language: Language, file: &Word) -> bool {
        match source_text(self, file) {
            Ok(source) => {
                let limit = self.budget.remaining_nodes().saturating_sub(256).min(1024);
                self.inspect_program_limited(language, &source, Some(&file.text), Some(limit))
            }
            Err(reason) => {
                self.unresolved_program(reason);
                false
            }
        }
    }

    fn inspect_program_limited(
        &mut self,
        language: Language,
        source: &str,
        origin: Option<&str>,
        limit: Option<usize>,
    ) -> bool {
        if !self.within_budget() {
            return false;
        }
        match if limit.is_some() {
            syntax::analyze_with_limit(language, source, &self.budget, limit)
        } else {
            syntax::analyze_with_budget(language, source, &self.budget)
        } {
            Ok(analysis) if analysis.print_only => {
                if matches!(language, Language::Python) {
                    self.emit_path(&["python", "-c", "@print"]);
                } else {
                    self.emit_path(&["lang", "@print"]);
                }
                true
            }
            Ok(analysis) => {
                if let Some(python) = analysis.python {
                    let complete = python.gaps.is_empty();
                    for gap in python.gaps {
                        self.unresolved_program(&gap);
                    }
                    // The standard-library model is conditional on import identity,
                    // just like bare system executables. Visible project shadows
                    // must never inherit the model of the library they replace.
                    for module in python.imports {
                        let mut prefixes = Vec::new();
                        let mut prefix = String::new();
                        for part in module.split('.') {
                            if !prefix.is_empty() {
                                prefix.push('/');
                            }
                            prefix.push_str(part);
                            prefixes.push(prefix.clone());
                        }
                        let base = origin
                            .and_then(|file| self.lexical_path(&literal_word(file)))
                            .and_then(|file| file.parent().map(std::path::Path::to_path_buf))
                            .or_else(|| self.cwd.clone());
                        if let Some(base) = base {
                            for candidate in prefixes.iter().flat_map(|relative| {
                                [
                                    base.join(format!("{relative}.py")),
                                    base.join(relative).join("__init__.py"),
                                ]
                            }) {
                                if candidate.exists() {
                                    self.unresolved_program("Python standard-library import is shadowed by project source");
                                    if self.python_imports.len() < 32
                                        && !self.python_imports.contains(&candidate)
                                    {
                                        self.python_imports.push(candidate.clone());
                                        self.inspect_file(
                                            Language::Python,
                                            &literal_word(&candidate.to_string_lossy()),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    for observation in python.observations {
                        self.source_observation(observation, origin);
                    }
                    if !complete || limit.is_some() {
                        // Preserve conditional hazards in unsupported classes,
                        // decorators, dynamic calls, and unmodeled statements.
                        for observation in analysis.observations {
                            self.source_observation(observation, origin);
                        }
                    }
                    for command in python.commands {
                        if self.python_command_depth
                            >= self.config.analysis.expansion_depth_max.min(8)
                        {
                            self.unresolved_program(
                                "Python subprocess inspection depth limit reached",
                            );
                            continue;
                        }
                        self.python_command_depth += 1;
                        let command = if command.shell {
                            command.argv.join(" ")
                        } else {
                            command
                                .argv
                                .iter()
                                .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
                                .collect::<Vec<_>>()
                                .join(" ")
                        };
                        self.analyze(&command, self.python_command_depth);
                        self.python_command_depth -= 1;
                    }
                    if complete {
                        self.raise(Severity::Low);
                    }
                    return false;
                }
                self.unresolved_program(
                    "Source includes behavior outside the supported static semantics",
                );
                for observation in analysis.observations {
                    self.source_observation(observation, origin);
                }
                for import in analysis.imports {
                    let Some(specifier) = import.specifier else {
                        self.unresolved_program("Node import specifier is dynamic or unsupported");
                        continue;
                    };
                    if specifier.starts_with("node:")
                        || matches!(
                            specifier.as_str(),
                            "fs" | "fs/promises"
                                | "child_process"
                                | "http"
                                | "https"
                                | "path"
                                | "url"
                                | "util"
                                | "assert"
                                | "assert/strict"
                        )
                    {
                        continue;
                    }
                    if !specifier.starts_with("./") && !specifier.starts_with("../") {
                        self.unresolved_program("Node package imports, custom loaders, or native modules are unresolved");
                        continue;
                    }
                    if self.node_imports.len() >= 32
                        || self.node_import_depth >= self.config.analysis.expansion_depth_max.min(8)
                    {
                        self.unresolved_program("Node local import file or depth limit reached");
                        continue;
                    }
                    let base = origin
                        .and_then(|file| self.lexical_path(&literal_word(file)))
                        .and_then(|file| file.parent().map(std::path::Path::to_path_buf))
                        .or_else(|| self.cwd.clone());
                    let Some(base) = base else {
                        self.unresolved_program("Node local import directory is unresolved");
                        continue;
                    };
                    let dependency = crate::normalize_path(&base.join(&specifier));
                    if self.node_imports.contains(&dependency) {
                        self.unresolved_program(
                            "Node local import cycle or repeated dependency remains partial",
                        );
                        continue;
                    }
                    self.node_imports.push(dependency.clone());
                    self.node_import_depth += 1;
                    self.node_file(&literal_word(&dependency.to_string_lossy()));
                    self.node_import_depth -= 1;
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

fn literal_word(text: &str) -> Word {
    Word {
        text: text.into(),
        dynamic: false,
        tilde_expansion: false,
        substitutions: vec![],
    }
}

fn info_only(args: &[Word], options: &[&str]) -> bool {
    args.len() == 1 && !args[0].dynamic && options.contains(&args[0].text.as_str())
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
