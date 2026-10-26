//! Build tools may execute hooks, processors, toolchain helpers and project code.
use crate::{Analyzer, syntax::Language, tooling::literal};
use distill_core::{EffectKind, Severity};
use distill_parse::Word;

impl Analyzer<'_> {
    pub(super) fn compiler_extended(&mut self, args: &[Word], rust: bool) {
        let opts = self.tool_options(
            args,
            &[
                "-o",
                "--out-dir",
                "--emit",
                "--crate-type",
                "--crate-name",
                "--edition",
                "--extern",
                "--cfg",
                "-C",
                "-L",
                "-l",
                "-I",
                "-D",
                "-U",
                "-include",
                "-imacros",
                "-isystem",
                "-iquote",
                "-isysroot",
                "--sysroot",
                "-x",
                "-target",
                "--target",
                "-Xclang",
                "-Xlinker",
                "-Xpreprocessor",
                "-B",
                "-MF",
                "-MJ",
                "--serialize-diagnostics",
                "-fplugin",
                "-fpass-plugin",
                "-specs",
                "--specs",
            ],
            &[
                "-c",
                "-S",
                "-E",
                "-fsyntax-only",
                "-g",
                "-O",
                "-O0",
                "-O1",
                "-O2",
                "-O3",
                "-Os",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wpedantic",
                "-pedantic",
                "-shared",
                "-fPIC",
                "-pthread",
                "-M",
                "-MM",
                "-MD",
                "-MMD",
                "-MP",
            ],
            false,
        );
        self.unresolved_program("Compiler dependencies, response files, plugins, linkers, and preprocessing are not fully resolved");
        let mut output = false;
        for target in opts.all(&["-o", "--out-dir", "-MF", "-MJ", "--serialize-diagnostics"]) {
            self.write_destination(target, true);
            output = true;
        }
        for source in opts.all(&["-include", "-imacros", "-specs", "--specs"]) {
            self.read_destination(source);
        }
        for value in opts.all(&["--emit"]) {
            for item in value.text.split(',') {
                if let Some((_, target)) = item.split_once('=') {
                    let mut word = value.clone();
                    word.text = target.into();
                    self.write_destination(&word, true);
                    output = true;
                }
            }
        }
        if opts.has(&[
            "-fplugin",
            "-fpass-plugin",
            "-Xclang",
            "-Xlinker",
            "-B",
            "-specs",
            "--specs",
            "--extern",
            "-C",
        ]) || args
            .iter()
            .any(|a| a.text.starts_with("-Wl,") || a.text.starts_with("-fplugin="))
        {
            self.finding(Severity::High, EffectKind::Execute, "compiler.extension", "Compiler options may execute a plugin, procedural macro, linker, or custom toolchain helper");
        }
        for arg in &opts.operands {
            if !self.within_budget() {
                return;
            }
            if let Some(path) = arg.text.strip_prefix('@') {
                let mut file = arg.clone();
                file.text = path.into();
                self.read_destination(&file);
                self.unknown("Compiler response-file arguments are unresolved");
            } else if arg.text.ends_with(".rs") && rust {
                self.inspect_file(Language::Rust, arg);
            } else if arg.text.ends_with(".c") && !rust {
                self.inspect_file(Language::C, arg);
            } else if [".cpp", ".cc", ".cxx"]
                .iter()
                .any(|ext| arg.text.ends_with(ext))
                && !rust
            {
                self.inspect_file(Language::Cpp, arg);
            }
        }
        if !output && !opts.has(&["-E", "-fsyntax-only", "-M", "-MM"]) {
            if opts.has(&["-c", "-S"]) {
                for source in opts.operands.iter().filter(|s| {
                    [".c", ".cc", ".cpp", ".cxx"]
                        .iter()
                        .any(|ext| s.text.ends_with(ext))
                }) {
                    if let Some(stem) = std::path::Path::new(&source.text).file_stem() {
                        self.write_destination(
                            &literal(format!(
                                "{}.{}",
                                stem.to_string_lossy(),
                                if opts.has(&["-S"]) { "s" } else { "o" }
                            )),
                            true,
                        );
                    }
                }
            } else if rust {
                self.finding(
                    Severity::Medium,
                    EffectKind::FileWrite,
                    "rustc.implicit-output",
                    "Rust compiler output names depend on crate type and emission options",
                );
            } else {
                self.write_destination(&literal("a.out"), true);
            }
        }
    }

    pub(super) fn go_extended(&mut self, args: &[Word]) {
        let global = self.tool_options(args, &["-C"], &[], true);
        let saved = self.cwd.clone();
        for directory in global.all(&["-C"]) {
            self.cwd = self.resolve(directory);
        }
        self.go_operation(&global.operands);
        self.cwd = saved;
    }

    fn go_operation(&mut self, args: &[Word]) {
        let Some(sub) = args.first().filter(|a| !a.dynamic) else {
            self.unresolved_program("Go operation is unresolved");
            return;
        };
        let opts = self.tool_options(
            &args[1..],
            &[
                "-o",
                "-toolexec",
                "-exec",
                "-overlay",
                "-modfile",
                "-mod",
                "-tags",
                "-ldflags",
                "-gcflags",
                "-asmflags",
                "-pkgdir",
                "-buildmode",
                "-coverprofile",
                "-cpuprofile",
                "-memprofile",
                "-trace",
                "-run",
                "-bench",
                "-timeout",
                "-p",
            ],
            &[
                "-v",
                "-x",
                "-n",
                "-race",
                "-trimpath",
                "-a",
                "-work",
                "-json",
                "-c",
                "-i",
                "-cache",
                "-testcache",
                "-modcache",
                "-fuzzcache",
                "-r",
                "-w",
                "-u",
            ],
            false,
        );
        match sub.text.as_str() {
            "build" | "run" | "test" | "install" | "generate" | "tool" => {
                self.unresolved_program("Go build/run may execute toolchain helpers, cgo, generators, tests, or package code");
                if sub.text == "install" {
                    self.package_change("go", &args[1..], false);
                }
                for source in &opts.operands {
                    if source.text.ends_with(".go") {
                        self.inspect_file(Language::Go, source);
                    }
                }
                for target in opts.all(&[
                    "-o",
                    "-coverprofile",
                    "-cpuprofile",
                    "-memprofile",
                    "-trace",
                ]) {
                    self.write_destination(target, true);
                }
                for file in opts.all(&["-overlay", "-modfile"]) {
                    self.read_destination(file);
                }
                if opts.has(&["-exec", "-toolexec"]) {
                    self.finding(
                        Severity::High,
                        EffectKind::Execute,
                        "go.helper",
                        "Go invokes an explicitly selected execution or toolchain helper",
                    );
                }
                if sub.text == "generate" {
                    self.finding(
                        Severity::High,
                        EffectKind::Execute,
                        "go.generate",
                        "Executes arbitrary commands declared by go:generate directives",
                    );
                }
                self.finding(
                    Severity::Medium,
                    EffectKind::FileWrite,
                    "go.build-output",
                    "Build may write binaries, generated files, and build caches",
                );
            }
            "clean" => self.finding(
                Severity::High,
                EffectKind::FileDelete,
                "go.clean",
                "Removes Go build outputs, installed artifacts, or caches",
            ),
            "get" | "mod" | "work" => {
                self.finding(
                    Severity::Medium,
                    EffectKind::FileWrite,
                    "go.dependencies",
                    "May update module/workspace files and download dependencies",
                );
                self.unresolved_program(
                    "Go dependency operation and toolchain selection are not fully resolved",
                );
            }
            "env" if opts.has(&["-w", "-u"]) => self.finding(
                Severity::High,
                EffectKind::Persistence,
                "go.environment",
                "Changes persistent Go toolchain configuration",
            ),
            "env" | "version" | "help" | "list" => self.finding(
                Severity::Low,
                EffectKind::FileRead,
                "go.query",
                "Queries Go toolchain or package metadata",
            ),
            "fmt" | "fix" => self.finding(
                Severity::Medium,
                EffectKind::FileWrite,
                "go.source-change",
                "Rewrites Go source files",
            ),
            _ => self.unresolved_program("Go subcommand is not modeled"),
        }
        self.context_partial = true;
        self.unknown(
            "Go environment, package graph, and implicit output paths are not fully resolved",
        );
    }

    pub(super) fn cargo(&mut self, args: &[Word]) {
        if args.len() == 1
            && !args[0].dynamic
            && matches!(args[0].text.as_str(), "--version" | "-V" | "--help")
        {
            self.raise(Severity::Safe);
            return;
        }
        let args = if args.first().is_some_and(|a| a.text.starts_with('+')) {
            self.unresolved_program("Rustup toolchain selection is unresolved");
            &args[1..]
        } else {
            args
        };
        let global = self.tool_options(
            args,
            &["--config", "-Z", "-C", "--color"],
            &[
                "--offline",
                "--locked",
                "--frozen",
                "--quiet",
                "-q",
                "--verbose",
                "-v",
            ],
            true,
        );
        let Some(sub) = global.operands.first().filter(|a| !a.dynamic) else {
            self.unresolved_program("Cargo subcommand is unresolved");
            return;
        };
        let rest = &global.operands[1..];
        let opts = self.tool_options(
            rest,
            &[
                "--manifest-path",
                "--target-dir",
                "--root",
                "--path",
                "--git",
                "--registry",
                "--index",
                "--config",
                "--target",
                "--features",
                "--profile",
                "--package",
                "-p",
                "--bin",
                "--example",
                "--test",
                "--bench",
                "--jobs",
                "-j",
                "--message-format",
                "--color",
                "-Z",
            ],
            &[
                "--release",
                "--workspace",
                "--all",
                "--all-targets",
                "--all-features",
                "--no-default-features",
                "--offline",
                "--locked",
                "--frozen",
                "--quiet",
                "-q",
                "--verbose",
                "-v",
                "--force",
                "--no-run",
                "--no-deps",
                "--lib",
                "--bins",
                "--tests",
                "--benches",
                "--examples",
                "--dry-run",
            ],
            false,
        );
        if global.has(&["--config", "-Z", "-C"]) || opts.has(&["--config", "-Z"]) {
            self.unresolved_program(
                "Cargo configuration can select executable aliases, runners, or compiler wrappers",
            );
        }
        let sub = sub.text.as_str();
        match sub {
            "install" | "uninstall" | "remove" | "rm" | "add" | "update" => {
                self.package_change("cargo", rest, matches!(sub, "uninstall" | "remove" | "rm"));
            }
            "build" | "b" | "check" | "c" | "run" | "r" | "test" | "t" | "bench" | "doc" | "rustc" | "rustdoc" | "clippy" | "fix" => self.unresolved_program("Cargo may execute build scripts, procedural macros, tests, runners, or compiler extensions"),
            "clean" => self.finding(Severity::High, EffectKind::FileDelete, "cargo.clean", "Deletes Cargo build outputs at the selected target directory"),
            "publish" | "login" | "owner" | "yank" => self.finding(Severity::High, EffectKind::NetworkSend, "cargo.registry", "Changes registry state or sends package contents or credentials"),
            "metadata" | "tree" | "locate-project" | "pkgid" | "version" | "help" | "search" | "info" => self.finding(Severity::Low, EffectKind::FileRead, "cargo.query", "Queries Cargo project, package, or registry metadata"),
            "fetch" | "vendor" | "new" | "init" | "fmt" | "package" | "generate-lockfile" => self.finding(Severity::Medium, EffectKind::FileWrite, "cargo.files", "Creates or updates project files, package archives, or dependency caches"),
            _ => self.unresolved_program("Cargo external subcommand or alias may execute arbitrary code"),
        }
        for target in opts.all(&["--target-dir", "--root"]) {
            if sub == "clean" {
                self.rm(&[literal("-rf"), target.clone()]);
            } else if sub == "uninstall" {
                self.finding(
                    Severity::High,
                    EffectKind::FileDelete,
                    "cargo.install-root-remove",
                    "Removes selected installed binaries from the configured installation root",
                );
            } else {
                self.write_destination(target, true);
            }
        }
        self.context_partial = true;
        self.unknown("Cargo configuration, workspace dependencies, build scripts, and implicit paths are not fully resolved");
        if matches!(
            sub,
            "build"
                | "b"
                | "check"
                | "c"
                | "run"
                | "r"
                | "test"
                | "t"
                | "bench"
                | "doc"
                | "install"
                | "rustc"
                | "clippy"
                | "package"
        ) {
            let manifest = opts
                .all(&["--manifest-path"])
                .last()
                .cloned()
                .unwrap_or_else(|| {
                    opts.all(&["--path"]).last().map_or_else(
                        || literal("Cargo.toml"),
                        |p| {
                            let mut w = p.clone();
                            w.text = format!("{}/Cargo.toml", p.text);
                            w
                        },
                    )
                });
            self.cargo_sources(&manifest);
        }
    }

    fn cargo_sources(&mut self, manifest: &Word) {
        let Some(path) = self.lexical_path(manifest) else {
            return;
        };
        let Ok(text) = self.inspect_read(&path, 64 * 1024) else {
            return;
        };
        let Ok(value) = text.parse::<toml::Value>() else {
            self.unknown("Cargo manifest cannot be parsed");
            return;
        };
        let Some(base) = path.parent() else {
            return;
        };
        let build = value.get("package").and_then(|v| v.get("build"));
        let mut sources = vec!["src/main.rs".to_owned(), "src/lib.rs".to_owned()];
        if build.and_then(toml::Value::as_bool) != Some(false) {
            sources.push(
                build
                    .and_then(toml::Value::as_str)
                    .unwrap_or("build.rs")
                    .into(),
            );
        }
        for source in sources {
            let path = base.join(source);
            if path.is_file() {
                self.inspect_file(Language::Rust, &literal(path.to_string_lossy()));
            }
        }
    }

    pub(super) fn java_tool(&mut self, name: &str, args: &[Word]) {
        if args.len() == 1
            && !args[0].dynamic
            && matches!(
                args[0].text.as_str(),
                "-version" | "--version" | "-help" | "--help"
            )
        {
            self.raise(Severity::Safe);
            return;
        }
        if name != "javac" {
            self.unresolved_program(
                "Java execution, build plugins, agents, or archive operations are unresolved",
            );
            if matches!(name, "mvn" | "mvnw" | "gradle" | "gradlew") {
                self.finding(
                    Severity::High,
                    EffectKind::Execute,
                    "java.build-hooks",
                    "Java build tools execute project plugins and build lifecycle code",
                );
            }
            for file in args.iter().filter(|a| a.text.ends_with(".java")) {
                self.inspect_file(Language::Java, file);
            }
            return;
        }
        let opts = self.tool_options(
            args,
            &[
                "-d",
                "-s",
                "-h",
                "-classpath",
                "-cp",
                "--class-path",
                "--module-path",
                "-p",
                "-sourcepath",
                "--source-path",
                "--module-source-path",
                "-processor",
                "-processorpath",
                "--processor-path",
                "--processor-module-path",
                "--release",
                "-source",
                "-target",
                "-encoding",
                "-Xmaxerrs",
                "-Xmaxwarns",
            ],
            &[
                "-proc:none",
                "-proc:only",
                "-proc:full",
                "-g",
                "-g:none",
                "-nowarn",
                "-deprecation",
                "-Werror",
                "-verbose",
                "-parameters",
                "--enable-preview",
            ],
            false,
        );
        self.unresolved_program("Java compiler inputs, annotation processors, plugins, and JVM configuration are not fully resolved");
        if opts.has(&[
            "-processor",
            "-processorpath",
            "--processor-path",
            "--processor-module-path",
            "-proc:only",
            "-proc:full",
        ]) || args
            .iter()
            .any(|a| a.text.starts_with("-J") || a.text.starts_with("-Xplugin:"))
        {
            self.finding(
                Severity::High,
                EffectKind::Execute,
                "java.compiler-extension",
                "Compilation may execute annotation processors, compiler plugins, or JVM agents",
            );
        }
        for target in opts.all(&["-d", "-s", "-h"]) {
            self.write_destination(target, true);
        }
        for source in &opts.operands {
            if source.text.ends_with(".java") {
                self.inspect_file(Language::Java, source);
                if !opts.has(&["-d"])
                    && let Some(path) = self
                        .lexical_path(source)
                        .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
                {
                    self.write_destination(&literal(path.to_string_lossy()), true);
                }
            } else if let Some(path) = source.text.strip_prefix('@') {
                let mut word = source.clone();
                word.text = path.into();
                self.read_destination(&word);
                self.unknown("Java compiler argument file is unresolved");
            }
        }
    }

    pub(super) fn python_module(&mut self, module: &Word, args: &[Word]) {
        match module.text.as_str() {
            "venv" => {
                self.finding(
                    Severity::Medium,
                    EffectKind::FileWrite,
                    "python.venv",
                    "Creates or updates a Python environment and executable scripts",
                );
                let opts = self.tool_options(
                    args,
                    &["--prompt"],
                    &[
                        "--clear",
                        "--upgrade",
                        "--without-pip",
                        "--upgrade-deps",
                        "--system-site-packages",
                        "--symlinks",
                        "--copies",
                    ],
                    false,
                );
                for target in &opts.operands {
                    if opts.has(&["--clear"]) {
                        self.rm(&[literal("-rf"), target.clone()]);
                    }
                    self.write_destination(target, true);
                }
            }
            "ensurepip" => self.package_change("pip", args, false),
            "http.server" => self.finding(
                Severity::High,
                EffectKind::NetworkSend,
                "python.http-server",
                "Serves local directory contents over the network",
            ),
            "compileall" | "py_compile" => self.finding(
                Severity::Medium,
                EffectKind::FileWrite,
                "python.bytecode",
                "Writes Python bytecode caches",
            ),
            _ => {
                // Local module names only; never import or execute a candidate module.
                if module.text.split('.').all(|p| {
                    !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                }) {
                    let file = literal(format!("{}.py", module.text.replace('.', "/")));
                    self.inspect_file(Language::Python, &file);
                }
            }
        }
    }
}
