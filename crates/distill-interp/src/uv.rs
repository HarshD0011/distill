//! uv wrappers keep the launched argv and stdin boundary intact.
use crate::{
    Analyzer,
    shell::ShellInput,
    tooling::{Options, literal},
};
use distill_core::{EffectKind, Severity};
use distill_parse::{Token, Word};

const VALUES: &[&str] = &[
    "--from",
    "--directory",
    "--project",
    "--config-file",
    "--cache-dir",
    "--python",
    "-p",
    "--color",
    "--allow-insecure-host",
    "--index",
    "--default-index",
    "--index-url",
    "--extra-index-url",
    "--index-strategy",
    "--keyring-provider",
    "--with",
    "-w",
    "--with-editable",
    "--with-requirements",
    "--group",
    "--only-group",
    "--no-group",
    "--extra",
    "--package",
    "--link-mode",
    "--python-platform",
    "--refresh-package",
    "--reinstall-package",
    "--upgrade-package",
    "--resolution",
    "--prerelease",
    "--fork-strategy",
    "--exclude-newer",
    "--config-setting",
    "--config-settings",
    "-C",
];
const FLAGS: &[&str] = &[
    "--offline",
    "--no-config",
    "--no-cache",
    "--quiet",
    "-q",
    "--verbose",
    "-v",
    "--locked",
    "--frozen",
    "--no-sync",
    "--no-project",
    "--isolated",
    "--active",
    "--managed-python",
    "--no-managed-python",
    "--no-python-downloads",
    "--native-tls",
    "--system-certs",
    "--no-progress",
    "--no-dev",
    "--only-dev",
    "--all-groups",
    "--no-default-groups",
    "--all-extras",
    "--all-packages",
    "--no-editable",
    "--no-install-project",
    "--no-install-workspace",
    "--no-sources",
    "--no-build",
    "--no-build-isolation",
    "--no-deps",
    "--refresh",
    "--reinstall",
    "--upgrade",
    "-U",
    "--exact",
    "--system",
    "--clear",
    "--seed",
    "--relocatable",
    "--allow-existing",
    "--check",
    "--short",
];

impl Analyzer<'_> {
    pub(super) fn uv(
        &mut self,
        name: &str,
        args: &[Word],
        depth: usize,
        input: Option<&ShellInput>,
    ) {
        if depth > self.config.analysis.expansion_depth_max || !self.within_budget() {
            self.stop_analysis("uv wrapper nesting limit reached");
            return;
        }
        if args.len() == 1
            && !args[0].dynamic
            && matches!(args[0].text.as_str(), "--version" | "-V" | "--help" | "-h")
        {
            self.raise(Severity::Safe);
            return;
        }
        let global = self.tool_options(args, VALUES, FLAGS, true);
        if global.incomplete {
            if name == "uvx" {
                self.workflow_execution("uvx package tool execution");
            }
            self.unresolved_program("uv option arity or program selection is unresolved");
            return;
        }
        let Some(sub) = global.operands.first().filter(|word| !word.dynamic) else {
            self.unresolved_program("uv subcommand is missing or dynamic");
            return;
        };
        let saved = self.cwd.clone();
        if name == "uvx" {
            self.uv_run(args, &Options::default(), true, depth, input);
        } else if sub.text == "run" {
            self.uv_run(&global.operands[1..], &global, false, depth, input);
        } else if sub.text == "tool"
            && global
                .operands
                .get(1)
                .is_some_and(|word| word.text == "run")
        {
            self.uv_run(&global.operands[2..], &global, true, depth, input);
        } else if sub.text == "venv" {
            self.uv_locations(&global);
            let options = self.tool_options(
                &global.operands[1..],
                &["--prompt", "--python", "-p"],
                FLAGS,
                false,
            );
            let target = options
                .operands
                .first()
                .cloned()
                .unwrap_or_else(|| literal(".venv"));
            if options.has(&["--clear"]) {
                self.rm(&[literal("-rf"), target.clone()]);
            }
            self.write_destination(&target, true);
            self.unresolved_program("uv environment creation can discover or download interpreters and install seed packages");
        } else if matches!(sub.text.as_str(), "lock" | "export" | "tree" | "init") {
            self.uv_locations(&global);
            let opts = self.tool_options(
                &global.operands[1..],
                &[
                    "--output-file",
                    "-o",
                    "--format",
                    "--python",
                    "-p",
                    "--name",
                ],
                FLAGS,
                false,
            );
            self.finding(
                Severity::Low,
                EffectKind::FileRead,
                "uv.query",
                "Reads uv project and dependency metadata",
            );
            if matches!(sub.text.as_str(), "lock" | "tree" | "export")
                && !opts.has(&["--locked", "--frozen", "--check"])
            {
                self.write_destination(&literal("uv.lock"), true);
            }
            if sub.text == "init" {
                self.write_destination(opts.operands.first().unwrap_or(&literal(".")), true);
            }
            for output in opts.all(&["--output-file", "-o"]) {
                self.write_destination(output, true);
            }
            self.unresolved_program(
                "uv project discovery, resolver inputs, and build metadata remain conditional",
            );
        } else {
            self.uv_locations(&global);
            if !self.uv_auxiliary(&global.operands) {
                self.package_tool("uv", args, depth);
                if matches!(sub.text.as_str(), "sync" | "build" | "add") {
                    self.uv_project_build(&global);
                }
            }
        }
        self.cwd = saved;
    }

    fn uv_locations(&mut self, opts: &Options) {
        if let Some(directory) = opts.all(&["--directory"]).last() {
            self.cwd = self.resolve(directory);
        }
        // --project changes metadata discovery, not relative program paths.
        for file in opts.all(&["--config-file", "--with-requirements"]) {
            self.read_destination(file);
        }
    }

    fn uv_run(
        &mut self,
        args: &[Word],
        global: &Options,
        tool: bool,
        depth: usize,
        input: Option<&ShellInput>,
    ) {
        let values = VALUES.to_vec();
        let mut flags = FLAGS.to_vec();
        flags.extend(["--script", "--module", "-m"]);
        let mut opts = self.tool_options(args, &values, &flags, true);
        opts.values.splice(0..0, global.values.clone());
        self.uv_locations(&opts);
        if !opts.has(&["--no-cache"]) {
            for cache in opts.all(&["--cache-dir"]) {
                self.write_destination(cache, true);
            }
        }
        if !tool && !opts.has(&["--no-sync", "--no-project"]) {
            self.uv_project_build(&opts);
            if opts.has(&["--isolated", "--active"]) {
                self.finding(Severity::Medium, EffectKind::FileWrite, "uv.environment", "uv creates or synchronizes an isolated or active environment at a runtime-selected path");
            } else {
                self.write_destination(&literal(".venv"), true);
            }
        }
        if !tool && !opts.has(&["--locked", "--frozen", "--no-sync", "--no-project"]) {
            self.write_destination(&literal("uv.lock"), true);
        }
        if tool
            || opts.has(&[
                "--with",
                "-w",
                "--with-editable",
                "--with-requirements",
                "--from",
            ])
        {
            self.package_change("uv", args, false);
        }
        self.unresolved_program("uv interpreter discovery, project configuration, dependencies, and build backends remain conditional");
        if opts.incomplete {
            self.unresolved_program(
                "uv run has an unsupported or dynamic option; nested argv cannot be established",
            );
            return;
        }
        let mut words = opts.operands.clone();
        if opts.has(&["--module", "-m"]) {
            let mut python = vec![literal("python3"), literal("-m")];
            python.extend(words);
            words = python;
        } else if let Some(file) = words.first() {
            if !file.dynamic
                && (file.text.starts_with("https://") || file.text.starts_with("http://"))
            {
                self.finding(
                    Severity::Critical,
                    EffectKind::Execute,
                    "exec.uv-remote-script",
                    "uv downloads and executes a remote script",
                );
                return;
            }
            if opts.has(&["--script"]) || file.text.ends_with(".py") || file.text == "-" {
                words.insert(0, literal("python3"));
            }
        }
        self.uv_nested(&words, depth, input);
    }

    fn uv_project_build(&mut self, opts: &Options) {
        if opts.has(&["--no-project", "--no-sync"]) {
            return;
        }
        let saved = self.cwd.clone();
        if let Some(project) = opts.all(&["--project"]).last() {
            self.cwd = self.resolve(project);
        }
        let mut project = self.cwd.clone();
        for _ in 0..16 {
            let Some(directory) = project else {
                break;
            };
            let metadata = directory.join("pyproject.toml");
            if metadata.is_file() {
                if let Ok(text) = self.inspect_read(&metadata, 64 * 1024)
                    && let Ok(value) = text.parse::<toml::Value>()
                {
                    let package = value.get("build-system").is_some()
                        || value
                            .get("tool")
                            .and_then(|v| v.get("uv"))
                            .and_then(|v| v.get("package"))
                            .and_then(toml::Value::as_bool)
                            == Some(true);
                    if package {
                        self.inspect_python_build(&[literal(directory.to_string_lossy())]);
                    }
                }
                break;
            }
            project = directory.parent().map(std::path::Path::to_path_buf);
        }
        self.cwd = saved;
    }

    fn uv_auxiliary(&mut self, args: &[Word]) -> bool {
        let Some(sub) = args.first() else {
            return false;
        };
        match sub.text.as_str() {
            "help" => self.raise(Severity::Safe),
            "python" | "cache" | "tool" => {
                let Some(action) = args.get(1).filter(|word| !word.dynamic) else {
                    self.unresolved_program("uv command group has no established action");
                    return true;
                };
                match action.text.as_str() {
                    "dir" | "find" | "list" | "help" => self.finding(
                        Severity::Low,
                        EffectKind::FileRead,
                        "uv.query",
                        "Queries uv interpreter, environment, tool, or cache metadata",
                    ),
                    "install" | "uninstall" | "upgrade" | "update-shell" | "pin" | "unpin" => self
                        .package_change(
                            "uv",
                            args,
                            matches!(action.text.as_str(), "uninstall" | "unpin"),
                        ),
                    "clean" | "prune" => self.finding(
                        Severity::Medium,
                        EffectKind::FileDelete,
                        "uv.cache-remove",
                        "Removes uv cache entries at a runtime-selected cache location",
                    ),
                    _ => self.unresolved_program("uv command-group action is unresolved"),
                }
                self.unresolved_program("uv tool/interpreter/cache paths, downloads, and configuration remain conditional");
            }
            "version" => {
                if args.len() == 1
                    || args
                        .iter()
                        .skip(1)
                        .all(|word| !word.dynamic && word.text == "--short")
                {
                    self.finding(
                        Severity::Low,
                        EffectKind::FileRead,
                        "uv.query",
                        "Reads the Python project version",
                    );
                } else {
                    self.write_destination(&literal("pyproject.toml"), true);
                }
                self.unknown(
                    "uv version project discovery and version arguments remain conditional",
                );
            }
            "format" => {
                self.workflow_execution("uv runs a formatter tool");
                let opts = self.tool_options(
                    &args[1..],
                    &["--config", "--exclude", "--line-length", "--target-version"],
                    &["--check", "--diff", "--quiet", "-q", "--verbose", "-v"],
                    false,
                );
                if !opts.has(&["--check", "--diff"]) {
                    if opts.operands.is_empty() {
                        self.write_destination(&literal("."), true);
                    }
                    for target in &opts.operands {
                        self.write_destination(target, true);
                    }
                }
                self.unresolved_program(
                    "uv formatter/tool installation and project configuration remain conditional",
                );
            }
            "publish" => {
                self.finding(
                    Severity::High,
                    EffectKind::NetworkSend,
                    "uv.publish",
                    "Uploads Python distributions to a package registry",
                );
                self.unresolved_program(
                    "uv publication archive contents, credentials, and destination are unresolved",
                );
            }
            "auth" => {
                self.finding(
                    Severity::High,
                    EffectKind::FileWrite,
                    "uv.credentials",
                    "Reads or changes stored package-index authentication state",
                );
                self.unknown("uv credential storage and remote authentication are unresolved");
            }
            "self" => self.package_change(
                "uv",
                args,
                args.get(1).is_some_and(|word| word.text == "uninstall"),
            ),
            "generate-shell-completion" => self.raise(Severity::Safe),
            _ => return false,
        }
        true
    }

    fn uv_nested(&mut self, words: &[Word], depth: usize, input: Option<&ShellInput>) {
        if words.is_empty() {
            self.unresolved_program("uv execution has no established command");
            return;
        }
        if depth >= self.config.analysis.expansion_depth_max {
            self.stop_analysis("uv wrapper nesting limit reached");
            return;
        }
        // Keep argv as tokens: rejoining with spaces would turn data into shell code.
        let tokens: Vec<_> = words
            .iter()
            .map(|word| {
                let mut word = word.clone();
                word.substitutions.clear();
                Token::Word(word)
            })
            .collect();
        self.analyze_segment(&tokens, depth + 1, input);
    }
}
