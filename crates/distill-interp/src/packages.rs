//! Software installation/removal adapters. Package metadata and lifecycle code remain partial.
use crate::Analyzer;
use distill_core::{EffectKind, Severity};
use distill_parse::Word;

impl Analyzer<'_> {
    pub(super) fn package_tool(&mut self, name: &str, args: &[Word], depth: usize) -> bool {
        if name == "install" {
            self.install_files(args);
            return true;
        }
        if !matches!(
            name,
            "pip"
                | "pip3"
                | "pipx"
                | "uv"
                | "conda"
                | "brew"
                | "npm"
                | "pnpm"
                | "yarn"
                | "apt"
                | "apt-get"
                | "dpkg"
                | "dnf"
                | "yum"
                | "rpm"
                | "pacman"
                | "apk"
                | "snap"
                | "flatpak"
                | "port"
                | "gem"
                | "installer"
                | "pkgutil"
                | "softwareupdate"
                | "rustup"
        ) {
            return false;
        }
        if args.len() == 1
            && !args[0].dynamic
            && matches!(args[0].text.as_str(), "--version" | "--help" | "-V")
        {
            self.raise(Severity::Safe);
            return true;
        }
        let opts = self.tool_options(
            args,
            &[
                "--prefix",
                "--root",
                "--target",
                "-t",
                "--python",
                "--index-url",
                "--extra-index-url",
                "--proxy",
                "--config-file",
                "--config",
                "-c",
                "--cache-dir",
                "--directory",
                "-C",
                "--cwd",
                "--registry",
                "--user-data-dir",
            ],
            &[
                "--user",
                "--system",
                "--global",
                "-g",
                "--quiet",
                "-q",
                "--verbose",
                "-v",
                "--yes",
                "-y",
                "--isolated",
                "--disable-pip-version-check",
                "--no-input",
                "--break-system-packages",
            ],
            true,
        );
        let mut operands = opts.operands.as_slice();
        if matches!(name, "uv" | "rustup")
            && operands.first().is_some_and(|a| {
                matches!(
                    a.text.as_str(),
                    "pip" | "tool" | "toolchain" | "component" | "target" | "self"
                )
            })
        {
            operands = &operands[1..];
        }
        let sub = operands
            .first()
            .filter(|a| !a.dynamic)
            .map(|a| a.text.as_str())
            .unwrap_or("");
        let removing = matches!(
            sub,
            "uninstall"
                | "remove"
                | "rm"
                | "un"
                | "uninst"
                | "unlink"
                | "purge"
                | "autoremove"
                | "autopurge"
                | "erase"
                | "uninstall-all"
                | "del"
                | "cleanup"
                | "clean"
                | "prune"
        ) || matches!(name, "dpkg" | "rpm" | "pacman")
            && args.iter().any(|a| {
                a.text.starts_with("-R")
                    || matches!(
                        a.text.as_str(),
                        "-r" | "-P" | "--remove" | "--purge" | "-e" | "--erase"
                    )
            })
            || name == "pkgutil" && args.iter().any(|a| a.text == "--forget");
        let installing = matches!(
            sub,
            "install"
                | "i"
                | "add"
                | "ci"
                | "update"
                | "upgrade"
                | "reinstall"
                | "rebuild"
                | "link"
                | "relink"
                | "sync"
                | "distro-sync"
                | "dist-upgrade"
                | "full-upgrade"
                | "develop"
                | "restore"
                | "default"
                | "override"
        ) || name == "yarn" && args.is_empty()
            || name == "installer"
            || matches!(name, "dpkg" | "rpm" | "pacman")
                && args.iter().any(|a| {
                    matches!(
                        a.text.as_str(),
                        "-i" | "--install" | "--unpack" | "--configure" | "-U" | "--upgrade"
                    ) || a.text.starts_with("-S")
                        || a.text.starts_with("-U")
                })
            || name == "softwareupdate"
                && args
                    .iter()
                    .any(|a| matches!(a.text.as_str(), "-i" | "--install"));
        if installing || removing {
            self.package_change(name, args, removing);
            // Decode location and input flags independently of subcommand discovery.
            let detail = self.tool_options(
                args,
                &[
                    "--prefix",
                    "--root",
                    "--target",
                    "-t",
                    "--destdir",
                    "--installroot",
                    "--directory",
                    "-C",
                    "--cwd",
                    "--requirements",
                    "-r",
                    "--constraint",
                    "-c",
                    "--log",
                    "--report",
                    "--cache-dir",
                    "--index-url",
                    "--extra-index-url",
                    "--python",
                    "--config",
                    "--registry",
                    "--pkg",
                    "-pkg",
                    "-target",
                ],
                &[
                    "--user",
                    "--global",
                    "-g",
                    "--system",
                    "--force",
                    "--force-reinstall",
                    "--ignore-installed",
                    "--break-system-packages",
                    "--ignore-dependencies",
                    "--zap",
                    "--cask",
                    "--formula",
                    "--yes",
                    "-y",
                    "--quiet",
                    "-q",
                    "--verbose",
                    "-v",
                    "--dry-run",
                    "--no-deps",
                    "--no-build-isolation",
                    "--ignore-scripts",
                    "--isolated",
                    "--no-input",
                ],
                false,
            );
            for target in detail.all(&[
                "--prefix",
                "--root",
                "--target",
                "-t",
                "--destdir",
                "--installroot",
                "--log",
                "--report",
                "-target",
            ]) {
                self.write_destination(target, true);
            }
            for source in detail.all(&[
                "--requirements",
                "-r",
                "--constraint",
                "-c",
                "--pkg",
                "-pkg",
            ]) {
                self.read_destination(source);
            }
            if matches!(name, "npm" | "pnpm" | "yarn") {
                self.expand_wrapper(name, args, depth);
            }
            if name == "brew" {
                self.brew(args);
            }
            if matches!(name, "pip" | "pip3" | "uv") && installing {
                self.inspect_python_build(operands);
            }
            return true;
        }
        if matches!(name, "npm" | "pnpm" | "yarn") {
            self.expand_wrapper(name, args, depth);
            return true;
        }
        if name == "brew" {
            return false;
        }
        if matches!(
            sub,
            "list"
                | "freeze"
                | "show"
                | "info"
                | "search"
                | "check"
                | "outdated"
                | "help"
                | "version"
        ) {
            self.finding(
                Severity::Low,
                EffectKind::FileRead,
                "package.query",
                "Queries package metadata or installed software",
            );
            self.context_partial = true;
            self.unknown(
                "Package query options, configuration, and remote lookups are not fully modeled",
            );
        } else if matches!(sub, "download" | "wheel" | "build") {
            self.unresolved_program("Package metadata and wheel builds may execute build backend code even without installation");
            self.finding(
                Severity::Medium,
                EffectKind::FileWrite,
                "package.build",
                "Writes downloaded packages or built distributions",
            );
            self.inspect_python_build(operands);
        } else {
            self.unresolved_program("Package-manager operation or plugin is unresolved");
        }
        true
    }

    fn inspect_python_build(&mut self, args: &[Word]) {
        // Only explicit literal local projects are inspected; remote dependency code stays unknown.
        for arg in args
            .iter()
            .filter(|a| {
                !a.dynamic && (a.text == "." || a.text.starts_with("./") || a.text.starts_with('/'))
            })
            .take(16)
        {
            if !self.within_budget() {
                return;
            }
            let Some(path) = self.lexical_path(arg).filter(|p| p.is_dir()) else {
                continue;
            };
            for name in ["setup.py", "pyproject.toml"] {
                let path = path.join(name);
                if !path.is_file() {
                    continue;
                }
                if let Ok(text) = self.inspect_read(&path, 64 * 1024) {
                    if name == "setup.py" {
                        self.inspect_program(crate::syntax::Language::Python, &text, path.to_str());
                    } else {
                        self.unresolved_program(
                            "Python build-system requirements and backend code are unresolved",
                        );
                    }
                } else {
                    self.unresolved_program("Python build metadata could not be inspected");
                }
            }
        }
    }

    fn install_files(&mut self, args: &[Word]) {
        let opts = self.tool_options(
            args,
            &[
                "-m",
                "--mode",
                "-o",
                "--owner",
                "-g",
                "--group",
                "-t",
                "--target-directory",
                "--strip-program",
                "-S",
                "--suffix",
            ],
            &[
                "-d",
                "--directory",
                "-D",
                "-p",
                "--preserve-timestamps",
                "-v",
                "--verbose",
                "-c",
                "-C",
                "-s",
                "--strip",
                "-T",
                "--no-target-directory",
                "-b",
            ],
            false,
        );
        if opts.has(&["--strip-program", "-s", "--strip"]) {
            self.unresolved_program("File installation invokes a strip program");
        }
        if opts.has(&["-o", "--owner", "-g", "--group", "-m", "--mode"]) {
            self.finding(
                Severity::High,
                EffectKind::PermissionChange,
                "install.permissions",
                "Installation changes file ownership or executable access permissions",
            );
        }
        let targets: Vec<_> = opts.all(&["-t", "--target-directory"]).cloned().collect();
        if opts.has(&["-d", "--directory"]) {
            for target in &opts.operands {
                self.write_destination(target, true);
            }
        } else if !targets.is_empty() {
            for target in &targets {
                self.write_destination(target, true);
            }
            for source in &opts.operands {
                self.read_destination(source);
            }
        } else if let Some((target, sources)) = opts
            .operands
            .split_last()
            .filter(|(_, rest)| !rest.is_empty())
        {
            self.write_destination(target, true);
            for source in sources {
                self.read_destination(source);
            }
        } else {
            self.unresolved_program("File installation source or destination is missing");
        }
    }
}
