//! Git operations beyond the legacy trie. Repository hooks/configuration stay unresolved.
use crate::{Analyzer, tooling::literal};
use distill_core::{EffectKind, Severity};
use distill_parse::Word;

impl Analyzer<'_> {
    pub(super) fn git_extended(&mut self, sub: &str, args: &[Word]) -> bool {
        match sub {
            "config" => {
                let opts = self.tool_options(
                    args,
                    &["--file", "-f", "--type", "--default", "--blob"],
                    &[
                        "--global",
                        "--system",
                        "--local",
                        "--worktree",
                        "--get",
                        "--get-all",
                        "--get-regexp",
                        "--get-urlmatch",
                        "--list",
                        "-l",
                        "--show-origin",
                        "--show-scope",
                        "--null",
                        "-z",
                        "--includes",
                        "--no-includes",
                        "--add",
                        "--replace-all",
                        "--unset",
                        "--unset-all",
                        "--remove-section",
                        "--rename-section",
                        "--edit",
                        "-e",
                        "--fixed-value",
                    ],
                    false,
                );
                let mutating = opts.has(&[
                    "--add",
                    "--replace-all",
                    "--unset",
                    "--unset-all",
                    "--remove-section",
                    "--rename-section",
                    "--edit",
                    "-e",
                ]) || opts.operands.first().is_some_and(|a| {
                    matches!(
                        a.text.as_str(),
                        "set" | "unset" | "edit" | "rename-section" | "remove-section"
                    )
                }) || !opts.has(&[
                    "--get",
                    "--get-all",
                    "--get-regexp",
                    "--get-urlmatch",
                    "--list",
                    "-l",
                ]) && opts.operands.len() >= 2
                    && !opts
                        .operands
                        .first()
                        .is_some_and(|a| matches!(a.text.as_str(), "get" | "list"));
                if mutating {
                    self.finding(Severity::High, EffectKind::Persistence, "git.config-write", "Changes persistent Git configuration, potentially installing executable helpers or disabling protections");
                    for target in opts.all(&["--file", "-f"]) {
                        self.write_destination(target, true);
                    }
                    if opts.has(&["--edit", "-e"])
                        || opts.operands.first().is_some_and(|a| a.text == "edit")
                    {
                        self.unresolved_program(
                            "Git configuration editing invokes a configured editor",
                        );
                    }
                } else {
                    self.finding(
                        Severity::Low,
                        EffectKind::FileRead,
                        "git.config-read",
                        "Reads Git configuration",
                    );
                    for source in opts.all(&["--file", "-f"]) {
                        self.read_destination(source);
                    }
                }
            }
            "clone" | "init" => {
                let opts = self.tool_options(
                    args,
                    &[
                        "--template",
                        "--separate-git-dir",
                        "--upload-pack",
                        "-u",
                        "--config",
                        "-c",
                        "--depth",
                        "--branch",
                        "-b",
                        "--origin",
                        "-o",
                        "--reference",
                        "--reference-if-able",
                        "--filter",
                        "--jobs",
                        "-j",
                        "--initial-branch",
                        "--object-format",
                    ],
                    &[
                        "--bare",
                        "--mirror",
                        "--no-checkout",
                        "-n",
                        "--quiet",
                        "-q",
                        "--verbose",
                        "-v",
                        "--recursive",
                        "--recurse-submodules",
                        "--single-branch",
                        "--no-tags",
                        "--local",
                        "-l",
                        "--shared",
                        "-s",
                        "--dissociate",
                    ],
                    false,
                );
                self.unresolved_program("Git initialization or checkout may use executable templates, hooks, filters, or transport helpers");
                if sub == "clone" {
                    self.finding(
                        Severity::Medium,
                        EffectKind::NetworkReceive,
                        "git.clone",
                        "Retrieves a repository and may check out executable content",
                    );
                }
                if opts.operands.len() >= if sub == "clone" { 2 } else { 1 } {
                    self.write_destination(opts.operands.last().unwrap(), true);
                } else {
                    self.finding(
                        Severity::Medium,
                        EffectKind::FileWrite,
                        "git.repository-create",
                        "Creates repository metadata or a checkout at an implicit destination",
                    );
                }
                for target in opts.all(&["--separate-git-dir"]) {
                    self.write_destination(target, true);
                }
                for source in opts.all(&["--template"]) {
                    self.read_destination(source);
                }
            }
            "log" | "show" | "rev-parse" | "rev-list" | "ls-files" | "ls-tree" | "for-each-ref"
            | "show-ref" | "describe" | "blame" | "cat-file" => {
                let opts = self.tool_options(
                    args,
                    &[
                        "--format",
                        "--pretty",
                        "--max-count",
                        "-n",
                        "--output",
                        "--since",
                        "--until",
                        "--author",
                        "--grep",
                        "--sort",
                        "--count",
                        "--abbrev",
                        "--date",
                        "--encoding",
                    ],
                    &[
                        "--oneline",
                        "--stat",
                        "--name-only",
                        "--name-status",
                        "--short",
                        "--verify",
                        "--show-toplevel",
                        "--is-inside-work-tree",
                        "--abbrev-ref",
                        "--all",
                        "--heads",
                        "--tags",
                        "--cached",
                        "--stage",
                        "-s",
                        "--others",
                        "--exclude-standard",
                        "--deleted",
                        "--modified",
                        "--no-patch",
                        "--patch",
                        "-p",
                        "-z",
                        "--no-ext-diff",
                        "--no-textconv",
                        "--decorate",
                        "--no-decorate",
                        "--graph",
                        "--raw",
                        "--quiet",
                        "-q",
                    ],
                    false,
                );
                self.finding(
                    Severity::Low,
                    EffectKind::FileRead,
                    "git.query",
                    "Reads repository history, objects, references, or file metadata",
                );
                for target in opts.all(&["--output"]) {
                    self.write_destination(target, true);
                }
                if matches!(sub, "log" | "show" | "blame") {
                    self.context_partial = true;
                    self.unknown("Git pager, text conversion, and external diff configuration are unresolved");
                    if args
                        .iter()
                        .take_while(|a| a.text != "--")
                        .any(|a| matches!(a.text.as_str(), "--ext-diff" | "--textconv"))
                    {
                        self.unresolved_program("Git query enables executable conversion helpers");
                    }
                }
            }
            "apply" | "am" | "merge" | "rebase" | "cherry-pick" | "revert" | "restore"
            | "switch" | "worktree" | "submodule" | "gc" | "prune" | "maintenance" => {
                self.finding(
                    Severity::High,
                    EffectKind::FileWrite,
                    "git.repository-change",
                    "Changes repository files, history, worktrees, submodules, or stored objects",
                );
                self.unresolved_program(
                    "Git operation may use hooks, filters, editors, or external helpers",
                );
                let opts = self.tool_options(
                    args,
                    &[
                        "--directory",
                        "--work-tree",
                        "--output",
                        "-o",
                        "--exec",
                        "-x",
                        "--strategy",
                        "-s",
                    ],
                    &[
                        "--force",
                        "-f",
                        "--hard",
                        "--recursive",
                        "--init",
                        "--checkout",
                        "--no-checkout",
                        "--quiet",
                        "-q",
                    ],
                    false,
                );
                for target in opts.all(&["--directory", "--work-tree", "--output", "-o"]) {
                    self.write_destination(target, true);
                }
                if sub == "worktree"
                    && opts.operands.first().is_some_and(|a| a.text == "add")
                    && let Some(target) = opts.operands.get(1)
                {
                    self.write_destination(target, true);
                }
            }
            "archive" => {
                let opts = self.tool_options(
                    args,
                    &[
                        "--output",
                        "-o",
                        "--format",
                        "--prefix",
                        "--remote",
                        "--exec",
                        "--add-file",
                        "--add-virtual-file",
                    ],
                    &["--verbose", "-v", "--list", "-l"],
                    false,
                );
                self.finding(
                    Severity::Low,
                    EffectKind::FileRead,
                    "git.archive",
                    "Reads repository contents to produce an archive",
                );
                for target in opts.all(&["--output", "-o"]) {
                    self.write_destination(target, true);
                }
                for source in opts.all(&["--add-file"]) {
                    self.read_destination(source);
                }
                self.unresolved_program(
                    "Git archive formats and remote helpers may select executable code",
                );
            }
            "clean" => {
                let opts = self.tool_options(
                    args,
                    &["-e", "--exclude"],
                    &[
                        "-f",
                        "--force",
                        "-d",
                        "-x",
                        "-X",
                        "-n",
                        "--dry-run",
                        "-i",
                        "--interactive",
                        "-q",
                        "--quiet",
                    ],
                    false,
                );
                if opts.has(&["-n", "--dry-run"]) && !opts.incomplete {
                    self.emit_path(&["git", "clean", "-n"]);
                } else {
                    self.finding(
                        Severity::High,
                        EffectKind::FileDelete,
                        "git.clean",
                        "Deletes untracked or ignored working-tree files and directories",
                    );
                    for path in &opts.operands {
                        self.rm(&[literal("-rf"), path.clone()]);
                    }
                    if let Some(cwd) = &self.cwd
                        && crate::application_path(cwd)
                    {
                        self.finding(
                            Severity::Critical,
                            EffectKind::FileDelete,
                            "git.clean-application",
                            "Cleans files inside an installed application or system directory",
                        );
                    }
                }
            }
            _ => return false,
        }
        true
    }
}
