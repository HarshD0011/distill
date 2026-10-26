# Distill

Distill 0.4.2 is a local command analyzer for coding agents. It separates **known impact**, **analysis coverage**, and the **policy decision**. An UNKNOWN verdict means the analyzer cannot establish an impact rating; a known rating with partial coverage still requires review under the default policy. No model or network service runs in the analysis path.

The workspace contains the embedded Rust analyzer, Codex/Claude hooks, a VS Code command trace extension, a bounded session policy ledger, and an opt-in execution gate. `analyze` and hook assessment never execute candidate commands. **`run` executes a command inside native containment.** Hooks remain analysis adapters: installing them does not automatically route host execution through the gate.

## Build and install

```sh
cargo test --workspace
cargo install --path crates/distill-cli --force
# Preview user-level definitions, then install them:
distill setup codex --check --workspace-root /absolute/workspace
distill setup codex --labels --workspace-root /absolute/workspace
distill doctor --json --workspace-root /absolute/workspace
```

Setup writes user-owned hook definitions, an isolated Python launcher, and a separate policy file under `~/.config/distill`. It pins the absolute CLI path and SHA-256, preserves unrelated handlers and existing strict mode, and leaves project files untouched. Rerunning setup preserves the host's stored policy and labels; `--config` deliberately replaces the stored policy. After upgrading the binary, rerun setup to refresh its pin. Codex may require reviewing and trusting changed definitions in `/hooks`. User hooks do not establish managed enforcement against project configuration or an agent that can modify user files.

Bundled defaults are strict. Pass an explicit reviewed advisory policy, such as a customized [example](config.example.toml), to `setup --config` when advisory behavior is desired. Advisory hooks show findings and preserve host permission checks. Strict Codex hooks deny commands requiring review because PreToolUse has no native ask response; Claude can request native review. A modeled safe/low command does not produce an automatic permission grant in strict mode.

## Analyze commands

```sh
distill analyze --command 'echo hello' --human
distill analyze --command 'rm -rf /' --cwd /tmp --human
distill inspect --format dockerfile --file Dockerfile
distill coverage --input saved-reports.json
```

Reports include impact, conservative approval risk, decision, coverage gaps, command digest, and hashes of inspected source/build files. Unsupported behavior remains partial or opaque. Resource exhaustion and watchdog expiry produce HIGH and deny, regardless of the incomplete-policy setting.

Bash structure and selected source languages use Tree-sitter plus bounded interpretation. Specialized profiles model file operations, Git, compilers, package scripts, and selected system tools. Reviewed capability adapters retain nested execution and remote effects for tools such as tar, xargs, SSH, package launchers, cloud CLIs, and SQL clients. Narrow literal `sed` printing/counting and `nl` numbering profiles account for source reads. Dockerfile, CI, SQL, awk, and sed artifact inspection extracts selected literal effects and always retains incomplete coverage. See [the supported model](docs/static-analysis.md) and [0.4 implementation notes](docs/v04-implementation.md).

Dedicated adapters also describe Python package/module operations, Git configuration and outputs, Docker host access, curl uploads/configuration/output files, Go builds, C/C++ compiler extensions, Cargo build scripts, and Java compilation. Install/removal operations remain reviewable across common package managers. Application bundles and installed executable directories receive shared protected-path treatment. See [tool coverage and limits](docs/tool-coverage.md); recognized behavior does not imply that arbitrary application code has been proven safe.

Typed argument grammars bind Git diff outputs, no-index inputs, and database-client programs/files to shared effects. Bounded SQL AST analysis collects modifying CTEs, distinguishes executing from plan-only statements, and evaluates supported constant predicates with SQL NULL semantics. Client shell commands and native loaders route through reviewed capabilities. These models contain no command-specific severity labels; configurable effect policy supplies ratings. See [the semantic-gap implementation](docs/semantic-gap-design.md).

Zsh uses a conservative dialect layer, not a complete Zsh grammar. Without a complete supported explicit option snapshot, it retains HIGH uncertainty. Unsupported expansion, aliases, options, modules, and grammar retain incomplete coverage. `run` establishes its own restricted shell options; ordinary hook calls do not infer a shell snapshot from the user's login environment.

## Signed approval labels

Optional Codex `--labels` setup creates a private HMAC key. The hook adds a fixed severity/coverage comment, authenticated against the exact comment and command bytes. Only authentic leading labels are stripped before reassessment; forged comments remain inert source text. Labels contain no raw filename or argument-derived reason. Existing command text is preserved apart from replacing an authentic leading label.

The documented Codex rewrite schema requires `permissionDecision: "allow"` with `updatedInput`. Normal host permission checks still apply; this is not a PermissionRequest approval. Omit labels for a nonmutating advisory response. Hook launch failures remain subject to the host's timeout/error behavior. [Codex hook contract](https://learn.chatgpt.com/docs/hooks).

## Session policy and privacy

The enabled ledger records bounded hashes, effect labels, timestamps, decisions, and explicit shell-option names in private user files. It correlates completed secret reads/copies with later network transfers, downloaded files with later execution, and repeated equivalent review attempts. A proposed effect becomes session evidence only after a matching completion. It does not record command text or output and is separate from editor history.

Defaults are a two-hour entry TTL, 1,000 entries per session, three prior equivalent review attempts before denial, 2 MiB per session file, and global caps of 256 files / 64 MiB. Corruption, contention, and capacity limits require review. TTL expiration removes entries on access, not idle files. `distill ledger-clear --session ID --source codex --cwd /absolute/workspace` clears a session, including corrupt state; administrators can remove obsolete ledger files when no hooks are using them. This is bounded effect correlation, not general interprocedural or byte-level taint analysis.

Editor history stays in a bounded memory broker and disappears when the editor application quits. Its private Unix socket uses peer-UID verification and token authentication. Presentation redaction is best effort. **Output capture defaults off**; opt in with `[privacy] capture_output = true`. The ledger persists hashed policy state even when the extension is absent. See [the extension guide](extensions/vscode/README.md).

## Contained execution

```sh
# Analyze and obtain a receipt without executing:
distill run --command 'echo hello' --cwd /absolute/workspace --check
# Execute an allowed command:
distill run --command 'echo hello' --cwd /absolute/workspace
# For a review decision, inspect --check and supply its exact execution_binding:
distill run --command 'touch output.txt' --cwd /absolute/workspace --write /absolute/workspace --approve RECEIPT
```

Receipts bind command, policy, source dependencies, cwd, shell hash, backend, timeout, and write grants. Denials cannot be overridden. Dependencies are rechecked immediately before spawn; this is **not an atomic filesystem snapshot**. The gate clears inherited environment, supplies scratch HOME/TMPDIR, null stdin, resource limits, a wall timeout, and process-group cleanup. Workspace access is read-only unless explicit write grants are supplied. Network and privileged IPC are blocked.

macOS uses a deny-default Seatbelt profile. Linux requires Landlock ABI >= 3 and architecture-checked seccomp; its additive filesystem grants require a small clean staging workspace and reject credentials, control directories, and symlinks. Unsupported backends fail closed. Linux runtime enforcement must be verified on a Linux kernel; compilation on macOS does not establish containment. Native sandbox policy is an additional boundary, not a claim that arbitrary programs are proven safe.

## Verification and development

```sh
make check
make smoke
make test-extension
DISTILL_SANDBOX_TESTS=1 cargo test -p distill-cli --test runtime -- --ignored
cd extensions/vscode && npm run package
```

Tests include real hook schemas, signed-label forgery, session isolation/retries, stale dependency receipts, actual macOS containment, 3,600 hazard transformations, 2,048 deterministic fuzz inputs, and 200 literal shell-oracle cases. `fuzz/` supplies a cargo-fuzz target and retained non-shell-whitespace regression. CI runs Mac/Linux checks and instrumented nightly fuzzing. Local stable libFuzzer smoke runs are not coverage-guided evidence. Corpus scores are regression results, not general detection accuracy.

`mine_specs.py` extracts syntax-only drafts from saved help text; every new capability requires explicit review and provenance. `coverage` ranks observed gaps without retaining raw argument values. There is no analysis daemon, automatic training, syscall tracer, or Endpoint Security helper.

License: [GPL-3.0](LICENSE).

See the [October 22 verdict audit](docs/verdict-audit-20261022.md) for the signed-label correlation fix, independently stated verdict expectations, and measured classification corrections.
