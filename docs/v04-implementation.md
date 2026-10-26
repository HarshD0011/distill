# Distill 0.4 implementation and verification

This release implements the supplied security/coverage roadmap as bounded local mechanisms. The analyzer predicts effects; it does not prove arbitrary shell programs safe. Analysis hooks preserve the selected host mode. The separate `run` command supplies execution containment when explicitly invoked.

## Hook integrity and installation

Labels use a fixed template and HMAC-SHA256 over exact label/command bytes. No argument-derived reason enters the comment. Only an authentic leading label is stripped. Forgery, byte changes, newline cases, mode restrictions, and preserved input/permission fields are covered by adapter tests. Nonmutating advisory output remains available by omitting labels.

Strict safe/low behavior already returned no permission opinion in 0.3; the guide's assertion that it auto-granted permission was not reproduced. That property is retained. The documented advisory rewrite schema still requires `allow` with `updatedInput`; host permission checks follow. Escalated-sandbox requests now produce an explicit HIGH finding.

`setup` writes user hooks, a private isolated Python launcher, a SHA-256 executable pin, and a per-host policy. It preserves unrelated hooks, strict mode, saved policy, and existing label preference. `doctor` inventories user/ancestor/inline sources, disabled hooks, project definitions, PATH handlers, and stale/missing pins. Setup checks for concurrent user-file modification. The editor refuses setup over an unsaved user hook document. No trust database is edited.

The actual Codex installation was migrated from an absolute but unpinned 0.3 handler to the pinned 0.4 user launcher, retaining advisory mode and signed labels. The duplicate project post hook was backed up and removed. A real harmless Bash invocation printed its execution string containing the signed leading comment, establishing that the configured pre-hook fired and rewrote the live command. Native approval-card rendering was not rechecked for every verdict in this release.

## Context, dependencies, and execution

Zsh has a bounded dialect layer, explicit option snapshots, and conservative handling of executable expansion, execution glob qualifiers, modules, and option mutation. It still uses the Bash structural parser. A compatible snapshot permits the supported literal subset to be modeled; missing or unsupported context retains HIGH uncertainty. Hook snapshots are explicit supplied context, not a live attestation of a login shell. The gate establishes its own restricted shell state.

An in-command mutation overlay invalidates old inspected source/build/package contents after writes, deletes, or unresolved mutation. It does not simulate rewritten file contents. This prevents using a stale print-only proof and retains HIGH approval risk. Sources, build/package metadata, and artifacts carry bounded file snapshots including lexical path, resolved path, bytes, and SHA-256. Gate receipts bind those dependencies plus command, policy, cwd, shell hash, backend, grants, and timeout. Changed receipts or dependencies stop execution. Rechecking immediately before spawn narrows a race; it does not eliminate concurrent filesystem mutation atomically.

`run` clears inherited environment, uses scratch HOME/TMPDIR and a fixed PATH, restricts shell startup, disconnects stdin, imposes rlimits and wall time, and kills its process group on expiry. macOS uses deny-default Seatbelt with explicit loader/runtime read grants and credential/control restrictions. Linux implements Landlock ABI >= 3 plus architecture-checked seccomp, refusing broad grants containing credentials, control directories, or symlinks. It requires a clean staging workspace. There is no unsandboxed fallback. Hooks do not automatically put all agent tools inside this gate, and `trace.enabled` remains unsupported: this is containment, not syscall tracing.

All cooperative limit overflows become stopped/HIGH/deny even when incomplete policy allows. A separate parent process bounds analysis worker wall time and output and returns event-specific denial schemas. The watchdog begins after bounded stdin acquisition; a host that never finishes sending stdin remains subject to the host timeout. Launch failure handling ultimately also depends on the host.

## Session effects and privacy

The private bounded ledger stores hashes, effect labels, timestamps, decisions, and supplied shell options. Completion-correlated secret reads/copies and remote downloads influence later network/execute requests. Proposed effects are not completion evidence. Retry matching now includes a lexical fingerprint that normalizes literal quoting/whitespace and retains operands/program text, avoiding a live-test false positive that grouped unrelated unresolved commands by finding ID alone. It does not solve arbitrary semantic equivalence or general source-language taint propagation.

The ledger is distinct from editor history. It has per-session locking with a bounded 500 ms acquisition wait (tested with 64 calls across eight concurrent workers), caps, global caps, lazy entry TTL, and explicit session clearing. Idle ledger files are not automatically removed by TTL. Corrupt, busy, or full state retains review through the hook's selected mode. Clearing can recover corrupt state.

Command presentation and recursively delivered values redact common credential formats. Redaction is best effort; output capture defaults off. Editor history remains in memory. The broker now uses private Unix sockets, token authentication, and peer-UID checks on both sides; its Rust peer helper is invoked asynchronously. The editor resolves a configured absolute executable or trusted installation paths, never workspace PATH. Clearing editor history does not clear the policy ledger.

## Coverage and policy

Reviewed authored capability adapters cover nested execution flags, transfer/fetch launchers, selected cloud/database verbs, expanded environment injection, and persistence targets. Literal nested payloads are recursively analyzed where recoverable. Ordinary deletion defaults MEDIUM; a static Git-index/blob match can annotate recoverability without lowering severity. Existing language print-only restrictions continue to reject unresolved imports/includes/plugins and extra code.

Package analysis inspects pre/script/post hooks, install/prepare lifecycle hooks, and lockfile install-script markers without running the package manager. Makefile parsing remains bounded/static; no `make -n` is run. SQL, awk, sed, Dockerfile, and CI artifact inspection extracts selected literal effects while keeping partial coverage. Narrow read-only `sed` print/count and `nl` numbering profiles were added in response to baseline gaps.

`coverage` aggregates retained report gaps by command, option name, and reason, excluding raw argument values. Help-text mining produces syntax-only, unreviewed drafts; schema validation and provenance are required before shipping reviewed capability data. No external GTFOBins/LOOBins dataset or automatic model-generated behavior specification is imported. The real-shell oracle runs generated harmless literal printf cases in tests; arbitrary expansion is not delegated to a real shell in the hook hot path.

## Saved hook comparison

The [machine-readable comparison](hook-comparison-20261022.json) contains every command, context, verdict, risk, coverage, and measured duration. `scripts/hook_comparison.py` called the actual configured PreToolUse handler before installation and after installation. The original binary and definitions were frozen before mutation. All 67 cases use identical command bytes, fixture files, cwd, and context. No candidate command was executed. Missing session/tool IDs isolate per-command classification from policy-ledger history.

UNKNOWN fell from 26 to 7 (73.1% fewer). Modeled coverage rose from 32 to 33; most gains are new known hazards with retained partial coverage. Known HIGH/CRITICAL impact findings rose from 9 to 32. Examples: shell/IFS environment injection SAFE to HIGH, multipart secret upload MEDIUM to CRITICAL, tar nested execution MEDIUM/modeled to CRITICAL/partial, and npm pre-script UNKNOWN to CRITICAL. A write-before-Python case correctly lost modeled coverage. Ordinary deletion LOW to MEDIUM is an intentional policy change.

Remaining UNKNOWN cases are an opaque executable, Make recipe, brace-bearing xargs invocation, computed executable, encoded shell input, Zsh without a snapshot, and Zsh executable expansion. They retain review risk; their impact is not invented to improve the score. Full command coverage remains deliberately incomplete.

Median end-to-end handler time changed from 2.341 ms to 38.438 ms; p95 changed from 3.907 ms to 40.731 ms. The new path includes Python startup and hashing the CLI, while the original directly launched Rust. Runs were sequential on this machine without controlling caches/process load. This is an authored regression corpus, including profiles improved after seeing baseline gaps; it is not a general detection-accuracy estimate. Saved UTC timestamps preserve the measurement machine's clock; the comparison is labeled October 22 for the user's local session date.

## Verification evidence

- Rust: 127 tests pass in the normal workspace suite; one containment test is separately opt-in. Clippy with all targets and warnings denied passes. The setup test also checks stored policy retention and stale-pin PermissionRequest denial.
- Smoke: CLI/schema fixtures pass; 155 source-language analyses and 155 signed-label checks pass; the 40 labeled policy cases report zero wrong impacts, unsafe allows, or unnecessary reviews.
- Generated cases: 3,600 literal hazard transformations retain CRITICAL/deny. Separate dynamic/encoded bypass families retain HIGH or stronger review risk; 2,048 deterministic fuzz inputs preserve stopped-analysis denial. Two hundred harmless literal cases compare decoded words against real Bash/Zsh.
- Fuzzing found and fixed a lexer nonprogress/OOM bug on non-shell whitespace. The saved reproducer includes `\x03\x0b@\n`. The post-fix stable libFuzzer smoke completed 57,615 executions in six seconds with about 34 MiB RSS. That local run lacked coverage instrumentation; CI defines a nightly instrumented cargo-fuzz job, whose remote result is not claimed here.
- Editor: 32 Node tests pass, including Rust-hook-to-broker delivery, privacy, socket authentication, reconnect, and lifecycle handling. An isolated packaged VS Code instance passed actual window reload and application-quit cleanup. The 0.4 VSIX is packaged.
- macOS containment: actual tests pass for cleared inherited secrets, denied outside writes, granted disposable writes, denied localhost connection, and denied credential-file reads. No hazardous command is used. Linux backend Rust code cross-compiles for x86_64 Linux; full workspace cross-compilation lacked the GNU C toolchain, and Linux runtime enforcement was not executed on this Mac. CI defines Linux runtime checks; no remote CI result is claimed.

Limits remain explicit: partial grammars and capability catalogs, supplied-context trust, conservative mutation handling, best-effort redaction, and non-atomic dependency recheck. These mechanisms improve the boundary without establishing universal command safety.
