# Adopting design.md in Distill

Review date: 7 November 2026. Scope: the current working tree, including existing uncommitted changes, compared with [design.md](../design.md). This is an implementation assessment and proposed roadmap; it does not change hook behavior or policy.

Distill already implements the main static-analysis path proposed in the draft. Extend the six existing crates rather than restart the project under the `cmdsev` name. The draft adds useful product and learning loops, but several of its safety, privacy, and lifecycle assumptions need correction before implementation.

## How much is covered

Of the draft's 11 functional requirements, **9 have an implementation foundation**: **3 have a present equivalent, 6 are partial, and 2 are absent**. These are qualitative requirement counts, not a completion percentage, test coverage, or a detection-accuracy estimate. A present equivalent still operates within documented bounds.

- **FR-1 — Present equivalent: Bash hook assessment.** Codex and Claude adapters, severity/reason output, policy decisions, user-hook setup, and command correlation exist. Codex also has `PermissionRequest`; advisory and strict modes differ. Installed advisory hooks do not enforce every internal `ask` as a host permission prompt. Missing shell metadata keeps uncertainty. Evidence: [agents](../crates/distill-agents/src/lib.rs), [setup](../crates/distill-cli/src/setup.rs), [hook registration](../extensions/vscode/src/hooks.js).
- **FR-2 — Partial: compound commands and combinations.** Tree-sitter shell walking handles supported pipelines, lists, subshells, substitutions, redirections, and heredocs. Network/credential/decoded-code combinations exist. Unsupported grammar and control flow stay partial. There is no exported `CommandIR` graph with per-node confidence or a second shell parser. Evidence: [shell](../crates/distill-interp/src/shell.rs), [interpreter](../crates/distill-interp/src/lib.rs), [word lexer](../crates/distill-parse/src/lib.rs).
- **FR-3 — Present equivalent: recursive wrapper handling.** Reviewed wrapper profiles and dedicated adapters unwrap supported `env`, privilege, timeout, shell, `find`, and `xargs` forms. Unknown option arity remains unresolved. The current expansion-depth default is 8; the draft proposes 4. Evidence: [profiles](../crates/distill-interp/src/profiles.rs), [wrappers](../crates/distill-interp/rules/wrappers.json), [interpreter](../crates/distill-interp/src/lib.rs).
- **FR-4 — Partial: static project/source resolution.** Package scripts and lifecycle hooks, literal Make recipes, shell/Python/JavaScript source, and several additional languages/workflows are inspected without running candidate code. Imported code, complex build semantics, and broader Node invocation forms remain unresolved. `.mjs`, `.cjs`, and TypeScript support are missing from the narrow Node file path. Evidence: [build tools](../crates/distill-interp/src/build_tools.rs), [Make](../crates/distill-interp/src/makefile.rs), [programs](../crates/distill-interp/src/program.rs), [syntax](../crates/distill-interp/src/syntax/mod.rs).
- **FR-5 — Partial: target context.** Shared path classes, protected destinations, source dependency snapshots, SQL/database scope, and limited read-only Git-index evidence exist. Full dirty-tree/default-branch context and kube/AWS/GCP production-context resolution do not. Git recoverability currently annotates evidence without lowering impact. Evidence: [target classification](../crates/distill-interp/src/class.rs), [recoverability](../crates/distill-core/src/recoverability.rs), [SQL](../crates/distill-interp/src/sql.rs), [capabilities](../crates/distill-interp/src/capabilities.rs).
- **FR-6 — Absent: model fallback.** No LLM judge, ONNX classifier, training pipeline, or analysis daemon exists. The editor recorder is a memory broker, not a judge service. Evidence: [workspace](../Cargo.toml), [broker](../extensions/vscode/src/broker.js), [CLI](../crates/distill-cli/src/main.rs).
- **FR-7 — Absent: direct Write/Edit assessment.** Hook matchers and event parsing currently target Bash. Sensitive paths are recognized when accessed through modeled shell/source operations; that does not cover direct editor tools. Evidence: [hooks](../extensions/vscode/src/hooks.js), [event validation](../crates/distill-agents/src/lib.rs).
- **FR-8 — Partial: session outcomes.** A bounded editor-memory store correlates assessment revisions with completion/output. A separate persistent ledger stores bounded hashes and effect evidence, not command history. SQLite history, spool/replay, and file-change audit events do not exist. Evidence: [store](../extensions/vscode/src/store.js), [ledger](../crates/distill-core/src/session.rs), [trace delivery](../crates/distill-agents/src/trace.rs).
- **FR-9 — Partial: editor product.** Sessions, paged commands, search, expanded assessment/effect details, completion state, output controls, and clear actions exist. Feedback, export, status-bar summaries, durable history, changed-file views, and exact source-span highlighting remain work. Evidence: [extension](../extensions/vscode/src/extension.js), [manifest](../extensions/vscode/package.json).
- **FR-10 — Partial: configurable policy.** Severity actions, shared effect ratings, protected paths/packages, privacy, shell limits, session controls, and advisory/strict integration settings exist. User-owned pattern overrides and project-only escalation rules are not implemented as drafted. Evidence: [configuration](../config.example.toml), [validation](../crates/distill-core/src/lib.rs), [scoring](../crates/distill-rules/src/lib.rs).
- **FR-11 — Present equivalent: manual explanation CLI.** `distill analyze --command ...` or `--stdin`, with structured JSON or `--human`, supplies the manual assessment use case. A public graph-IR dump would be additional work. Evidence: [CLI](../crates/distill-cli/src/main.rs).

## Existing implementation to preserve

The current implementation already goes beyond the draft in several areas:

- **Known impact is separate from approval risk.** `Report.impact_severity` can be absent while the conservative `severity` remains HIGH. Coverage also distinguishes accounted, partial, opaque, and stopped analysis. Replacing these fields with a single S0–S4/UNKNOWN enum would lose useful information. See [Report](../crates/distill-core/src/lib.rs:416) and [scoring](../crates/distill-rules/src/lib.rs:11).
- **Approval and execution have explicit boundaries.** Codex command labels are authenticated; setup pins the launcher binary; the separate `distill run` gate binds command, policy, inspected dependencies, shell, and write grants. macOS and Linux containment backends already exist. These are separate from static certainty. See [setup](../crates/distill-cli/src/setup.rs), [gate](../crates/distill-cli/src/gate.rs), and [integrity](../crates/distill-core/src/integrity.rs).
- **Cross-command evidence exists.** Completed reads, downloads, and later transfers/execution can contribute hashed ledger evidence. Proposed commands do not automatically become proof of execution. See [session policy](../crates/distill-core/src/session.rs).
- **Recorder authentication exceeds file modes alone.** The Unix-socket broker checks peer UID, a token, workspace scope, and editor identity. Retain these checks if adding a service. See [broker](../extensions/vscode/src/broker.js) and [transport](../extensions/vscode/src/transport.js).
- **Shared semantic policy already exists.** Typed argument grammars, reviewed capabilities, source observations, SQL scope handling, and effect policy avoid assigning unrelated ratings to equivalent operations. Improve the current registries incrementally. They embed JSON and initialize some registries with `OnceLock`; they are not yet the draft's build-time TOML compiler.

## Changes required in the proposed design

### 1. Resolve the model/UNKNOWN contradiction (§§7, 11, 12, 20)

The draft says UNKNOWN always asks, models can only raise the static floor, and models reduce unknown-driven asks. All three cannot deliver the intended approval reduction under a single risk ordering.

Keep deterministic findings, coverage gaps, policy risk, and model suggestions separate. A first judge should propose additional effects/explanations while preserving the existing unknown decision floor. Model output must not set `static_accounted`. A lower model estimate does not establish what an imported package, plugin, or runtime loader will do. If model-assisted approval is later desired, define it as an explicit separate policy with measured false-allows and documented residual uncertainty; do not implicitly weaken the existing mode.

The agent-provided `description` is also untrusted. Agreement between a command and that description is not proof of user authorization. Intent mismatch may add a review signal; a claimed match must not lower risk.

### 2. Preserve actual host contracts (§§7, 12, 15)

The draft's main lifecycle centers on Claude Code. Distill already supports distinct Codex pre-use, permission-request, and completion contracts. Preserve host-specific translation and advertise capabilities rather than assuming one JSON response has identical semantics everywhere.

Do not infer shell or execution cwd from the hook process. Record whether the host supplied shell, options, and execution directory. Earlier hook diagnostics showed missing shell/options and execution-cwd fields. Any repair needs evidence at the adapter boundary; inference from `$SHELL` would not fix it.

Separate analysis latency, broker delivery, and human approval time. Today the analysis budget defaults to 900 ms, while the outer worker watchdog can wait 6 seconds and hook registration has separate timeouts. None of those settings proves an end-to-end p99 below one second.

### 3. Correct lifecycle and audit claims (§§7.3, 13, 14)

No matching completion is not evidence that the user rejected a command. The process may have been interrupted, the host may omit an event, or delivery may fail. Use an outcome such as `completion_missing` until explicit evidence establishes more. A completion can establish observed completion/exit status; it does not necessarily establish that a person approved execution.

Git status deltas describe changes observed between two times, not exclusive attribution to one command. Concurrent agent and user edits require attribution uncertainty. Preserve assessment revisions, source IDs, and explicit outcome provenance.

### 4. Keep privacy as a deliberate product choice (§§12.5, 13, 19)

The draft's default-on hosted judge, script transmission, 30-day command store, and spool would change Distill's current memory-only command-history contract. Make remote analysis and persistent command storage independently opt-in, with previewable payloads, bounded retention, purge/export controls, and a clear output-capture setting. Redaction is best effort, not proof that arbitrary command/script text contains no secrets.

Do not introduce disk spooling when persistent history is disabled. Retain the existing hashed security ledger as a distinct store with its own purpose and limits. Local socket access should keep peer checks and token authentication, not just `0600` permissions.

### 5. Tighten shortcuts that can understate risk (§§9, 10, 20, 25)

- `npm test` is not automatically a reversible workspace action: test scripts, lifecycle hooks, and dependencies can execute arbitrary operations. Inspect what is available and preserve unresolved behavior.
- A lockfile pins dependencies; it does not prove a package or `npx`/`uvx` execution safe.
- A directory named `node_modules`, `build`, or `dist` is not proof that its contents are disposable. Keep scope, symlink, protected-path, and uncertainty checks.
- A tracked file may contain uncommitted data. Broader Git context should annotate recoverability with provenance, not automatically lower destructive impact.
- Do not silently substitute defaults after invalid security configuration: a stronger user policy could be lost. Keep a conservative failure result and a visible diagnostic.
- Keep candidate execution out of the analyzer. Native dry runs should be commands the user chooses to run, not a general discovery mechanism inside assessment. GNU Make explicitly documents exceptions to `-n`; Distill already reads Makefiles without launching Make. [GNU Make manual](https://www.gnu.org/software/make/manual/make.html).

### 6. Make quality targets measurable before making them release claims (§§2, 16–18, 23)

The 85% static coverage, 99% S3+ recall, 5% false-ask rate, and sub-second p99 in the draft are targets. Current tests and historical microbenchmarks do not establish those population metrics. The checked-in October 17 latency artifact measures five warm in-process cases and fresh CLI invocations for `echo hello`; it excludes full hook/recorder/UI latency.

Define a versioned, independently labeled evaluation set, its command/context fixtures, severity policy, and split by project/session. Report sample sizes and misses, distinguish observed dangerous effects from conservative uncertainty, and count incomplete/host-metadata cases explicitly. A trace is evidence of effects on the exercised execution path, not a complete label for all possible behavior. Keep model-generated labels as proposals requiring review; avoid evaluating a model against its own labels.

Current CI runs Mac/Linux tests, smoke checks, extension checks, spec validation, and a 30-second fuzz job. It does not enforce the draft's statistical thresholds, p99 threshold, or 30-minute release fuzz requirement. Source: [checks workflow](../.github/workflows/checks.yml), [historical benchmark](latency-local.json).

## Incremental implementation roadmap

### P0 — Fix observed gaps and establish a baseline

Extend the current Node adapter with a typed invocation parser, using the existing Python CLI parser and shared argument grammars as patterns. Cover `.js`/`.mjs`/`.cjs`, bounded stdin/`-e` forms, `--input-type`, `--`, and script-argument boundaries. Recognize preloads, loaders, runtime configuration, environment files, and `NODE_OPTIONS` as additional behavior; never discard them while finding the main program. Node documents that `--require` and `--import` execute preload modules. [Node CLI](https://nodejs.org/api/cli.html).

Add bounded ESM import bindings and observations for known built-ins, followed by literal relative-import resolution with source snapshots, cycle detection, dependency/file/depth limits, and unresolved bare-package/native-addon boundaries. Do not recursively analyze all `node_modules` or auto-allow `@oai/artifact-tool` by package name. Trusted package summaries, if later added, need reviewed semantics plus version/content binding and explicit assumptions.

Add structured gap codes and per-stage timings. Build an explicit-consent transcript sampler that retains context fixtures and reports top programs/flags/gaps; extend `distill coverage` instead of replacing it. Separate host-metadata gaps from invocation, language, dependency, and budget gaps. `mine_specs.py` currently mines saved help syntax, not usage transcripts.

Exit evidence: the same literal-print fixture in `.js`, `.mjs`, and `.cjs` reaches source analysis; recognized module flags no longer hide the payload; preloads and unsupported options retain risk; root deletion remains CRITICAL; imported third-party behavior remains visibly unresolved. Publish a baseline with denominators rather than promising 85% coverage in advance.

### P1 — Add structured evidence while keeping the current engine

Introduce additive `CommandNode`, `Span`, and typed `CoverageGap` structures in `distill-core`; lower the existing tree-sitter walk into those structures. Keep the existing report fields during schema migration. Preserve per-source byte spans, program/argument boundaries, dependency snapshots, and edge provenance for combination rules.

Evaluate a second parser in offline differential tests first. Compare structures for the agreed supported dialect, not raw parser tree shapes. Measure additional false-unknowns and cold-start cost before enabling a second parser on every hook. Compile stable registries at build time only if fresh-process measurements justify it. Keep reviewed semantic roles separate from configurable severity.

Exit evidence: exact evidence spans survive nested scripts; quoted examples remain inert; parser differences never create an allow; replay produces the same static decision under fixed context and policy.

### P2 — Improve context, direct tools, and user feedback

Add provenance-bearing context adapters for explicit cloud/DB targets and bounded Git state; unknown production context must stay unknown. Introduce host-specific direct Write/Edit events with path/content effects and contract tests for sensitive policy, hook, credential, startup, and CI files. Hooks cannot be their own sole tamper-resistance boundary.

Add feedback and session export to the current extension, then optional persistence behind a store interface. Reuse the broker's authentication, IDs, paging, revisions, and redaction behavior. A SQLite writer/spool is justified only when durable history is enabled; bound queue/disk use, replay idempotently, version events, and preserve completion-missing states. Exported/feedback data should not change policy automatically.

Exit evidence: memory-only remains the default; no disk spool in that mode; repeated pre/post events are deduplicated without merging distinct calls; missing completion is never labeled rejection; user-owned policy cannot be weakened by workspace content.

### P3 — Evaluate an optional advisory judge

Add a small `Judge` boundary accepting the unresolved portion of the report, bounded script excerpts, explicit context, and the remaining deadline. Use a separate service/client so the static path remains local and independent. The current Node editor broker supplies useful transport/lifecycle patterns but should not acquire hosted-model calls inside its request handler.

Run the judge in shadow/advisory mode first: validate schema, attach model/prompt versions and proposed-effect provenance, retain static impact/policy floors, and exercise outage/malformed/injection/timeout cases. Budget connection, queueing, payload preparation, inference, and scoring together. Cache exact requests with policy/analyzer/model versions, cwd/shell/environment snapshot, and dependency content identities; a two-second TTL alone cannot validate a decision.

Exit evidence: no unavailable judge changes an existing static decision to allow; no model output relabels static coverage as complete; a measured latency/benefit report supports any wider rollout.

### P4 — Offline traces and classifier, after the evaluation loop exists

Use isolated disposable fixtures for trace-derived observed effects and reconcile them with independently reviewed labels. Keep traces out of the pre-execution path. Add a local classifier only when held-out evidence shows useful benefit, calibrated abstention, and acceptable dangerous false-allows; a fixed count such as 10,000 examples is not itself a readiness criterion.

Keep the six existing crates during these phases. Extract a judge/store service when a real ownership/dependency boundary appears; the draft's fourteen-crate layout is not a prerequisite for any of the first improvements.

## Verification performed for this review

- Read the draft and current implementation, configuration, test, CI, privacy, recorder, and containment boundaries.
- `cargo test --workspace --quiet`: **180 passed, 0 failed, 1 ignored**. The ignored containment test was not exercised in this review; these results do not establish runtime containment on every target platform.
- Extension `npm run check` and `npm test`: **syntax/assets passed; 51 tests passed**. The first restricted run failed process-inspection checks with `EPERM`; rerunning the existing suite with host process/socket access passed.
- Seven nonexecuting probes against the freshly built CLI: literal `node -e` and `.js` prints were LOW/accounted; dynamic package import, `--input-type=module`, `.mjs`, and `.cjs` were UNKNOWN/partial; a known Node root-deletion operation was CRITICAL/deny despite partial source coverage. These probes used explicit Bash analysis and synthetic files, so they do not remove the separate missing-shell-metadata limitation in real hooks.
- No detector, runtime policy, installed hook, or original design-document changes were made as part of this review.
