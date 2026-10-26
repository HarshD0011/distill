# Distill Chat Command Trace · 0.4.4

A VS Code sidebar for commands observed by Distill's Codex and Claude Code hooks. The chat picker uses Codex chat headings. Each compact row shows just the command and severity. Click a row for a plain-language reason, policy decision, status, and output. **More details** contains the full command, coverage, bounded modeled effects (including database row scope), directory, shell, and time; **Assessment history** contains distinct revisions and provenance. Output starts with five lines (up to 1,800 characters); **Read more** loads retained output. Search covers the selected chat's complete retained history, with 100 commands per page.

Use **Clear logs** beside the command count, the trash action in the view header, or **Distill: Clear Logs** in the Command Palette. It removes temporary command logs for the current window's workspace folders, resets filters and expanded output, and keeps recording new commands. Other workspace histories and analyzer configuration are preserved.

Chat headings come from Codex's local `session_index.jsonl` metadata and update after renames. Only titles for observed chats are retained in extension memory. No transcripts or state databases are read. If metadata is unavailable, the picker uses a friendly host/date label. Set **Distill: Codex Home** for a non-default home. This metadata format is a best-effort adapter; it is not a guaranteed hook API field. The raw session ID remains available inside an expanded command's assessment history.

## Install and connect

From the repository root:

```sh
cargo build -p distill-cli
cd extensions/vscode
npm run check
npm test
npm run package
```

No npm dependencies or build step are needed. In VS Code, use **Extensions: Install from VSIX…** and select `distill-trace-0.4.4.vsix`. The default resolver uses trusted user/system installation locations and does not search workspace PATH. Set **Distill: Binary Path** to the absolute path of this repository's `target/debug/distill`, or install the updated CLI with `cargo install --path crates/distill-cli --force` from the repository root. `distill doctor --json` reports product version, behavior policy version, output-capture status, and supported capabilities.

Run **Distill: Connect User Hooks** from the Command Palette, choose Codex or Claude Code, and open the Distill activity bar icon. Setup inspects user and ancestor project sources, including Codex inline TOML hooks, then installs user-owned definitions through `distill setup`. The isolated launcher pins the absolute executable path and its SHA-256. Setup preserves unrelated handlers, existing strict mode, and stored host policy; it leaves project files untouched and warns about remaining project handlers. Save or revert an unsaved user hook document before connecting. CLI defaults are strict unless an existing policy selects advisory mode. In Codex, use `/hooks` to review changed definitions. A window reload may be needed for an already running chat. Configuration alone does not verify live capture: run a harmless command and expand its row to check output.

**Upgrading from 0.3:** Install extension 0.4.4 alongside CLI 0.4.2, then fully quit and reopen VS Code once. The old TCP recorder survives window reloads and cannot accept the new Unix-socket events. The sidebar reports this mismatch explicitly. As with every application quit, temporary editor history clears. Commands missed while the recorder was incompatible are not backfilled.

**Upgrading from 0.4.1–0.4.3:** Reload the window to activate the updated sidebar. Existing Unix-socket recorders remain compatible and retain their temporary history. With an older running recorder, expanding a row identifies missing assessments and reveals retained uncertainty reasons; newly started recorders include the assessment state in compact rows immediately. CLI 0.4.1 / policy 7 authenticates its signed labels before correlating new completions. The extension does not reinterpret labels or rewrite old verdicts. CLI 0.4.2 / policy 8 supplies typed file/database/native-loading effects. Recorder version 6 retains up to 32 effects per report with bounded target/location text. Older running recorders continue to show ratings but cannot recover effect details they already discarded; the updated recorder starts on the next full VS Code restart, which clears temporary history.

For extension development, open this folder in VS Code and press F5 using **Run Distill Extension**.

## Temporary lifetime

History lives only in a separate local Node process's memory. That process follows VS Code's **main application process**, using `VSCODE_PID` and its process start identity. Window and extension-host reloads reconnect to the same broker and keep all chats and output, including commands completed during reload. Quitting VS Code, including an application crash, causes the broker to clear history, delete its endpoint, and exit on its next 500 ms lifetime check. A fresh VS Code application process starts with empty history, even when a previous chat is resumed.

Closing a window while the VS Code application remains running keeps history until the application quits. Windows share one broker per main application process; each sidebar filters its workspace roots. Adding workspace folders registers them without replacing the broker. **Distill: Clear Temporary Traces** or **Clear workspace traces** clears the current workspace's history. During an upgrade from 0.1.0, the extension keeps the existing broker and its history until the application quits; that older broker explicitly shows **Clear all traces**, since it cannot clear one workspace. Disabling or uninstalling the extension leaves the memory process until VS Code quits; clear traces first for immediate removal. A broker crash loses its memory; a reconnecting sidebar reports that restart.

This extension never writes commands, reports, or output to global/workspace storage, logs, databases, or webview storage. Transport uses a private Unix socket, peer-UID verification, and token authentication. Only a private endpoint file (authentication token, Unix socket path, process IDs, workspace roots) and a PID lock live in a user-specific temporary directory. They contain no history and are removed when the broker stops. If the broker itself is forcibly killed, stale metadata can remain; it contains no history. The CLI separately persists bounded hashed policy state in its session ledger, even when the extension is absent; editor history remains memory-only.

## Capture contract

- Chats are separated by `(host, session_id)`; commands join on `tool_use_id`. Approval retries do not duplicate entries. Missing chat IDs are rejected rather than merged into a shared chat.
- Equivalent consecutive assessments merge despite different report IDs or analysis timings. Changes to policy, evidence, coverage, blocking, or hook stage remain distinct. The updated UI also merges equivalent revisions from older running brokers without discarding their history. Previously recorded ratings retain their original assessment; analyzer fixes apply to new commands.
- `PreToolUse` records Distill's report, shell context, policy digest, and assessment revisions. **Distill policy** is the analyzer's decision, not a claim that the host approved a command. Proposed commands show **No completion observed** until a post hook arrives; explicit Distill denials show **blocked**. A missing completion cannot establish whether a command ran. A tool failure can also occur before a process starts.
- `PostToolUse` retains `tool_response` and displays stdout/stderr or host text. Nonzero exit codes show **failed**. A completion without an assessment shows **unassessed**; an assessment whose impact cannot be established shows **unknown**. Expanding a row shows retained unresolved behavior, and **More details** includes its behavior policy version. Known impact with partial coverage retains its rating and uncertainty reasons. Claude setup also installs `PostToolUseFailure` to retain tool-level errors.
- Output is limited to what the host provides. Host-side truncation, unsupported tool paths, missing hooks, commands before activation, and interactive input not represented by hooks cannot be recovered. The extension does not read transcripts or record unrelated terminal commands.
- Each hook/RPC event is limited to 32 MiB. The broker retains up to 10,000 commands, 64 MiB of accounted payload, 4 MiB of output per command, and 16 assessment revisions per command. Prior commands are not evicted. Capture-limit drops and output truncation are visible in the sidebar. Oversized events or delivery failures produce CLI diagnostics; output already truncated by the host cannot be recovered. Full retained output is fetched only when expanded.
- `[editor_trace] enabled = false` disables editor recording. `[privacy] capture_output = false` retains metadata and available status without command output. Output capture defaults to disabled. Opt in with `[privacy] capture_output = true`. The deprecated `[editor_trace] capture_output = false` remains a disable-only compatibility alias: either explicit false disables output. The reserved `[history]` settings do not create disk history.
- Setup checks `distill doctor --json` capabilities before changing hooks. Hook responses are emitted before optional trace delivery, which has a separate 100 ms delivery budget. A known editor PID is never routed to another editor; ambiguous routing is rejected.
- V1 supports trusted local folders in desktop VS Code on macOS/Linux. Remote SSH, containers, WSL, Windows, virtual workspaces, and browser VS Code are unsupported. CLI and editor must run as the same user with the same temporary directory. `DISTILL_TRACE_DIR` can set a shared private directory for custom launch environments.

## Verification

`make target` and its returned output form one trace row. The analyzer inspects literal Makefile recipes and prerequisites; recipe commands do not become independent execution rows unless the host issues separate tool calls. See the [Makefile analysis boundary](../../docs/static-analysis.md#makefiles).

`make test-extension` from the repository root builds the CLI and runs syntax checks and tests for chat titles/renames, compact rows, lazy details, chat isolation, ordering/retries, large output, privacy opt-outs, capture limits, pagination/search, hook migration, authentication, workspace registration, editor-quit cleanup, stalled recorders, and real Rust-hook-to-broker delivery. `python3 extensions/vscode/scripts/host_smoke.py` installs the VSIX in an isolated profile, performs an actual window reload, verifies the heading, compact snapshot, retained details/output, and quits that application to check cleanup. `cargo test --workspace` covers analyzer and host approval behavior.

The bridge follows the official [Codex hook input and tool-coverage contract](https://learn.chatgpt.com/docs/hooks). The webview follows VS Code's [message passing and content security guidance](https://code.visualstudio.com/api/extension-guides/webview). Application-process detection uses `VSCODE_PID` from [VS Code's startup source](https://github.com/microsoft/vscode/blob/main/src/vs/code/electron-main/main.ts); activation reports an error when that identity is unavailable.
