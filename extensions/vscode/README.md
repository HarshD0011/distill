# Distill Chat Command Trace · 0.5.12

A VS Code sidebar for commands observed by Distill's Codex and Claude Code hooks. The chat picker uses Codex chat headings. Each compact row shows just the command and severity. Click a row for a plain-language reason, policy decision, status, and output. **More details** contains the full command, coverage, bounded modeled effects (including database row scope), directory, shell, and time; **Assessment history** contains distinct revisions and provenance. Output starts with five lines (up to 1,800 characters); **Read more** loads retained output. Search covers the selected chat's complete retained history, with 100 commands per page.

Use **Clear logs** beside the command count, the trash action in the view header, or **Distill: Clear Logs** in the Command Palette. It removes temporary command logs for the current window's workspace folders, resets filters and expanded output, and keeps recording new commands. Other workspace histories and analyzer configuration are preserved.

Chat headings come from Codex's local `session_index.jsonl` metadata and update after renames. Only titles for observed chats are retained in extension memory. No transcripts or state databases are read. If metadata is unavailable, the picker uses a friendly host/date label. Set **Distill: Codex Home** for a non-default home. This metadata format is a best-effort adapter; it is not a guaranteed hook API field. The raw session ID remains available inside an expanded command's assessment history.

## Install and connect

1. Install Distill in VS Code and open a trusted local folder. For a downloaded `.vsix`, use **Extensions: Install from VSIX…**.
2. Choose **Connect Distill** in the single setup prompt. It names the services being connected: **Distill for Codex**, and **Distill for Claude Code** when Claude is installed. **Not Now** leaves your user hook files untouched; run **Distill: Connect User Hooks** when ready.
3. In Codex, open `/hooks` and trust the handlers labeled **Distill for Codex**. Restart or resume Claude Code to load its hooks.
4. Open the Distill activity bar icon and run a command in your agent chat.

**The CLI and optional local service are bundled and installed automatically. No Rust, Cargo, Python, terminal installation command, or separate download is required.** Model advice is optional and starts disabled; static command checks work without an API key.

Distill is one service connection. Agents require separate lifecycle handlers for checking commands, reviewing permissions, and recording results. Every Distill handler has the same service label, with one handler per event. Codex owns its trust screen and may prefix those labels with a number or require trust for each event; the extension cannot combine or bypass that review. Existing unnamed/duplicate Distill handlers in the user hook file are consolidated on reconnection, preserving strict mode and unrelated services.

Packages support local desktop VS Code 1.95+ on macOS and Linux (glibc), on arm64 and x64. Apple Silicon uses `distill-trace-0.5.12-darwin-arm64.vsix`. Use the package matching your operating system and architecture; Marketplace installations select the matching platform automatically when published.

Extension 0.5.8 bundles CLI 0.5.8 / behavior policy 10. Recognized safe commands retain their conditional SAFE impact when Codex omits execution-shell metadata; analysis remains partial with HIGH approval risk. Unknown commands and unsupported syntax request background advice when routing is enabled; completed fallback ratings are marked as model advice. The installer requires `conditional-shell-impact` and `hook-debug-log` so stale custom CLIs cannot silently retain the old behavior. Python interpreter flags and stdin, pytest/unittest discovery, uv wrappers and environment operations, and Cargo workspace build/test effects remain supported. Dependency, plugin, and shell-context uncertainty remains visible; recognizing a test command does not certify arbitrary test code as safe.

Optional `distill setup codex --debug-log /absolute/private/directory/hooks.jsonl` diagnostics record hook-entry metadata and verdicts before/after analysis, excluding command text and tool output. Automatic hook refresh preserves an existing debug-log path across reloads and upgrades. Omit `--debug-log` in a manual CLI setup to disable it. This logging starts at hook entry; diagnostics before host dispatch require host-side logging.

The installer verifies the bundled SHA-256 before running the CLI, installs it in private extension storage at a path containing its hash, and uses VS Code's own runtime for the pinned hook launcher. An upgrade installs a new binary alongside the old one, so existing hook pins remain valid until setup refreshes them. Approve changed hook definitions after an update. Reopening or reloading the same version reuses the installed binary and leaves unchanged hook files alone.

Fresh installations use advisory mode for noncritical verdicts. **CRITICAL commands always require a human decision**, including under automatic approval. On macOS the bundled CLI opens a Distill-owned AppKit popup in the foreground across Spaces with **Approve once** and **Deny**. It shows the exact command, working directory, and reason. Only the approval click releases that invocation; dismissal, timeout, unavailable UI, or changed inspected files/policy deny it. The popup is provided by Distill, not Codex. Other platforms currently retain the denial fallback. Pre-execution hook timeouts allow 150 seconds for the 120-second dialog and bounded analysis. The installer requires `native-critical-approval` and `foreground-critical-approval` so an older custom CLI cannot silently retain the old behavior. Existing strict modes, stored policies, global policies, unrelated handlers, and project files are preserved. Command output capture defaults off; existing privacy choices are retained.

**Distill: Connect User Hooks** repairs/retries setup through the same named approval prompt. Save or revert an unsaved hook document first. **Distill: Binary Path** is an optional absolute override for development or a separately managed CLI; custom CLIs must support the current hook protections, including `named-hook-services`. Workspace PATH lookup remains disabled. Remote, Windows, Alpine Linux, browser, and virtual workspaces are unsupported.

For maintainers, build a package from the repository root:

```sh
cargo build --locked -p distill-cli -p distill-service
cd extensions/vscode
npm ci
npm run check
npm test
npm run package
```

Packaging builds the release CLI and service for the packaging host and embeds both executables, their checksum manifest, and the first-run policy in a platform-specific VSIX. The pinned official `@vscode/vsce` packager validates Marketplace metadata and includes the README, changelog, and license. Packaging verifies the final archive's native checksums and platform target. Rust, Python, Node.js 22+, and npm are maintainer tools only; the installed extension has no npm runtime dependencies. To reuse a matching release build, run `python3 scripts/package.py --binary /absolute/path/distill`, with `distill-service` beside it. Development hosts can set `distill.binaryPath` and press F5 with **Run Distill Extension**.

Run `python3 scripts/package_smoke.py path/to/package.vsix` to check fresh CLI/service installation, one named setup approval for both hosts, actual safe-hook invocation, and unchanged reconnection from the packaged files. This test uses disposable directories and needs no editor UI. `python3 scripts/host_smoke.py` additionally checks a real VS Code reload and quit; choose **Connect Distill** in its disposable window when prompted.

## Publish to the VS Code Marketplace

The **extension packages** GitHub Actions workflow builds and tests `darwin-arm64`, `darwin-x64`, `linux-arm64`, and `linux-x64` packages on native runners. Run it manually or push an `extension-v0.5.12` tag, then download the VSIX artifacts. For a first release, create or verify ownership of the `distill` publisher in [Marketplace publisher management](https://marketplace.visualstudio.com/manage), then upload the matching packages there. The manifest publisher must match the account you control. Building a VSIX does not publish it or verify publisher ownership.

Publish all supported platform packages under the same extension ID and version so users get the correct bundled binaries automatically. Follow [VS Code's publishing guide](https://code.visualstudio.com/api/working-with-extensions/publishing-extension) for account setup and authenticated publishing; use its Trusted Publishing guidance when adding automated release publishing. The build workflow only produces artifacts.

**Upgrading from 0.3:** Install the current extension, approve the updated hooks, then fully quit and reopen VS Code once. The old TCP recorder survives window reloads and cannot accept the new Unix-socket events. The sidebar reports this mismatch explicitly. As with every application quit, temporary editor history clears. Commands missed while the recorder was incompatible are not backfilled.

**Upgrading from a Unix-socket recorder:** reload the window to load the new settings form and recorder version 8. The extension verifies the old recorder's PID and process identity, stops it, and starts the current code automatically. Temporary traces are discarded during this upgrade. Very old TCP recorders still require one full editor restart.

## History lifetime and privacy

Command history, output, feedback, title lookups and view caches stay in memory. Every extension activation receives a fresh recorder lease. A window reload clears the previous activation's traces; an extension-host crash or exit clears its unshared workspace traces and stops an unused recorder within its 500 ms lifetime check. Socket reconnects within the same activation preserve current-session traces. **Clear logs** also clears expanded details, output previews, filters and late replies.

The extension does not restore durable history or persist feedback. Its managed hook policy disables persistent history, the approval ledger and hook debug logging. Nonsecret connection preferences and installed, checksum-pinned executables remain on disk. Explicit session exports are user-owned files. Standalone CLI installations can still opt into their separate durable-history feature.

API keys entered in **LLM settings** are the deliberate exception: they are saved through VS Code's encrypted **SecretStorage**, never in `settings.json`, global/workspace state, endpoint metadata or webview storage. Keys are bound to the selected provider, endpoint and key-variable name. The form never reads a saved key back into its password field. **Remove saved key** deletes the selected connection's credential. The extension does not fall back to inherited environment credentials after a key is removed or the endpoint changes.

Transport uses a private Unix socket, peer-UID verification and token authentication. Temporary endpoint/lock files contain only rendezvous metadata, not command history or API keys; normal shutdown removes them. A forcibly killed recorder can leave metadata behind. The model service also follows its owning extension-host process, so its in-memory credentials and advice cache are discarded on host exit. Replacing a key restarts that service even when the rest of the policy is unchanged.

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

`make test-extension` from the repository root builds the CLI and runs syntax checks and tests for chat titles/renames, compact rows, lazy details, chat isolation, ordering/retries, large output, privacy opt-outs, capture limits, pagination/search, hook migration, authentication, workspace registration, editor-quit cleanup, stalled recorders, and real Rust-hook-to-broker delivery. `python3 extensions/vscode/scripts/host_smoke.py` installs the VSIX in an isolated profile, performs an actual window reload, checks that previous history clears, verifies fresh compact snapshots and details/output, and quits that application to check cleanup. `cargo test --workspace` covers analyzer and host approval behavior.

The bridge follows the official [Codex hook input and tool-coverage contract](https://learn.chatgpt.com/docs/hooks). The webview follows VS Code's [message passing and content security guidance](https://code.visualstudio.com/api/extension-guides/webview). Application-process detection uses `VSCODE_PID` from [VS Code's startup source](https://github.com/microsoft/vscode/blob/main/src/vs/code/electron-main/main.ts); activation reports an error when that identity is unavailable.

## Version 0.5: evidence, feedback and optional services

Direct Write/Edit/MultiEdit hooks and expanded Node/ESM/TypeScript effect observations accompany categorized coverage gaps, parsed command spans, context provenance and timings. Expanded rows distinguish optional model advice from static impact. Rating feedback never changes policy automatically; export retained sessions as JSON or Markdown.

The VSIX installs separately checksum-verified static CLI and service binaries. Model routing starts disabled; disabled means static analysis only, including no optional local classifier. The extension always keeps command history temporary.

Click **LLM settings** in the trace header, its gear icon, or run **Distill: Configure LLM Router**. In version **0.5.5** this opens a dedicated form:

1. Select a provider: OpenAI-compatible, Gemini, Claude, llama.cpp or vLLM.
2. Select a **Model** from the provider's dropdown, keep **Provider default**, or choose **Custom model…** to enter an exact model ID. Local servers use their exact served model name or alias.
3. Select the **API key variable** dropdown: provider default, a standard variable, no key, or a custom variable name.
4. Paste the actual key into the masked **API key** field. It is stored in SecretStorage; exporting variables or relaunching VS Code from a terminal is unnecessary.
5. Choose the endpoint if needed, enable routing, and click **Apply settings**. Leave the endpoint empty to use the provider preset.

Version **0.5.15** bundles CLI/service **0.5.13**. **API mode** was added in 0.5.12. Under **OpenAI / compatible API**, choose **OpenAI Decisions (GPT-6 Luna)** for typed severity classifications. This selects GPT-6 Luna and Severity only, and disables reasoning-effort and output-token controls because the Decisions endpoint does not accept them. Leave Endpoint empty to use `https://api.openai.com/v1/decisions`, or provide an explicitly chosen compatible proxy. Switching back restores the chat model, endpoint, reasoning effort, reply format and token-budget draft. The existing provider API remains the default; this setting never changes the active route until Apply settings.

**Critical descriptions** is an optional checkbox in the LLM form and native VS Code settings, off by default. With routing enabled, it uses **GPT-6 Luna** to explain a critical shell command in two short sentences in the macOS confirmation dialog. It uses the selected OpenAI-compatible connection and saved key; a Decisions route uses the same server with the sibling `/chat/completions` path for this explanation. The verdict route and selected verdict model stay unchanged. Other providers do not support this option.

Descriptions are a separate text-generation request with normal input/output charges, even when Decisions verdicts have no output charge. Reasoning is off and output is capped at 256 tokens. Only the redacted command, directory, and static reason are shared; script source is not included. A matching explanation can be reused in memory for 60 seconds. The request has a maximum 1.8-second provider budget; failure or unavailable service still shows the static warning. Headless `--no-prompt` checks and noncritical commands make no description request.

The macOS popup separates the explanation, exact command, directory, and static findings in selectable scrollable areas. Escape selects **Block command** and there is no implicit approval shortcut. **Allow once** requires an explicit button action; a model response cannot grant consent. The full command remains visible with control characters escaped. Source and policy bindings are checked again after the human decision. Dialog data travels over stdin instead of command arguments.

For normal OpenAI-compatible requests, **Reasoning effort → None (disable reasoning)** explicitly sends `reasoning_effort: "none"`. Provider default omits the parameter and can still enable reasoning. Model support varies; invalid requests fail without switching models. Decisions and Chat Completions have distinct preset endpoints, so a key saved for one is not silently reused for the other: paste it into the selected connection when needed.

Decisions answers are matched to commands by their question names and validated as one complete batch. Refusals, missing or duplicate answers, invalid labels and malformed probability data keep the review unavailable; they do not trigger a chat fallback. Confidence and probabilities are retained as advisory metadata, never permission to run a command. Static findings, coverage gaps, source-sharing opt-in and approval requirements remain authoritative. See the [official Decisions guide](https://developers.openai.com/api/docs/guides/decisions). The implementation is tested with local HTTP fixtures; no latency, cost or classification-quality improvement is claimed without a representative live evaluation.

Version 0.5.14 also protects shared home roots and complete user-home directories in static Python, shell and Node deletion analysis. This fixes the accounted `shutil.rmtree("/home")` case without requiring model advice, while bounded project deletions retain their effect policy.

Version 0.5.13 shares an explicit effect rubric across Decisions (`decisions-2`) and text severity reviews (`severity-3`). It distinguishes printed text from executed code, secret content from ordinary reads, and a bounded download from downloaded code execution. Background advice caches are bound to the prompt revision. Model advice still cannot clear static uncertainty or approve a command.

From the repository root, compare frozen command expectations against the configured running service without executing candidates:

```sh
python3 scripts/evaluate_reviews.py \
  --corpus corpus/review-prompt-regression.jsonl \
  --corpus corpus/review-prompt-challenge.jsonl \
  --expect-prompt decisions-2 \
  --output /tmp/distill-review-evaluation.json
```

This performs two uncached live reviews per command using the service's internal credentials. Labels are fixed before requests; exact and accepted-label agreement are reported separately. A small synthetic corpus is a regression check, not a general accuracy guarantee. Direct model results are separate from the installed hook, which normally requests advice only for unresolved analysis.

The model dropdown uses bundled suggestions and makes no provider API calls when opened. The IDs must be available to your endpoint and account. Existing custom model IDs remain selectable, and switching providers restores each provider's unsaved model and endpoint draft. Choosing a model only changes the form until you apply it; there is no automatic model fallback.

An empty password field keeps an existing saved key. **Remove saved key** removes it. The advanced VS Code settings button exposes only nonsecret preferences; it has no plaintext API-key setting. Workspace settings cannot enable routing or choose an endpoint.

OpenAI-compatible defaults to `gpt-6-luna` with a 512-token output cap. Gemini defaults to `gemini-3.1-flash-lite` with `GEMINI_API_KEY`; Claude defaults to `claude-haiku-5-5` with `ANTHROPIC_API_KEY`. Gemini endpoint overrides are API base URLs; other providers use full request URLs. llama.cpp and vLLM use loopback ports 8080 and 8000 and default to keyless access. Editor starts read saved keys only from SecretStorage and transfer them over a route-bound one-shot stdin pipe. There is no ambient environment-key fallback after removal or an endpoint change. CLI-only service starts can still read the explicitly selected variable.

Settings apply to managed hook policies and restart the optional model service when needed. Requests use exactly the selected provider and model, with no cloud fallback or upgrade. Missing credentials, invalid/truncated responses and timeouts preserve static analysis. See the [implementation and testing guide](../../docs/v05-implementation.md).

When missing host shell metadata is the only analysis gap, Distill skips model routing and shows the skipped reason in command details. It retains the metadata warning and HIGH approval risk. A model cannot recover facts the execution host omitted; refreshing cached hooks does not supply them. Additional unresolved code or dependency gaps still use the enabled model route.

Background model fallback returns the static verdict promptly and updates temporary command rows after advice completes. The Model timeout defaults to 5000 ms and is independent of the hook wait (at most 40 ms for local acknowledgement). Known static findings and unresolved coverage remain visible; late advice does not rewrite a past approval. Identical pending requests share work, completed advice is cached for 60 seconds, and failures have a five-second cooldown. A retry can consume cached advice and tighten its decision. Unsupported Python remains unsupported statically even when model advice supplies a display rating.

Independent model reviews use worker threads with a fixed ceiling of **five simultaneous provider requests per service**. With Batch window set to zero, each distinct review is sent immediately on its own worker. Synchronous RPC calls and optional batches share the same provider-request cap. When capacity is full, additional background reviews receive `busy` and keep the static review requirement; there is no unbounded queue or automatic provider retry. Duplicates share existing work. Parallelism can shorten a burst of independent reviews, but does not reduce API call count or speed up an agent that submits only after each prior result. Provider rate limits can still return HTTP 429. See the [five-request concurrency tests and measurements](../../docs/parallel-reviews-20261109.md).

Extension 0.5.6 expands the OpenAI Model dropdown to 21 choices, including GPT-5.4 Mini/Nano, GPT-5 Mini/Nano, GPT-5.6 Luna/Terra/Sol, GPT-5.5/5.4/5.2/5.1/5, GPT-6 variants and GPT-4 alternatives. Deprecated entries show their scheduled retirement dates from the official OpenAI catalog. Shut-down models and Responses-only Pro models are omitted from the suggestions. Custom model IDs remain available for compatible endpoints. This bundled list does not query account availability, change the saved model, or make API calls when opened. Native CLI/service and hook pins remain version 0.5.5.

Extension 0.5.7 also makes **Settings → Extensions → Distill → Llm: Model** a native VS Code dropdown. It contains the shared OpenAI, Gemini, and Claude catalog, a provider-default choice, and **Custom model…**. For a custom endpoint or local server, enter the exact ID in **Llm: Custom Model** and choose **Custom model…**. The dedicated **Distill: Configure LLM Router** form continues to show provider-specific choices and secure key entry. Both interfaces resolve to the same exact model ID; existing manually entered IDs remain supported. After editing the catalog, run `npm run sync-models` to update the declarative VS Code contribution; `npm run check` rejects catalog/schema drift.

Extension 0.5.8 removes model-name-specific request tuning. Model IDs are passed through unchanged; provider adapters only select wire formats, authentication, and endpoint conventions. **Reasoning effort** is a dropdown in both Settings and the LLM form. **Provider default** omits the parameter for every model. An explicit value is sent unchanged to OpenAI-compatible APIs (including llama.cpp/vLLM); support is determined by the endpoint/model. Gemini and Claude use provider defaults. Unsupported options return an error with no retry, parameter downgrade, or fallback model. Model changes preserve an explicit effort. Effort changes invalidate local model cache entries and restart the managed service. For a latency comparison, select the same explicit effort, token limit, timeout, commands, and context for both models; provider defaults can differ. Internal routing/policy hashes stay local and do not change the model prompt.

The installer requires the `model-agnostic-router` native capability; a stale custom CLI is rejected rather than silently retaining earlier model-specific behavior. The optional service explicitly disables HTTP retries as well as redirects.


Severity reviews and batching

The editor defaults to **Severity only**, requesting exactly one of `safe`, `low`, `medium`, `high`, `critical` per item, separated by `;`. **Structured effects** preserves the legacy JSON protocol. Enable **Include inspected script excerpts** to review the actual snapshot of `node scripts/test.js` or another unresolved inspected program. Source sharing remains an explicit setting; without available source a review cannot establish that the script is safe. Up to 8 KiB of hash-verified, redacted script source is shared per command. Source edits invalidate cached advice. A low model rating never clears static uncertainty or authorizes execution.

**Batch window** (`distill.llm.batchWindowMs`) accepts 0–500 ms and requires severity reviews. Zero sends immediately; a nonzero window starts at the first arrival and groups overlapping requests, up to 16 items and a 64 KiB batch. The window counts against the model timeout. Independent calls can already run concurrently, so saving requests does not imply lower latency. Sequential commands awaiting each prior verdict cannot be batched. Local tests favored leaving the default at zero; see [measurements and security choices](../../docs/command-review-security-20261109.md).

Saved keys persist in VS Code SecretStorage across normal reloads. The extension, launcher and service need transient plaintext in memory during handoff; this is not a service-only security boundary against a compromised editor or same-user malware. Workspace settings cannot replace the key-receiving binary. Keys are absent from service-start arguments/environments, policy files and public RPC results; Rust-owned credential buffers are zeroized on drop. The service has no credential-read RPC, and HTTPS redirects are disabled. For strict service-only custody, use a separate service identity or remote broker as described in the security choices above.

Extension 0.5.9 includes the fragmented service-IPC fix and a 250 ms bounded recorder acknowledgement deadline. Expanded command rows keep the analysis-limit list under **More details**, while model connection failures expose their actual local error. File-review results disclose whether source sharing was disabled, files were omitted by the 8 KiB limit, or source was unavailable. Severity requests keep the static graph in local provenance and send a bounded list of gap descriptions; the command and available inspected source remain in the model input. A window reload activates a newly installed extension and its verified native binaries.

Extension 0.5.10 fixes a response/snapshot race in expanded command rows. Pending detail requests are bound to their command version, so a model result arriving before the next snapshot cannot leave a row permanently loading. Native CLI/service remain 0.5.9.
