# Distill 0.5 implementation and testing guide

The CLI, optional service and extension use version 0.5.8 with background model fallback and model-agnostic request options; the extension exposes the expanded model dropdown in both its provider-specific form and VS Code’s native Settings editor. Built-in semantic policy is version 10. The static hook binary does not link SQLite or HTTP. The platform VSIX also contains a separately verified `distill-service` binary for explicitly enabled history and model advice.

## Static analysis and direct tools

Python source has bounded value and effect analysis for common agent test snippets, across `-c`, source files and literal stdin/heredocs. It accounts for primitive/container operations, JSON/TOML decoding, selected math/statistics/regex/time calls, comprehensions, branches, loops and simple positional functions. Approved standard-library imports are conditional on library identity; visible local module/package shadows are inspected and retain a gap. Arbitrary third-party imports are not trusted by name.

Explicit `open` and pathlib reads, writes and deletes use the shared target/effect policy. File writes remain MEDIUM or higher even when source coverage is accounted; secret reads and protected writes retain their policy floors. Literal subprocess argv and literal `shell=True` commands are recursively analyzed without execution. Mutable argv aliases are invalidated, and unsupported descriptors, stdin payloads, callbacks, environment/executable overrides and computed commands retain uncertainty. `py_compile`, explicit-target `compileall` and `json.tool` have separate CLI models; compiling source never treats its body as executed code.

This is conditional coverage for the supported Python subset, not a promise to decide every Python program. Dynamic execution/imports, arbitrary classes and descriptors, decorators, unresolved callbacks and framework/plugin discovery still require review. Node/deadline/size/call-depth limits are shared and bounded. Missing host shell metadata remains a separate gap. Accounted Python commands skip the optional judge even when routing is enabled; source support does not supply missing host metadata.

The Node option grammar separates interpreter options from application arguments, including options following an eval. `.js`, `.mjs`, `.cjs`, literal evals, bounded stdin and CommonJS/ESM input modes reach source inspection. Preloads, loaders, interactive mode, configuration and environment files retain additional execution risk. Unknown flags and repeated evals are not guessed safe.

ESM default, namespace and named built-in imports contribute conditional effects. Literal relative JS imports are read with dependency snapshots, a maximum of 32 imported files and depth bounded by the configured limit or 8. Cycles, bare packages, native modules, custom loaders and unresolved specifiers retain gaps. Known destructive operations remain visible through local imports and preloads. TypeScript files and simple `ts-node`/`tsx` file invocations contribute source observations while retaining transformation/runner uncertainty. There is no automatic approval by package name, lockfile, test name, or directory name.

Reports now include typed `coverage_gaps`, a bounded root-shell `graph` with byte spans and parent IDs, `context_evidence`, per-stage millisecond timings, and optional model advice. The graph describes parsed syntax, not a proof of complete behavior. Git HEAD/default-ref files are snapshot-bound observations; selected explicit cloud/DB targets and analyzer-environment names are provenance-labeled hints, not verified production identity or a complete execution environment. Missing host shell metadata continues to require review.

Installed hooks match `Bash`, `Write`, `Edit` and `MultiEdit`. Direct file operations use path effects without executing or interpreting proposed contents as shell code. Agent-hook/security-policy edits receive critical tampering findings and are denied; the shell approval dialog cannot bind approval to editor content. These adapters cannot protect their own configuration against an actor that fully controls the account. Other host tool names require a real schema adapter; they are not silently aliased to Write.

User `[[override]]` regex rules apply to the whole command. Downward adjustments do not discharge incomplete analysis or critical floors. A workspace may define `.distill-policy.toml` with `[[raise]]` rules using `pattern`, `severity`, and optional `note`; these rules only increase approval risk. Invalid workspace rules retain review, and inspected policy bytes participate in execution bindings.

## Extension

Expanded command details show categorized gaps, source effect locations, parsed command structure, context provenance, timings and optional model advice. Known impact remains distinct from approval risk. “Rating too high/low” records feedback without changing policy. Feedback is temporary by default and can be exported with the session.

Use **Distill: Export Session** or the sidebar button for redacted JSON/Markdown. Exports describe retained observations and output previews; a size limit is disclosed when reached. No completion is labeled rejection just because an event is missing. A status item opens the trace and shows observed command counts.

Recorder version 8 keeps structured evidence only for the current extension activation. Window reloads discard prior history and view caches. Verified older Unix recorders are replaced automatically. No durable events or feedback are restored into the editor. Very old TCP recorders still need one full editor restart.

## Standalone CLI durable history

The VS Code extension enforces memory-only history for its managed hooks: `configure-router --memory-only` disables `service.history_enabled`, reserved `history.enabled` and the approval ledger. It also removes debug-log flags from managed hooks. Saved connection preferences and executable installations are retained; entered keys are remembered only through encrypted SecretStorage. Explicit exports and separately configured standalone CLI archives are user-owned files.

The standalone CLI still supports separately configured durable history. Use an explicit policy outside the editor-managed `hook-policy-v3-*.toml` files. The old reserved `history.enabled` flag does not opt into persistence; `[service] history_enabled = true` is required. CLI commands:

```sh
distill service start --config /absolute/user-policy.toml
distill service status --config /absolute/user-policy.toml
distill query --config /absolute/user-policy.toml --root /absolute/workspace
distill export --config /absolute/user-policy.toml --root /absolute/workspace --format json
distill stats --config /absolute/user-policy.toml
distill service stop --config /absolute/user-policy.toml
```

The service uses a private Unix socket, peer-UID verification and a token. SQLite WAL has a versioned schema, single connection behind a mutex, event-ID deduplication, retention, event and byte limits. When enabled history cannot reach the service, the hook writes a bounded private per-event spool; startup replays accepted events idempotently. No spool or history DB is created when persistence is disabled. Recorder and persistence errors do not replace the static assessment with an allow.

The default state directory is `~/.config/distill/service`. Custom directories must be private, absolute and short enough for Unix socket paths. Output capture remains independently off unless `[privacy] capture_output = true`. Redaction is best effort. Purging requires an explicit root or `--all`:

```sh
distill purge --config /absolute/user-policy.toml --root /absolute/workspace
```

The service keeps the configuration loaded at startup. Stop and start it after policy/model changes. Use an explicit `--config` when managing a non-Codex or custom service policy. Without that flag, the CLI prefers the installed Codex user policy, then global configuration.

## Optional model advice

Run **Distill: Configure LLM Router** or click **LLM settings** to open the dedicated settings form. Select the provider and key-variable dropdown, paste the key into the masked field, and apply. Keys are stored through VS Code SecretStorage, bound to the provider/endpoint/variable; the password field is cleared after submission and saved keys are never returned to the webview. Remove a key with **Remove saved key**. Nonsecret `distill.llm.*` preferences remain user/machine settings. The router defaults to disabled. Disabled assessments use static analysis only: they do not contact the model service or run the optional local classifier.

In 0.5.1 the trace header also has an **LLM settings** button, a routing-mode label and an extension version label. A gear icon in the trace view title opens the same settings. These controls remain accessible when the recorder is disconnected. Run **Developer: Reload Window** after installing 0.5.5; prior temporary history clears and the recorder code updates automatically.

When enabled, `openai_compatible` defaults to `gpt-6-luna`, OpenAI's efficient model for focused workloads. Set `model` to any exact compatible model ID you choose. There are no fallback models, automatic upgrades or model-request retries. Output defaults to a 512-token cap (configurable from 64 to 2048). [Official OpenAI model documentation](https://developers.openai.com/api/docs/models/gpt-6-luna).

Version 0.5.2 adds native **Gemini** and **Claude** providers to the same dropdown:

- `gemini` defaults to `gemini-3.1-flash-lite` and the `GEMINI_API_KEY` environment variable. It uses Google's `generateContent` API with JSON-schema output. The endpoint setting is an API **base URL**, defaulting to `https://generativelanguage.googleapis.com/v1beta`; the configured model is added to the request path. [Gemini model and structured-output examples](https://ai.google.dev/gemini-api/docs/models/gemini-3.1-flash-lite?authuser=1), [Gemini API authentication](https://ai.google.dev/api?authuser=5).
- `claude` defaults to `claude-haiku-5-5` and `ANTHROPIC_API_KEY`. It uses `https://api.anthropic.com/v1/messages`, API-version headers, and `output_config.format` for structured output. Reasoning settings use provider defaults for every Claude model; explicit model IDs are retained. [Claude models](https://platform.claude.com/docs/en/models/overview), [Messages authentication](https://platform.claude.com/docs/en/api/overview), [structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs).

Choose the provider, set any exact model override, and paste the key into the masked API-key field in the dedicated form. The separate **API Key Env** dropdown selects the credential slot/CLI-only environment variable name; use **custom** and `distill.llm.customApiKeyEnv` for another name. Missing native-provider credentials, API failures, refusals, incomplete/truncated outputs and invalid schemas preserve the static verdict. Keys are sent in provider-specific headers and never added to URLs or saved settings. Requests do not switch providers or models after a failure.

Choose `llama_cpp` for `http://127.0.0.1:8080/v1/chat/completions`, or `vllm` for port 8000. Both local presets require the server's exact served model name in `distill.llm.model`; they never substitute a cloud model. `distill.llm.endpoint` overrides the complete URL. llama.cpp uses its schema-constrained JSON-object format; vLLM and OpenAI-compatible endpoints use the JSON-schema response format. Output is independently validated for every provider. See the [llama.cpp server documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md) and [vLLM structured outputs](https://docs.vllm.ai/en/latest/features/structured_outputs/).

Routing settings are user/machine scoped; workspace settings cannot choose an endpoint or enable transmission. Saving valid settings applies them to the versioned host policies and starts/restarts the optional service when needed. Disabling routing stops the editor-managed service and clears its advice cache. Invalid settings disable the route instead of continuing to use an old endpoint. The status item's tooltip shows static-only mode or the configured model.

Saved credentials come from SecretStorage and are passed in a bounded, route-bound one-shot stdin pipe, never service-start environments, command arguments, policy JSON or settings. Editor starts do not fall back to ambient environment keys; CLI-only starts may read the selected variable and forward it over a pipe. The extension and CLI temporarily handle plaintext during handoff, so this does not claim isolation against a compromised same-user editor. The `auto` key-variable choice uses the selected provider preset; local presets default to keyless access. Replacing/removing a key restarts the service even with an unchanged policy. The editor-managed service exits when its extension-host owner exits, discarding in-memory credentials and advice cache. Endpoints require HTTPS, except loopback HTTP; redirects and embedded URL credentials are rejected.

CLI-only users can configure `[judge] enabled`, `provider`, `endpoint`, `model`, `api_key_env`, `max_output_tokens` and `background_deadline_ms` directly in their user policy. Omitted fields use the selected provider's defaults. When changing a fully serialized policy, update or remove the previous provider's explicit endpoint/model/key-variable values as well. The extension manages this section from its settings when active. Its disabled default takes precedence over manual judge edits. Background work defaults to 5000 ms (`background_deadline_ms`, allowed 100–15000 ms). The legacy synchronous `judge` RPC retains its 20–800 ms budget; hooks use `judge_enqueue` and wait at most 40 ms for local acknowledgement.

The judge sees bounded redacted command/IR/effect/context data. Script excerpts require the independent `send_script_contents` opt-in and matching dependency snapshots; at most 8 KiB is supplied. No candidate program is executed. The judge is untrusted: schema failures, unsupported proposals, outages and deadlines preserve static policy. Proposals may raise approval risk; they cannot lower deterministic findings, erase uncertainty, mark static coverage complete, establish user authorization, or turn UNKNOWN into an automatic allow. When static impact is UNKNOWN, completed advice supplies a fallback display rating labeled as model advice. Known static impact wins. Coverage, uncertainty, and the recorded decision remain intact; exact-context retries reuse advice and can tighten the next decision.

The client queues redacted command/IR/context through authenticated IPC. The service admits at most four background jobs and retains at most 256 entries in memory. Duplicate pending requests share a job; successful advice lasts 60 seconds, failures have a five-second per-request and provider cooldown. Keys bind command, context, policy, analyzer version, dependency snapshots, and model configuration. Results are polled in batches of at most 16 by the temporary broker through the native `advice` command, preserving Unix peer validation. Service restart discards results. Clearing history never restores entries from late results. These bounds are not an end-to-end p99 guarantee.

Routing skips assessments whose only unresolved facts are missing host execution metadata. No service IPC, HTTP request or model-cache lookup occurs on that path; advice is labeled `skipped` with the reason. The shell warning, partial coverage, impact rating and review requirement are preserved. A missing shell together with an unresolved program, import, source file, target or other nonmetadata gap still follows normal model routing. Fixing omitted shell/workdir fields requires the host integration to forward them; the extension and launcher do not infer them from their own environment. Reloading a cached hook can activate newer analyzer code but cannot add absent event fields.

## Offline evaluation and local classifier

The repository contains an independently authored seed fixture set, not a representative accuracy benchmark. Evaluation never executes candidate commands and forces optional services/ledger off:

```sh
python3 scripts/evaluate_corpus.py corpus/reviewed-seed.jsonl --output /tmp/distill-evaluation.json --check
python3 scripts/parser_differential.py corpus/reviewed-seed.jsonl
python3 -m unittest discover -s scripts -p test_design_tools.py
```

The parser differential compares Bash syntax-only acceptance under an empty environment with the current graph's parser status. It is an offline second opinion, not structural equivalence, runtime tracing, or an extra hook subprocess.

`mine_transcripts.py` accepts only explicitly named local files plus `--allow-transcript-read`. It extracts literal command candidates, redacts best effort, hashes source grouping identifiers and writes private JSONL with `reviewed=false`; mining does not supply gold labels or a verified execution context. Populate context fixtures and independent labels before including samples in accuracy metrics. The evaluator reports denominators, critical misses, dangerous false allows, unexpected asks and static coverage. `--check` enforces the reviewed fixture safety gates, not the design draft's population-level targets.

`train_classifier.py` requires reviewed, disjoint train/test groups and rejects exact-command leakage. It exports a transparent JSON feature-table adviser with support thresholds and abstention; this implementation deliberately uses reviewable JSON rather than adding an ONNX runtime. Features are program names, gap categories and effect kinds. Bucket frequencies are empirical label shares, not a calibration guarantee for new projects. A private model may be selected with `service.classifier_path`; default minimum support is 20 and minimum share 0.99. Accepted local advice can avoid an LLM call but still cannot authorize an unresolved command. The small seed set is not a useful production-trained model; no model is enabled or shipped as validated general protection.

`trace_harness.py` is an explicit offline tool requiring `--execute-isolated` and a preinstalled image pinned by SHA-256. It refuses image pulls and host mounts, disables networking, drops capabilities, uses an unprivileged user, read-only root, bounded tmpfs/resources and cleanup deadlines. The image must already contain strace and the required shell utilities. Only independently reviewed records with `trace_allowed=true` run. Results distinguish attempted from successful syscalls and remain unreviewed labels for reconciliation. Container tracing availability and one exercised path do not prove all possible effects.

Real provider latency/quality, representative corpus accuracy, Linux containment and pinned-image trace collection require their respective environments and data. Local mock-provider, replay, parser, source, extension and privacy regressions exercise the implemented boundaries without making those broader claims.

The native Model contribution is an enum generated from `src/models.js`, with friendly labels for all hosted providers and a Custom model choice. Native custom selection stores a dedicated `llm.customModel` value. Router reads use global values only and resolve the marker before generating native policy. Form saves serialize unlisted IDs into that native representation; existing raw model IDs in user settings continue to resolve unchanged. The syntax/assets check also checks the native dropdown against the shared catalog.

## Model-independent requests (0.5.8)

The service treats model IDs as opaque values. There are no model-name branches for reasoning, sampling, tokens, timeouts, retries, or fallback. Provider defaults only choose a model when no model was selected. The same prompt and proposal validator apply to every model. Provider adapters retain the API-specific endpoint/authentication/schema/token field names. Local policy and model-routing digests are authenticated and bound in cache keys, then omitted from the remote prompt so a model/effort change does not inject a different opaque hash into otherwise identical input.

`judge.reasoning_effort` is optional and omitted by default. An explicit `none`, `minimal`, `low`, `medium`, `high`, `xhigh` or `max` is passed to the OpenAI-compatible API unchanged, including local adapters. Invalid values are rejected; Gemini and Claude require the field to be omitted. The native Settings and masked form expose `distill.llm.reasoningEffort`, defaulting to `provider_default`. Workspace overrides are ignored. No model catalog or name inference changes this option. Endpoint errors retain static review requirements without another model request. Effort is part of model/config digests, so changes invalidate cached advice.

Request-parity tests cover known model IDs and unlisted aliases across all five adapters. Real local HTTP/IPC tests capture complete requests for GPT-6 Luna, GPT-5.6 Luna and an unlisted alias at matching effort: bodies differ only in model ID, the same delayed endpoint yields validated advice, repeats hit the local cache, and HTTP 400 produces one request without fallback. These establish code/request parity, not an intrinsic model latency ranking. External latency also includes network, provider scheduling, inference and output length.


Severity-only replies, opt-in microbatching, credential-pipe hardening and measured tradeoffs are documented in [the command-review security report](command-review-security-20261109.md).
