# Design implementation work log

User-authorized scope: the entire incremental roadmap in `design-review-20261107.md`, including updates to the CLI/hook and VS Code extension, installation of the updated build, then user-led live testing. Preserve existing uncommitted work. Persistent command history and model requests are independently opt-in.

## Implementation sequence

- [x] P0: typed Node invocations, `.mjs`/`.cjs`, module/stdin forms, startup risks, bounded import observations/resolution, regression fixtures.
- [x] P1: additive command graph/spans, typed coverage gaps, per-stage timings, offline parser differential checks, labeled baseline and usage mining.
- [x] P2: provenance-bearing context, direct Write/Edit adapters, feedback/export, independently optional SQLite history/spool with bounded replay and accurate lifecycle states.
- [x] P3: optional judge service/client, validated effect proposals, deadline/caching/provenance, conservative failure behavior, opt-in payload controls.
- [x] P4: isolated offline trace harness, label reconciliation and classifier training/evaluation infrastructure with abstention; no claimed accuracy without held-out evidence.
- [x] Verification: Rust, extension, hook contracts, smoke fixtures, packaging, install VSIX and refresh hook binary pins while preserving user policy/debug logging.

## Constraints

- No candidate code executes during static analysis.
- Known destructive effects and unresolved execution retain their policy floors.
- Model suggestions do not mark static coverage complete or supply user authorization.
- Missing completion is not rejection; proposed effects are not observed execution.
- Default command history remains memory-only; output capture remains opt-in.
- User selected an OpenAI-compatible endpoint for the optional judge. It remains disabled until configured.
- Extension router settings default to GPT-6 Luna with a 512-token output cap when enabled, permit exact custom model IDs, and provide llama.cpp/vLLM presets without cloud fallback. Disabled routing uses static analysis only, including no local classifier.

## Verification and upgrade repair

Current source checks: 196 Rust tests passed (one host containment test is excluded from the default run and passed separately during the implementation); 59 extension tests passed; Clippy with warnings denied passed. Smoke fixtures passed: 155 language analyses and 155 label checks, 65 workflow checks, and 40 policy cases with no wrong impacts or unsafe allows. The independent seed corpus has 12 reviewed cases; these are regression evidence rather than population accuracy estimates.

Model tests use loopback HTTP mocks and real local IPC. They check exact model routing, output caps, all three provider formats, keyless requests, conservative proposal handling, and static-only behavior with the router disabled. Real external-provider quality/latency and actual llama.cpp/vLLM inference remain for live testing. Offline trace infrastructure has not collected a pinned-image real execution corpus, and the seed classifier abstains on all held-out cases; no validated general classifier is shipped.

An upgrade exposed that active hosts cache hook commands: rewriting the old policy with new fields broke the cached executable. The legacy policy was repaired, and setup now migrates settings into `hook-policy-v2-<host>.toml` without modifying the old file. Migration and idempotence regressions cover that compatibility boundary. Worker failure messages now include exit status and output size without command text or environment data.

Installed `distill-trace-0.5.0-darwin-arm64.vsix` and separately verified both native executables. The installed main executable SHA-256 is `55911d2295581b4c3d35333d92b1fc1c191e9a6375d950f6687df5ab4059e7ab`. Codex has one managed handler for each of PreToolUse, PermissionRequest and PostToolUse, matching Bash/Write/Edit/MultiEdit; debug logging and advisory mode are preserved. The versioned user policy has model routing and durable history off, configured model `gpt-6-luna`, a 512-token cap, and output capture off. The optional service is stopped. The legacy executable still validates its preserved policy.

Installed-binary probes classify a built-in Node ESM file read as LOW conditional impact and an unresolved package import as UNKNOWN; neither invokes a model. Fully quit and reopen VS Code for the new extension/recorder code, then reload/trust the updated host hooks before user-led live testing.

## Live command checks and 0.5.1 patch

Ran eight harmless real commands through the active host: printf, CommonJS file read, ESM eval file read, a missing-package import with a caught error, exclusive disposable-file creation, guarded deletion of that exact fixture, an `.mjs` file with a relative import, and ESM stdin. All eight tool calls returned exit code 0 and all eight completion events reached recorder version 7. Output capture and model routing remained disabled. The measured static analysis times were 1–26 ms for this small sample, not a general latency benchmark.

Observed impacts were SAFE for printf, LOW for the four read/module forms, MEDIUM for creation and UNKNOWN for the unresolved package. The guarded deletion initially retained only its preceding read: a literal `Error(...)` guard invalidated the filesystem binding. Version 0.5.1 preserves bindings across conditionally built-in Error constructors with zero or one statically known string argument; shadowed constructors and dynamic arguments still invalidate bindings. Replaying the same command through the installed 0.5.1 hook now reports MEDIUM and includes the delete effect. Separate assessment-only critical shell and direct-Write payloads return deny; neither dangerous candidate was executed.

Every actual host command still has partial coverage and HIGH approval risk because the host omits execution-shell metadata; several Node forms also retain unsupported-language gaps. The recorder receives completion events but no parsed exit-code metadata in this host integration, so its exit-code field stays unknown even though the tool-call results independently reported 0. These limitations are not presented as successful complete analysis.

The initial 0.5 UI exposed settings only through VS Code Settings and the Command Palette. Version 0.5.1 adds an always-visible **LLM settings** header button, view-title gear shortcut, router-state label and version label, with router updates independent of recorder events. UI tests derive element IDs from shipped markup and verify that configuration remains accessible before connection and after recorder errors. Native desktop inspection was unavailable because computer-use access was not approved.

Installed the verified 0.5.1 VSIX and refreshed all three hook pins while preserving the legacy policy and debug logging. Final checks: 197 Rust tests passed, one containment test remains separately verified as above; 60 extension tests passed; Clippy, formatting and diff checks passed. Router and history remain disabled and the optional service is stopped. Run **Developer: Reload Window** to load the new panel controls; reload/trust updated `/hooks` to select the patched native analyzer. Existing version-7 temporary recorder history can remain intact.

After the host reload, reran exclusive disposable-file creation and the guarded delete through real tool calls. Both now report MEDIUM and both completion events reached the recorder; the delete report contains both read and delete effects. Their analyzer times were 7 ms and 9 ms in this sample. The fixture was removed. This confirms the patched analyzer is active, beyond the earlier assessment-only replay. VS Code's extension registry selects 0.5.1 and the extension activation log records a fresh activation.

Added an integration check that connects the shipped frontend button to the real extension message handler, registered command and VS Code Settings query using a mocked editor API, without desktop interaction or provider calls. The complete extension suite now passes 61 tests. The configured model remains `gpt-6-luna`, routing remains disabled and the optional service remains stopped.

## Gemini and Claude support in 0.5.2

Added native Gemini generateContent and Claude Messages adapters to the extension provider dropdown and optional service. Gemini defaults to `gemini-3.1-flash-lite` with `GEMINI_API_KEY`; Claude defaults to `claude-haiku-5-5` with `ANTHROPIC_API_KEY`. Model, endpoint and key-variable overrides remain configurable. Provider-specific deserialization defaults prevent partial native configurations from implicitly inheriting OpenAI's endpoint or credential variable. Keys are supplied in the appropriate HTTP headers, not URLs or saved settings; Claude includes the API-version header. Native refusals, truncated output and unexpected tool blocks are rejected before the shared proposal validator. No model or provider fallback is added.

Policy generation v3 preserves both v2 and legacy files, protecting cached older hook executables from unsupported provider enum values. Installed the verified 0.5.2 VSIX, verified both native binary hashes, refreshed the three hook pins, and confirmed older policy bytes were unchanged. Installed-binary probes in a disposable home directory confirm the two native provider presets; actual user routing remains disabled, history remains off, and the optional service remains stopped.

Validation: 201 Rust tests passed (one containment test remains separately verified as above), all 62 extension tests passed against release binaries, and Clippy/format/diff checks passed. Local HTTP mocks verify request paths, exact models, schema fields, token caps, provider-specific auth headers, response parsing and conservative policy floors for all five providers. One debug CLI health check timed out during concurrent builds; the isolated test and full release-binary suite subsequently passed without changing production deadlines. No real API keys or paid provider calls were used. External-provider latency, account access and live inference remain for explicit user testing.

## Baseline

Before implementation: 180 Rust tests passed (one ignored containment test); 51 extension tests passed when run with required host process/socket access. Existing installed extension: `distill.distill-trace-0.4.10`; installed user hooks use a SHA-256-pinned binary and retain opt-in debug logging. Existing working-tree modifications predate this task.


## Secure key entry and temporary editor state in 0.5.3

User clarification: remember API keys securely, while keeping command history temporary. **LLM settings** now opens a dedicated form with provider and API-key-variable dropdowns, a masked key field, key removal, model/endpoint overrides and the existing bounded routing controls. The same key-variable dropdown is available in advanced VS Code Settings, with a separate custom-name field. Entered secrets are stored exclusively through VS Code SecretStorage, bound to provider + endpoint + variable. No secret returns to the webview or enters settings, policy JSON, command arguments or recorder metadata; it reaches only the selected service-start environment. Disabled routing does not read SecretStorage. Environment-supplied keys remain supported when no saved key exists.

Recorder 8 assigns each extension activation a lease, clears old traces on reload, drops dead-host leases and removes an unused recorder. Ordinary socket reconnects within the same activation preserve current-session traces. Verified older Unix recorders are replaced automatically using their private lock and process identity; old TCP recorders still require one full application restart. History restoration and durable feedback writes were removed from the editor. Extension-managed policies disable persistent history, the approval ledger and debug logging. The standalone CLI's separately configured durable-history feature remains available. User preferences, installed executables, explicit exports and securely saved API keys are intentionally retained.

The optional model service follows its owning extension-host PID and exits when that host exits. Key replacement/removal forces a restart even when the policy digest is unchanged; disabling or rejecting a route stops the service, discarding its in-memory credentials and advice cache. Clear logs invalidates title/detail/output caches and rejects late responses. Recorder-instance changes invalidate previous view snapshots.

Verification: **202 Rust tests passed**, one unchanged containment test remains separately verified earlier; **70 extension tests passed** against the release binary. New checks cover SecretStorage-only persistence, provider/endpoint isolation, masked form submission with no key echo, removal, disabled credential access, same-policy key rotation, reload clearing, dead-host cleanup and automatic recorder replacement. Clippy with warnings denied, formatting, extension syntax/assets and diff checks passed. Tests used disposable files/processes and local mock APIs; no paid provider calls or real keys were used. The isolated desktop host-smoke script was updated for the new reload contract but was not run; native editor UI access remains unavailable.

Installed `distill-trace-0.5.3-darwin-arm64.vsix`; verified installed source/media/config bytes against the workspace and both bundled native hashes. Main binary SHA-256: `8c76ff4b071805a4a8fce3e14a54530cbac132aeed188914274c3e693a907a92`. Refreshed the three managed Codex hook pins, removed debug-log flags, disabled history/ledger writes and retained the selected disabled router. No service archive/spool files were present. Both legacy and v2 policy bytes were preserved. A window reload loads the new form; reload/trust `/hooks` selects the new native hook pins in cached host sessions.
