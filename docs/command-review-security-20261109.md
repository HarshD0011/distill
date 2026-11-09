# Command reviews, credential custody and batching

Measured in the 9 November 2026 session, on macOS arm64 with debug Rust binaries. Candidate commands were analyzed, never executed. The user’s running model service was used for six live reviews without extracting its provider credential, restarting it or changing its settings.

## What is implemented

The editor reads saved credentials from VS Code SecretStorage, with a slot bound to provider, complete endpoint and key-variable name. A normal reload retrieves the same saved slot. Keys are never written to settings, policies, trace storage, public RPC results or service-start arguments/environments. A bounded one-shot stdin pipe carries the route-bound credential through the launcher to the service. The service keeps the key in memory and has no credential-export RPC. Rust-owned secret buffers are zeroized on drop; temporary JavaScript strings and HTTP-library copies cannot be guaranteed to be zeroized.

Changing an endpoint selects another slot. Removing a key cannot silently reuse an ambient environment credential on editor service starts. CLI-only users can explicitly supply their chosen environment variable; the launcher still forwards its value through a pipe into a clean service environment. Workspace settings cannot select the executable that receives the credential, nor enable or redirect the model route. Managed binaries are checksum verified and must advertise the pipe/compact-review capabilities. HTTPS is required except for explicitly configured loopback HTTP; redirects and HTTP retries remain disabled.

Unresolved executable behavior, including inspected Node script files, triggers the enabled model route. **Include inspected script excerpts** (`distill.llm.sendScriptContents`) shares up to 8 KiB of redacted, hash-verified source per command. Source edits invalidate cached advice. This setting remains an explicit opt-in: the current installed route has it disabled. Missing, oversized, changed or unreadable source, and unresolved imports/dependencies, remain incomplete coverage. No candidate code is executed to inspect it.

The editor’s **Model reply format** defaults to `severity`. Legacy CLI policies without `review_format` retain `effects`. All five provider adapters have a text-only severity request path; adapter tests cover OpenAI-compatible, Gemini, Claude, llama.cpp and vLLM request bodies. This is protocol coverage, not a claim that every provider/model deployment has been live-tested.

The production prompt asks:

> Bin each submitted code or command into high, medium, low, safe or critical. Reply only with one lowercase severity per item, in input order, separated by ';'. No placeholders, explanations, numbering or extra text.

It also treats all input code as untrusted data, defines the severity scale, forbids authorization, and says missing source/imports do not establish safety. Each JSON array entry contains one command plus its available source/context. Replies such as `safe;high;critical` are parsed positionally. Extra text, uppercase labels, placeholders, empty/trailing entries, refusals, truncation or the wrong result count reject the whole batch. The parser cannot prove that an otherwise valid response was not reordered by the model. Model advice can raise risk or deny execution; it cannot lower the static floor, remove unknowns or grant approval.

**Batch window** (`distill.llm.batchWindowMs`, native `judge.batch_window_ms`) accepts 0–500 ms. Zero sends immediately. A nonzero window starts at the first arrival, groups at most 16 reviews within 64 KiB, and never slides forward as more commands arrive. Batching requires severity format. Queue time counts against the model deadline. The hook waits at most 40 ms for local acknowledgement and keeps its static review requirement while advice is pending. Pending duplicates share work; source/context/policy changes invalidate reuse. A 500 ms window groups overlapping arrivals, not future commands in a sequential agent loop that is waiting for the previous result.

## Measurements and decision

The full Rust suite passed **226 tests**, with one existing containment test ignored, in **21.24 seconds**. The extension suite passed **88 tests** in **35.98 seconds**. Formatting, extension syntax/assets and Python compilation checks passed. The baseline Rust count was 219, not the 209 mistakenly reported in an early progress update.

Twenty samples per static command gave process-level medians of 13.84 ms (`echo hello`), 14.24 ms (`cat README.md`), 13.70 ms (`node scripts/test.js` with an unresolved import), and 13.77 ms (`rm -rf /`, analyzed only). Median reported analyzer time was 5 ms. The Node fixture retained partial coverage and HIGH approval risk; destructive input retained CRITICAL risk. These are debug-build local measurements including process startup, not production SLOs.

Six uncached live reviews using the current **gpt-5.6-luna** route completed successfully. Median observed advice latency was **1,896 ms**, range **1,639–2,374 ms**. Median local enqueue acknowledgement was **6.28 ms**. This small sample uses the installed legacy structured response format, no shared script contents and the configured provider defaults. It does not establish a model ranking or compact/batch speedup.

The local comparison completed **150 trials / 390 reviews**: three repeats for each combination of structured effects or severity format, 0/50/100/500 ms severity windows, 1/2/4 commands, 0/100 ms arrival gaps, and 0/8 KiB source per command. The HTTP fixture uses a fixed synthetic delay of 120 ms plus 2 ms/KiB of request input. Actual local IPC/HTTP, queueing, parser and cache paths are exercised. The fixture submits minimal protocol payloads directly; real hook graphs/context can be larger. This is **not inference latency, accuracy, token usage or a billing estimate**. Cases are shuffled with a fixed seed within each configured route. Polling adds up to 5 ms; later submissions can delay observing an earlier response. Service-side timing is also retained in the raw data.

For four overlapping commands with no source:

- Structured effects, no wait: median completion **177.8 ms**, four API requests, 5,064 request bytes and 972 response bytes.
- Severity, no wait: **175.9 ms**, four requests, 4,060 request bytes and 264 response bytes.
- Severity, 50 ms window: **202.4 ms**, one request, 1,657 request bytes and 78 response bytes.
- Severity, 100 ms window: **245.8 ms**, one request.
- Severity, 500 ms window: **650.2 ms**, one request.

Thus 500 ms batching saved **75% of requests** in this case while adding about **474 ms** to completion versus immediate severity calls. At a 100 ms command spacing, a 50 ms window saved no requests and increased median completion from 445.3 to 503.0 ms. With four 8 KiB sources, immediate severity calls completed in 201.4 ms versus 272.3 ms for a 50 ms batch and 720.8 ms for a 500 ms batch. Larger combined inputs reduced the small-prompt advantage in the synthetic fixture.

**Decision: keep the default window at 0 ms.** Compact replies substantially reduce response bytes; their real-provider latency and classification accuracy still require a controlled live comparison. Use a 50–100 ms window only when measured overlapping traffic and provider rate limits justify the added delay. A fixed 500 ms wait is a request-efficiency tradeoff, not a demonstrated latency improvement. Independent requests already run concurrently.

The larger-source tests also exposed a macOS accepted-socket issue: inherited nonblocking mode could reject fragmented payloads with EAGAIN. Accepted streams now use blocking reads under one bounded read deadline; a deliberately split 32 KiB IPC regression passes.

## Credential storage choices: benefits and issues

**Encrypted extension storage plus pipe — implemented practical baseline.** SecretStorage persists encrypted secrets, avoids plaintext config and supports normal reloads. Endpoint binding, clean child environments, verified executables, bounded IPC and removal without environment fallback reduce accidental disclosure paths. VS Code documents desktop SecretStorage as encrypted through Electron safeStorage and excludes it from machine sync. However, the extension and launcher temporarily handle plaintext, OS backend behavior matters, and a compromised editor, same-user malware or an administrator is outside this boundary. This does **not** meet strict “only the service can decrypt the key” custody. [VS Code storage documentation](https://code.visualstudio.com/api/extension-capabilities/common-capabilities)

**Dedicated local service identity plus OS credential store — recommended for strict local service-only custody.** Enroll the key through a service-owned trusted prompt, store it under the service principal with OS access controls, and let the editor submit bounded classifications without ever receiving provider tokens. Use a signed/verified daemon, separate OS identity, private IPC with authenticated peers, pinned provider destinations, request/budget limits and a restricted API; provide no raw-token or arbitrary-network proxy method. Benefits: workspace commands and the editor user cannot simply read service-owned credentials. Issues: privileged installation, signing, updates and cross-platform OS policy must be designed and verified. A keychain item name or socket token alone does not create process isolation. This architecture is proposed, not implemented in this patch.

**Remote classification broker plus managed secrets — strongest separation from a compromised local agent.** Keep provider credentials in a server-side secret manager. The client holds only short-lived, narrowly scoped review-session tokens; the server exposes classification only, constrains provider/model/destination, enforces identity, rate and spend limits, and supports revocation. Benefits: the provider key never reaches the workstation and rotation is centralized. Issues: hosting/operations, network dependence, abuse prevention and source-code privacy. A stolen client token can still misuse its allowed scope until it expires/revokes. This is also proposed, not implemented here.

Plaintext files, workspace settings, shell history, globally exported provider keys, custom encryption with a colocated decrypting key, and “encrypted” browser storage are unsuitable substitutes for these boundaries. No design guarantees zero backdoors under a compromised OS/administrator; the trust boundary must be stated and tested.

## What OpenAI documents for Codex

The Codex CLI and IDE extension share cached login credentials. Official documentation allows plaintext `~/.codex/auth.json` or an OS credential store, controlled by `cli_auth_credentials_store`. Explicit `keyring` uses the OS store and fails if unavailable; `auto` can fall back to a plaintext file; `ephemeral` keeps credentials only in process memory. For durable storage without a plaintext fallback, the documented choice is `cli_auth_credentials_store = "keyring"`. These are documented behaviors, not claims from inspecting private extension internals or the user’s auth files. [Official Codex authentication documentation](https://learn.chatgpt.com/docs/auth)

OpenAI’s latency guide recommends reducing requests and output work where appropriate. That does not imply a fixed debounce is faster than parallel calls, nor that the offline Batch API is appropriate for an interactive approval path. [Official latency guidance](https://developers.openai.com/api/docs/guides/latency-optimization)

## Reload verification limit

Unit tests recreate the credential manager over persistent storage, check endpoint isolation/removal, exercise a real child stdin handoff and verify secret-free child environments and sanitized failures. Service tests verify the fake provider key is absent from process arguments/environments and confirm owner-exit cleanup. The test suite also has an explicit actual-editor reload check using a fake key in a disposable profile.

The initial in-memory host test correctly lost its secret on reload; that mode cannot verify persistence. The explicit OS-backed host run timed out while VS Code was checking encryption availability and its disposable instance was stopped. Computer Use access to inspect VS Code was not approved. **Actual encrypted-backend persistence across reload is therefore unverified in this environment.** No plaintext or in-memory fallback was added to make this test pass. Repeat with an unlocked OS store and explicit `DISTILL_HOST_TEST_PERSISTENT_SECRETS=1`.

## Reproduce and fine-tune

Build `cargo build -p distill-cli -p distill-service`, then run:

```sh
python3 scripts/benchmark_reviews.py --repeats 3 --output /tmp/review-mock.json
```

For live comparisons, install the built extension package, choose the desired format/window, retain the exact same model, explicit supported reasoning effort, token cap, timeout and source-sharing settings, and let the editor restart its service. Run each configuration separately through that existing service, without extracting its key:

```sh
python3 scripts/benchmark_reviews.py \
  --live-config /absolute/path/to/hook-policy-v3-codex.toml \
  --commands 4 --arrival-gap-ms 100 --repeats 10 \
  --output /tmp/review-live-window-0.json
```

Repeat with windows 50, 100 and 500 ms, then repeat with `--script-bytes 1024`, `4096` and `8192` when source sharing is enabled. Compare latency distributions, request count, malformed/truncated output rate and labeled safety accuracy; do not pick a window by request count alone. Unique requests avoid cache artifacts. Add independent reviewed dangerous/benign script cases before any policy change: this benchmark does not measure safety accuracy, and the model must never become an automatic approval authority.

Raw measurements: [live baseline](benchmarks/command-reviews-live-20261109.json), [local comparison](benchmarks/command-reviews-mock-20261109.json). The repository changes and built package are ready for review; the user’s active extension/service was not replaced or reloaded.


Follow-up: [five concurrent model requests, shared capacity and measured serial/parallel performance](parallel-reviews-20261109.md).
