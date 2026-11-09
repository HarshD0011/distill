# Live model responses and trace display

## Latest retest: 9 November, 10:22 IST

Two fresh groups of five reviews passed through the live native service and the active workspace recorder. All **10/10 responses** were valid, uncached `gpt-6-luna` advisory results, with distinct request digests, no unavailable results and no trace-delivery stderr. Both groups reached **five simultaneous model requests**. The candidate commands were assessed only; none was executed.

Model response times ranged from **823 to 3,311 ms**, with a **1,257 ms median**. The recorder retained each complete group after approximately **1,889 ms** and **3,493 ms**, respectively. Both groups included a command over 10 KB. These are observed sample timings, not a latency guarantee.

The installed **0.5.10** renderer was tested against these actual retained responses: all five rows displayed normally and all five displayed under the forced snapshot/detail ordering race in each group. This is a renderer-harness check using the installed JavaScript, rather than a screenshot of the open panel. The live trace sessions are named **Distill live retest 1 (no execution)** and **Distill live retest 2 (no execution)**. The native service remains **0.5.9**.

The sanitized [fresh retest results](benchmarks/command-reviews-live-retest-20261109.json) preserve per-request timings and delivery checks without credentials or source contents.

The regression rerun passed **232 Rust tests** (one existing containment test ignored) and **90 extension tests**. Extension syntax/assets, Rust formatting and whitespace checks also passed.

## Previous response check

The post-reload check confirmed that the active native service is **0.5.9**, the limit is **five simultaneous requests**, and the configured route is **gpt-6-luna**, severity format, zero batch window and a 5,000 ms model deadline. File-source sharing remains disabled; these probes supplied code inline in their commands.

Five distinct review probes were submitted through the real CLI hook, configured model service and existing workspace recorder. They were assessments only: none of the candidate commands was executed. One command contained 10,053 bytes to exercise larger-payload handling. The service returned **five valid, uncached advisory responses**, with five distinct request digests, no unavailable results and no trace-delivery stderr. All five retained records contain the corresponding response and keep their recorded `ask` decision.

Service-side elapsed times were **3,980 / 3,437 / 2,855 / 3,131 / 2,855 ms**, median **3,131 ms**. The recorder contained all five terminal responses after approximately **4,499 ms** from submission. This is a small live sample confirming response delivery, not an accuracy or latency guarantee. The test session is named **Distill live review test (no execution)**; like other editor traces, it is temporary.

## Display race found and fixed

The initial display check rendered only three model-advice sections even though all five backend responses existed. A command can advance to a new version after the compact snapshot but before its detail response. The old renderer discarded the mismatching reply and kept a versionless pending marker. On the next snapshot, the same command ID still existed, so no replacement detail request was made and the row could remain loading.

Pending requests now track the requested command version. A newer snapshot clears the obsolete request and fetches current details. Older replies cannot replace the current response. A deterministic regression reproduces the ordering.

Using the five actual retained responses, the installed 0.5.9 renderer displayed all five with a stable snapshot, but refetched zero rows and displayed zero detail sections under the forced race. The patched renderer refetched all five and displayed all five model-advice sections under the same ordering. This verifies the stored responses and the rendering behavior without making additional model calls.

The fix is packaged in extension **0.5.10**; the native service remains **0.5.9**. A window reload activates an extension update. The response records are also preserved in the [sanitized live result artifact](benchmarks/command-reviews-live-responses-20261109.json), without credentials, raw source, command output or authentication tokens.

The Rust workspace rerun passed **232 tests**, with one existing containment test ignored. All **90 extension tests** passed, including the new response/snapshot regression. The tested 0.5.10 extension package was installed successfully; reload the window to activate the display fix.
