# Five concurrent model reviews

Implemented and measured on 9 November 2026. The service already used threads for up to four background requests; it now supports **five simultaneous provider requests per service**, with one shared limit across background workers, synchronous `judge` RPCs and optional severity batches.

With a zero batch window, every distinct review starts on its own worker without a collection delay. Requests use the existing shared HTTP client. Identical pending reviews still share work, and cached/classifier results do not consume a provider slot. When five background workers are occupied, a new background review receives `busy`; static review requirements remain in force. Synchronous overflow receives an explicit capacity error. There is no unbounded queue or automatic retry. A request permit is released on success, response validation failure, HTTP error or timeout.

The shared permit prevents the synchronous API from bypassing the limit. The limit covers in-flight client requests; a provider might continue processing a request after the client times out. Parallel requests do not reduce API request count or token charges. They help independent overlapping work; a sequential agent waiting for each result does not gain parallelism. Provider rate limits and available capacity can reduce the benefit or return HTTP 429.

## Validation

The full Rust workspace suite passed **229 tests**, with one existing host-containment test ignored, in **17.88 seconds**. Formatting, benchmark syntax and diff checks passed. New integration tests hold provider responses behind a gate to prove five actual overlapping HTTP requests rather than merely five spawned threads. They cover:

- Independent severity responses completing out of order and retaining the correct request digest and severity.
- No accidental batching when the batch window is zero.
- A sixth background request receiving `busy`, and a synchronous request being unable to bypass the shared ceiling.
- Duplicate submissions sharing the existing request at full capacity.
- The same ceiling for legacy effects and opt-in batches.
- Successful capacity reuse, HTTP 429 cooldown and permit release after HTTP failures/timeouts.

## Performance

A local mock-provider comparison ran **72 trials / 192 reviews**, with three repeats for each combination of 1/2/5 commands, serial/parallel submission, severity/effects response format, and 0/8 KiB script source per command. Batching was disabled. The fixture uses **400 ms + 2 ms per KiB request input** as a synthetic delay. Requests are unique cache misses, cases are shuffled within each route with a fixed seed, and all results are advisory successes. Every serial trial records peak provider concurrency of one; each five-command parallel trial records peak concurrency of exactly five and five API calls.

For five commands, median total completion times were:

- Severity, no script source: **2,139.04 ms serial → 469.06 ms parallel**, about **4.56× faster**.
- Severity, 8 KiB source per command: **2,251.00 ms → 486.53 ms**, about **4.63× faster**.
- Structured effects, no script source: **2,121.81 ms → 467.22 ms**, about **4.54× faster**.
- Structured effects, 8 KiB source per command: **2,228.22 ms → 490.05 ms**, about **4.55× faster**.

These figures measure the real local HTTP/IPC and scheduling paths against controlled provider delay, not live model inference or production latency. They compare five serial requests with five parallel requests, not the previous four-request ceiling with the new five-request ceiling. Debug binaries, IPC admission overhead and result polling are included in total completion time. No candidate code was executed, and no external API was called for this comparison.

## Reproduce

```sh
cargo build -p distill-cli -p distill-service
python3 scripts/benchmark_reviews.py --parallel --repeats 3 \
  --output /tmp/review-parallel.json
cargo test --workspace
```

The benchmark asserts actual overlap, request count and successful result count for every case. For a later live measurement after updating the installed service, the same harness accepts `--live-config /absolute/policy.toml --commands 5 --repeats 10 --output /tmp/review-live-five.json`; it uses the existing service without extracting its key. Keep the batch window at zero for independent parallel reviews. The previous live measurements used the old installed service and do not validate this new limit.

[Raw benchmark data](benchmarks/command-reviews-parallel-20261109.json). A local test VSIX is built; the user's active editor extension/service was not replaced or reloaded.


## Repeat validation

A fresh rerun passed all **229 Rust tests** (one existing containment test ignored) in **17.76 seconds**, all **88 extension tests** in **37.91 seconds**, and **20 additional concurrency test executions across 10 iterations**, with no failures. The repeated mock benchmark passed **72 trials / 192 uncached reviews** and verified the expected actual overlap in every trial. Five no-source severity reviews completed in a median **2,140.43 ms serially versus 472.82 ms in parallel** (4.53×). The provider-request ceiling remained five. These remain local mock-provider timings. [Raw repeat measurements](benchmarks/command-reviews-parallel-retest-20261109.json).
