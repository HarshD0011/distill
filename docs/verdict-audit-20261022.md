# Verdict audit — October 22, 2026

The audit found a recorder correlation bug and actual classification errors. CLI 0.4.1 / behavior policy 7 fixes the covered cases. This is targeted regression evidence, not a general detection-accuracy estimate.

## Why UNKNOWN looked excessive

A live recorder sample contained 43 rows: 31 UNKNOWN, of which 21 were completed rows with no assessment. Their signed leading comments differed from the original proposed command. TraceStore correctly separated different executable text, but the hook bridge had failed to authenticate and normalize its own label before sending the completion. That left an assessed proposed row and an unassessed completed row for one tool call.

The bridge now authenticates the label using the configured private HMAC key for both assessment and completion events. Only an authentic exact-byte label is removed. Forged labels remain separate. This joins completion to the original report without reading a severity from the label or weakening the store's text/context check.

An isolated replay used four synthetic commands and synthetic completion JSON; no candidate command was executed. Before: eight rows, five UNKNOWN, four unassessed rows. After: four completed rows, one genuinely UNKNOWN command, zero unassessed rows. Forged labels stayed separate before and after.

## Classification corrections

- `git diff --check` and literal legacy head/tail counts now have supported query/read profiles.
- `ls .env` reads metadata and is SAFE under the metadata policy; `cat`, `wc`, `sed`, and `rg` reading that file retain HIGH credential-access impact. Pattern values are distinguished from file operands.
- Ripgrep hostname providers, preprocessors, and decompressor options retain helper-execution risk. A preprocessor argument is an executable path, not shell source: a space-containing argument is not recursively interpreted as a shell deletion command. Explicitly disabled preprocessing does not create a spurious helper finding. Recursive search contents and unknown flags retain incomplete coverage.
- `LD_AUDIT`, `LD_DEBUG_OUTPUT`, Git external-diff/pager, and ripgrep configuration overrides join the conservative runtime-environment table. Loader controls are treated conservatively across platforms; LD_AUDIT's actual loader behavior is Linux-specific.
- Literal `{}` within an argument stays one word, enabling xargs replacement-token analysis. Real comma/range brace expansion stays dynamic. Find nested programs, including later exec clauses, are recovered without executing them.
- SQL CLI payloads use the shared bounded lexical scanner instead of substring matching. Strings, quoted identifiers, dollar quoting, nested comments, and statement-level WHERE context are distinguished. EXPLAIN with actual ANALYZE still retains execution risk; EXPLAIN without execution is not labeled as data deletion. Query/filter operands containing words such as `delete` no longer establish a destructive cloud operation.

The SQL layer remains a bounded lexical effect extractor, not a full SQL grammar or remote-state proof. Stored procedures, executable comments, CTE/data-flow semantics, imports, filesystem races, runtime aliases, and arbitrary program behavior can exceed the model. Partial coverage is retained. A zero-discrepancy result on the selected cases does not establish universal correctness.

## Validation

The [authored corpus](../corpus/verdict-audit.json) states expected impact, review requirement, minimum risk where applicable, and rationale independently of the analyzer output. The [machine-readable results](verdict-audit-20261022.json) preserve the frozen original binary's hash and both sets of results.

On 65 selected cases, the original disagreed with 32 expectations: 30 wrong impacts, eight unsafe allows, six unnecessary reviews, and 13 understated risks; categories overlap. The update matches all 65 expectations, with zero unsafe allows in this corpus. Analyzer UNKNOWN count is seven to four; the remaining four are deliberately unresolved opaque/computed/encoded execution and Python imports.

Nine benign oracle probes run the real tools in a disposable directory. They check head/tail/sed output, metadata listing, literal braces, ordinary ripgrep reads, controlled hostname-helper invocation, the preprocessor's executable-path semantics, and a local import executing a fixture module. Hazardous commands and SQL statements are analyzed only. Run:

```sh
python3 scripts/verdict_audit.py --before /path/to/frozen-distill --after target/debug/distill --output /tmp/verdict-audit.json
node scripts/trace_label_audit.js target/debug/distill
```

Validation passes: 129 Rust tests, 34 recorder tests, Clippy with warnings denied, 155 language analyses and 155 label checks, and the existing 40 policy cases. An additional stable, uninstrumented fuzz smoke completed 10,000 runs; this is not coverage-guided evidence. A Rust integration test runs all 65 expectations. The recorder integration test runs the real signed pre/post CLI path and checks one completed row per invocation plus forgery isolation. Existing reports keep their original assessment; these fixes apply to newly observed commands. Existing orphan rows remain until temporary history is cleared or the editor application quits. Installation refreshes the pinned user hook; changed definitions may require review in `/hooks`.

## Semantic references

The audit consulted ripgrep's installed `--help` and its [official flag definitions](https://github.com/BurntSushi/ripgrep/blob/master/crates/core/flags/defs.rs), [Git's diff documentation](https://git-scm.com/docs/git-diff), [PostgreSQL's lexical rules](https://www.postgresql.org/docs/current/sql-syntax-lexical.html), and the [Linux dynamic-loader manual](https://man7.org/linux/man-pages/man8/ld.so.8.html). The oracle results and label replay are local measurements; no remote CI result or general accuracy percentage is claimed.
