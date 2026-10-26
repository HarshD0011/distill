# Covering severity gaps through compositional static analysis

Status: implemented on October 22, 2026 in CLI 0.4.2 / behavior policy 8 and extension 0.4.4. The design below records the rationale; the implementation and validation notes at the end describe the delivered boundaries. Native Codex hook trust remains a user review step after installing the changed executable.

Baseline: CLI 0.4.1 / policy 7 had nine discrepancies in the 32-case challenge. A further [28 targeted variations and controls](semantic-gap-probes-20261022.json) produced 21 impact discrepancies: six argument-role cases, four nested SQL cases, six constant-predicate cases, three shell handoffs, and two native-loader cases. All six inert-text/plan-only controls retained their expected ratings. The harmless shell-payload case also retained its expected aggregate MEDIUM rating; that alone did not establish that its nested shell behavior was modeled. Candidate commands in the new probe were analyzed only. These deliberately selected cases are evidence of missing semantic families, not an accuracy estimate. The new probe did not independently assert approval-risk minima.

## What “static, without hardcoded verdicts” means

Use documented command and language semantics to derive behavior, then apply an independent policy. Do not match complete command strings, SQL snippets, table names, or particular fixture paths to verdicts. Moving such matches into JSON would still be hardcoding examples.

Some knowledge is unavoidable: a model must know that Git's `--output` supplies a destination and SQLite's `load_extension` requests native loading. Put that knowledge in reviewed, versioned grammar/capability specifications. Those specifications describe argument roles, evaluation order, and effects; they contain no severity labels. Reuse the same file, execution, and database policy across all callers. Unknown commands cannot acquire semantics from their names or `--help` output alone.

The repository already has useful pieces: `Behavior`, `record_behavior`, `target_class`, shared `evaluate_behavior`, bounded source inspection with dependency hashes, nested shell analysis, and validated bundled wrapper profiles. The remaining gaps occur where specialized handlers bypass or cannot express that structure.

## Five reusable capabilities

### 1. Typed command arguments and file roles — three original gaps

Current location: `crates/distill-interp/src/lib.rs`, `Analyzer::git`; `crates/distill-interp/src/capabilities.rs`, `semantic_verbs`.

The Git handler recognizes option spellings but does not bind diff output values or no-index inputs to filesystem effects. The database handler extracts some inline payloads but does not model script-file arguments. Introduce an argument decoder whose output includes ordered options, values, operands, selected mode, and unresolved spans. Each command grammar specifies arity, accepted attached/separate forms, delimiter behavior, repetition, and precedence.

For Git diff, an output argument emits `FileWrite(destination, truncate)`. In no-index mode, the two filesystem operands emit `FileRead(path)`; directory expansion retains uncertainty when it is not inspected. For psql, script-file arguments emit `FileRead(path)` before attempting any source inspection. Their literal contents can then feed the client-language analyzer using the existing bounded, hashed dependency mechanism. Unreadable contents do not erase the file-read effect. Standard-input sources and dynamic filenames remain explicitly unresolved.

This handles `.env`, other credential-classified paths, ordinary files, and protected targets through the same existing path policy. Classification itself remains an approximation; no new per-command credential-path list is needed. [Git documents output destinations and no-index filesystem operands](https://git-scm.com/docs/git-diff); [psql documents ordered command/file input options](https://www.postgresql.org/docs/current/app-psql.html).

An illustrative grammar entry would describe `--output` as a path-valued option with a truncate-write effect. It would never say “if this command contains .env, return HIGH.” Flags that look similar are not automatically equivalent across tools. Unknown option arity must stop confident operand binding rather than shifting the remaining arguments by guesswork.

### 2. SQL syntax trees and execution context — one original gap

Current location: `crates/distill-interp/src/artifact.rs`, `inspect_sql` and `sql_tokens`.

The current extractor intentionally collects only depth-zero tokens. It loses the DELETE inside a CTE. Its lexer also replaces quoted values with a marker and discards most operators, making later semantic reasoning impossible.

Replace this extractor with a bounded SQL AST adapter for explicitly selected dialects. Visit executable statements, CTE bodies, expressions, and function calls, preserving source references and whether each node is executed, planned, defined for later execution, or unresolved. Join child effects into their parents. An outer SELECT or unused CTE result must not suppress a modifying CTE. PostgreSQL explicitly describes [data-modifying CTE execution](https://www.postgresql.org/docs/current/queries-with.html#QUERIES-WITH-MODIFYING).

Execution context matters: a plain EXPLAIN does not execute the contained DELETE; EXPLAIN ANALYZE does. Disabling ANALYZE must survive option parsing. Planning and configuration uncertainty can remain even when row-deletion effects are absent. [PostgreSQL EXPLAIN semantics](https://www.postgresql.org/docs/current/sql-explain.html).

Evaluate `sqlparser-rs` as the Rust parsing dependency, pin a tested version, and require the CTE/EXPLAIN/dialect corpus to pass before adopting it. Its maintainers explicitly distinguish [syntax parsing from semantic validation](https://github.com/apache/datafusion-sqlparser-rs#syntax-vs-semantics). A parser dependency supplies structure, not a safety proof or complete engine compatibility. Unhandled AST nodes, parse failures, and budget exhaustion must retain explicit uncertainty. Parsing, tokenization, traversal, and recursive handoffs need byte/node/depth/time bounds; existing limits must not be bypassed by a new dependency.

### 3. Abstract evaluation of predicates — two original gaps

The current test is whether a WHERE token exists. Replace it with bounded evaluation of the WHERE expression using typed literal values, parentheses, checked arithmetic, comparisons, and Boolean operations. Derive selection scope as `all_rows`, `no_rows`, `conditional_rows`, or `unresolved`.

Examples under supported pure literal semantics:

- `TRUE`, `9 = 9`, `NOT FALSE`, and `2 * 3 = 6` establish all-row selection without enumerating those expressions.
- `FALSE` and `1 = 0` establish no selected rows for that deletion expression.
- `account_id = 7` is conditional selection, not proof of a small affected-row count.
- Unknown functions, casts, collations, types, or overflow prevent exact evaluation.

Use SQL truth values TRUE, FALSE, and NULL, keeping analysis uncertainty distinct from SQL NULL. An abstract set of possible truth values is one implementation. Do not simplify `column = column` to TRUE when nullability is unknown. [PostgreSQL documents three-valued Boolean logic](https://www.postgresql.org/docs/current/functions-logical.html).

Collect effects from expression evaluation separately from selection scope. A false predicate does not prove that the entire command has no effects: functions, statement triggers, configuration, and other statements may still matter. Unknown predicates should not be advertised as bounded mutations.

### 4. Client-language parsing and nested execution — two original gaps

The SQL clients accept more than SQL. Decode the client program first, then hand SQL segments to the SQL adapter, shell payloads to the existing shell adapter, and source-file references to the bounded reader. Reuse this mechanism for future clients that embed another language.

`psql -c` accepts a SQL program or one backslash command; scripts have different mixing rules. `\!` delegates its remaining text to a shell. SQLite dot-commands have their own line and quoting grammar, and `.shell` / `.system` invoke a system shell. Parsing every payload as SQL misses these transitions; substring matching would incorrectly execute text inside SQL strings. [psql client semantics](https://www.postgresql.org/docs/current/app-psql.html), [SQLite client semantics](https://www.sqlite.org/cli.html).

Preserve the client's documented argument reconstruction and selected shell context. A literal payload can be analyzed recursively; dynamic text or an uncertain shell context retains coverage gaps. Recursion must share the parent budget, and nested cwd/state must not leak into the outer shell. The same mechanism can later cover input-file, output-file, pipe, and helper commands, each with its own grammar and execution conditions.

### 5. Function capabilities and native loading — one original gap

Model resolved AST calls and client metacommands through a capability registry. A native-load capability emits an execution effect with the module target, source location, and unresolved runtime contents. This applies to both SQLite `load_extension(...)` and `.load`, independent of the filename. A string containing `load_extension(...)` is just data. [SQLite documents SQL and client interfaces for native extension loading](https://www.sqlite.org/loadext.html).

Function identity is conditional on dialect, namespace, configuration, and overrides. Unsupported or dynamically selected functions remain unresolved; no arbitrary function is considered pure merely because it appears inside SELECT. The same capability schema can describe file reads/writes, process execution, and network access across languages.

## Shared effect model and policy

Extend `distill-core::Behavior` with database operations and selection scope instead of representing SQL DELETE as filesystem deletion. Keep target identity, conditionality, source evidence, and unresolved reasons available to policy, session tracking, and the extension. A structured operation variant can prevent invalid combinations such as a filesystem path carrying database row scope.

The configurable policy in `distill-rules` should determine ratings from those facts: credential file access is HIGH under today's policy; confirmed whole-table deletion is CRITICAL; native code loading is HIGH with incomplete coverage. Ordinary file access uses ordinary file policy. Partially modeled commands keep their known impact and their separate approval-risk/coverage assessment. The proposed database policy must explicitly define unknown scope rather than treating the mere presence of WHERE as safe narrowing.

Adapters must not call `finding(Severity::...)` to assign ratings to the new semantic paths. Emit facts first. Add database policy defaults and validation in core, implement their evaluation in rules, and bump behavior-policy provenance when this ships. The extension should display this evidence and the engine's verdict; it should not reclassify command text.

## Implementation sequence and acceptance criteria

1. Introduce typed argument roles and migrate Git diff plus database client inputs. Reuse existing file classification and source bindings.
2. Add explicit client-program routing and bounded SQL parsing. Replace the flat SQL token classifier, preserving known effects on unsupported paths.
3. Add predicate evaluation, database effect types, and the capability registry. Move their ratings into shared configurable policy.
4. Validate the original 65 regression cases, the 32-case challenge, the new 28 variants, and generated combinations. Keep every hazardous candidate as analysis input only.
5. Run Rust checks and the extension's signed hook-to-renderer tests; verify impact, risk, coverage, evidence, and session correlation together. Then package/install through the existing reviewed-hook workflow.

Acceptance requires more than the nine original labels:

- Semantic-preserving transformations: whitespace/comments, supported quoting, equivalent option forms, renamed tables/modules, nested expressions, and valid option ordering preserve the appropriate effects.
- Contrasting controls: quoted command text and plan-only statements do not acquire embedded execution effects; real execution forms do.
- Composition: independently executable hazardous children retain their effects in larger programs. This does not override genuine non-executing contexts or proven control flow.
- Uncertainty: malformed input, unknown flags, unsupported dialect constructs, dynamic targets, and exhausted budgets cannot become fully modeled harmless commands.
- Policy independence: the same effect/target facts receive the same policy treatment across adapters; changing a policy value changes the rating without changing parsing.
- Independent oracles: pure constant predicates can be checked against private in-memory rows; file and shell routing can use fake files and harmless marker output. PostgreSQL-specific effects require the matching engine or documented semantics, not SQLite equivalence claims.

Remaining unknowns are legitimate where runtime state is necessary: arbitrary stored procedures, unknown source, environment-selected helpers, configuration/plugins, and schema-dependent behavior. This design can cover the nine observed literal cases without executing them or writing nine verdict exceptions; it cannot prove all arbitrary programs safe.

## Delivered implementation

- `arguments.rs` interprets the bundled `rules/arguments.json`: option arity, supported value spellings, short clusters, ordered programs, startup I/O, last-value precedence, append mode, and pipe roles. Unknown arity stops further binding while preserving earlier effects. Git diff and psql/mysql/sqlite3 use this decoder.
- `client.rs` interprets the reviewed `rules/languages.json`, routing client programs into SQL, bounded source reads, native loading, and nested shell analysis. Literal psql command/file ordering and SQLite startup/positional programs are represented. SQLite shell reconstruction follows its client argument decoding and space quoting, rather than treating dot-command arguments as original shell source. Nested shell cwd/dialect state is restored afterward.
- `sql.rs` uses pinned `sqlparser` 0.63.0 for explicit PostgreSQL, SQLite and MySQL dialects; generic SQL artifact inspection remains dialect-unresolved. An AST visitor retains CTE effects, separates executable statements from EXPLAIN/definitions/prepared statements, and preserves earlier complete statements if a later statement is unsupported. Quoted SQL data never becomes a metacommand or loader call.
- `sql/eval.rs` evaluates bounded integer/Boolean expressions and abstract three-valued truth. It distinguishes all/no/conditional/unresolved selection, does not infer small row counts, and retains uncertainty for unsupported casts/functions and arithmetic overflow. Function effects are collected independently of row selection.
- `distill-core::Behavior` carries typed database action/scope metadata under a database effect kind, with a constructor and policy consistency checks. Database operations no longer masquerade as filesystem deletion. `distill-rules` rates those facts through the configurable `database_query`, `database_modify`, `database_all_rows`, and `database_unknown_scope` policies. Grammar/capability specifications have no severity fields.
- Extension 0.4.4 / recorder 6 retains at most 32 modeled effects per assessment, bounds target/location text, and shows them under **More details → Modeled effects**. Database selection scope is visible alongside the engine's original rating. Older recorders remain compatible for ratings; details they discarded cannot be recovered until a new recorder starts.

The SQL input cap is 64 KiB, with 4,096 total tokens, 1,024 significant tokens, parser/visitor depth 64, and constant-evaluation depth 48. Token and AST work consume the shared node budget; parsing and recursive handoffs check the shared deadline. Tokenization and parsing themselves are bounded monolithic library calls, not hard real-time cancellation points. The host watchdog remains the external time bound. These limits and partial coverage prevent a successful parse from becoming a purity proof.

The client model remains deliberately partial: startup files, database/server configuration, arbitrary functions/procedures, unsupported metacommands/interpolation, source generated by commands, and runtime schema behavior are not resolved. SQL artifact inspection does not invent a server dialect. A row-dependent predicate can still match every existing row. A no-row predicate does not eliminate statement triggers or other effects.

## Validation and reproduction

The [before/after receipt](semantic-gap-implementation-20261022.json) records executable hashes and all cases. The frozen 0.4.1 baseline has 9/32 challenge discrepancies and 21/28 variation discrepancies; the updated analyzer has zero discrepancies in all 65 regression, 32 challenge, and 28 variation cases. Four intentionally opaque regression cases remain UNKNOWN. Suite counts can overlap and are not a general accuracy estimate.

Verification includes 143 passing Rust tests (one separate host-containment test remains ignored), 43 passing extension tests, 40 policy cases, 155 language analyses and 155 approval-label checks, format/clippy/specification checks, and the isolated installed-VSIX lifecycle test. Signed real CLI events reach the actual renderer with corrected Git, SQL CTE/predicate, client-shell, script-read and native-loader badges, including typed effect evidence. The packaged test verifies activation, real window reload, Clear Logs, workspace isolation and continued recording. It does not inspect the user's existing VS Code UI. An existing concurrent-ledger test hit a transient busy timeout during an earlier run; its focused rerun and final complete suite passed, with no ledger behavior changes.

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
python3 scripts/validate_specs.py
python3 scripts/semantic_evaluation.py target/debug/distill --output /tmp/distill-semantic-results.json
python3 scripts/verdict_challenge.py target/debug/distill --output /tmp/distill-challenge.json
make smoke
make test-extension
python3 extensions/vscode/scripts/host_smoke.py
```

The semantic evaluation only analyzes candidate commands. The challenge's five separate effect probes use disposable fake files, harmless printf, and private in-memory rows; no hazardous candidate payload is executed. Installation updates the hash-pinned user hook through `distill setup`; it does not change native trust records or turn advisory policy into enforced blocking.
