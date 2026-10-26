# Current version

This document describes the bounded analyzer. [0.4 implementation notes](v04-implementation.md) add the signed hook labels, Zsh context layer, file dependency bindings, session ledger, execution gate, capability adapters, and current limitations. Coverage formerly called “complete” is displayed as “modeled” in current approval labels.

# Static source analysis

Distill parses shell structure and source with embedded Tree-sitter grammars for Bash, Python, JavaScript,
Go, C, C++, Rust, and Java. It does not start an interpreter, import a module, compile a
candidate, or execute candidate code during analysis. The normal CLI and agent
hooks use the same analyzer.

Parsing identifies structure; the semantic checks determine which operations
Distill understands. A successful parse alone cannot lower severity. Every
executable statement must fit the supported subset before a program receives
the LOW print-program rating. Comments are separate syntax nodes and cannot
hide adjacent executable statements. Syntax errors, missing syntax, unsupported
constructs, and exhausted limits retain the unresolved execution floor.

## Recognized behavior

Shell structure determines command boundaries, pipelines, redirections, command
substitutions, subshells, and heredocs. The word decoder removes quotes without
executing expansion. Unsupported constructs and parser recovery remain partial;
recoverable hazardous subtrees still contribute findings. Zsh uses a documented
Bash-compatible subset and is always partial. Other unsupported dialects are
never silently interpreted as Bash. CLI callers can supply `--shell` and repeat
`--workspace-root`; extension-generated hooks supply their workspace root.

Bundled, validated JSON profiles describe wrapper argument grammars and selected
file-operation operands. Unknown flags stop wrapper peeling. Privilege and
environment effects survive peeling; wrapper/substitution/subshell cwd changes
do not leak to subsequent outer commands. Specialized handlers remain for Git,
find, package scripts, and other commands with richer semantics. Profiles are
compiled into the binary; workspace files cannot replace them.

Downloaded streams remain potentially remote across intermediate pipeline
stages. Recognized interpreter consumers are checked after wrapper resolution.
Literal interpreter heredocs are routed to the existing language analysis only
when stdin is code for that invocation. Quoted delimiters suppress outer-shell
expansion; unquoted heredoc command substitutions are inspected separately.
Dynamic interpreter input remains unresolved. These checks are conservative
data-flow predictions, not observations of executed effects.

- Python: `-c` or a `.py` file, printing literals and primitive expressions,
  simple assignments to primitive values, parentheses, ordinary arithmetic,
  and supported `sep`, `end`, and `flush` arguments. Names must have been assigned
  a supported primitive expression. Rebinding `print` is rejected.
- JavaScript: Node `-e`/`--eval` or one `.js` file, `console.log` of literals or
  primitive expressions, and simple `const`, `let`, or `var` bindings. Computed
  properties, getters, spread arguments, interpolation, and rebinding `console`
  remain unresolved.
- Go: a single `main` program importing only `fmt`, with literal arguments to
  `fmt.Print`, `fmt.Println`, or `fmt.Printf`. Additional functions, imports,
  initializers, and custom execution flags remain unresolved.
- C: `<stdio.h>`, a single `int main`, literal `puts` or `printf`, and optional
  `return 0`. `printf` conversions, including `%n` and encoded format strings,
  remain unresolved. Ordinary escapes such as `\n` are supported; trigraph
  preprocessing remains unresolved.
- C++: `<iostream>`, a single `int main`, literal `std::cout` insertions and
  `std::endl`, and optional `return 0`. Global initializers and preprocessing
  beyond the recognized include remain unresolved.
- Rust: one `main` function using literal `print!`, `println!`, `eprint!`, or
  `eprintln!`. Macro definitions, captured format identifiers, other functions,
  and additional code remain unresolved.
- Java: conditional observations of selected `Files` operations, literal `Path.of`/`Paths.get`
  targets, file-stream constructors, and process/native-library calls. Java never
  receives the print-only proof. Annotation processors, plugins, class loading,
  escaped targets, and runtime dependencies remain unresolved.

Whitespace, line layout, URLs inside strings, and ordinary comments do not
change these structural checks. Arbitrary imports, calls, loops, custom types,
and dynamic loading are not yet interpreted.

Python option parsing follows the first `-c`; subsequent arguments are program
arguments. Node uses a deliberately narrow option grammar so preload options
and repeated eval flags cannot be mistaken for harmless application arguments.
Shell quoting preserves literal tildes and backslashes when resolving files.
Tildes inside language string literals are never expanded as shell home paths.

## Makefiles

The analyzer reads bounded regular makefiles without starting Make, including
for `make -n`. It follows literal normal and order-only prerequisites, handles
multiple goals/files, `-f`/`--file`/`--makefile`, and repeated `-C`/`--directory`.
Relative makefile paths resolve after the directory options. Default discovery
uses `GNUmakefile`, `makefile`, then `Makefile`.

Literal tabbed and inline recipes are inspected with Make's `@`, `-`, and `+`
prefixes removed. Continuations and `$$` escaping are handed to the shell
analyzer. Ordinary recipe lines have separate working directories; a literal
`.ONESHELL` declaration joins a target's recipe lines for analysis. Prerequisite
cycles, depth, shared time/node budgets, 256 KiB per-file reads, and 1 MiB of
retained rule text bound inspection. Multiple rules may be over-approximated.

Coverage always remains partial. Make variables/functions, includes, implicit
or pattern rules, conditional evaluation, variable overrides, custom recipe
prefixes/shells, and timestamp-dependent scheduling are unresolved. Recipes
containing unresolved Make expansions are skipped with an explicit reason;
other literal recipes still contribute findings. Effects are a conservative
inspection of recognized recipes, not an execution plan or permission grant.

GNU Make's [options](https://www.gnu.org/software/make/manual/html_node/Options-Summary.html)
and [recipe syntax](https://www.gnu.org/software/make/manual/html_node/Recipe-Syntax.html)
define the supported spellings. Full GNU/BSD Make compatibility is not claimed.

## Literal temporary-file templates

`mktemp TEMPLATE` and its short `-d`/`-q` forms are modeled when the template
ends in at least six `X` characters. The template identifies a predicted write
location; it is not the generated name. Shared write, sensitive/protected-path,
and workspace-boundary policy still applies. Environment-selected defaults,
`-t`, `-u`, and other options retain partial coverage rather than guessing
`TMPDIR` or claiming that a file was created.

## Findings and compiler outputs

For unresolved programs, an ordered local analysis reports recognized file
reads, writes, deletions, additional execution, and network calls. It propagates
plain string constants, copies, and bounded string concatenation through simple
assignments in Python, JavaScript, Go, C, C++, and Rust. Python module/function
import aliases, selected Node `require` aliases, and Go module aliases are
recognized. Reassignment, shadowing, compound assignments, parameter bindings,
unknown calls, and control-flow joins prevent stale values from being reused.
Unsupported joins conservatively lose exact values; this is not a full
control-flow graph or interprocedural analysis.

The call target is captured before argument evaluation, and argument values are
captured in evaluation order. Calls in nested arguments and function defaults
are inspected. Go and Rust process builders are distinguished from their
execution methods. File modes can flow through bindings; unknown modes include
possible writes, and update modes include reads and writes. Observations retain
the canonical call name, source file when available, and a one-based line and
byte-column.

These observations are conditional: call spelling and aliases do not prove
runtime identity. They never authorize a command or discharge unknown behavior.
Unrecognized and escaped targets remain unresolved. Recursive deletion of a
resolved root, home directory, or configured protected path receives CRITICAL
under the default policy.

Compiler analysis accepts one source and a bounded option set. Compiler outputs
are modeled even when the source includes unresolved behavior. A currently
absent ordinary output is a LOW build-artifact write; existing outputs and
source-file outputs receive MEDIUM overwrite findings, while startup and
protected paths receive stronger findings. These are metadata observations,
not an atomic reservation of the output path.

Broader compiler invocations now retain explicit source and output observations even
when additional flags, multiple inputs, plugins, or response files are unresolved.
These invocations never receive a print-only output proof. Cargo reads a bounded
literal manifest and selected local Rust sources/build scripts; Java compilation
uses a bounded Tree-sitter grammar. See [tool coverage](tool-coverage.md) for exact
adapter boundaries and installation/removal behavior.

Explicit and default executable outputs receive a print-program proof only
across an immediate `&&` edge.
Pipelines, `;`, `||`, and intervening commands invalidate that proof. Existing
outputs and source-file outputs receive overwrite findings; symlink outputs
remain partial and their resolved targets are checked. Startup and protected
paths retain their existing stronger policies.

## Shared behavior and severity policy

Language adapters emit `Behavior` records without a severity: operation kind,
canonical call, resolved target when known, target class, recursion, append
mode, and source location. The policy in `distill-rules` rates these facts.
Shell deletion, shell writes, modeled syscall deletion, and compiler outputs
use this same policy. Command-profile rules also live in `distill-rules`;
specialized host and network checks still have individual semantic handlers.

`[policy.effects]` in `config.example.toml` contains the configurable effect
ratings. Defaults distinguish ordinary reads (LOW), writes (MEDIUM), recursive
ordinary deletion (MEDIUM), sensitive operations (HIGH), and protected
modification (CRITICAL). Unknown targets retain HIGH. Validation rejects
unknown keys, invalid severity values, and inconsistent ordinary/protected
rating relationships. `behavior_policy_version` and `policy_digest` identify
the built-in policy version and configured policy; these are provenance fields,
not cryptographic attestations.

## Known impact and unresolved behavior

Reports expose two separate ratings:

- `impact_severity`: highest conditional modeled impact, or `null` when no
  impact rating can be established. Hooks display `null` as UNKNOWN.
- `severity`: conservative approval rating, including unresolved execution.
  This existing JSON field is retained for compatibility. A program with a
  known LOW file read can still have HIGH approval risk and an `ask` decision.

`Finding.basis` distinguishes impact findings from uncertainty findings.
`coverage`, `unknowns`, and `decision` remain independent fields. A recognized
low-impact operation never clears unresolved behavior elsewhere in a program.
Default policy requires review for incomplete analysis; advisory hooks leave
the host's native approval policy in control.

For example, `print(1); import os` displays UNKNOWN and partial analysis with
HIGH approval risk. `path = '/etc/passwd'; print(open(path).read())` displays a
known LOW read, partial analysis, and HIGH approval risk. `/etc/passwd` is not
automatically classified as a credential file. Imported code can execute
module initialization and is not treated as harmless solely because an import
name is familiar.

Approval comments include analysis coverage and, when incomplete, the
conservative approval rating. A comment such as
`# Distill severity: LOW 🔵 | Analysis: partial | Approval risk: HIGH ...`
describes known impact while keeping the unresolved risk visible. Diagnostics
are kept on one comment line; executable command text and approval fields are
preserved.

Version-only invocations are SAFE. Explicit runtime preload/environment
overrides and interpreter/compiler paths outside the trusted tool locations
retain HIGH. Installed runtimes and standard libraries in trusted locations are
assumed trustworthy; this is not executable attestation.

## SQL and client programs (0.4.2 / policy 8)

Reviewed argument grammars describe file roles and ordered program inputs for Git diff and database clients. Git output targets and no-index filesystem operands use the same file policy as shell redirection/readers. Client script files are read with bounded dependency hashes; prior writes invalidate their old contents. Unknown option arity stops further binding.

Pinned `sqlparser` 0.63.0 supplies dialect ASTs. A bounded visitor collects nested modifying CTEs and distinguishes executing statements from plan-only EXPLAIN, stored definitions, and prepared statements. Supported constant predicates use SQL TRUE/FALSE/NULL with explicit analysis uncertainty. Selection scope is all/no/conditional/unresolved rows, not a row-count guarantee. Unsupported functions, triggers, configuration and dialect features retain partial coverage.

Client syntax is routed before SQL: reviewed shell metacommands feed the existing shell analyzer with isolated cwd/dialect state; source commands use bounded file inspection; native loader calls emit execution effects. Quoted SQL strings remain data. Rules assign severity to typed effects, including database action/scope, using configurable policy rather than full-command matches. See [implementation details and validation](semantic-gap-design.md#delivered-implementation).

SQL parsing has byte/token/recursion limits and consumes the shared analysis budget; the parser's monolithic calls are checked before and after, not hard real-time interrupted. Successful syntax parsing alone never establishes complete semantics.

## Limits and validation

Each source is limited to 64 KiB, 4,096 named syntax nodes, and 64 tree levels.
Parsing, recursive shell/language handoffs, and bounded file inspection share
the request's deadline and node budget. Exhaustion produces stopped coverage
and preserves already collected findings. Cancellation is cooperative: an OS
filesystem call may itself block, so this is not a hard real-time guarantee.
File reads use nonblocking opens, check regular-file metadata, and cap bytes.
Existing path prefixes are resolved before lexical cleanup, including symlink
parent traversal. Declared workspace boundaries feed the shared behavior policy;
missing workspace roots never imply an invented boundary. The analyzer
does not take a filesystem snapshot; files, symlinks, or runtime state can still
change between assessment and execution. Module identity, monkey-patching,
general alias/pointer analysis, complete branch reachability, cross-file imports,
interprocedural data flow, general source-level sensitive-data taint tracking, and syscall tracing
remain outside the current model. Bounded shell/session effect correlation and a separate execution sandbox are available in 0.4. Source effects are conditional observations and cannot
establish a complete program proof.

`cargo test --workspace` exercises syntax boundaries, shadowing, comments,
global initializers, macro redefinitions, malformed code, effects, and limits.
`make smoke` additionally checks CLI reports and Codex command-label rewrites
for language fixtures. The smoke fixtures pass candidate commands as data to
Distill and never execute them. Separate hook tests use harmless shell prints
to verify that inserting a comment preserves execution.

`scripts/policy_evaluation.py` uses separately labeled cases in
`corpus/behavior-policy.json`. It checks known impact, target propagation,
missing/spurious effects, commands incorrectly allowed when review is required,
and unnecessary reviews for supported harmless cases. It never executes a
candidate command. This small authored corpus is a regression/evaluation set,
not an unbiased estimate of real-world accuracy; expand it with independently
reviewed cases before making accuracy claims.

`cargo run --release -p distill-cli --example latency` reports p50/p95/p99 warm
in-process analysis and scoring separately across five workloads. It excludes
process startup, hook transport, and editor rendering; it does not establish
an end-to-end sub-millisecond SLA. Begin host rollout with advisory hooks and
review decision changes against the regression corpus before strict enforcement.
