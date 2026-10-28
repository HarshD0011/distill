# Tool coverage and application protection

The analyzer extracts known effects without running the candidate command. It
keeps unknown configuration, dependency code, plugins, remote services and
unsupported arguments in the report. A known rating with partial coverage still
requires review under the default policy. This is broader semantic coverage, not
a claim of complete analysis or universal malware detection.

## Recognized operations

CLI 0.4.3 / behavior policy 9 adds the coding-workflow models below. Supported
command syntax and known effects are distinct from complete execution coverage.
Arbitrary Python imports, test plugins, build backends, and missing host shell
metadata can still make coverage partial or the impact UNKNOWN. These gaps are
never removed merely because a command is named `test`, `pytest`, or `uv run`.

- Python options support separate/attached `-c` and `-m`, short flag clusters,
  `-I`, `-S`, `-W`, `-X`, `--`, extensionless scripts, directory `__main__.py`,
  and flag-prefixed stdin/heredocs. Program arguments remain data after the
  interpreter boundary. Custom warning categories, startup modules, interactive
  input, and untrusted interpreter paths retain uncertainty.
- Pytest and `python -m unittest` have known test-execution effects, bounded
  inspection of selected test files/directories and local runner modules, pytest
  `conftest.py`, node IDs, and explicit report/output paths. Discovery does not
  run imports or test code. Plugins, dynamic selection and discovery limits
  retain review requirements.
- `uv run`, module/script modes, `uvx`, and `uv tool run` forward nested argv and
  stdin to the same models. `--directory` changes execution cwd; `--project`
  changes metadata discovery. Environment and lock writes, local build backends,
  package/interpreter changes, caches, queries, and publishing have explicit
  effects. Remote-script execution remains CRITICAL. `--no-sync`, `--frozen`,
  `--no-project`, and `--no-cache` do not establish that dependency code is safe.
- Cargo build/check/clippy expose artifact writes; run/test/bench expose project
  execution, while `test --no-run` omits that execution effect. `fmt --check`
  reports a read rather than a source rewrite. Bounded workspace member globs,
  custom manifest target paths, build scripts and conventional source trees are
  inspected. Compiler configuration, aliases, macros and dependencies remain
  conditional.

`python3 scripts/workflow_smoke.py target/debug/distill` replays representative
workflows through both analysis and the actual hook API. Candidate commands are
JSON data and are never executed by that check.

- **Python:** `python -m pip` and selected package/module entry points; local
  literal module files; virtual-environment creation and clearing; HTTP serving;
  bytecode compilation; selected `pathlib` reads/writes/deletions, file copying,
  replacement, permissions and process calls. Existing inline and file analysis
  remains available. Arbitrary imports, installed modules and interpreter startup
  code remain unresolved. Explicit local package projects can contribute
  `setup.py` observations and a binding to `pyproject.toml`.
- **Git:** attached/separate global arguments; configuration reads and changes;
  executable helper overrides; clone/init destinations; query and archive outputs;
  working-tree changes; cleanup and selected lifecycle operations. Repository
  configuration, aliases, filters, hooks and transport helpers are not assumed
  harmless. Argument values are separated from options, including `--`.
- **Docker/Podman:** daemon/context selection, state queries, image changes,
  container execution, host mounts/control sockets, privilege settings, published
  ports, restart policies, copy destinations and removal/prune operations. Build
  inspection retains Dockerfile observations. Compose configuration and delegated
  daemon behavior remain unresolved. Container command arguments are not parsed
  as Docker options or interpreted as host shell commands.
- **curl:** payload/file upload distinctions, form and URL-encoded file reads,
  header files, credentials, output/header/cookie files, write-out destinations,
  bounded literal configuration lines, local service sockets and remote commands.
  Explicit configuration inspection does not recursively follow config chains.
  Implicit configuration retains a coverage gap unless the first option disables
  it. Unsupported escapes, variable expansion and option interactions remain partial.
- **Go:** build/run/test/install/generate/tool effects, helper selection, explicit
  source and output paths, dependency/workspace changes, cleanup and persistent
  environment changes. Module graphs, cgo, toolchain selection and implicit output
  destinations remain unresolved. Existing narrowly supported `go run` print
  programs retain their bounded model.
- **C/C++ and rustc:** preserve source and output findings for broader invocations,
  including compile-only outputs, explicit emission paths, dependency files,
  compiler extensions and custom helpers. Response files, includes, linker options
  and dependencies remain partial. Broader invocations do not produce executable
  print proofs. Compiler include-path environment overrides retain execution risk.
- **Cargo:** install/uninstall, build/check/run/test/doc, cleanup, registry actions
  and metadata queries. Literal `Cargo.toml` inspection follows bounded workspace
  members, explicit/default build-script paths, custom manifest targets and
  conventional Rust source trees. Dependency build scripts, procedural macros,
  Cargo aliases, configuration and unsupported target layouts remain unresolved.
- **Java:** `javac` output/source/header directories, source files, argument files,
  annotation processor paths, plugins and JVM agent options. Java source uses the
  same bounded parsing budget and emits conditional operations with locations.
  `java`, Maven and Gradle execution retains unresolved-code risk. Java compilation
  does not receive a safe-program proof, including when `-proc:none` is supplied.

Source observations describe potential behavior in the inspected code. They do
not establish that compiling an ordinary source file executes its `main` function.

## Installation and removal

Common install, upgrade, reinstall, remove and uninstall forms are recognized for
pip/pipx/uv, Conda, Homebrew, npm/pnpm/Yarn, apt/apt-get, dpkg, dnf/yum, rpm, pacman,
apk, Snap, Flatpak, MacPorts, RubyGems, macOS installers/software updates, Rustup,
Cargo and Go installation. System package removal can also invoke maintainer
scripts. Package metadata, hooks, dependency relationships and implicit locations
are not enumerated, so these operations remain partial. Unsupported aliases and
flags retain uncertainty; listing a manager here does not mean every option is modeled.

`protected_packages` now applies across these adapters to explicit package
operands, including common version suffixes. File-copy `install` models its sources,
destinations, permissions and strip helper. A dry-run flag does not discharge
unresolved build/backend code.

Shared filesystem classification protects application bundles (`*.app`), system
application/executable roots such as `/Applications`, `/usr`, `/opt`, `/Library`
and `/etc`, and selected user executable/toolchain directories. Existing secret
and startup-file policy remains more specific. Prefixes respect directory
boundaries: `/usr-local` is not `/usr`. Writes and deletions use the same target
policy across shell, source analysis, downloads, installers and compiler outputs.

Application availability checks also retain signal risk when a later signal
option overrides `kill -0`, and recognize `sysctl` configuration-loading forms.

## Verification and limits

`tool_tests.rs` covers installation/removal families, application destinations,
argument/data boundaries, Docker host access, compiler environment/plugins,
Java and Cargo source inspection, curl file transfers and malformed invocations.
Fixtures contain synthetic source; candidate programs, installers, containers and
payloads are never executed by these tests. Existing fuzz transformations, shell
oracles, language fixtures and independently labeled policy checks still apply.

The session ledger retains file locking and bounded contention failure. Unchanged
transactions no longer truncate/fsync the ledger, and lock acquisition allows up
to two seconds per transaction instead of 500 ms. Tests verify unchanged reads,
delayed lock release, bounded busy failure and all 64 entries from concurrent hooks.
The outer CLI watchdog remains the final runtime bound.

There is no sandbox tracing in this change. The existing containment gate has not
been redesigned, and runtime execution remains a separate capability. Unsupported
program paths must not be automatically approved just because common tool names
are recognized.

## Semantic references

- [Python command-line interface](https://docs.python.org/3/using/cmdline.html), [uv run](https://docs.astral.sh/uv/concepts/projects/run/), [uv CLI](https://docs.astral.sh/uv/reference/cli/), and [pytest plugin discovery](https://docs.pytest.org/en/stable/how-to/plugins.html)
- [pip build-system interface](https://pip.pypa.io/en/stable/reference/build-system/) and [uninstall](https://pip.pypa.io/en/stable/cli/pip_uninstall/)
- [Git global options](https://git-scm.com/docs/git), [clone](https://git-scm.com/docs/git-clone), and [configuration](https://git-scm.com/docs/git-config)
- [Docker run](https://docs.docker.com/reference/cli/docker/container/run/)
- [curl options](https://curl.se/docs/manpage.html)
- [Go command reference](https://pkg.go.dev/cmd/go)
- [Clang command-line reference](https://clang.llvm.org/docs/ClangCommandLineReference.html)
- [Cargo build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html) and [installation](https://doc.rust-lang.org/cargo/commands/cargo-install.html)
- [javac](https://docs.oracle.com/en/java/javase/25/docs/specs/man/javac.html) and [Tree-sitter Java grammar](https://github.com/tree-sitter/tree-sitter-java)
