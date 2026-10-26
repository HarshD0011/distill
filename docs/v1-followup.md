# V1 follow-up · 0.2.0

Implemented:

- Codex chat headings from the local title index, rename refresh, and a friendly fallback when metadata is unavailable. The extension never opens transcripts or state databases.
- Compact command/severity rows. Details and output previews are requested only when a command is expanded; full retained output requires **Read more**. Incoming logs preserve expanded rows.
- Read-only hook-source inspection and workspace migration that reuses compatible user/ancestor handlers. Migration preserves unrelated settings and rejects conflicting policy options rather than silently weakening them.
- One effective output opt-out: an explicit `[privacy].capture_output = false` disables capture. The legacy editor flag can still disable capture.
- Executable-path validation rejects parent traversal, prefix lookalikes, and symlink escapes from trusted directories. Bare command names still use a conditional system-command model: PATH shadowing, aliases, and executable attestation remain outside this proof.
- Workspace-scoped clearing with compatibility for an already-running 0.1.0 broker. Upgrading the UI does not discard its temporary history.

Validation separates a built artifact, installation, and live capture. The
isolated VS Code check exercises actual reload and application quit; Node
integration checks exercise real Rust hook processes against the memory broker.
Neither alone establishes that the user's host has trusted its configured hooks.

Local readiness check on 2026-10-18:

- Rust: 96 tests passed; formatting and Clippy passed.
- Extension: 25 Node tests passed; syntax, VSIX integrity, isolated VS Code reload, and quit cleanup passed.
- Regression fixtures: 155 language analyses and 155 approval labels passed; all 40 authored behavior-policy cases passed.
- Installed CLI and VS Code extension both report 0.2.0. This workspace reuses its existing user PreToolUse/PermissionRequest definitions and retains its PostToolUse command unchanged. User hook files were not modified.
- An actual Codex tool call reached the running broker with policy version 4; its chat heading resolved. Its completion event was still absent on a second check. Live PostToolUse output capture therefore remains unverified in this running window. Reload VS Code to load the updated extension, review PostToolUse in Codex's `/hooks`, and run a harmless command to check its expanded output. The running 0.1.0 broker is retained to preserve current history until application quit.

[The old/new comparison](v1-decision-comparison.json) analyzes 44 synthetic
cases against the saved prior binary. Two path-traversal cases changed from
ALLOW to ASK with partial coverage; no decisions became less restrictive.
These are regression results, not a general accuracy measurement.

Capture remains limited to host events, with 10,000 commands, 64 MiB accounted
payload, 4 MiB output per command, and 16 assessment revisions. Missing events,
host-truncated output, other tools, and unrelated terminals cannot be recovered.
Titles and command history remain temporary in this extension. Codex owns its
existing metadata index; Distill does not alter or delete it.
