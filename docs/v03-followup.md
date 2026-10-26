# Expanded trace and analyzer fixes · 0.3.0

- The exact `git branch --show-current` query now receives SAFE/ALLOW within the supported system-command model. Additional operands/options and Git configuration overrides retain their conservative handling.
- Literal `mktemp` templates ending in six or more `X` characters use the shared write policy. Under defaults, ordinary creation is MEDIUM/ASK. Environment-dependent and unsupported forms remain partial.
- Equivalent consecutive assessments merge across generated IDs/timings. Policy, evidence, coverage, blocking, different hook stages, and changes back to earlier results remain distinct. Existing broker history is normalized for display without restarting the broker.
- Expanded command rows show a plain reason, decision/status, and output first. Full commands and technical context are inside **More details**. Assessment history remains optional.
- Literal Makefile prerequisites, multiple goals/files, `-f`, `-C`, recipe prefixes, inline recipes, continuations, escaped shell substitutions, and `.ONESHELL` receive bounded inspection. All Makefile coverage remains partial; variables, includes, functions, implicit rules, and custom execution semantics are unresolved. Make is never launched during analysis.

Validation: 105 Rust tests, 30 extension tests, formatting, Clippy, 155 language
analyses, 155 approval-label fixtures, and 40 authored behavior-policy cases
passed. The isolated VS Code lifecycle check retained deduplicated history and
output across an actual window reload and verified cleanup after application
quit. UI tests cover lazy details, the new folds, and preserving expanded rows
while new commands arrive.

[The comparison against 0.2.0](v03-decision-comparison.json) covers 51 synthetic
cases. The intended SAFE/ALLOW correction for the exact current-branch query is
the only less restrictive decision. Literal temporary-file creation now has a
known write effect; two Makefile cases now expose critical effects that the
previous scanner missed. These results establish regression coverage only.

Existing command rows retain their original analyzer assessment. Run a fresh
command to see new ratings. Reload VS Code after installing the extension to
load the UI changes; current temporary history is preserved. Hook definitions
do not need to change when their installed Distill executable is updated.

Installed verification: the CLI reports 0.3.0 with behavior policy version 5,
and the 0.3.0 VSIX was installed into the normal VS Code profile. A fresh actual
Codex current-branch query reached the existing broker as SAFE/ALLOW, completed,
and retained matching output. Its normalized details contained one assessment
and a plain-language reason. Reload the current window to activate the UI.
