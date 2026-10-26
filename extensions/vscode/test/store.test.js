'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { TraceStore, outputText, previewOutput } = require('../src/store');
const { mergeHooks, shellQuote, workspaceHookPlan } = require('../src/hooks');

const event = (overrides = {}) => ({ protocol: 1, kind: 'assessment', source: 'codex', session_id: 'chat-a', tool_use_id: 'call-1', timestamp: 10, command: 'echo hello', session_cwd: '/workspace', cwd: '/workspace', hook_event_name: 'PreToolUse', report: { impact_severity: 'safe', severity: 'safe', decision: 'allow', coverage: { summary: 'static_accounted' }, explanation: 'Safe output' }, ...overrides });

test('chat and host IDs isolate identical tool IDs; retries merge into one command', () => {
  const store = new TraceStore();
  store.record(event());
  store.record(event({ hook_event_name: 'PermissionRequest', timestamp: 11 }));
  store.record(event({ session_id: 'chat-b' }));
  store.record(event({ source: 'claude' }));
  const snapshot = store.snapshot();
  assert.equal(snapshot.sessions.length, 3);
  assert.ok(snapshot.sessions.every(session => session.commands.length === 1));
  assert.equal(snapshot.sessions[0].commands[0].startedAt, 10);
});

test('post-before-pre preserves output, execution status, and original severity', () => {
  const store = new TraceStore();
  const full = Array.from({ length: 60 }, (_, index) => `line ${index}`).join('\n');
  store.record(event({ kind: 'completion', hook_event_name: 'PostToolUse', timestamp: 12, tool_response: { stdout: full, stderr: 'warning', exit_code: 7 } }));
  store.record(event());
  store.record(event({ hook_event_name: 'PermissionRequest', report: { impact_severity: 'critical' }, timestamp: 11 }));
  const session = store.snapshot().sessions[0];
  const entry = session.commands[0];
  assert.equal(entry.status, 'failed');
  assert.equal(entry.exitCode, 7);
  assert.equal(entry.severity, 'safe');
  assert.equal(entry.output.text, 'line 0\nline 1\nline 2\nline 3\nline 4');
  assert.equal(entry.output.hasMore, true);
  assert.equal(store.readOutput(session.key, entry.id), `${full}\n[stderr]\nwarning`);
});

test('policy denial is distinct from enforced blocking and confirmed execution', () => {
  const store = new TraceStore();
  store.record(event({ report: { decision: 'deny', severity: 'critical', impact_severity: 'critical' } }));
  assert.equal(store.snapshot().sessions[0].commands[0].status, 'proposed');
  store.record(event({ blocked: true }));
  assert.equal(store.snapshot().sessions[0].commands[0].status, 'blocked');
  store.record(event({ kind: 'completion', tool_response: '', timestamp: 15 }));
  assert.equal(store.snapshot().sessions[0].commands[0].status, 'completed');
});

test('unassessed commands remain unknown and clear removes output and chats', () => {
  const store = new TraceStore();
  store.record(event({ kind: 'completion', tool_response: 'Process exited with code 1\nOutput:\nfailed' }));
  assert.equal(store.snapshot().sessions[0].commands[0].severity, 'unknown');
  assert.equal(store.snapshot().sessions[0].commands[0].assessmentState, 'missing');
  assert.equal(store.snapshot().sessions[0].commands[0].status, 'failed');
  const key = store.snapshot().sessions[0].key;
  store.clear();
  assert.deepEqual(store.snapshot().sessions, []);
  assert.throws(() => store.readOutput(key, 'call-1'));
  assert.throws(() => store.record(event({ session_id: '' })));
});

test('missing assessments, unresolved impacts and rated partial analyses stay distinct in compact pages and details', () => {
  const store = new TraceStore();
  store.record(event({ kind: 'completion', tool_use_id: 'missing' }));
  const gaps = ['Executable behavior is not modeled'];
  store.record(event({ tool_use_id: 'unresolved', report: { impact_severity: null, severity: 'high', decision: 'ask', unknowns: gaps, behavior_policy_version: 7, coverage: { summary: 'opaque' } } }));
  store.record(event({ tool_use_id: 'rated', report: { impact_severity: 'low', severity: 'medium', decision: 'ask', unknowns: gaps, coverage: { summary: 'partial' } } }));
  const session = store.snapshot({ compact: true }).sessions[0];
  assert.deepEqual(session.commands.map(row => [row.id, row.severity, row.assessmentState]), [
    ['missing', 'unknown', 'missing'], ['unresolved', 'unknown', 'unknown'], ['rated', 'low', 'rated'],
  ]);
  const unresolved = store.readCommand(session.key, 'unresolved');
  assert.deepEqual(unresolved.unknowns, gaps);
  assert.equal(unresolved.behaviorPolicyVersion, 7);
  assert.equal(unresolved.approvalRisk, 'high');
  assert.equal(store.snapshot({ query: 'unassessed' }).sessions[0].commands[0].id, 'missing');
  assert.deepEqual(store.snapshot({ query: 'unknown' }).sessions[0].commands.map(row => row.id), ['unresolved']);
  store.record(event({ tool_use_id: 'missing' }));
  assert.equal(store.readCommand(session.key, 'missing').assessmentState, 'rated');
  assert.equal(store.readCommand(session.key, 'missing').status, 'completed');
});

test('modeled effects retain bounded semantic facts without retaining arbitrary source objects', () => {
  const store = new TraceStore();
  const behavior = { kind: 'database', operation: 'sql', target: 'accounts', target_class: 'ordinary', database: { action: 'delete', scope: 'all_rows' }, location: { file: 'input.sql', line: 2, column: 1 }, source: 'must not retain this arbitrary field' };
  store.record(event({ report: { impact_severity: 'critical', severity: 'critical', decision: 'deny', behaviors: Array.from({ length: 40 }, () => ({ ...behavior, target: 'x'.repeat(900) })) } }));
  const session = store.snapshot({ compact: true }).sessions[0];
  const detail = store.readCommand(session.key, 'call-1');
  assert.equal(detail.behaviors.length, 32);
  assert.equal(detail.behaviors[0].target.length, 512);
  assert.equal(detail.behaviorsTruncated, true);
  assert.equal(detail.behaviors[0].source, undefined);
  assert.deepEqual(detail.behaviors[0].database, behavior.database);
  assert.equal(session.commands[0].behaviors, undefined, 'Collapsed pages remain compact');
});

test('output previews handle long lines and preserve raw text without interpreting markup', () => {
  assert.deepEqual(previewOutput('a\nb'), { text: 'a\nb', hasMore: false });
  assert.equal(previewOutput('a'.repeat(5000)).text.length, 1800);
  assert.equal(previewOutput('a'.repeat(5000)).hasMore, true);
  assert.equal(outputText({ content: [{ type: 'text', text: '<script>attack()</script>' }, { type: 'text', text: 'tail' }] }), '<script>attack()</script>\ntail');
  assert.equal(outputText({ stdout: '', stderr: 'error' }), '[stderr]\nerror');
});

test('hook setup is idempotent, quotes paths, and preserves unrelated settings and hooks', () => {
  const existing = { env: { A: 'B' }, hooks: { PreToolUse: [{ matcher: '^Bash$', hooks: [{ command: 'distill hook codex --mode strict' }, { command: 'other-hook --flag' }] }] } };
  const merged = mergeHooks(existing, 'codex', '/a path/distill');
  assert.equal(existing.hooks.PreToolUse[0].hooks.length, 2);
  assert.equal(merged.hooks.PreToolUse.length, 1);
  assert.equal(merged.hooks.PreToolUse[0].hooks[1].command, 'other-hook --flag');
  assert.equal(merged.hooks.PreToolUse[0].hooks[0].command, "'/a path/distill' hook codex --mode strict");
  assert.equal(merged.env.A, 'B');
  assert.deepEqual(mergeHooks(merged, 'codex', '/a path/distill'), merged);
  const fresh = mergeHooks({}, 'claude', 'distill');
  assert.equal(fresh.hooks.PostToolUseFailure[0].hooks[0].command, "'distill' hook claude --mode advisory");
  assert.equal(shellQuote("a'b"), "'a'\"'\"'b'");
  assert.throws(() => mergeHooks({ hooks: [] }, 'codex', 'distill'));
});

test('capture limits are visible without silently evicting prior commands', () => {
  const store = new TraceStore({ commands: 2, outputBytes: 8 });
  store.record(event());
  store.record(event({ kind: 'completion', tool_response: '123456789012345', timestamp: 12 }));
  store.record(event({ tool_use_id: 'call-2' }));
  store.record(event({ tool_use_id: 'call-3' }));
  const snapshot = store.snapshot();
  assert.equal(snapshot.sessions[0].commands.length, 2);
  assert.equal(snapshot.sessions[0].commands[0].outputTruncated, true);
  assert.equal(snapshot.capture.droppedEvents, 1);
  assert.equal(snapshot.capture.truncatedOutputs, 1);
  assert.equal(store.readOutput(snapshot.sessions[0].key, 'call-1'), '12345678');
});

test('fresh reports with equivalent assessments occupy one revision, while policy and evidence changes are retained', () => {
  const store = new TraceStore();
  const base = event().report;
  store.record(event({ report: { ...base, report_id: 'one', explanation: 'distill SAFE (1 ms; approval risk SAFE): Safe output' } }));
  store.record(event({ report: { ...base, report_id: 'two', explanation: 'distill SAFE (5 ms; approval risk SAFE): Safe output' }, timestamp: 11 }));
  assert.equal(store.snapshot().sessions[0].commands[0].assessmentCount, 1);
  store.record(event({ report: { ...base, report_id: 'three', policy_digest: 'different-policy' }, timestamp: 12 }));
  store.record(event({ report: { ...base, report_id: 'four' }, timestamp: 13 }));
  store.record(event({ report: { ...base, report_id: 'five', findings: [{ impact: 'changed evidence' }] }, timestamp: 14 }));
  assert.equal(store.snapshot().sessions[0].commands[0].assessmentCount, 4);
  assert.equal(store.commandCount, 1);
});

test('duplicates, changed command text, revisions and reordered completions remain distinct', () => {
  const store = new TraceStore();
  store.record(event()); store.record(event());
  assert.equal(store.snapshot().sessions[0].commands[0].assessmentCount, 1);
  store.record(event({ hook_event_name: 'PermissionRequest', timestamp: 11, report: { decision: 'ask', impact_severity: 'high' } }));
  store.record(event({ kind: 'completion', timestamp: 20, tool_response: 'latest' }));
  store.record(event({ kind: 'completion', timestamp: 15, tool_response: 'older' }));
  store.record(event({ command: 'echo changed' }));
  const session = store.snapshot().sessions[0];
  assert.equal(session.commands.length, 2);
  assert.equal(session.commands[0].assessments.length, 2);
  assert.equal(session.commands[0].severity, 'safe');
  assert.equal(store.readOutput(session.key, 'call-1'), 'latest');
});

test('pagination and search reach commands beyond the first page', () => {
  const store = new TraceStore();
  for (let i = 0; i < 250; i++) store.record(event({ tool_use_id: `call-${i}`, command: `echo marker-${i}`, timestamp: i }));
  const first = store.snapshot({ paged: true, limit: 100 });
  assert.equal(first.sessions[0].commands.length, 100);
  assert.equal(first.page.total, 250); assert.equal(first.page.hasMore, true);
  const last = store.snapshot({ paged: true, offset: 200 });
  assert.equal(last.sessions[0].commands.length, 50);
  const searched = store.snapshot({ paged: true, query: 'marker-249' });
  assert.equal(searched.sessions[0].commands.length, 1);
  assert.equal(searched.sessions[0].commands[0].command, 'echo marker-249');
});

test('workspace context is appended to hooks without changing existing policy flags', () => {
  const existing = { hooks: { PreToolUse: [{ matcher: '^Bash$', hooks: [{ command: 'distill hook codex --mode strict' }] }] } };
  const merged = mergeHooks(existing, 'codex', 'distill', '/workspace with spaces');
  assert.match(merged.hooks.PreToolUse[0].hooks[0].command, /--mode strict --workspace-root '\/workspace with spaces'/);
  assert.deepEqual(mergeHooks(merged, 'codex', 'distill', '/workspace with spaces'), merged);
});

test('compact pages exclude details and output until the specific command is requested', () => {
  const store = new TraceStore();
  store.record(event()); store.record(event({ kind: 'completion', timestamp: 12, tool_response: 'private output' }));
  const snapshot = store.snapshot({ compact: true, paged: true });
  const session = snapshot.sessions[0];
  assert.deepEqual(Object.keys(session.commands[0]).sort(), ['assessmentState', 'command', 'id', 'severity', 'version']);
  assert.ok(!JSON.stringify(snapshot).includes('private output'));
  assert.equal(store.readCommand(session.key, 'call-1').output.text, 'private output');
});

test('clearing workspace traces preserves other workspaces and reclaims their own accounted memory', () => {
  const store = new TraceStore();
  store.record(event());
  store.record(event({ session_id: 'other', session_cwd: '/other', cwd: '/other' }));
  const before = store.bytes;
  store.clear(['/workspace']);
  assert.equal(store.snapshot().sessions.length, 1);
  assert.equal(store.snapshot().sessions[0].id, 'other');
  assert.ok(store.bytes < before); assert.equal(store.commandCount, 1);
});

test('workspace migration reuses existing user hooks without modifying them or unrelated hooks', () => {
  const existing = { hooks: { PreToolUse: [{ matcher: '^Bash$', hooks: [{ command: 'distill hook codex --mode advisory --label-command' }, { command: 'other-hook' }] }] } };
  const external = { scope: 'user', path: '/home/.codex/hooks.json', event: 'PreToolUse', matcher: '^Bash$', executable: '/bin/distill', command: '/bin/distill hook codex --mode advisory', args: ['--mode', 'advisory'] };
  const local = { path: '/workspace/.codex/hooks.json', event: 'PreToolUse', command: existing.hooks.PreToolUse[0].hooks[0].command, args: ['--mode', 'advisory', '--label-command'] };
  const inventory = { handlers: [external, local], warnings: [] };
  const original = JSON.stringify(existing);
  const plan = workspaceHookPlan(existing, 'codex', 'distill', '/workspace', '/workspace/.codex/hooks.json', inventory);
  assert.equal(plan.reused.length, 1);
  assert.deepEqual(plan.configuration.hooks.PreToolUse[0].hooks, [{ command: 'other-hook' }]);
  assert.equal(plan.configuration.hooks.PostToolUse.length, 1);
  assert.equal(JSON.stringify(existing), original);
  assert.equal(inventory.handlers[0].command, '/bin/distill hook codex --mode advisory');
  assert.throws(() => workspaceHookPlan(existing, 'codex', 'distill', '/workspace', '/workspace/.codex/hooks.json', { ...inventory, handlers: [...inventory.handlers, external] }), /Multiple existing/);
  assert.throws(() => workspaceHookPlan(existing, 'codex', 'distill', '/workspace', '/workspace/.codex/hooks.json', { ...inventory, handlers: [external, { ...local, args: ['--mode', 'strict'] }] }), /different or unrecognized options/);
});
