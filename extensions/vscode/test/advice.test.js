'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { TraceStore } = require('../src/store');
const { advicePoller } = require('../src/advice');
const { app } = require('./helpers/webview');
const digest = 'a'.repeat(64);
function event(id = 'one', command = 'python3 -c unknown', judge = { status: 'pending', request_digest: digest }) {
  return { protocol: 1, source: 'codex', kind: 'assessment', hook_event_name: 'PreToolUse', session_id: 'chat', tool_use_id: id, command, cwd: '/workspace', session_cwd: '/workspace', timestamp: 10,
    report: { impact_severity: null, severity: 'high', decision: 'ask', coverage: { summary: 'partial' }, unknowns: ['Unresolved Python call'], judge } };
}
test('late model advice becomes the fallback rating and preserves static coverage, decision, and output', () => {
  const store = new TraceStore(); store.record(event());
  store.record({ ...event(), kind: 'completion', timestamp: 20, tool_response: { stdout: 'ok', exit_code: 0 } });
  const session = store.snapshot().sessions[0];
  const before = store.readCommand(session.key, 'one');
  assert.deepEqual(store.pendingAdvice(), [digest]);
  const result = { status: 'advisory', request_digest: digest, severity: 'low', proposal: { effects: [], explanation: 'Read-only computation' } };
  store.applyAdvice([result]);
  const after = store.readCommand(session.key, 'one');
  assert.equal(after.severity, 'low'); assert.equal(after.assessmentState, 'advisory');
  assert.equal(after.approvalRisk, 'high'); assert.equal(after.decision, 'ask'); assert.equal(after.coverage, 'partial');
  assert.deepEqual(after.unknowns, before.unknowns); assert.deepEqual(after.output, before.output);
  assert.equal(after.assessments[0].report.impact_severity, null);
  assert.ok(after.version > before.version); assert.deepEqual(store.pendingAdvice(), []);
  const compact = store.snapshot({ compact: true }).sessions[0].commands[0];
  assert.equal(compact.severity, 'low'); assert.equal(compact.assessmentState, 'advisory');
  const version = store.version; store.applyAdvice([result]); assert.equal(store.version, version);
});
test('advice cannot override a known static impact, attach to another request, or restore cleared history', () => {
  const store = new TraceStore(); const known = event(); known.report.impact_severity = 'critical'; known.report.severity = 'critical'; known.report.decision = 'deny'; store.record(known);
  const key = store.snapshot().sessions[0].key;
  store.applyAdvice([{ status: 'advisory', request_digest: 'b'.repeat(64), severity: 'safe' }]);
  assert.equal(store.readCommand(key, 'one').judge.status, 'pending');
  store.applyAdvice([{ status: 'advisory', request_digest: digest, severity: 'safe' }]);
  assert.equal(store.readCommand(key, 'one').severity, 'critical'); assert.equal(store.readCommand(key, 'one').decision, 'deny');
  store.clear(); store.applyAdvice([{ status: 'advisory', request_digest: digest, severity: 'safe' }]);
  assert.deepEqual(store.snapshot().sessions, []);
});
test('model polling deduplicates work, preserves unknown on failure, and backs off after service errors', async () => {
  const store = new TraceStore(); store.record(event()); let resolve; let calls = 0;
  const poll = advicePoller(store, '/trusted/distill', async (_binary, keys) => { calls++; assert.deepEqual(keys, [digest]); return new Promise(done => { resolve = done; }); });
  const first = poll(); await poll(); assert.equal(calls, 1);
  resolve([{ status: 'unavailable', request_digest: digest, reason: 'Deadline exceeded' }]); await first;
  const row = store.snapshot().sessions[0].commands[0]; assert.equal(row.severity, 'unknown'); assert.equal(row.decision, 'ask');
  await poll(); assert.equal(calls, 1);
  store.record(event('two', 'another command', { status: 'pending', request_digest: 'b'.repeat(64) }));
  const failing = advicePoller(store, '/trusted/distill', async () => { calls++; throw new Error('Service stopped'); });
  await failing(); await failing(); assert.equal(calls, 2);
});
test('the real webview labels model ratings and keeps analysis limits collapsed', () => {
  const ui = app();
  ui.receive({ type: 'snapshot', sessions: [{ key: 'chat', id: 'chat', commands: [{ id: 'one', version: 2, command: 'python3 -c unknown', severity: 'low', assessmentState: 'advisory' }] }], page: { sessionKey: 'chat', total: 1, limit: 100, offset: 0 } });
  const rows = ui.elements.get('commands'); assert.match(rows.textContent, /low · model/);
  rows.children[0].open = true; rows.children[0].dispatch('toggle');
  ui.receive({ type: 'command', sessionKey: 'chat', command: { id: 'one', version: 2, command: 'python3 -c unknown', severity: 'low', assessmentState: 'advisory', reason: 'Unresolved', status: 'completed', decision: 'ask', coverage: 'partial', startedAt: 0, approvalRisk: 'high', unknowns: ['Unresolved Python call'], judge: { status: 'advisory', severity: 'low', proposal: { explanation: 'Read-only' } }, output: { text: '' }, outputChars: 0 } });
  assert.match(rows.textContent, /Rating from model advice/); assert.match(rows.textContent, /Unresolved Python call/);
  const section = rows.children[0].children[1];
  assert.ok(!section.children.some(child => child.className === 'analysis-gaps'));
  assert.doesNotMatch(rows.textContent, /Unresolved behavior/);
});
test('legacy unavailable advice shows its actual connection failure and source-sharing gaps', () => {
  const ui = app();
  ui.receive({ type: 'snapshot', sessions: [{ key: 'chat', id: 'chat', commands: [{ id: 'one', version: 1, command: 'node test.js', severity: 'unknown' }] }], page: { sessionKey: 'chat', total: 1, limit: 100, offset: 0 } });
  ui.elements.get('commands').children[0].open = true;
  ui.elements.get('commands').children[0].dispatch('toggle');
  const command = { id: 'one', version: 1, command: 'node test.js', severity: 'unknown', reason: 'Review required', status: 'completed', decision: 'ask', coverage: 'partial', startedAt: 0, output: { text: '' }, outputChars: 0 };
  for (const detail of ['Service write: Broken pipe (os error 32)', 'Resource temporarily unavailable (os error 35)']) {
    ui.receive({ type: 'command', sessionKey: 'chat', command: { ...command, judge: { status: 'unavailable', reason: 'Optional judge unavailable', detail } } });
    assert.match(ui.elements.get('commands').textContent, /Model advice · connection failed/);
    assert.ok(ui.elements.get('commands').textContent.includes(detail));
  }
  ui.receive({ type: 'command', sessionKey: 'chat', command: { ...command, judge: { status: 'advisory', severity: 'high', source_review: { sharing_enabled: false, inspected_files: 1, shared_files: 0, omitted_files: 1 } } } });
  assert.match(ui.elements.get('commands').textContent, /Script source was not shared/);
  ui.receive({ type: 'command', sessionKey: 'chat', command: { ...command, judge: { status: 'advisory', severity: 'high', source_review: { sharing_enabled: true, inspected_files: 0, shared_files: 0, omitted_files: 0, missing_source: true } } } });
  assert.match(ui.elements.get('commands').textContent, /file contents could not be reviewed/);
});
