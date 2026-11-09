'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { TraceStore } = require('../src/store');
const { normalizeDetails } = require('../src/assessments');
const { exportSession } = require('../src/export');
const { app } = require('./helpers/webview');
const event = { protocol: 1, kind: 'assessment', source: 'codex', session_id: 'chat', tool_use_id: 'call', timestamp: 10, command: 'node app.mjs', session_cwd: '/workspace', cwd: '/workspace', hook_event_name: 'PreToolUse', report: { impact_severity: null, severity: 'high', decision: 'ask', unknowns: ['Node package imports are unresolved'], coverage: { summary: 'partial' }, coverage_gaps: [{ code: 'dependency', message: 'Node package imports are unresolved' }], graph: { parse_complete: true, nodes: [{ id: 0, kind: 'command', program: 'node', span: { start_byte: 0, end_byte: 12, line: 1, column: 1 } }] }, judge: { status: 'advisory', proposal: { explanation: '<script>not HTML</script>', effects: [] } }, timings_ms: { total: 3, stages: { static: 2, judge: 1 } } } };

test('LLM settings stay accessible before connection and routing status updates without recorder events', () => {
  const ui = app();
  ui.elements.get('router-settings').dispatch('click');
  assert.equal(ui.messages.at(-1).type, 'configure-router');
  ui.receive({ type: 'router-state', router: { status: 'ready', enabled: false } });
  assert.equal(ui.elements.get('router-status').textContent, 'Static analysis only · LLM router off');
  ui.receive({ type: 'router-state', router: { status: 'ready', enabled: true, running: true, model: 'my-local-model' } });
  assert.match(ui.elements.get('router-status').textContent, /LLM advice · my-local-model/);
  ui.receive({ type: 'router-state', router: { status: 'ready', enabled: true, running: false, model: 'my-local-model' } });
  assert.match(ui.elements.get('router-status').textContent, /unavailable · static fallback/);
  ui.receive({ type: 'error', message: 'Recorder disconnected' });
  ui.elements.get('router-settings').dispatch('click');
  assert.equal(ui.messages.at(-1).type, 'configure-router');
});

test('structured evidence survives recorder compaction and older-broker normalization', () => {
  const store = new TraceStore(); store.record(event);
  const key = store.snapshot().sessions[0].key;
  const detail = normalizeDetails(store.readCommand(key, 'call'));
  assert.equal(detail.coverageGaps[0].code, 'dependency'); assert.equal(detail.graph.nodes[0].span.end_byte, 12);
  assert.equal(detail.judge.status, 'advisory'); assert.equal(detail.timings.stages.judge, 1);
  const older = normalizeDetails({ assessments: [{ hook: 'PreToolUse', report: event.report }] });
  assert.deepEqual(older.coverageGaps, detail.coverageGaps);
});
test('feedback is bounded, exports are redacted, and missing completion stays unobserved', () => {
  const store = new TraceStore(); store.record(event); const key = store.snapshot().sessions[0].key;
  store.feedback(key, 'call', { kind: 'over', note: 'token=private-value' });
  const data = store.exportSession(key); assert.equal(data.commands[0].status, 'proposed');
  const json = exportSession(data); assert.ok(!json.includes('private-value')); assert.match(json, /REDACTED/);
  const markdown = exportSession(data, 'markdown'); assert.match(markdown, /missing completion does not establish rejection/i);
  assert.throws(() => store.feedback(key, 'call', { kind: 'allow' }), /Invalid/);
  const persistentKey = require('node:crypto').createHash('sha256').update(JSON.stringify(['codex', 'chat', '/workspace'])).digest('hex');
  const restored = { session_key: persistentKey, tool_id: 'call', kind: 'under', note: 'Restored feedback', timestamp: 5 };
  store.restoreFeedback([restored, restored]);
  assert.equal(store.readCommand(key, 'call').feedback.filter(v => v.note === 'Restored feedback').length, 1);
  const bounded = new TraceStore({ bytes: 1 }); assert.throws(() => bounded.feedback(key, 'call', { kind: 'over' }), /available/);
});
test('the webview presents categorized gaps and model advice as text, and sends feedback', () => {
  const ui = app();
  ui.receive({ type: 'snapshot', version: 1, page: { sessionKey: 'key', offset: 0, limit: 100, total: 1 }, sessions: [{ key: 'key', id: 'chat', commands: [{ id: 'call', version: 1, command: event.command, severity: 'unknown' }] }] });
  const row = ui.elements.get('commands').children[0]; row.open = true; row.dispatch('toggle');
  const store = new TraceStore(); store.record(event); const detail = normalizeDetails(store.readCommand(store.snapshot().sessions[0].key, 'call'));
  ui.receive({ type: 'command', sessionKey: 'key', command: { ...detail, version: 1 } });
  const section = ui.elements.get('commands').children[0].children[1];
  assert.match(section.textContent, /Dependency.*Node package/); assert.match(section.textContent, /Model advice.*advisory/);
  assert.match(section.textContent, /Parsed command structure/); assert.ok(section.textContent.includes('<script>not HTML</script>'));
  const feedback = section.children.find(v => v.className === 'toolbar'); feedback.children[0].dispatch('click');
  assert.equal(ui.messages.at(-1).type, 'feedback'); assert.equal(ui.messages.at(-1).kind, 'over');
});
