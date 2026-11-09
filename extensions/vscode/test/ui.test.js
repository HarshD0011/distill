'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { app } = require('./helpers/webview');
const snapshot = { type: 'snapshot', version: 1, page: { sessionKey: 'session-key', total: 1, limit: 100, offset: 0 }, sessions: [{ key: 'session-key', id: 'opaque-id', title: 'Fix command trace', commandCount: 1, commands: [{ id: 'tool', version: 1, severity: 'low', command: 'echo one\necho two' }] }] };
const detail = { type: 'command', sessionKey: 'session-key', command: { id: 'tool', version: 1, command: 'echo one\necho two', severity: 'low', decision: 'allow', coverage: 'static_accounted', reason: 'Reason visible only after clicking', status: 'completed', shell: 'bash', startedAt: 1, completedAt: 2, cwd: '/workspace', outputChars: 23, output: { text: 'one\ntwo', hasMore: true }, assessments: [], sessionId: 'opaque-id' } };

test('collapsed command rows show severity and a compact command, and fetch details only on click', () => {
  const ui = app(); ui.receive(snapshot);
  assert.match(ui.elements.get('chat').textContent, /Fix command trace/);
  assert.ok(!ui.elements.get('chat').textContent.includes('opaque-id'));
  const commands = ui.elements.get('commands');
  assert.equal(commands.children[0].tagName, 'details');
  assert.equal(commands.children[0].children.length, 1);
  assert.match(commands.textContent, /low.*echo one echo two/);
  assert.ok(!commands.textContent.includes('Reason visible'));
  assert.equal(ui.messages.filter(message => message.type === 'command').length, 0);
  const row = commands.children[0]; row.open = true; row.dispatch('toggle');
  assert.equal(ui.messages.filter(message => message.type === 'command').length, 1);
  ui.receive(detail);
  assert.match(commands.textContent, /Reason visible only after clicking/);
  assert.match(commands.textContent, /Read more/);
  const expanded = commands.children[0]; expanded.open = false; expanded.dispatch('toggle');
  assert.equal(expanded.children.length, 1);
  assert.ok(!commands.textContent.includes('Reason visible'));
});

test('incoming commands preserve an expanded row and do not refetch unchanged details', () => {
  const ui = app(); ui.receive(snapshot);
  const row = ui.elements.get('commands').children[0]; row.open = true; row.dispatch('toggle'); ui.receive(detail);
  ui.receive({ ...snapshot, version: 2 });
  assert.equal(ui.elements.get('commands').children[0].open, true);
  assert.match(ui.elements.get('commands').textContent, /Reason visible only after clicking/);
  assert.equal(ui.messages.filter(message => message.type === 'command').length, 1);
});

test('a model response ahead of its snapshot cannot leave command details permanently loading', () => {
  const ui = app(); ui.receive(snapshot);
  const row = ui.elements.get('commands').children[0]; row.open = true; row.dispatch('toggle');
  const updated = { ...detail, command: { ...detail.command, version: 2, assessmentState: 'advisory', judge: { status: 'advisory', severity: 'low', proposal: { explanation: 'Live model response' } } } };
  ui.receive(updated); // Broker has advanced while the visible snapshot is older.
  assert.equal(ui.messages.filter(message => message.type === 'command').length, 1);
  ui.receive({ ...snapshot, version: 2, sessions: [{ ...snapshot.sessions[0], commands: [{ ...snapshot.sessions[0].commands[0], version: 2, assessmentState: 'advisory' }] }] });
  assert.equal(ui.messages.filter(message => message.type === 'command').length, 2, 'The new command version must get a fresh detail request');
  ui.receive(detail); // Old replies cannot clear or replace the current request.
  assert.doesNotMatch(ui.elements.get('commands').textContent, /Live model response/);
  ui.receive(updated);
  assert.match(ui.elements.get('commands').textContent, /Model advice · advisory · low/);
  assert.match(ui.elements.get('commands').textContent, /Live model response/);
  assert.doesNotMatch(ui.elements.get('commands').textContent, /Loading command details/);
});

test('expanded rows keep the full command and technical context behind More details', () => {
  const ui = app(); ui.receive(snapshot);
  const row = ui.elements.get('commands').children[0]; row.open = true; row.dispatch('toggle'); ui.receive(detail);
  const section = ui.elements.get('commands').children[0].children[1];
  assert.ok(!section.children.some(child => child.className === 'command-full'));
  const more = section.children.find(child => child.tagName === 'details' && child.children[0].textContent === 'More details');
  assert.ok(more); assert.ok(!more.open);
  assert.match(more.textContent, /Analysis.*Directory.*Shell.*Time/);
  assert.ok(more.children.some(child => child.className === 'command-full'));
  assert.match(section.children.find(child => child.className === 'metadata').textContent, /Decision.*allow.*Status.*completed/);
});

test('unassessed completions have a separate badge and analysis limits stay behind More details', () => {
  const ui = app();
  const rows = [
    { id: 'missing', version: 1, command: 'echo missed pre-hook', severity: 'unknown', assessmentState: 'missing' },
    { id: 'opaque', version: 1, command: 'opaque-program', severity: 'unknown', assessmentState: 'unknown' },
  ];
  ui.receive({ ...snapshot, page: { ...snapshot.page, total: 2 }, sessions: [{ ...snapshot.sessions[0], commandCount: 2, commands: rows }] });
  const commands = ui.elements.get('commands');
  assert.equal(commands.children[0].children[0].children[0].textContent, 'unassessed');
  assert.equal(commands.children[1].children[0].children[0].textContent, 'unknown');
  const row = commands.children[1]; row.open = true; row.dispatch('toggle');
  ui.receive({ ...detail, command: { ...detail.command, ...rows[1], assessmentState: 'unknown', unknowns: ['Executable behavior is not modeled'], behaviorPolicyVersion: 7 } });
  assert.match(commands.textContent, /could not establish an impact rating/);
  assert.doesNotMatch(commands.textContent, /Unresolved behavior/);
  const section = commands.children[1].children[1];
  assert.ok(!section.children.some(child => child.className === 'analysis-gaps'));
  const more = section.children.find(child => child.tagName === 'details' && child.children[0].textContent === 'More details');
  assert.ok(!more.open);
  assert.match(more.textContent, /Analysis limits.*Executable behavior is not modeled/);
  assert.match(commands.textContent, /Behavior policy.*7/);
});

test('an older recorder can identify a missing assessment on expansion without rewriting history', () => {
  const ui = app();
  ui.receive({ ...snapshot, sessions: [{ ...snapshot.sessions[0], commands: [{ ...snapshot.sessions[0].commands[0], severity: 'unknown' }] }] });
  const row = ui.elements.get('commands').children[0]; row.open = true; row.dispatch('toggle');
  ui.receive({ ...detail, command: { ...detail.command, severity: 'unknown', assessmentState: 'missing', decision: 'unavailable', reason: 'No pre-command assessment was received.' } });
  assert.equal(ui.elements.get('commands').children[0].children[0].children[0].textContent, 'unassessed');
  assert.match(ui.elements.get('commands').textContent, /No pre-command assessment was received/);
});

test('Clear logs sends a clear request and only removes rows after the recorder acknowledges it', () => {
  const ui = app(); ui.receive({ ...snapshot, scopedClear: true });
  const button = ui.elements.get('clear');
  assert.equal(button.textContent, 'Clear logs');
  assert.match(button.title, /this workspace/);
  assert.equal(button.disabled, false);
  button.dispatch('click');
  assert.deepEqual(ui.messages.at(-1), { type: 'clear' });
  assert.equal(ui.elements.get('commands').children.length, 1);
  ui.receive({ type: 'cleared' });
  assert.equal(ui.elements.get('commands').children.length, 0);
  assert.equal(ui.elements.get('count').textContent, '0 commands');
  assert.equal(ui.elements.get('chat').disabled, true);
  assert.equal(button.disabled, true);
});

test('clearing drops expanded details, cached output, filters and late responses, then accepts new logs', () => {
  const ui = app(); ui.receive(snapshot);
  const row = ui.elements.get('commands').children[0]; row.open = true; row.dispatch('toggle');
  ui.receive(detail);
  ui.receive({ type: 'output', sessionKey: 'session-key', id: 'tool', version: 1, text: 'old retained full output' });
  ui.elements.get('search').value = 'old filter';
  ui.receive({ type: 'cleared' });
  ui.receive(detail);
  ui.receive({ type: 'output', sessionKey: 'session-key', id: 'tool', version: 1, text: 'late retained full output' });
  assert.equal(ui.elements.get('commands').children.length, 0);
  assert.equal(ui.elements.get('search').value, '');
  ui.receive(snapshot);
  const fresh = ui.elements.get('commands').children[0];
  assert.equal(fresh.open, false);
  fresh.open = true; fresh.dispatch('toggle');
  assert.match(ui.elements.get('commands').textContent, /Loading command details/);
  assert.ok(!ui.elements.get('commands').textContent.includes('retained full output'));
  assert.equal(ui.elements.get('clear').disabled, false);
});
