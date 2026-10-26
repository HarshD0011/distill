'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { SessionTitles } = require('../src/titles');

function fixture(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'distill-title-test-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return { home, file: path.join(home, 'session_index.jsonl'), titles: new SessionTitles(home) };
}
const sessions = [{ source: 'codex', id: 'chat-id', key: 'key', updatedAt: 100, commands: [] }];
test('Codex titles are matched by ID, renamed, and limited to observed chats', async t => {
  const { file, titles } = fixture(t);
  fs.writeFileSync(file, [
    { id: 'chat-id', thread_name: 'Old heading', updated_at: '2026-10-17T10:00:00Z' },
    { id: 'unrelated-chat', thread_name: 'Do not retain this title', updated_at: '2026-10-18T10:00:00Z' },
    { id: 'chat-id', thread_name: 'Actual Codex heading', updated_at: '2026-10-18T10:00:00Z' },
  ].map(row => JSON.stringify(row)).join('\n') + '\n');
  assert.equal((await titles.enrich(sessions))[0].title, 'Actual Codex heading');
  assert.equal(titles.titles.has('unrelated-chat'), false);
  fs.appendFileSync(file, JSON.stringify({ id: 'chat-id', thread_name: 'Renamed heading', updated_at: '2026-10-18T11:00:00Z' }) + '\n');
  titles.checkedAt = 0;
  assert.equal((await titles.enrich(sessions))[0].title, 'Renamed heading');
});
test('unavailable or partially written title metadata never replaces the label with an ID', async t => {
  const { file, titles } = fixture(t);
  const fallback = (await titles.enrich(sessions))[0].title;
  assert.match(fallback, /^Codex chat/); assert.ok(!fallback.includes('chat-id'));
  fs.writeFileSync(file, '{incomplete\n' + JSON.stringify({ id: 'chat-id', thread_name: '<b>Literal</b>\n title', updated_at: '2026-10-18' }) + '\n{"id":');
  titles.checkedAt = 0;
  assert.equal((await titles.enrich(sessions))[0].title, '<b>Literal</b> title');
});
test('host-provided titles work without a Codex index and Claude IDs remain hidden', async t => {
  const { titles } = fixture(t);
  const named = await titles.enrich([{ ...sessions[0], title: 'Host heading' }, { ...sessions[0], source: 'claude', id: 'claude-id' }]);
  assert.equal(named[0].title, 'Host heading');
  assert.match(named[1].title, /^Claude chat/); assert.ok(!named[1].title.includes('claude-id'));
});
