'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { promisify } = require('node:util');
const execFile = promisify(require('node:child_process').execFile);
const { app } = require('./helpers/webview');
const { normalizeDetails } = require('../src/assessments');
const root = path.resolve(__dirname, '../../..');
const binary = process.env.DISTILL_TEST_BINARY || path.join(root, 'target/debug/distill');

test('real signed hooks and recorder preserve impact badges, separate approval risk, UNKNOWN and unassessed in the sidebar renderer', { skip: !fs.existsSync(binary) }, async () => {
  const { stdout } = await execFile(process.execPath, [path.join(root, 'scripts/trace_label_audit.js'), binary, '--extension-check'], { timeout: 20000 });
  const result = JSON.parse(stdout);
  assert.equal(result.candidateExecution, false);
  assert.equal(result.rows, 14);
  assert.equal(result.unassessed, 1);
  assert.equal(result.completed, 10);
  assert.equal(result.blocked, 4);
  const session = result.extension.session;
  const ui = app();
  ui.receive({ type: 'snapshot', scopedClear: true, sessions: [session], page: { sessionKey: session.key, total: 14, offset: 0, limit: 100 } });
  const expected = { literal: 'safe', 'ordinary-read': 'low', 'root-delete': 'critical', opaque: 'unknown', 'credential-read': 'high', 'sql-query': 'medium', 'partial-read': 'low', 'git-credential-output': 'high', 'sql-cte-delete': 'critical', 'sql-constant-delete': 'critical', 'client-shell-delete': 'critical', 'native-loader': 'high', 'client-script-read': 'high', missing: 'unassessed' };
  for (const [id, badge] of Object.entries(expected)) {
    const index = session.commands.findIndex(entry => entry.id === id);
    assert.notEqual(index, -1, id);
    let row = ui.elements.get('commands').children[index];
    assert.equal(row.children[0].children[0].textContent, badge, `${id} collapsed badge`);
    row.open = true; row.dispatch('toggle');
    const command = normalizeDetails(result.extension.details.find(detail => detail.id === id));
    ui.receive({ type: 'command', sessionKey: session.key, command });
    row = ui.elements.get('commands').children[index];
    assert.equal(row.children[0].children[0].textContent, badge, `${id} expanded badge`);
    if (id === 'partial-read') {
      assert.equal(command.approvalRisk, 'medium');
      assert.match(row.textContent, /Approval risk.*medium/);
    }
    if (id === 'opaque') assert.match(row.textContent, /could not establish an impact rating/);
    if (id === 'missing') assert.match(row.textContent, /No pre-command assessment was received/);
    // The renderer presents the actual engine effect, without classifying command text itself.
    if (id === 'git-credential-output') {
      assert.equal(command.approvalRisk, 'high');
      assert.ok(command.assessments.some(revision => revision.report?.behaviors?.some(behavior => behavior.kind === 'file_write' && behavior.target_class === 'secret')));
    }
    if (id === 'sql-cte-delete' || id === 'sql-constant-delete') {
      const primary = command.assessments.find(revision => revision.hook === 'PreToolUse').report;
      assert.equal(primary.behavior_policy_version, '9');
      assert.ok(primary.behaviors.some(behavior => behavior.kind === 'database' && behavior.database?.action === 'delete' && behavior.database.scope === 'all_rows'));
      assert.match(row.textContent, /Modeled effects.*all rows/);
    }
  }
});
