'use strict';
// Run by the isolated lifecycle driver, not the standalone Node test runner.
const assert = require('node:assert/strict');
const vscode = require('vscode');
const { connectBroker } = require('../../src/client');
const { rpc } = require('../../src/transport');
const { SessionTitles } = require('../../src/titles');
const { app } = require('../helpers/webview');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

async function smoke() {
  const extension = vscode.extensions.getExtension('distill.distill-trace');
  assert.ok(extension, 'Packaged extension was discovered');
  await extension.activate();
  const runtime = await extension.exports.ready();
  assert.equal(runtime.managed, true, 'The extension installs its CLI without a configured binary');
  assert.ok(runtime.binary.startsWith(path.dirname(process.env.DISTILL_HOST_TEST_RESULT)), 'The CLI lives in the isolated profile, not a system installation');
  process.env.DISTILL_TEST_BINARY = runtime.binary;
  assert.ok(extension.isActive);
  assert.equal(require('node:fs').realpathSync(extension.extensionPath), require('node:fs').realpathSync(process.env.DISTILL_HOST_TEST_EXTENSION), 'The installed VSIX is active');
  assert.ok(Number(process.env.VSCODE_PID) > 1, 'Main application identity is available');
  const roots = vscode.workspace.workspaceFolders.map(folder => require('node:fs').realpathSync(folder.uri.fsPath));
  const endpoint = await connectBroker(roots, process.env.DISTILL_TEST_BINARY);
  const fs = require('node:fs');
  assert.equal(fs.existsSync(path.join(process.env.HOME, '.cargo/bin/distill')), false);
  const hookPath = path.join(process.env.CODEX_HOME, 'hooks.json');
  const installedHooks = JSON.parse(fs.readFileSync(hookPath, 'utf8'));
  const handler = installedHooks.hooks.PreToolUse.find(group => group.matcher === '^Bash$').hooks[0].command;
  assert.ok(handler.includes(runtime.binary));
  assert.match(handler, /hook-launcher\.js/);
  assert.ok(!handler.includes('python'));
  const autoEvent = { hook_event_name:'PreToolUse', tool_name:'Bash', cwd:roots[0], tool_input:{command:'echo first-run',shell:'/bin/bash'} };
  const automatic = require('node:child_process').spawnSync('/bin/sh', ['-c', handler], { input:JSON.stringify(autoEvent), encoding:'utf8', timeout:10000 });
  assert.equal(automatic.status, 0, automatic.stderr);
  assert.match(JSON.parse(automatic.stdout).systemMessage, /Severity: SAFE/);
  const otherRoot = path.join(path.dirname(roots[0]), 'other-workspace');
  fs.mkdirSync(otherRoot, { recursive: true });
  await rpc(endpoint, { action: 'register', roots: [otherRoot] });
  const phaseFile = process.env.DISTILL_HOST_TEST_RESULT + '.reload';
  const reloaded = process.env.DISTILL_HOST_TEST_RESULT && fs.existsSync(phaseFile);
  const event = { protocol: 1, source: 'codex', kind: 'completion', session_id: 'extension-host-smoke', tool_use_id: 'smoke-command', timestamp: Date.now(), command: 'echo smoke', session_cwd: roots[0], tool_response: 'one\ntwo\nthree\nfour\nfive\nsix' };
  if (!reloaded) {
    for (const [id, latency] of [['one', 1], ['two', 5]]) await rpc(endpoint, { action: 'record', event: { ...event, kind: 'assessment', hook_event_name: 'PreToolUse', report: {
      report_id: id, severity: 'safe', impact_severity: 'safe', decision: 'allow', coverage: { summary: 'static_accounted' }, explanation: `distill SAFE (${latency} ms; approval risk SAFE): No modeled hazardous effect found`,
    } } });
    await rpc(endpoint, { action: 'record', event });
    await rpc(endpoint, { action: 'record', event: { ...event, session_id: 'other-workspace', session_cwd: otherRoot, cwd: otherRoot, tool_use_id: 'other-command' } });
    const policy = path.join(roots[0], 'test-policy.toml');
    const key = path.join(roots[0], 'test-label-key');
    fs.writeFileSync(key, require('node:crypto').randomBytes(32), { mode: 0o600 });
    fs.writeFileSync(policy, `[security]\nlabel_key_path=${JSON.stringify(key)}\n[privacy]\ncapture_output=false\n[ledger]\nenabled=false\n`, { mode: 0o600 });
    fs.writeFileSync(path.join(roots[0], 'input.txt'), 'ordinary fixture\n');
    fs.writeFileSync(path.join(roots[0], '.env'), 'fake_sensitive_fixture=needle\n');
    // These are hook events only; none of the candidate commands are executed.
    for (const [id, command] of [['safe', 'echo hello'], ['low', 'cat input.txt'], ['high', 'cat .env'], ['critical', 'rm -rf /'], ['unknown', 'mystery-command --flag'], ['partial', 'cat --unmodeled-option input.txt'],
      ['git-output', 'git diff --output=.env'], ['sql-cte', "psql -c 'WITH gone AS (DELETE FROM accounts RETURNING *) SELECT * FROM gone'"],
      ['sql-predicate', "psql -c 'DELETE FROM accounts WHERE 2 * 3 = 6'"], ['client-shell', "sqlite3 scratch.db '.shell rm -rf /'"],
      ['native-loader', "sqlite3 scratch.db \"SELECT load_extension('./module')\""], ['script-read', 'psql -f .env']]) {
      const pre = { hook_event_name: 'PreToolUse', tool_name: 'Bash', session_id: event.session_id, tool_use_id: `hook-${id}`, cwd: roots[0], tool_input: { command, shell:'/bin/bash' } };
      const args = ['hook', 'codex', '--no-prompt', '--mode', 'advisory', '--config', policy];
      const labeled = JSON.parse(execFileSync(process.env.DISTILL_TEST_BINARY, [...args, '--label-command'], { input: JSON.stringify(pre), encoding: 'utf8', timeout: 5000 }));
      if (labeled.hookSpecificOutput.permissionDecision !== 'deny') execFileSync(process.env.DISTILL_TEST_BINARY, args, { input: JSON.stringify({ ...pre, hook_event_name: 'PostToolUse', tool_input: labeled.hookSpecificOutput.updatedInput, tool_response: { exit_code: 0 } }), encoding: 'utf8', timeout: 5000 });
    }
    await rpc(endpoint, { action: 'record', event: { ...event, tool_use_id: 'unassessed', command: 'echo missing-assessment' } });
    if (process.env.DISTILL_HOST_TEST_RESULT) {
      fs.writeFileSync(phaseFile, JSON.stringify({ socket: endpoint.socket, owner: process.env.VSCODE_PID, binary:runtime.binary, hookMtime:fs.statSync(hookPath).mtimeMs }));
      // Reload destroys this extension host and cancels its command promise.
      void vscode.commands.executeCommand('workbench.action.reloadWindow').then(() => {}, () => {});
      await new Promise(() => {});
    }
  } else {
    const previous = JSON.parse(fs.readFileSync(phaseFile, 'utf8'));
    assert.equal(endpoint.socket, previous.socket, 'Window reload retains the same broker');
    assert.equal(process.env.VSCODE_PID, previous.owner, 'Reload preserves the owning application');
    assert.equal(runtime.binary, previous.binary, 'Reload reuses the immutable installed CLI');
    assert.equal(fs.statSync(hookPath).mtimeMs, previous.hookMtime, 'Reload does not rewrite approved hook definitions');
  }
  await vscode.commands.executeCommand('distill.openTrace');
  const reconnected = await connectBroker(roots, process.env.DISTILL_TEST_BINARY);
  assert.equal(reconnected.socket, endpoint.socket);
  const session = (await rpc(reconnected, { action: 'snapshot' })).sessions.find(session => session.id === event.session_id);
  assert.equal((await new SessionTitles().enrich([session]))[0].title, 'Reload smoke chat');
  const compact = (await rpc(reconnected, { action: 'snapshot', compact: true })).sessions.find(session => session.id === event.session_id);
  assert.deepEqual(Object.keys(compact.commands[0]).sort(), ['assessmentState', 'command', 'id', 'severity', 'version']);
  assert.equal(compact.commands[0].assessmentState, 'rated');
  const clearCommand = extension.packageJSON.contributes.commands.find(command => command.command === 'distill.clearTrace');
  assert.equal(clearCommand.title, 'Distill: Clear Logs');
  assert.ok(extension.packageJSON.contributes.menus['view/title'].some(item => item.command === 'distill.clearTrace'));
  const ui = app(path.join(extension.extensionPath, 'media/trace.js'));
  ui.receive({ type: 'snapshot', scopedClear: true, sessions: [compact], page: { sessionKey: session.key, total: compact.commands.length, offset: 0, limit: 100 } });
  for (const [id, severity] of [['hook-safe', 'safe'], ['hook-low', 'low'], ['hook-high', 'high'], ['hook-critical', 'critical'], ['hook-unknown', 'unknown'], ['hook-partial', 'low'], ['hook-git-output', 'high'], ['hook-sql-cte', 'critical'], ['hook-sql-predicate', 'critical'], ['hook-client-shell', 'critical'], ['hook-native-loader', 'high'], ['hook-script-read', 'high'], ['unassessed', 'unassessed']]) {
    const index = compact.commands.findIndex(command => command.id === id);
    assert.notEqual(index, -1, id);
    assert.equal(ui.elements.get('commands').children[index].children[0].children[0].textContent, severity, `${id} packaged sidebar badge`);
  }
  const partial = (await rpc(reconnected, { action: 'command', sessionKey: session.key, id: 'hook-partial' })).command;
  assert.equal(partial.severity, 'low');
  assert.equal(partial.approvalRisk, 'medium');
  assert.equal(ui.elements.get('clear').textContent, 'Clear logs');
  ui.elements.get('clear').dispatch('click');
  assert.deepEqual(ui.messages.at(-1), { type: 'clear' });
  const detail = (await rpc(reconnected, { action: 'command', sessionKey: session.key, id: event.tool_use_id })).command;
  assert.equal(detail.output.hasMore, true);
  assert.equal(detail.sessionId, event.session_id);
  assert.equal(detail.assessmentCount, 1, 'Equivalent assessments stay merged across reload');
  assert.equal(session.commands[0].output.hasMore, true);
  assert.equal(session.commands[0].output.text.split('\n').length, 5);
  assert.equal((await rpc(reconnected, { action: 'output', sessionKey: session.key, id: event.tool_use_id })).text, event.tool_response);
  await vscode.commands.executeCommand('distill.clearTrace');
  assert.deepEqual((await rpc(endpoint, { action: 'snapshot', roots })).sessions, []);
  assert.equal((await rpc(endpoint, { action: 'snapshot', roots: [otherRoot] })).sessions[0].id, 'other-workspace', 'Clear logs preserves other workspace history');
  await rpc(endpoint, { action: 'record', event: { ...event, timestamp: Date.now(), tool_use_id: 'after-clear', command: 'echo new-log' } });
  assert.equal((await rpc(endpoint, { action: 'snapshot', roots })).sessions[0].commands.length, 1, 'Recording continues after clearing');
  console.log('Distill extension-host smoke passed: installed package activation, actual reload, real signed hook verdict badges, impact versus approval risk, clear action, workspace isolation, continued recording.');
}

async function run() {
  try {
    await smoke();
    if (process.env.DISTILL_HOST_TEST_RESULT) require('node:fs').writeFileSync(process.env.DISTILL_HOST_TEST_RESULT, 'passed');
  } catch (error) {
    if (process.env.DISTILL_HOST_TEST_RESULT) require('node:fs').writeFileSync(process.env.DISTILL_HOST_TEST_RESULT, error.stack || String(error));
    throw error;
  }
}

module.exports = { run };
