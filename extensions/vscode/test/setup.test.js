'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { promisify } = require('node:util');
const execFile = promisify(require('node:child_process').execFile);
const { configureUserHooks, detectHosts } = require('../src/setup');
const extensionPath = path.resolve(__dirname, '..');
const binary = process.env.DISTILL_TEST_BINARY || path.resolve(extensionPath, '../../target/debug/distill');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'distill auto setup '));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home');
  const workspace = path.join(root, 'workspace');
  fs.mkdirSync(home); fs.mkdirSync(workspace);
  return { root, home, workspace, binary, extensionPath, roots: [workspace], env: { ...process.env, HOME: home, CODEX_HOME: path.join(home, '.codex'), DISTILL_TRACE_DIR: path.join(root, 'no-recorder') } };
}

test('automatic hook setup needs no Python, preserves other hooks, and is idempotent', { skip: !fs.existsSync(binary) }, async t => {
  const options = fixture(t);
  fs.mkdirSync(options.env.CODEX_HOME);
  const file = path.join(options.env.CODEX_HOME, 'hooks.json');
  const other = { matcher: 'Other', hooks: [{ type: 'command', command: 'echo unrelated' }] };
  fs.writeFileSync(file, JSON.stringify({ hooks: { PreToolUse: [other] } }));
  const [setup] = await configureUserHooks(options);
  assert.equal(setup.changed, true);
  const hooks = JSON.parse(fs.readFileSync(file));
  assert.deepEqual(hooks.hooks.PreToolUse[0], other);
  const handler = hooks.hooks.PreToolUse[1].hooks[0].command;
  assert.match(handler, /hook-launcher\.js/);
  assert.match(handler, /--mode advisory --label-command/);
  assert.ok(!handler.includes('python'));
  const before = fs.statSync(file).mtimeMs;
  assert.equal((await configureUserHooks(options))[0].changed, false);
  assert.equal(fs.statSync(file).mtimeMs, before);
  const payload = path.join(options.root, 'injected.js');
  const marker = path.join(options.root, 'must-not-run');
  fs.writeFileSync(payload, `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'unexpected');`);
  const env = { ...options.env, NODE_OPTIONS: `--require=${JSON.stringify(payload)}` };
  const event = { hook_event_name: 'PreToolUse', tool_name: 'Bash', cwd: options.workspace, tool_input: { command: 'echo hello', shell: '/bin/bash' } };
  // Candidate commands are JSON only; the launcher invokes analysis, not execution.
  const { spawnSync } = require('node:child_process');
  const run = input => spawnSync('/bin/sh', ['-c', handler + ' --no-prompt'], { env, input: JSON.stringify(input), encoding: 'utf8', timeout: 10000 });
  const safe = run(event);
  assert.equal(safe.status, 0, safe.stderr);
  assert.match(JSON.parse(safe.stdout).systemMessage, /Severity: SAFE/);
  assert.equal(fs.existsSync(marker), false, 'NODE_OPTIONS must be stripped before the editor runtime starts');
  const critical = run({ ...event, permission_mode: 'bypassPermissions', tool_input: { command: 'rm -rf /' } });
  assert.equal(JSON.parse(critical.stdout).hookSpecificOutput.permissionDecision, 'deny');
  const wrongPin = handler.replace(/--sha256 [0-9a-f]{64}/, '--sha256 ' + '0'.repeat(64));
  const mismatch = spawnSync('/bin/sh', ['-c', wrongPin], { env, input: JSON.stringify({ ...event, hook_event_name:'PermissionRequest' }), encoding:'utf8', timeout:10000 });
  assert.equal(mismatch.status, 2);
  assert.equal(JSON.parse(mismatch.stdout).hookSpecificOutput.decision.behavior, 'deny');
  assert.equal(fs.existsSync(path.join(options.home, '.config/distill/hook-launcher.py')), false);
  const inventory = JSON.parse((await execFile(binary, ['hook-sources', 'codex'], { env: options.env })).stdout);
  assert.equal(inventory.handlers.length, 3);
});

test('existing strict policy is preserved and dirty hook documents are never overwritten', { skip: !fs.existsSync(binary) }, async t => {
  const options = fixture(t);
  const directory = path.join(options.home, '.config/distill');
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const policy = path.join(directory, 'hook-policy-codex.toml');
  fs.writeFileSync(policy, '[agents.codex]\nmode="strict"\n[privacy]\ncapture_output=false\n');
  const [setup] = await configureUserHooks(options);
  const hooks = JSON.parse(fs.readFileSync(setup.path));
  assert.match(hooks.hooks.PreToolUse[0].hooks[0].command, /--mode strict/);
  const before = fs.readFileSync(setup.path, 'utf8');
  await assert.rejects(configureUserHooks({ ...options, force: true, isDirty: () => true }), /Save or revert/);
  assert.equal(fs.readFileSync(setup.path, 'utf8'), before);
  assert.match(fs.readFileSync(policy, 'utf8'), /mode = "strict"/);
});

test('Codex is configured on first install and existing Claude installs are also connected', t => {
  const options = fixture(t);
  assert.deepEqual(detectHosts(options.home), ['codex']);
  fs.mkdirSync(path.join(options.home, '.claude'));
  assert.deepEqual(detectHosts(options.home), ['codex', 'claude']);
});
