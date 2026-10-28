'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { rpc, readEndpoint, processIdentity, endpointPath } = require('../src/transport');

const repository = path.resolve(__dirname, '../../..');
const binary = process.env.DISTILL_TEST_BINARY || path.join(repository, 'target/debug/distill');
const brokerScript = path.resolve(__dirname, '../src/broker.js');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function waitFor(check, message) {
  for (let i = 0; i < 100; i++) {
    try { const result = await check(); if (result) return result; } catch {}
    await pause(30);
  }
  throw new Error(message);
}
async function launch(t) {
  const directory = fs.mkdtempSync('/tmp/distill-trace-test-');
  const owner = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  let broker;
  t.after(async () => {
    owner.kill();
    if (broker && broker.exitCode === null) {
      await Promise.race([once(broker, 'exit'), pause(1500)]);
      if (broker.exitCode === null) broker.kill();
    }
    fs.rmSync(directory, { recursive: true, force: true });
  });
  await once(owner, 'spawn');
  const identity = processIdentity(owner.pid);
  const file = endpointPath(directory, owner.pid, identity, [repository]);
  broker = spawn(process.execPath, [brokerScript], { stdio: ['pipe', 'ignore', 'pipe'] });
  broker.stderr.on('data', chunk => process.stderr.write(chunk));
  broker.stdin.end(JSON.stringify({ directory, ownerPid: owner.pid, ownerIdentity: identity, roots: [repository], peerBinary: binary }));
  const endpoint = await waitFor(() => readEndpoint(file), 'Broker did not start');
  return { directory, file, endpoint, owner, broker };
}

test('broker authenticates, rejects other workspaces, and retains traces across client reconnects', async t => {
  const { directory, endpoint } = await launch(t);
  await assert.rejects(rpc({ ...endpoint, token: 'a'.repeat(64) }, { action: 'snapshot' }), /Unauthorized/);
  const event = { protocol: 1, source: 'codex', kind: 'completion', session_id: 'chat', tool_use_id: 'tool', command: 'echo private-marker', session_cwd: repository, timestamp: 10, tool_response: 'private-output-marker' };
  await assert.rejects(rpc(endpoint, { action: 'record', event: { ...event, session_cwd: `${repository}-different` } }), /another workspace/);
  await rpc(endpoint, { action: 'record', event });
  const snapshot = await rpc(endpoint, { action: 'snapshot' });
  assert.equal(snapshot.sessions[0].commands[0].command, event.command);
  // Each RPC opens a fresh socket, just as an extension host reconnects after reload.
  const reconnected = await rpc(endpoint, { action: 'snapshot' });
  assert.deepEqual(reconnected.sessions, snapshot.sessions);
  assert.equal((await rpc(endpoint, { action: 'snapshot', version: snapshot.version })).unchanged, true);
  for (const file of fs.readdirSync(directory)) {
    if (!fs.statSync(path.join(directory, file)).isFile()) continue;
    const bytes = fs.readFileSync(path.join(directory, file), 'utf8');
    assert.ok(!bytes.includes('private-marker') && !bytes.includes('private-output-marker'));
    assert.equal(fs.statSync(path.join(directory, file)).mode & 0o077, 0);
  }
  await rpc(endpoint, { action: 'clear' });
  assert.deepEqual((await rpc(endpoint, { action: 'snapshot' })).sessions, []);
});

test('editor quit terminates the broker and removes its endpoint and lock', async t => {
  const { owner, broker, file, endpoint, directory } = await launch(t);
  const exited = once(broker, 'exit');
  owner.kill();
  await Promise.race([exited, pause(3000)]);
  assert.notEqual(broker.exitCode, null, 'Broker must exit when the editor exits');
  assert.equal(fs.existsSync(file), false);
  assert.deepEqual(fs.readdirSync(directory), []);
  await assert.rejects(rpc(endpoint, { action: 'snapshot' }));
});

test('real CLI joins assessments to large completion output and keeps native hook responses', { skip: !fs.existsSync(binary) }, async t => {
  const { endpoint, directory, owner } = await launch(t);
  const policy = path.join(directory, 'test-policy.toml');
  fs.writeFileSync(policy, '[privacy]\ncapture_output=true\n[ledger]\nenabled=false\n');
  async function hook(event, mode = 'advisory') {
    const process = spawn(binary, ['hook', 'codex', '--no-prompt', '--mode', mode, '--config', policy], { env: { ...global.process.env, DISTILL_TRACE_DIR: directory, VSCODE_PID: String(owner.pid) }, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = '';
    process.stdout.on('data', chunk => { stdout += chunk; });
    process.stderr.on('data', chunk => { stderr += chunk; });
    process.stdin.end(JSON.stringify(event));
    const [code] = await once(process, 'exit');
    assert.equal(code, 0, stderr);
    assert.equal(stderr, '');
    return JSON.parse(stdout);
  }
  const pre = { hook_event_name: 'PreToolUse', tool_name: 'Bash', session_id: 'chat-a', tool_use_id: 'tool-1', cwd: repository, tool_input: { command: 'echo private-command', shell: '/bin/bash' } };
  const response = await hook(pre);
  assert.equal(response.hookSpecificOutput.permissionDecision, undefined);
  await hook(pre); // Fresh report IDs/timings for the same result must not duplicate history.
  await hook({ ...pre, hook_event_name: 'PermissionRequest' });
  const output = Array.from({ length: 30000 }, (_, index) => `private-output-${index}`).join('\n');
  assert.deepEqual(await hook({ ...pre, hook_event_name: 'PostToolUse', tool_response: { stdout: output, stderr: 'failure detail', exit_code: 2 } }), {});
  await hook({ ...pre, session_id: 'chat-b' });
  const snapshot = await rpc(endpoint, { action: 'snapshot' });
  assert.equal(snapshot.sessions.length, 2);
  const session = snapshot.sessions.find(session => session.id === 'chat-a');
  assert.equal(session.commands.length, 1);
  assert.equal(session.commands[0].assessmentCount, 2, 'One PreToolUse and one PermissionRequest assessment');
  assert.equal(session.commands[0].status, 'failed');
  assert.equal(session.commands[0].severity, 'safe');
  assert.equal(session.commands[0].output.text.split('\n').length, 5);
  assert.equal(session.commands[0].output.hasMore, true);
  assert.equal((await rpc(endpoint, { action: 'output', sessionKey: session.key, id: 'tool-1' })).text, output + '\n[stderr]\nfailure detail');
  const denied = await hook({ ...pre, tool_use_id: 'denied', tool_input: { command: 'rm -rf /' } }, 'strict');
  assert.equal(denied.hookSpecificOutput.permissionDecision, 'deny');
  const updated = await rpc(endpoint, { action: 'snapshot' });
  assert.equal(updated.sessions.find(session => session.id === 'chat-a').commands.find(command => command.id === 'denied').status, 'blocked');
});

test('workspace registration updates roots without replacing editor-owned history', async t => {
  const { endpoint, file, directory, owner } = await launch(t);
  const additional = fs.mkdtempSync(path.join(os.tmpdir(), 'distill-root-'));
  t.after(() => fs.rmSync(additional, { recursive: true, force: true }));
  const event = { protocol: 1, source: 'codex', kind: 'completion', session_id: 'original', tool_use_id: 'tool', command: 'echo old', session_cwd: repository, timestamp: 10 };
  await rpc(endpoint, { action: 'record', event });
  await rpc(endpoint, { action: 'register', roots: [additional] });
  assert.equal(readEndpoint(file).socket, endpoint.socket);
  assert.ok(readEndpoint(file).roots.includes(fs.realpathSync(additional)));
  await rpc(endpoint, { action: 'record', event: { ...event, session_id: 'additional', session_cwd: fs.realpathSync(additional) } });
  assert.equal((await rpc(endpoint, { action: 'snapshot' })).sessions.length, 2);
  assert.equal((await rpc(endpoint, { action: 'snapshot', roots: [repository] })).sessions.length, 1);
  await assert.rejects(rpc(endpoint, { action: 'record', event: { ...event, editor_pid: owner.pid + 100000 } }), /another editor/);
  for (const name of fs.readdirSync(directory)) if (fs.statSync(path.join(directory, name)).isFile()) assert.ok(!fs.readFileSync(path.join(directory, name), 'utf8').includes('echo old'));
});

test('a stalled recorder has a bounded effect on the native hook response', { skip: !fs.existsSync(binary) }, async t => {
  const { directory, endpoint, file, owner } = await launch(t);
  const sockets = new Set();
  const server = require('node:net').createServer(socket => { sockets.add(socket); socket.on('error', () => {}); });
  const stalledSocket = path.join(directory, 'stall.sock');
  await new Promise(resolve => server.listen(stalledSocket, resolve));
  t.after(() => { for (const socket of sockets) socket.destroy(); server.close(); });
  fs.writeFileSync(file, JSON.stringify({ ...endpoint, socket: stalledSocket }), { mode: 0o600 });
  const started = Date.now();
  const child = spawn(binary, ['hook', 'codex', '--mode', 'advisory'], { env: { ...process.env, DISTILL_TRACE_DIR: directory, VSCODE_PID: String(owner.pid) } });
  let output = ''; child.stdout.on('data', chunk => { output += chunk; }); child.stderr.resume();
  child.stdin.end(JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', session_id: 'stall', tool_use_id: 'tool', cwd: repository, tool_input: { command: 'echo hello' } }));
  const [code] = await once(child, 'exit');
  assert.equal(code, 0); assert.ok(Date.now() - started < 1000, 'Recorder must not consume the full hook timeout');
  assert.equal(JSON.parse(output).hookSpecificOutput.permissionDecision, undefined);
});

for (const [name, settings] of [
  ['privacy', '[privacy]\ncapture_output = false\n[editor_trace]\ncapture_output = true\n'],
  ['legacy editor', '[editor_trace]\ncapture_output = false\n'],
]) test(`${name} output controls preserve status without retaining command output`, { skip: !fs.existsSync(binary) }, async t => {
  const { directory, endpoint, owner } = await launch(t);
  const config = path.join(directory, 'settings.toml');
  fs.writeFileSync(config, settings);
  const child = spawn(binary, ['hook', 'codex', '--config', config], { env: { ...process.env, DISTILL_TRACE_DIR: directory, VSCODE_PID: String(owner.pid) } });
  child.stdout.resume(); let stderr = ''; child.stderr.on('data', chunk => { stderr += chunk; });
  child.stdin.end(JSON.stringify({ hook_event_name: 'PostToolUse', tool_name: 'Bash', session_id: 'private', tool_use_id: 'tool', cwd: repository,
    tool_input: { command: 'echo sensitive' }, tool_response: { stdout: 'must-not-retain-this', exit_code: 2 } }));
  const [code] = await once(child, 'exit'); assert.equal(code, 0, stderr);
  const snapshot = await rpc(endpoint, { action: 'snapshot' });
  const entry = snapshot.sessions[0].commands[0];
  assert.equal(entry.status, 'failed'); assert.equal(entry.exitCode, 2);
  assert.equal(entry.outputCaptureDisabled, true); assert.equal(entry.outputChars, 0);
  assert.equal((await rpc(endpoint, { action: 'output', sessionKey: snapshot.sessions[0].key, id: entry.id })).text, '');
});
