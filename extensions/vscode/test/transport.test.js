'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { readEndpoint, endpointPath, processIdentity, traceDirectory } = require('../src/transport');
const { connectBroker } = require('../src/client');
const path = require('node:path');
const binary = process.env.DISTILL_TEST_BINARY || path.resolve(__dirname, '../../../target/debug/distill');

test('upgrading from a live TCP recorder reports the required full restart before attempting another broker', async t => {
  const directory = fs.mkdtempSync('/tmp/distill-upgrade-test-');
  const previous = { directory: process.env.DISTILL_TRACE_DIR, pid: process.env.VSCODE_PID };
  process.env.DISTILL_TRACE_DIR = directory;
  process.env.VSCODE_PID = String(process.pid);
  t.after(() => {
    for (const [key, value] of [['DISTILL_TRACE_DIR', previous.directory], ['VSCODE_PID', previous.pid]]) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const file = endpointPath(traceDirectory(), process.pid, processIdentity(process.pid), [directory]);
  const legacy = { protocol: 1, broker_version: 3, port: 53301, token: 'a'.repeat(64), editor_pid: process.pid, roots: [directory] };
  fs.writeFileSync(file, JSON.stringify(legacy), { mode: 0o600 });
  fs.writeFileSync(file + '.lock', JSON.stringify({ pid: process.pid, identity: processIdentity(process.pid) }), { mode: 0o600 });
  assert.throws(() => readEndpoint(file), error => error.code === 'DISTILL_RECORDER_UPGRADE');
  await assert.rejects(connectBroker([directory], binary), error => error.code === 'DISTILL_RECORDER_UPGRADE' && /Fully quit and reopen/.test(error.message));
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), legacy, 'Do not replace an active recorder or discard its temporary history');
});
