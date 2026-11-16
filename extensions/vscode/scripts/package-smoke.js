'use strict';
// Run against an extracted VSIX. All installation and hook files stay in a fixture.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { promisify } = require('node:util');
const { execFile, spawnSync } = require('node:child_process');

async function main() {
  const extensionPath = path.resolve(process.argv[2]);
  const { ensureBinary } = require(path.join(extensionPath, 'src/install'));
  const { configureUserHooks } = require(path.join(extensionPath, 'src/setup'));
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'distill-package-smoke-'));
  try {
    const home = path.join(directory, 'home'), workspace = path.join(directory, 'workspace');
    fs.mkdirSync(home); fs.mkdirSync(workspace);
    const env = { ...process.env, HOME: home, CODEX_HOME: path.join(home, '.codex'), DISTILL_TRACE_DIR: path.join(directory, 'trace') };
    const run = (binary, args, options) => promisify(execFile)(binary, args, { ...options, env });
    const options = { extensionPath, storagePath: path.join(directory, 'storage'), run };
    const installed = await ensureBinary(options);
    assert.equal(installed.managed, true);
    assert.ok(fs.existsSync(path.join(path.dirname(installed.binary), 'distill-service')));
    assert.equal((await ensureBinary(options)).binary, installed.binary);
    let approvals = 0;
    const setup = { binary: installed.binary, extensionPath, home, env, roots: [workspace], hosts: ['codex', 'claude'], run,
      approve: async services => { approvals++; assert.deepEqual(services.map(service => service.name), ['Distill for Codex', 'Distill for Claude Code']); return true; } };
    const connected = await configureUserHooks(setup);
    assert.equal(approvals, 1);
    for (const service of connected) {
      const hooks = JSON.parse(fs.readFileSync(service.path)).hooks;
      for (const groups of Object.values(hooks)) {
        assert.equal(groups.length, 1); assert.equal(groups[0].hooks.length, 1);
        assert.equal(groups[0].hooks[0].statusMessage, service.service_name);
      }
      const handler = hooks.PreToolUse[0].hooks[0].command;
      const response = spawnSync('/bin/sh', ['-c', handler + ' --no-prompt'], { env, input: JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', cwd: workspace, tool_input: { command: 'echo package-smoke', shell: '/bin/bash' } }), encoding: 'utf8', timeout: 10000 });
      assert.equal(response.status, 0, response.stderr);
      assert.match(JSON.parse(response.stdout).systemMessage, /Severity: SAFE/);
    }
    assert.ok((await configureUserHooks(setup)).every(service => !service.changed));
    assert.equal(approvals, 1, 'An unchanged install must not prompt again');
    const { configure, readRouterSettings } = require(path.join(extensionPath, 'src/router'));
    const route = readRouterSettings({ inspect: key => ({ globalValue: key === 'llm.apiMode' ? 'decisions' : undefined }) });
    const updated = await configure(installed.binary, 'codex', route, { env });
    assert.equal(updated.router.api_mode, 'decisions');
    assert.equal(updated.router.model, 'gpt-6-luna');
    assert.equal(updated.router.endpoint, 'https://api.openai.com/v1/decisions');
    assert.equal(updated.router.enabled, false, 'Packaging checks must not contact a model endpoint');
    console.log('Packaged CLI/service installation, named hook approval, safe hook invocation, reconnect, and Decisions configuration passed.');
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
