'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { HookSetupDeclined } = require('../src/setup');

function activate(choice) {
  const file = path.resolve(__dirname, '../src/extension.js');
  const nativeRequire = createRequire(file);
  const handlers = new Map();
  const prompts = [], errors = [], order = [];
  let connected = false;
  const state = { choice, writes: 0 };
  const disposable = () => ({ dispose() {} });
  const vscode = {
    env: {},
    workspace: {
      isTrusted: true, workspaceFolders: [{ uri: { scheme: 'file', fsPath: process.cwd() } }], textDocuments: [],
      getConfiguration: () => ({ get: (_key, fallback) => fallback, inspect: () => ({}) }),
      onDidChangeWorkspaceFolders: disposable, onDidChangeConfiguration: disposable,
    },
    window: {
      registerWebviewViewProvider: disposable,
      showInformationMessage: async (message, options, ...buttons) => {
        if (options?.modal) { prompts.push({ message, options, buttons }); order.push('approval'); return state.choice; }
      },
      showErrorMessage: message => errors.push(message),
    },
    commands: { registerCommand: (name, action) => { handlers.set(name, action); return disposable(); } },
  };
  const mocks = {
    vscode,
    './install': { trustedBinarySetting: () => '', ensureBinary: async () => { order.push('install'); return { binary: '/fixture/distill' }; } },
    './setup': { configureUserHooks: async options => {
      if (!connected) {
        if (!await options.approve([{ host: 'codex', name: 'Distill for Codex' }, { host: 'claude', name: 'Distill for Claude Code' }])) throw new HookSetupDeclined();
        order.push('write'); state.writes++; connected = true;
      }
      return [{ host: 'codex', changed: true }, { host: 'claude', changed: true }];
    } },
    './client': { connectBroker: async () => ({ broker_version: 8 }) },
    './transport': { rpc: async () => ({}) },
    './router': { readRouterSettings: () => ({ enabled: false }), syncRouter: async () => ({ enabled: false }) },
    './settings': { createRouterSettings: () => ({}) },
    './titles': { SessionTitles: class { clear() {} } },
  };
  const sandbox = { require: name => Object.hasOwn(mocks, name) ? mocks[name] : nativeRequire(name), module: { exports: {} }, process, setInterval: () => 1, clearInterval() {} };
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), sandbox, { filename: file });
  const extension = sandbox.module.exports.activate({ subscriptions: [], secrets: {} });
  return { extension, handlers, prompts, errors, order, state };
}

test('first run presents one service-named setup approval after installing the tool and before writing hooks', async () => {
  const app = activate('Connect Distill');
  await Promise.all([app.extension.ready(), app.extension.ready()]);
  assert.equal(app.prompts.length, 1);
  assert.equal(app.prompts[0].message, 'Connect Distill for Codex and Distill for Claude Code?');
  assert.deepEqual(app.prompts[0].buttons, ['Connect Distill', 'Not Now']);
  assert.deepEqual(app.order, ['install', 'approval', 'write']);
  assert.equal(app.state.writes, 1);
  assert.deepEqual(app.errors, []);
});

for (const choice of ['Not Now', undefined]) test(`setup ${choice ?? 'dismissal'} does not write hooks or report an error, and the Connect command retries`, async () => {
  const app = activate(choice);
  await assert.rejects(app.extension.ready(), { code: 'DISTILL_SETUP_DECLINED' });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(app.state.writes, 0);
  assert.equal(app.prompts.length, 1);
  assert.deepEqual(app.errors, []);
  app.state.choice = 'Connect Distill';
  await app.handlers.get('distill.setupHooks')();
  assert.equal(app.state.writes, 1);
  assert.equal(app.prompts.length, 2);
  assert.deepEqual(app.errors, []);
});
