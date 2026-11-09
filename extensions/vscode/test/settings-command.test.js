'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { app } = require('./helpers/webview');

test('the shipped LLM settings button opens the masked settings form, with advanced settings available', async () => {
  const file = path.resolve(__dirname, '../src/extension.js');
  const extensionPath = path.dirname(path.dirname(file));
  const nativeRequire = createRequire(file);
  const handlers = new Map();
  const opened = [];
  const errors = [];
  const messages = [];
  let provider;
  let receive;
  let receiveSettings;
  let settingsHtml;
  let secretReads = 0;
  const preferences = new Map();
  const routedModels = [];
  const routedEfforts = [];
  const disposable = () => ({ dispose() {} });
  const uri = fsPath => ({ scheme: 'file', fsPath });
  const vscode = {
    env: {},
    StatusBarAlignment: { Left: 1 },
    ViewColumn: { Active: 1 },
    ConfigurationTarget: { Global: 1 },
    Uri: { file: uri, joinPath: (base, ...parts) => uri(path.join(base.fsPath, ...parts)) },
    workspace: {
      isTrusted: true,
      workspaceFolders: [{ uri: uri(path.resolve(extensionPath, '../..')) }],
      textDocuments: [],
      getConfiguration: () => ({ get: (key, fallback) => preferences.get(key) ?? fallback, inspect: key => ({ globalValue: preferences.get(key) }), update: async (key, value) => preferences.set(key, value) }),
      onDidChangeWorkspaceFolders: disposable,
      onDidChangeConfiguration: disposable,
    },
    window: {
      createStatusBarItem: () => ({ show() {}, dispose() {} }),
      registerWebviewViewProvider: (_id, value) => { provider = value; return disposable(); },
      showInformationMessage() {},
      showErrorMessage: message => errors.push(message),
      createWebviewPanel: (_type, title, _column, options) => {
        assert.match(title, /LLM settings/); assert.equal(options.enableScripts, true);
        return { reveal() {}, dispose() {}, onDidDispose: disposable, webview: { cspSource: 'test-webview', asWebviewUri: value => value.fsPath, onDidReceiveMessage: handler => { receiveSettings = handler; return disposable(); }, postMessage: async message => { messages.push(message); return true; }, set html(value) { settingsHtml = value; } } };
      },
    },
    commands: {
      registerCommand: (id, handler) => { handlers.set(id, handler); return disposable(); },
      executeCommand: async (id, ...args) => {
        if (handlers.has(id)) return handlers.get(id)(...args);
        opened.push({ id, args });
      },
    },
  };
  const mocks = {
    vscode,
    './install': { trustedBinarySetting: nativeRequire('./install').trustedBinarySetting, ensureBinary: async () => ({ binary: '/trusted/distill' }) },
    './setup': { configureUserHooks: async options => { assert.equal(options.debugLog, ''); return [{ host: 'codex', changed: false }]; } },
    './router': { readRouterSettings: nativeRequire('./router').readRouterSettings, syncRouter: async ({ router }) => { routedModels.push(router.model); routedEfforts.push(router.reasoning_effort); return { enabled: false, running: false, model: router.model }; } },
    './client': { connectBroker: async () => ({ broker_version: 7, instance_id: 'test-recorder' }) },
    './transport': { rpc: async () => ({ version: 1, sessions: [], page: { sessionKey: '', offset: 0, limit: 100, total: 0 } }) },
    './titles': { SessionTitles: class { async enrich(sessions) { return sessions; } clear() {} } },
  };
  const sandbox = {
    require: name => Object.hasOwn(mocks, name) ? mocks[name] : nativeRequire(name),
    module: { exports: {} }, process,
    setInterval: () => 1, clearInterval() {},
  };
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), sandbox, { filename: file });
  const context = { extensionPath, extensionUri: uri(extensionPath), subscriptions: [], secrets: { get: async () => { secretReads++; return undefined; } } };
  const activated = sandbox.module.exports.activate(context);
  await activated.ready();
  assert.equal(secretReads, 0, 'Disabled routing must not access saved credentials');
  provider.resolveWebviewView({
    webview: {
      cspSource: 'test-webview',
      asWebviewUri: value => value.fsPath,
      onDidReceiveMessage: handler => { receive = handler; return disposable(); },
      postMessage: async message => { messages.push(message); return true; },
      set html(value) { assert.match(value, /id="router-settings"/); assert.match(value, /LLM settings/); },
    },
    onDidDispose: disposable,
  });
  const frontend = app();
  frontend.elements.get('router-settings').dispatch('click');
  await receive(frontend.messages.at(-1));
  assert.match(settingsHtml, /id="llm-api-key" type="password"/);
  assert.match(settingsHtml, /select id="llm-apiKeyEnv"/);
  assert.match(settingsHtml, /select id="llm-model"/);
  await receiveSettings({ type: 'ready' });
  assert.ok(messages.some(message => message.type === 'settings-state' && message.hasKey === false));
  const { FIELDS } = nativeRequire('./settings');
  await receiveSettings({ type: 'save', values: { ...FIELDS, model: 'private-model-v2', reasoningEffort: 'none' }, apiKey: '' });
  assert.equal(preferences.get('llm.model'), '__custom__');
  assert.equal(preferences.get('llm.customModel'), 'private-model-v2');
  assert.equal(routedModels.at(-1), 'private-model-v2');
  assert.equal(routedEfforts.at(-1), 'none');
  assert.equal(preferences.get('llm.reasoningEffort'), 'none');
  assert.equal(messages.at(-1).values.model, 'private-model-v2');
  await receiveSettings({ type: 'save', values: { ...FIELDS, model: 'gpt-5.4-mini' }, apiKey: '' });
  assert.equal(preferences.get('llm.model'), 'gpt-5.4-mini');
  assert.equal(preferences.get('llm.customModel'), '');
  assert.equal(routedModels.at(-1), 'gpt-5.4-mini');
  assert.equal(routedEfforts.at(-1), undefined);
  assert.equal(preferences.get('llm.reasoningEffort'), 'provider_default');
  await receiveSettings({ type: 'advanced' });
  assert.equal(opened.length, 1);
  assert.equal(opened[0].id, 'workbench.action.openSettings');
  assert.equal(opened[0].args[0], '@ext:distill.distill-trace llm');
  await receive({ type: 'ready' });
  assert.ok(messages.some(message => message.type === 'router-state' && message.router.enabled === false));
  assert.deepEqual(errors, []);
  for (const subscription of context.subscriptions) subscription.dispose();
});
