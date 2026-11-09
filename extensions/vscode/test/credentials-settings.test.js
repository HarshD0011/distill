'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { RouterCredentials, credentialSlot } = require('../src/credentials');
const { runWithInput } = require('../src/router');
const { PRESETS, readRouterSettings } = require('../src/router');
const { FIELDS, validateForm, createRouterSettings } = require('../src/settings');
const { app } = require('./helpers/webview');
const route = provider => readRouterSettings({ inspect: key => ({ globalValue: key === 'llm.provider' ? provider : undefined }) });
function secrets() {
  const saved = new Map();
  return { saved, get: async key => saved.get(key), store: async (key, value) => { saved.set(key, value); }, delete: async key => { saved.delete(key); } };
}
test('real child handoff uses stdin and sanitizes child errors that echo secrets', async () => {
  const key = 'pipe-fixture-secret';
  const source = "let text='';process.stdin.setEncoding('utf8');process.stdin.on('data',s=>text+=s);process.stdin.on('end',()=>{const key=JSON.parse(text).key;process.stdout.write(JSON.stringify({received:typeof key==='string'&&key.length>0,env:JSON.stringify(process.env).includes(key),argv:JSON.stringify(process.argv).includes(key)}));});";
  assert.ok(!source.includes(key));
  const result = await runWithInput(process.execPath, ['-e', source], { env: { PATH: '/usr/bin:/bin' }, input: JSON.stringify({ key }), timeout: 2000, maxBuffer: 4096 });
  const actual = JSON.parse(result.stdout);
  assert.equal(actual.received, true); assert.equal(actual.env, false);
  // Node -e hides the source from process.argv; the handoff key is never an argument.
  assert.equal(actual.argv, false);
  const fail = "process.stdin.on('data',data=>process.stderr.write(data));process.stdin.on('end',()=>process.exit(1));";
  await assert.rejects(runWithInput(process.execPath, ['-e', fail], { env: {}, input: JSON.stringify({ key }), timeout: 2000, maxBuffer: 4096 }), error => !JSON.stringify(Object.getOwnPropertyDescriptors(error)).includes(key));
});
test('keys persist only through SecretStorage, are connection-bound, and are removed without modifying the parent environment', async () => {
  const storage = secrets(); const first = new RouterCredentials(storage); const gemini = route('gemini');
  await first.save(gemini, 'fixture-api-key');
  assert.ok(await new RouterCredentials(storage).has(gemini), 'Reload can use the encrypted store');
  assert.ok(!credentialSlot(gemini).includes('fixture-api-key'));
  const base = { PATH: '/untrusted/bin', HOME: '/fixture/home', GEMINI_API_KEY: 'ambient-key', NODE_OPTIONS: '--require evil.js' }; const env = first.environment(gemini, base);
  assert.equal(env.GEMINI_API_KEY, undefined); assert.equal(base.GEMINI_API_KEY, 'ambient-key');
  assert.equal(env.NODE_OPTIONS, undefined); assert.equal(env.PATH, '/usr/bin:/bin');
  assert.equal((await first.handoff(gemini)).key, 'fixture-api-key');
  assert.equal(env.DISTILL_SERVICE_OWNER_PID, String(process.pid));
  assert.equal((await first.handoff(route('claude'))).key, null);
  assert.equal((await first.handoff({ ...gemini, endpoint: 'https://another.example/api' })).key, null);
  await first.forget(gemini); assert.equal(await first.has(gemini), false); assert.equal(storage.saved.size, 0);
  assert.equal((await first.handoff(gemini)).key, null, 'Removal cannot fall back to an ambient key');
  await assert.rejects(first.save(gemini, 'bad\nkey'), /valid API key/);
  await assert.rejects(first.save({ ...gemini, api_key_env: '' }, 'key'), /Select an API key/);
});
test('the actual settings frontend submits a masked key separately, clears the field, and never restores a key', () => {
  const ui = app(path.resolve(__dirname, '../media/settings.js'), path.resolve(__dirname, '../src/settings.js'));
  ui.receive({ type: 'settings-state', values: { ...FIELDS, provider: 'gemini' }, presets: PRESETS, hasKey: true });
  assert.equal(ui.elements.get('llm-apiKeyEnv').children[0].textContent, 'Provider default (GEMINI_API_KEY)');
  assert.equal(ui.elements.get('llm-api-key').value, '');
  ui.elements.get('llm-api-key').value = 'fixture-api-key';
  ui.elements.get('llm-form').dispatch('submit');
  const message = ui.messages.at(-1);
  assert.equal(message.apiKey, 'fixture-api-key'); assert.equal(message.values.provider, 'gemini');
  assert.ok(!JSON.stringify(message.values).includes('fixture-api-key'));
  assert.equal(ui.elements.get('llm-api-key').value, '');
  const { values, router } = validateForm({ ...message.values, apiKey: 'must-not-be-saved-in-settings' });
  assert.ok(!Object.hasOwn(values, 'apiKey')); assert.equal(router.api_key_env, 'GEMINI_API_KEY');
  ui.receive({ type: 'settings-state', values: { ...FIELDS, provider: 'vllm', model: 'local-model' }, presets: PRESETS, hasKey: false });
  assert.equal(ui.elements.get('llm-api-key').disabled, true);
});
test('the settings controller sends only key-presence metadata and supports key removal', async () => {
  const storage = secrets(); const credentials = new RouterCredentials(storage); const messages = []; let receive;
  let values = { ...FIELDS, provider: 'claude' }; const subscriptions = [];
  const configuration = () => ({ inspect: key => ({ globalValue: values[key.slice(4)] }) });
  const disposable = () => ({ dispose() {} });
  const vscode = { ViewColumn: { Active: 1 }, Uri: { joinPath: (...parts) => parts.join('/') }, window: { createWebviewPanel: () => ({ reveal() {}, dispose() {}, onDidDispose: disposable, webview: { asWebviewUri: String, cspSource: 'test', onDidReceiveMessage: handler => { receive = handler; return disposable(); }, postMessage: async value => messages.push(value) } }) } };
  const panel = createRouterSettings(vscode, { extensionUri: '/extension', subscriptions }, { configuration, credentials,
    apply: async (next, router, key) => { values = next; if (key) await credentials.save(router, key); }, forget: router => credentials.forget(router),
  });
  panel.open(); await receive({ type: 'ready' });
  await receive({ type: 'save', values, apiKey: 'fixture-api-key' });
  assert.equal(messages.at(-1).hasKey, true);
  assert.ok(messages.at(-1).modelOptions.gemini.some(model => model.id === 'gemini-3.1-flash-lite'));
  assert.ok(!JSON.stringify(messages).includes('fixture-api-key'));
  await receive({ type: 'forget', values }); assert.equal(messages.at(-1).hasKey, false);
});
