'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { FIELDS, validateForm, settingsHtml, formValues } = require('../src/settings');
const { PRESETS, readRouterSettings } = require('../src/router');
const { MODEL_OPTIONS, CUSTOM_MODEL, modelPreference } = require('../src/models');
const { app } = require('./helpers/webview');

function form(values = {}) {
  const ui = app(path.resolve(__dirname, '../media/settings.js'), path.resolve(__dirname, '../src/settings.js'));
  ui.receive({ type: 'settings-state', values: { ...FIELDS, ...values }, presets: PRESETS, modelOptions: MODEL_OPTIONS, hasKey: false });
  return ui;
}
function choose(ui, field, value) { ui.elements.get(`llm-${field}`).value = value; ui.elements.get(`llm-${field}`).dispatch('change'); }
function save(ui) { ui.elements.get('llm-form').dispatch('submit'); return ui.messages.at(-1); }

test('VS Code built-in settings contribute a real Model dropdown and a separate custom model field', () => {
  const properties = require('../package.json').contributes.configuration.properties;
  const setting = properties['distill.llm.model'];
  assert.equal(setting.type, 'string');
  assert.ok(Array.isArray(setting.enum), 'An enum is required for VS Code to render a dropdown');
  assert.ok(setting.enum.includes('gpt-5.4-mini')); assert.ok(setting.enum.includes('gpt-5-mini')); assert.ok(setting.enum.includes('gpt-5-nano'));
  assert.ok(setting.enum.includes('gemini-3.5-flash-lite')); assert.ok(setting.enum.includes('claude-haiku-5-5'));
  assert.ok(setting.enum.includes(CUSTOM_MODEL)); assert.ok(setting.enum.includes(''));
  assert.equal(setting.enum.length, new Set(setting.enum).size);
  assert.equal(setting.enum.length, setting.enumItemLabels.length);
  assert.equal(properties['distill.llm.customModel'].scope, 'machine');
});

test('native dropdown custom IDs, legacy IDs, and the separate form preserve the actual routed model', () => {
  for (const id of ['private-model-v2', 'my/local-alias', 'gpt-5.4-mini', '']) {
    const prefs = { ...FIELDS, ...modelPreference(id) };
    const configuration = { inspect: key => ({ globalValue: prefs[key.slice(4)] }) };
    assert.equal(formValues(configuration).model, id);
    assert.equal(readRouterSettings(configuration).model, id || PRESETS.openai_compatible.model);
    assert.deepEqual(modelPreference(formValues(configuration).model), modelPreference(id));
  }
  const legacy = { inspect: key => ({ globalValue: key === 'llm.model' ? 'legacy-custom-model' : undefined }) };
  assert.equal(formValues(legacy).model, 'legacy-custom-model');
  assert.equal(readRouterSettings(legacy).model, 'legacy-custom-model');
  const missing = { inspect: key => ({ globalValue: { 'llm.model': CUSTOM_MODEL, 'llm.enabled': true }[key], workspaceValue: key === 'llm.customModel' ? 'untrusted-workspace-model' : undefined }) };
  assert.throws(() => readRouterSettings(missing), /Select a served model/);
  assert.throws(() => modelPreference(CUSTOM_MODEL), /exact custom model ID/);
});

test('the real settings markup uses a native model dropdown with a labeled custom input', () => {
  const vscode = { Uri: { joinPath: (...parts) => parts.join('/') } };
  const html = settingsHtml(vscode, { extensionUri: '/extension' }, { cspSource: 'test', asWebviewUri: String });
  assert.match(html, /<select id="llm-model"/);
  assert.match(html, /for="llm-customModel"/);
  assert.match(html, /id="llm-customModel" type="text" maxlength="256"/);
  assert.doesNotMatch(html, /<input id="llm-model"/);
});

test('each hosted provider offers only its own model choices and preserves the default setting', () => {
  for (const provider of ['openai_compatible', 'gemini', 'claude']) {
    const ui = form({ provider });
    const options = ui.elements.get('llm-model').children;
    assert.deepEqual(options.map(option => option.value), ['', ...MODEL_OPTIONS[provider].map(model => model.id), '__custom__']);
    assert.match(options[0].textContent, new RegExp(PRESETS[provider].model.replaceAll('.', '\\.')));
    assert.equal(ui.elements.get('llm-customModel').hidden, true);
    assert.equal(save(ui).values.model, '');
    const chosen = MODEL_OPTIONS[provider].at(-1).id;
    choose(ui, 'model', chosen);
    assert.equal(save(ui).values.model, chosen);
    assert.equal(validateForm(save(ui).values).router.model, chosen);
  }
});

test('saved explicit choices and unlisted model IDs round-trip without changing the model', () => {
  const known = form({ provider: 'gemini', model: 'gemini-3.5-flash-lite' });
  assert.equal(known.elements.get('llm-model').value, 'gemini-3.5-flash-lite');
  assert.equal(save(known).values.model, 'gemini-3.5-flash-lite');
  const custom = form({ provider: 'openai_compatible', model: 'my-private-model-v2' });
  assert.equal(custom.elements.get('llm-model').value, '__custom__');
  assert.equal(custom.elements.get('llm-customModel').hidden, false);
  assert.equal(custom.elements.get('llm-customModel').value, 'my-private-model-v2');
  assert.equal(save(custom).values.model, 'my-private-model-v2');
  assert.ok(!Object.hasOwn(save(custom).values, 'customModel'));
});

test('selecting a custom model sends its exact ID and never serializes the UI marker', () => {
  const ui = form({ provider: 'gemini', enabled: true });
  choose(ui, 'model', '__custom__');
  ui.elements.get('llm-customModel').value = 'models/my-reviewed-model';
  assert.equal(ui.elements.get('llm-customModel').required, true);
  const message = save(ui);
  assert.equal(message.values.model, 'models/my-reviewed-model');
  assert.ok(!JSON.stringify(message).includes('__custom__'));
  choose(ui, 'model', 'gemini-3.1-flash-lite');
  assert.equal(ui.elements.get('llm-customModel').hidden, true);
  assert.equal(ui.elements.get('llm-customModel').required, false);
  assert.equal(save(ui).values.model, 'gemini-3.1-flash-lite');
});

test('provider switching restores model and endpoint drafts without carrying another provider model or key', () => {
  const ui = form({ provider: 'gemini', model: 'gemini-3.5-flash-lite', endpoint: 'https://gemini.example/v1beta' });
  ui.elements.get('llm-api-key').value = 'unsaved-fixture-key';
  choose(ui, 'provider', 'claude');
  assert.equal(ui.elements.get('llm-model').value, '');
  assert.equal(ui.elements.get('llm-endpoint').value, '');
  assert.equal(ui.elements.get('llm-api-key').value, '');
  choose(ui, 'model', 'claude-sonnet-5-5');
  ui.elements.get('llm-endpoint').value = 'https://claude.example/v1/messages';
  choose(ui, 'provider', 'gemini');
  assert.equal(ui.elements.get('llm-model').value, 'gemini-3.5-flash-lite');
  assert.equal(ui.elements.get('llm-endpoint').value, 'https://gemini.example/v1beta');
  choose(ui, 'provider', 'claude');
  assert.equal(ui.elements.get('llm-model').value, 'claude-sonnet-5-5');
  assert.equal(ui.elements.get('llm-endpoint').value, 'https://claude.example/v1/messages');
});

test('local providers use exact custom aliases and an empty enabled custom choice cannot silently select a default', () => {
  for (const provider of ['llama_cpp', 'vllm']) {
    const ui = form({ provider, model: 'served-model-alias', enabled: true });
    assert.equal(ui.elements.get('llm-model').value, '__custom__');
    assert.equal(ui.elements.get('llm-customModel').hidden, false);
    assert.equal(save(ui).values.model, 'served-model-alias');
    assert.equal(validateForm(save(ui).values).router.model, 'served-model-alias');
  }
  const ui = form({ provider: 'gemini', enabled: true });
  choose(ui, 'model', '__custom__');
  ui.elements.get('llm-customModel').value = '   ';
  const count = ui.messages.length;
  ui.elements.get('llm-form').dispatch('submit');
  assert.equal(ui.messages.length, count);
  assert.match(ui.elements.get('llm-result').textContent, /Enter a custom model ID/);
  ui.elements.get('llm-enabled').checked = false;
  ui.elements.get('llm-enabled').dispatch('change');
  assert.equal(ui.elements.get('llm-customModel').required, false);
  assert.equal(save(ui).values.enabled, false);
});
