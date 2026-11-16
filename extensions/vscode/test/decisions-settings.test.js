'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { API_MODES, PRESETS, readRouterSettings } = require('../src/router');
const { FIELDS, validateForm } = require('../src/settings');
const { MODEL_OPTIONS } = require('../src/models');
const { RouterCredentials } = require('../src/credentials');
const { app } = require('./helpers/webview');
const settings = (global = {}, workspace = {}) => ({ inspect: key => ({ globalValue: global[key], workspaceValue: workspace[key] }) });
function form(values = {}) {
  const ui = app(path.resolve(__dirname, '../media/settings.js'), path.resolve(__dirname, '../src/settings.js'));
  ui.receive({ type: 'settings-state', values: { ...FIELDS, ...values }, presets: PRESETS, modelOptions: MODEL_OPTIONS, hasKey: false });
  const field = name => ui.elements.get(`llm-${name}`);
  return { ui, field, choose(name, value) { field(name).value = value; field(name).dispatch('change'); }, save() { field('form').dispatch('submit'); return ui.messages.at(-1); } };
}

test('API mode is user-scoped, preserves the default route, and resolves the Decisions preset', () => {
  const schema = require('../package.json').contributes.configuration.properties['distill.llm.apiMode'];
  assert.deepEqual(schema.enum, API_MODES);
  assert.equal(schema.default, 'provider_default');
  assert.equal(schema.scope, 'machine');
  const standard = readRouterSettings(settings({}, { 'llm.apiMode': 'decisions' }));
  assert.equal(standard.endpoint, PRESETS.openai_compatible.endpoint);
  assert.ok(!Object.hasOwn(standard, 'api_mode'));
  const decisions = readRouterSettings(settings({ 'llm.apiMode': 'decisions', 'llm.enabled': true }));
  assert.equal(decisions.api_mode, 'decisions');
  assert.equal(decisions.endpoint, 'https://api.openai.com/v1/decisions');
  assert.equal(decisions.model, 'gpt-6-luna');
  assert.equal(decisions.review_format, 'severity');
  assert.ok(!Object.hasOwn(decisions, 'reasoning_effort'));
});

test('invalid Decisions combinations and mismatched endpoints are rejected before applying a route', () => {
  for (const values of [
    { provider: 'gemini' }, { provider: 'claude' }, { provider: 'vllm' },
    { model: 'gpt-6-astra' }, { reasoningEffort: 'none' }, { reasoningEffort: 'low' },
    { reviewFormat: 'effects' }, { endpoint: 'https://api.openai.com/v1/chat/completions' },
  ]) assert.throws(() => validateForm({ ...FIELDS, apiMode: 'decisions', ...values }), /Decisions|matching the API/);
  assert.throws(() => validateForm({ ...FIELDS, apiMode: 'invalid' }), /API mode/);
  assert.throws(() => validateForm({ ...FIELDS, endpoint: 'https://api.openai.com/v1/decisions' }), /matching the API/);
});

test('the shipped form switches to Decisions and restores the chat model, effort, endpoint and token budget', () => {
  const view = form({ model: 'private-model', endpoint: 'https://proxy.example/chat', reasoningEffort: 'none', reviewFormat: 'effects', maxOutputTokens: 128 });
  view.field('api-key').value = 'unsaved-fixture-secret';
  view.choose('apiMode', 'decisions');
  assert.equal(view.field('api-key').value, '');
  for (const field of ['model', 'reasoningEffort', 'maxOutputTokens', 'reviewFormat']) assert.equal(view.field(field).disabled, true);
  assert.equal(view.field('endpoint').placeholder, PRESETS.openai_compatible.decisionsEndpoint);
  assert.match(view.field('api-hint').textContent, /Static review requirements/);
  assert.equal(view.field('customModel').hidden, true);
  const message = view.save();
  assert.equal(message.values.model, 'gpt-6-luna');
  assert.equal(validateForm(message.values).router.api_mode, 'decisions');
  view.choose('apiMode', 'provider_default');
  for (const field of ['model', 'reasoningEffort', 'maxOutputTokens', 'reviewFormat']) assert.equal(view.field(field).disabled, false);
  const restored = view.save().values;
  assert.equal(restored.model, 'private-model');
  assert.equal(restored.endpoint, 'https://proxy.example/chat');
  assert.equal(restored.reasoningEffort, 'none');
  assert.equal(restored.reviewFormat, 'effects');
  assert.equal(restored.maxOutputTokens, 128);
});

test('Decisions mode survives provider switching without leaking an incompatible mode or unsaved key', () => {
  const view = form({ apiMode: 'decisions', model: 'gpt-6-luna' });
  view.field('api-key').value = 'unsaved-key';
  view.choose('provider', 'gemini');
  assert.equal(view.field('apiMode').disabled, true);
  assert.equal(view.field('apiMode').value, 'provider_default');
  assert.equal(view.field('api-key').value, '');
  assert.equal(validateForm(view.save().values).router.provider, 'gemini');
  view.choose('provider', 'openai_compatible');
  assert.equal(view.field('apiMode').disabled, false);
  assert.equal(view.field('apiMode').value, 'decisions');
  assert.equal(validateForm(view.save().values).router.api_mode, 'decisions');
});

test('a saved unsupported Decisions model is visible and rejected rather than silently substituted', () => {
  const view = form({ apiMode: 'decisions', model: 'unlisted-model' });
  assert.equal(view.save().values.model, 'unlisted-model');
  assert.throws(() => validateForm(view.save().values), /Decisions requires/);
});

test('changing API presets keeps saved credentials bound to their original endpoint', async () => {
  const saved = new Map();
  const credentials = new RouterCredentials({ get: async key => saved.get(key), store: async (key, value) => saved.set(key, value), delete: async key => saved.delete(key) });
  const chat = readRouterSettings(settings());
  const decisions = readRouterSettings(settings({ 'llm.apiMode': 'decisions' }));
  await credentials.save(chat, 'fixture-chat-key');
  assert.equal((await credentials.handoff(decisions)).key, null);
  await credentials.save(decisions, 'fixture-decisions-key');
  assert.equal((await credentials.handoff(chat)).key, 'fixture-chat-key');
  assert.equal((await credentials.handoff(decisions)).key, 'fixture-decisions-key');
});
