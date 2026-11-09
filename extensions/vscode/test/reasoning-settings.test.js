'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { readRouterSettings, PRESETS, REASONING_EFFORTS } = require('../src/router');
const { FIELDS, formValues, validateForm } = require('../src/settings');
const { MODEL_OPTIONS } = require('../src/models');
const { app } = require('./helpers/webview');
const settings = (global = {}, workspace = {}) => ({ inspect: key => ({ globalValue: global[key], workspaceValue: workspace[key] }) });

test('every OpenAI catalog model and unlisted alias gets identical explicit settings', () => {
  for (const effort of REASONING_EFFORTS) {
    let reference;
    for (const model of [...MODEL_OPTIONS.openai_compatible.map(model => model.id), 'custom/private-alias']) {
      const router = readRouterSettings(settings({ 'llm.model': model, 'llm.reasoningEffort': effort }));
      assert.equal(router.model, model);
      if (effort === 'provider_default') assert.ok(!Object.hasOwn(router, 'reasoning_effort'));
      else assert.equal(router.reasoning_effort, effort);
      delete router.model;
      if (reference) assert.deepEqual(router, reference);
      reference = router;
    }
  }
  assert.ok(!Object.hasOwn(readRouterSettings(settings({}, { 'llm.reasoningEffort': 'max' })), 'reasoning_effort'));
});

test('native dropdown and router round-trip explicit effort and reject unsupported provider options', () => {
  const schema = require('../package.json').contributes.configuration.properties['distill.llm.reasoningEffort'];
  assert.deepEqual(schema.enum, REASONING_EFFORTS);
  assert.equal(schema.default, 'provider_default');
  assert.equal(schema.scope, 'machine');
  for (const provider of Object.keys(PRESETS)) {
    const preferences = settings({ 'llm.provider': provider, 'llm.reasoningEffort': 'provider_default' });
    assert.ok(!Object.hasOwn(readRouterSettings(preferences), 'reasoning_effort'));
    if (['gemini', 'claude'].includes(provider)) {
      assert.throws(() => readRouterSettings(settings({ 'llm.provider': provider, 'llm.reasoningEffort': 'none' })), /Provider default/);
    } else {
      assert.equal(readRouterSettings(settings({ 'llm.provider': provider, 'llm.reasoningEffort': 'none' })).reasoning_effort, 'none');
    }
  }
  const values = formValues(settings({ 'llm.reasoningEffort': 'none', 'llm.model': 'gpt-5.6-luna' }));
  assert.equal(validateForm(values).router.reasoning_effort, 'none');
  assert.throws(() => readRouterSettings(settings({ 'llm.reasoningEffort': 'invented' })), /valid reasoning effort/);
});

test('the shipped settings form keeps effort across model changes and restores provider drafts', () => {
  const ui = app(path.resolve(__dirname, '../media/settings.js'), path.resolve(__dirname, '../src/settings.js'));
  ui.receive({ type: 'settings-state', values: { ...FIELDS, model: 'gpt-6-luna', reasoningEffort: 'none' }, presets: PRESETS, modelOptions: MODEL_OPTIONS, hasKey: false });
  const field = name => ui.elements.get(`llm-${name}`);
  const choose = (name, value) => { field(name).value = value; field(name).dispatch('change'); };
  const save = () => { field('form').dispatch('submit'); return ui.messages.at(-1); };
  choose('model', 'gpt-5.6-luna');
  assert.equal(save().values.reasoningEffort, 'none');
  assert.equal(validateForm(save().values).router.reasoning_effort, 'none');
  choose('provider', 'gemini');
  assert.equal(field('reasoningEffort').disabled, true);
  assert.equal(save().values.reasoningEffort, 'provider_default');
  choose('provider', 'openai_compatible');
  assert.equal(field('reasoningEffort').disabled, false);
  assert.equal(field('reasoningEffort').value, 'none');
  assert.equal(save().values.model, 'gpt-5.6-luna');
});
