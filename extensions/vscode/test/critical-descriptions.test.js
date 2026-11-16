'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { FIELDS, validateForm } = require('../src/settings');
const { PRESETS, readRouterSettings } = require('../src/router');
const { MODEL_OPTIONS } = require('../src/models');
const { app } = require('./helpers/webview');

test('critical descriptions are off by default, machine-scoped, and ignore workspace opt-in', () => {
  const schema = require('../package.json').contributes.configuration.properties['distill.llm.criticalDescriptions'];
  assert.equal(schema.default, false);
  assert.equal(schema.scope, 'machine');
  const route = readRouterSettings({ inspect: () => ({ workspaceValue: true }) });
  assert.ok(!Object.hasOwn(route, 'critical_descriptions'));
  const configured = validateForm({ ...FIELDS, apiMode: 'decisions', enabled: true, criticalDescriptions: true });
  assert.equal(configured.router.critical_descriptions, true);
  assert.equal(configured.router.api_mode, 'decisions');
  assert.match(schema.description, /normal input\/output charges/);
});

test('critical descriptions reject incompatible providers and unsupported routes', () => {
  for (const provider of ['gemini', 'claude', 'llama_cpp', 'vllm']) {
    assert.throws(() => validateForm({ ...FIELDS, provider, criticalDescriptions: true }), /Critical descriptions/);
  }
  assert.throws(() => validateForm({ ...FIELDS, endpoint: 'https://proxy.example/custom', criticalDescriptions: true }), /Critical descriptions/);
  assert.throws(() => validateForm({ ...FIELDS, criticalDescriptions: 'true' }), /type/);
});

test('the shipped form round-trips the checkbox, preserves Decisions, and clears incompatible opt-in', () => {
  const ui = app(path.resolve(__dirname, '../media/settings.js'), path.resolve(__dirname, '../src/settings.js'));
  ui.receive({ type: 'settings-state', values: { ...FIELDS, enabled: true, apiMode: 'decisions', model: 'gpt-6-luna', criticalDescriptions: true }, presets: PRESETS, modelOptions: MODEL_OPTIONS, hasKey: true });
  const field = name => ui.elements.get(`llm-${name}`);
  assert.equal(field('criticalDescriptions').checked, true);
  assert.equal(field('criticalDescriptions').disabled, false);
  assert.match(field('critical-hint').textContent, /normal input\/output charges/);
  field('form').dispatch('submit');
  const saved = ui.messages.at(-1);
  assert.equal(saved.values.criticalDescriptions, true);
  assert.equal(validateForm(saved.values).router.critical_descriptions, true);
  field('provider').value = 'claude';
  field('provider').dispatch('change');
  assert.equal(field('criticalDescriptions').checked, false);
  assert.equal(field('criticalDescriptions').disabled, true);
});
