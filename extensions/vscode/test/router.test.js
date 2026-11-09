'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readRouterSettings, syncRouter } = require('../src/router');
const settings = (global = {}, workspace = {}) => ({ inspect: key => ({ globalValue: global[key], workspaceValue: workspace[key] }) });

test('router defaults to disabled and Luna, ignoring workspace routing and opt-in', () => {
  const config = readRouterSettings(settings({}, { 'llm.enabled': true, 'llm.endpoint': 'https://untrusted.invalid', 'llm.model': 'expensive' }));
  assert.equal(config.enabled, false); assert.equal(config.model, 'gpt-6-luna');
  assert.equal(config.endpoint, 'https://api.openai.com/v1/chat/completions');
  assert.equal(config.api_key_env, 'OPENAI_API_KEY'); assert.equal(config.max_output_tokens, 512);
});
test('local server presets require an exact model and do not inherit a cloud API key', () => {
  for (const [provider, port] of [['llama_cpp', 8080], ['vllm', 8000]]) {
    const selected = readRouterSettings(settings({ 'llm.enabled': true, 'llm.provider': provider, 'llm.model': 'my-local-model' }));
    assert.equal(selected.model, 'my-local-model'); assert.equal(selected.api_key_env, '');
    assert.equal(selected.endpoint, `http://127.0.0.1:${port}/v1/chat/completions`);
    assert.throws(() => readRouterSettings(settings({ 'llm.enabled': true, 'llm.provider': provider })), /served model/);
  }
  const custom = readRouterSettings(settings({ 'llm.model': 'my-budget-model', 'llm.endpoint': 'https://provider.example/v1/chat/completions', 'llm.apiKeyEnv': 'MY_PROVIDER_KEY' }));
  assert.equal(custom.model, 'my-budget-model'); assert.equal(custom.api_key_env, 'MY_PROVIDER_KEY');
  assert.equal(readRouterSettings(settings({ 'llm.apiKeyEnv': '' })).api_key_env, '');
  for (const name of ['HOME', 'NODE_OPTIONS', 'DYLD_INSERT_LIBRARIES', 'DISTILL_SERVICE_OWNER_PID']) assert.throws(() => readRouterSettings(settings({ 'llm.apiKeyEnv': 'custom', 'llm.customApiKeyEnv': name })), /dedicated API key variable/);
  for (const endpoint of ['http://remote.invalid/v1/chat/completions', 'https://key@remote.invalid/v1/chat/completions', 'file:///tmp/model']) assert.throws(() => readRouterSettings(settings({ 'llm.endpoint': endpoint })), /HTTPS/);
});
test('Gemini and Claude presets select their own models, endpoints and key variables', () => {
  for (const [provider, model, key, endpoint] of [
    ['gemini', 'gemini-3.1-flash-lite', 'GEMINI_API_KEY', 'https://generativelanguage.googleapis.com/v1beta'],
    ['claude', 'claude-haiku-5-5', 'ANTHROPIC_API_KEY', 'https://api.anthropic.com/v1/messages'],
  ]) {
    const config = readRouterSettings(settings({ 'llm.provider': provider, 'llm.enabled': true }));
    assert.equal(config.model, model); assert.equal(config.api_key_env, key); assert.equal(config.endpoint, endpoint);
    const custom = readRouterSettings(settings({ 'llm.provider': provider, 'llm.model': 'my-chosen-model', 'llm.apiKeyEnv': 'MY_PROVIDER_KEY' }));
    assert.equal(custom.model, 'my-chosen-model'); assert.equal(custom.api_key_env, 'MY_PROVIDER_KEY');
    assert.throws(() => readRouterSettings(settings({ 'llm.provider': provider, 'llm.enabled': true, 'llm.apiKeyEnv': '' })), /API key/);
  }
  assert.throws(() => readRouterSettings(settings({ 'llm.provider': 'gemini', 'llm.endpoint': 'https://generativelanguage.googleapis.com/v1beta/models/wrong:generateContent' })), /base URL/);
});
test('disabling routing stops an existing service and never restarts history', async () => {
  const actions = []; const applied = []; let running = true;
  const result = await syncRouter({ binary: '/trusted/distill', hosts: ['codex'], router: { enabled: false, model: 'gpt-6-luna' }, apply: async (_binary, host, router) => { applied.push({ host, router }); return { policy_digest: 'new', history_enabled: true }; }, run: async (_binary, args) => {
    const action = args[1]; actions.push(action);
    if (action === 'stop') running = false;
    if (action === 'start') running = true;
    return { stdout: JSON.stringify({ running, policy_digest: action === 'start' ? 'new' : 'old' }) };
  } });
  assert.deepEqual(actions, ['status', 'stop', 'status']);
  assert.equal(applied[0].router.enabled, false); assert.equal(result.enabled, false);
});
test('key variable dropdown resolves defaults, explicit presets, custom names and keyless access', () => {
  assert.equal(readRouterSettings(settings({ 'llm.provider': 'gemini', 'llm.apiKeyEnv': 'auto' })).api_key_env, 'GEMINI_API_KEY');
  assert.equal(readRouterSettings(settings({ 'llm.apiKeyEnv': 'ANTHROPIC_API_KEY' })).api_key_env, 'ANTHROPIC_API_KEY');
  assert.equal(readRouterSettings(settings({ 'llm.apiKeyEnv': 'custom', 'llm.customApiKeyEnv': 'MY_PROVIDER_KEY' })).api_key_env, 'MY_PROVIDER_KEY');
  assert.equal(readRouterSettings(settings({ 'llm.apiKeyEnv': '' })).api_key_env, '');
});
test('credential rotation restarts a service even with an unchanged policy and passes keys only on start', async () => {
  const calls = []; let running = true;
  const env = { PATH: '/usr/bin:/bin' };
  const credential = { provider: 'openai_compatible', endpoint: 'https://api.openai.com/v1/chat/completions', api_key_env: 'OPENAI_API_KEY', key: 'local-fixture-key' };
  await syncRouter({ binary: '/trusted/distill', hosts: ['codex'], router: { enabled: true }, env, credential, restart: true,
    apply: async () => ({ policy_digest: 'same', history_enabled: false }),
    run: async (_binary, args, options) => { const action = args[1]; calls.push({ args, options }); if (action === 'stop') running = false; if (action === 'start') running = true; return { stdout: JSON.stringify({ running, policy_digest: 'same' }) }; },
  });
  assert.deepEqual(calls.map(v => v.args[1]), ['status', 'stop', 'status', 'start']);
  assert.deepEqual(calls.at(-1).args, ['service', 'start', '--credential-stdin']);
  assert.equal(JSON.parse(calls.at(-1).options.input).key, 'local-fixture-key');
  for (const call of calls) assert.ok(!JSON.stringify(call.options.env).includes('local-fixture-key'));
  for (const call of calls.slice(0, -1)) assert.equal(call.options.input, undefined);
  assert.ok(!JSON.stringify(calls.map(v => v.args)).includes('local-fixture-key'));
});
test('compact batching is opt-in, bounded and uses user settings only', () => {
  assert.equal(readRouterSettings(settings()).review_format, 'severity');
  assert.equal(readRouterSettings(settings()).batch_window_ms, 0);
  assert.equal(readRouterSettings(settings({ 'llm.batchWindowMs': 500 })).batch_window_ms, 500);
  for (const values of [{ 'llm.batchWindowMs': 501 }, { 'llm.batchWindowMs': 500, 'llm.backgroundDeadlineMs': 300 }, { 'llm.reviewFormat': 'effects', 'llm.batchWindowMs': 100 }]) assert.throws(() => readRouterSettings(settings(values)), /Batch window/);
  assert.equal(readRouterSettings(settings({}, { 'llm.batchWindowMs': 500 })).batch_window_ms, 0);
});
test('an invalid route disables every host and never selects a fallback model', async () => {
  const applied = []; const actions = [];
  await assert.rejects(syncRouter({ binary: '/trusted/distill', hosts: ['codex', 'claude'], router: { enabled: true, model: 'chosen-local-model' }, apply: async (_binary, host, router) => {
    applied.push({ host, router }); if (router.enabled) throw new Error('invalid route'); return {};
  }, run: async (_binary, args) => { actions.push(args[1]); assert.equal(args[1], 'stop'); return {}; } }), /invalid route/);
  assert.deepEqual(applied.map(v => [v.host, v.router.enabled]), [['codex', true], ['codex', false], ['claude', false]]);
  assert.equal(applied[0].router.model, 'chosen-local-model');
  assert.deepEqual(actions, ['stop']);
});
