'use strict';
const { execFile } = require('node:child_process');
function runWithInput(binary, args, { input, ...options }) {
  return new Promise((resolve, reject) => {
    const child = execFile(binary, args, options, (error, stdout) => {
      // Child errors may carry env/stdio metadata. Keep the secret path opaque.
      if (error) return reject(new Error('Service command failed. Check the installed service and router settings.'));
      resolve({ stdout });
    });
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}
const { CUSTOM_MODEL } = require('./models');
const REASONING_EFFORTS = ['provider_default', 'none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'];
const PRESETS = {
  openai_compatible: { endpoint: 'https://api.openai.com/v1/chat/completions', model: 'gpt-6-luna', key: 'OPENAI_API_KEY' },
  gemini: { endpoint: 'https://generativelanguage.googleapis.com/v1beta', model: 'gemini-3.1-flash-lite', key: 'GEMINI_API_KEY' },
  claude: { endpoint: 'https://api.anthropic.com/v1/messages', model: 'claude-haiku-5-5', key: 'ANTHROPIC_API_KEY' },
  llama_cpp: { endpoint: 'http://127.0.0.1:8080/v1/chat/completions', model: '', key: '' },
  vllm: { endpoint: 'http://127.0.0.1:8000/v1/chat/completions', model: '', key: '' },
};

// Routing is a user/machine choice. Never accept an endpoint or opt-in from a
// workspace, even when a caller supplies a resource-scoped configuration object.
function readRouterSettings(configuration) {
  const read = (key, fallback) => configuration.inspect(`llm.${key}`)?.globalValue ?? fallback;
  const provider = read('provider', 'openai_compatible');
  if (!Object.hasOwn(PRESETS, provider)) throw new Error('Unsupported LLM provider.');
  const preset = PRESETS[provider];
  const endpoint = read('endpoint', '') || preset.endpoint;
  const enabled = read('enabled', false);
  const selection = read('model', '');
  const model = selection === CUSTOM_MODEL ? read('customModel', '') : selection || preset.model;
  const keyChoice = read('apiKeyEnv', 'auto');
  const api_key_env = keyChoice === 'auto' ? preset.key : keyChoice === 'custom' ? read('customApiKeyEnv', '') : keyChoice;
  const reserved = new Set(['HOME', 'PATH', 'NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'ELECTRON_RUN_AS_NODE', 'DISTILL_SERVICE_OWNER_PID']);
  if (reserved.has(api_key_env)) throw new Error('Choose a dedicated API key variable, not a process-control variable.');
  const max_output_tokens = read('maxOutputTokens', 512);
  const reasoning = read('reasoningEffort', 'provider_default');
  if (!REASONING_EFFORTS.includes(reasoning)) throw new Error('Select a valid reasoning effort.');
  if (reasoning !== 'provider_default' && ['gemini', 'claude'].includes(provider)) throw new Error('Reasoning Effort must be Provider default for Gemini or Claude. Explicit effort uses the OpenAI-compatible API.');
  const deadline_ms = read('deadlineMs', 800);
  const background_deadline_ms = read('backgroundDeadlineMs', 5000);
  if (!Number.isInteger(background_deadline_ms) || background_deadline_ms < 100 || background_deadline_ms > 15000) throw new Error('Background model timeout must be between 100 and 15000 milliseconds.');
  const send_script_contents = read('sendScriptContents', false);
  const review_format = read('reviewFormat', 'severity');
  const batch_window_ms = read('batchWindowMs', 0);
  if (!['severity', 'effects'].includes(review_format) || !Number.isInteger(batch_window_ms) || batch_window_ms < 0 || batch_window_ms > 500 || batch_window_ms >= background_deadline_ms || (batch_window_ms > 0 && review_format !== 'severity')) throw new Error('Batch window must be 0–500 ms, shorter than the timeout, and requires severity reviews.');
  const url = new URL(endpoint);
  if (typeof enabled !== 'boolean' || typeof send_script_contents !== 'boolean' || typeof model !== 'string' || model.length > 256 || (enabled && !model.trim())) throw new Error('Select a served model before enabling the local LLM router.');
  if (endpoint.length > 2048 || url.username || url.password || url.hash || !(url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) throw new Error('LLM endpoint must use HTTPS or loopback HTTP, without URL credentials.');
  if (typeof api_key_env !== 'string' || !/^[A-Z0-9_]*$/.test(api_key_env)) throw new Error('LLM API Key Env must be an environment-variable name, or empty for a keyless server.');
  if (enabled && ['gemini', 'claude'].includes(provider) && !api_key_env) throw new Error('Gemini and Claude require an API key environment-variable name.');
  if (provider === 'gemini' && (url.search || url.pathname.includes(':generateContent'))) throw new Error('Gemini endpoint must be the API base URL; select the model separately.');
  if (!Number.isInteger(max_output_tokens) || max_output_tokens < 64 || max_output_tokens > 2048 || !Number.isInteger(deadline_ms) || deadline_ms < 20 || deadline_ms > 800) throw new Error('LLM output or deadline limit is invalid.');
  return { enabled, provider, endpoint, model, api_key_env, max_output_tokens, deadline_ms, background_deadline_ms, send_script_contents, review_format, batch_window_ms, max_script_bytes: 8192, ...(reasoning === 'provider_default' ? {} : { reasoning_effort: reasoning }) };
}

// execFile does not accept stdin. Keep JSON off command arguments and bound both
// streams, without invoking a shell or exposing credentials in settings.
async function configure(binary, host, router, { env = process.env } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(binary, ['configure-router', host, '--memory-only'], { env, timeout: 5000, maxBuffer: 65536 }, (error, stdout) => {
      if (error) return reject(error);
      try { resolve(JSON.parse(stdout)); } catch (error) { reject(error); }
    });
    child.stdin.on('error', () => {});
    child.stdin.end(JSON.stringify(router));
  });
}

async function syncRouter({ binary, hosts, router, env = process.env, credential, restart = false, run = runWithInput, apply = configure }) {
  const results = [];
  for (const host of hosts) {
    try { results.push(await apply(binary, host, router, { env })); }
    catch (error) {
      // A broken new route must not leave a previously enabled cloud route live.
      for (const target of hosts) await apply(binary, target, { enabled: false }, { env });
      try { await run(binary, ['service', 'stop'], { timeout: 2000, maxBuffer: 65536 }); } catch {}
      throw error;
    }
  }
  const result = results[hosts.indexOf('codex')] || results[0];
  if (!result) throw new Error('No configured hook host is available.');
  const call = async action => JSON.parse((await run(binary, ['service', action, ...(action === 'start' && credential ? ['--credential-stdin'] : [])], { env, ...(action === 'start' && credential ? { input: JSON.stringify(credential) } : {}), timeout: 6000, maxBuffer: 65536 })).stdout);
  let status = await call('status');
  if (status.running && (restart || !router.enabled || status.history_enabled || status.policy_digest !== result.policy_digest)) {
    await call('stop');
    // Stop is acknowledged before the listener exits; wait for endpoint cleanup.
    for (let count = 0; count < 40; count++) {
      await new Promise(resolve => setTimeout(resolve, 25));
      status = await call('status');
      if (!status.running) break;
    }
    if (status.running) throw new Error('Previous optional service is still stopping. Retry the router update.');
    if (router.enabled) status = await call('start');
  } else if (router.enabled && !status.running) status = await call('start');
  return { ...result, running: Boolean(status.running), model: router.model, enabled: router.enabled };
}

module.exports = { PRESETS, REASONING_EFFORTS, readRouterSettings, syncRouter, configure, runWithInput };
