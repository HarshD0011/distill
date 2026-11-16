/* global acquireVsCodeApi */
'use strict';
const vscode = acquireVsCodeApi();
const fieldNames = ['enabled', 'provider', 'apiMode', 'endpoint', 'model', 'reasoningEffort', 'apiKeyEnv', 'customApiKeyEnv', 'maxOutputTokens', 'deadlineMs', 'backgroundDeadlineMs', 'sendScriptContents', 'criticalDescriptions', 'reviewFormat', 'batchWindowMs'];
const get = name => document.getElementById(`llm-${name}`);
let presets = {};
let modelOptions = {};
let activeProvider;
let activeApiMode;
const connectionDrafts = new Map();
const apiDrafts = new Map();
const CUSTOM_MODEL = '__custom__';
const isDecisions = () => get('provider').value === 'openai_compatible' && get('apiMode').value === 'decisions';
function modelValue() { return get('model').value === CUSTOM_MODEL ? get('customModel').value : get('model').value; }
function values() { return Object.fromEntries(fieldNames.map(name => [name, name === 'model' ? modelValue() : ['enabled', 'sendScriptContents', 'criticalDescriptions'].includes(name) ? get(name).checked : ['maxOutputTokens', 'deadlineMs', 'backgroundDeadlineMs', 'batchWindowMs'].includes(name) ? Number(get(name).value) : get(name).value])); }
function updateCustomModel() {
  const custom = !isDecisions() && get('model').value === CUSTOM_MODEL;
  get('customModel').hidden = !custom;
  get('custom-model-label').hidden = !custom;
  get('customModel').required = custom && get('enabled').checked;
}
function populateModels(model) {
  const provider = get('provider').value;
  const preset = presets[provider] || {};
  const choices = modelOptions[provider] || [];
  const option = (value, label) => { const element = document.createElement('option'); element.value = value; element.textContent = label; return element; };
  if (isDecisions()) {
    const selected = model || 'gpt-6-luna';
    get('model').replaceChildren(option('gpt-6-luna', 'GPT-6 Luna (gpt-6-luna)'),
      ...(selected === 'gpt-6-luna' ? [] : [option(selected, `Unsupported saved model: ${selected}`)]));
    get('model').value = selected;
    get('customModel').value = '';
    get('model-hint').textContent = 'Decisions currently supports GPT-6 Luna only.';
    updateCustomModel();
    return;
  }
  get('model').replaceChildren(
    option('', preset.model ? `Provider default (${preset.model})` : 'Choose a served model'),
    ...choices.map(model => option(model.id, `${model.label} (${model.id})`)),
    option(CUSTOM_MODEL, 'Custom model…'),
  );
  const custom = !preset.model || Boolean(model) && !choices.some(choice => choice.id === model);
  get('model').value = custom ? CUSTOM_MODEL : model;
  get('customModel').value = custom ? model : '';
  get('model-hint').textContent = preset.model ? 'Choose a model available to your endpoint and account, or enter an exact custom ID.' : 'Enter the exact model name or alias served by your local server.';
  updateCustomModel();
}
function updateProvider() {
  const preset = presets[get('provider').value] || {};
  get('apiMode').disabled = get('provider').value !== 'openai_compatible';
  if (get('apiMode').disabled) get('apiMode').value = 'provider_default';
  const decisions = isDecisions();
  const reasoningSupported = !decisions && !['gemini', 'claude'].includes(get('provider').value);
  get('reasoningEffort').disabled = !reasoningSupported;
  if (!reasoningSupported && !decisions) get('reasoningEffort').value = 'provider_default';
  get('reasoning-hint').textContent = decisions ? 'Not used by Decisions. No reasoning-effort parameter is sent.' : reasoningSupported ? 'None disables reasoning on supported models. Provider default leaves the model’s own setting unchanged; it does not necessarily turn reasoning off.' : 'This provider uses its default reasoning settings.';
  get('api-hint').textContent = decisions ? 'Typed severity classifications with GPT-6 Luna. Reasoning effort and output-token limits are not sent. Static review requirements stay in force.' : get('provider').value === 'openai_compatible' ? 'Uses Chat Completions. Choose Decisions for typed severity classifications, or set Reasoning effort to None on a supported chat model.' : 'Uses the selected provider’s native API. Decisions is available with OpenAI / compatible API only.';
  get('model').disabled = decisions;
  get('maxOutputTokens').disabled = decisions;
  get('reviewFormat').disabled = decisions;
  if (get('reviewFormat').children[0]) get('reviewFormat').children[0].textContent = decisions ? 'Severity only (typed decisions)' : 'Severity only (semicolon separated)';
  get('endpoint').placeholder = (decisions ? preset.decisionsEndpoint : preset.endpoint) || '';
  let descriptionsSupported = false;
  try { descriptionsSupported = get('provider').value === 'openai_compatible' && /\/(?:chat\/completions|decisions)$/.test(new URL(get('endpoint').value || (decisions ? preset.decisionsEndpoint : preset.endpoint)).pathname); } catch {}
  get('criticalDescriptions').disabled = !descriptionsSupported;
  if (!descriptionsSupported) get('criticalDescriptions').checked = false;
  get('critical-hint').textContent = descriptionsSupported ? 'Uses GPT-6 Luna on this connection to explain critical commands in plain language. Requires enabled routing. Adds a text request with normal input/output charges; explanations never approve commands.' : 'Critical descriptions require an OpenAI-compatible Chat Completions or Decisions connection.';
  const custom = get('apiKeyEnv').value === 'custom';
  get('customApiKeyEnv').hidden = !custom; get('custom-label').hidden = !custom;
  const noKey = get('apiKeyEnv').value === '' || (get('apiKeyEnv').value === 'auto' && !preset.key);
  get('api-key').disabled = noKey;
  get('apiKeyEnv').children[0].textContent = preset.key ? `Provider default (${preset.key})` : 'Provider default (no key)';
}
function busy(value) { get('save').disabled = value; get('forget').disabled = value; }
function connectionChanged() { get('api-key').value = ''; get('key-status').textContent = 'Apply to check the saved key for this connection.'; updateProvider(); }
function captureDraft(apiMode = get('apiMode').value) {
  return { apiMode, model: modelValue(), endpoint: get('endpoint').value, reasoningEffort: get('reasoningEffort').value, reviewFormat: get('reviewFormat').value, maxOutputTokens: get('maxOutputTokens').value };
}
function defaultDraft(apiMode = 'provider_default') {
  return { apiMode, model: apiMode === 'decisions' ? 'gpt-6-luna' : '', endpoint: '', reasoningEffort: 'provider_default', reviewFormat: 'severity', maxOutputTokens: '512' };
}
function restoreDraft(draft) {
  for (const name of ['apiMode', 'endpoint', 'reasoningEffort', 'reviewFormat', 'maxOutputTokens']) get(name).value = draft[name];
  activeApiMode = draft.apiMode;
  populateModels(draft.model);
}
get('provider').addEventListener('change', () => {
  if (activeProvider) {
    const draft = captureDraft(activeApiMode);
    connectionDrafts.set(activeProvider, draft);
    if (activeProvider === 'openai_compatible') apiDrafts.set(activeApiMode, draft);
  }
  activeProvider = get('provider').value;
  restoreDraft(connectionDrafts.get(activeProvider) || defaultDraft());
  connectionChanged();
});
get('apiMode').addEventListener('change', () => {
  const selected = get('apiMode').value;
  apiDrafts.set(activeApiMode, captureDraft(activeApiMode));
  restoreDraft(apiDrafts.get(selected) || defaultDraft(selected));
  connectionChanged();
});
for (const name of ['endpoint', 'apiKeyEnv', 'customApiKeyEnv']) get(name).addEventListener('change', connectionChanged);
get('model').addEventListener('change', updateCustomModel);
get('enabled').addEventListener('change', updateCustomModel);
get('form').addEventListener('submit', event => {
  event.preventDefault();
  const selected = values();
  if (selected.enabled && get('model').value === CUSTOM_MODEL && !selected.model.trim()) { get('result').textContent = 'Enter a custom model ID or select a provider model.'; return; }
  busy(true); const apiKey = get('api-key').value; get('api-key').value = ''; vscode.postMessage({ type: 'save', values: selected, apiKey });
});
get('forget').addEventListener('click', () => { busy(true); get('api-key').value = ''; vscode.postMessage({ type: 'forget', values: values() }); });
get('advanced').addEventListener('click', () => vscode.postMessage({ type: 'advanced' }));
window.addEventListener('message', ({ data }) => {
  if (data.type === 'settings-state') {
    presets = data.presets;
    modelOptions = data.modelOptions || {};
    for (const name of fieldNames) {
      if (name === 'model') continue;
      const field = get(name);
      if (['enabled', 'sendScriptContents', 'criticalDescriptions'].includes(name)) field.checked = data.values[name];
      else field.value = String(data.values[name]);
    }
    activeProvider = data.values.provider;
    activeApiMode = data.values.apiMode || 'provider_default';
    connectionDrafts.clear();
    apiDrafts.clear();
    populateModels(data.values.model);
    // Preserve pre-dropdown custom variable names without exposing credentials.
    if (!['auto', '', 'custom', 'OPENAI_API_KEY', 'GEMINI_API_KEY', 'ANTHROPIC_API_KEY'].includes(data.values.apiKeyEnv)) { get('apiKeyEnv').value = 'custom'; get('customApiKeyEnv').value = data.values.apiKeyEnv; }
    get('api-key').value = '';
    get('key-status').textContent = data.hasKey ? 'A key is saved securely for this connection. Leave the field empty to keep it.' : 'No saved key for this connection. You can paste one above or use the selected environment variable.';
    get('result').textContent = data.message || '';
    updateProvider(); busy(false);
  } else if (data.type === 'settings-error') { get('api-key').value = ''; get('result').textContent = data.message; busy(false); }
});
vscode.postMessage({ type: 'ready' });
