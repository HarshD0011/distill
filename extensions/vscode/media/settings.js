/* global acquireVsCodeApi */
'use strict';
const vscode = acquireVsCodeApi();
const fieldNames = ['enabled', 'provider', 'endpoint', 'model', 'reasoningEffort', 'apiKeyEnv', 'customApiKeyEnv', 'maxOutputTokens', 'deadlineMs', 'backgroundDeadlineMs', 'sendScriptContents', 'reviewFormat', 'batchWindowMs'];
const get = name => document.getElementById(`llm-${name}`);
let presets = {};
let modelOptions = {};
let activeProvider;
const connectionDrafts = new Map();
const CUSTOM_MODEL = '__custom__';
function modelValue() { return get('model').value === CUSTOM_MODEL ? get('customModel').value : get('model').value; }
function values() { return Object.fromEntries(fieldNames.map(name => [name, name === 'model' ? modelValue() : ['enabled', 'sendScriptContents'].includes(name) ? get(name).checked : ['maxOutputTokens', 'deadlineMs', 'backgroundDeadlineMs', 'batchWindowMs'].includes(name) ? Number(get(name).value) : get(name).value])); }
function updateCustomModel() {
  const custom = get('model').value === CUSTOM_MODEL;
  get('customModel').hidden = !custom;
  get('custom-model-label').hidden = !custom;
  get('customModel').required = custom && get('enabled').checked;
}
function populateModels(model) {
  const provider = get('provider').value;
  const preset = presets[provider] || {};
  const choices = modelOptions[provider] || [];
  const option = (value, label) => { const element = document.createElement('option'); element.value = value; element.textContent = label; return element; };
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
  const reasoningSupported = !['gemini', 'claude'].includes(get('provider').value);
  get('reasoningEffort').disabled = !reasoningSupported;
  if (!reasoningSupported) get('reasoningEffort').value = 'provider_default';
  get('reasoning-hint').textContent = reasoningSupported ? 'Applies to every model unchanged. Model support varies; unsupported options return an error. Use the same effort when comparing latency.' : 'This provider uses its default reasoning settings.';
  get('endpoint').placeholder = preset.endpoint || '';
  const custom = get('apiKeyEnv').value === 'custom';
  get('customApiKeyEnv').hidden = !custom; get('custom-label').hidden = !custom;
  const noKey = get('apiKeyEnv').value === '' || (get('apiKeyEnv').value === 'auto' && !preset.key);
  get('api-key').disabled = noKey;
  get('apiKeyEnv').children[0].textContent = preset.key ? `Provider default (${preset.key})` : 'Provider default (no key)';
}
function busy(value) { get('save').disabled = value; get('forget').disabled = value; }
function connectionChanged() { get('api-key').value = ''; get('key-status').textContent = 'Apply to check the saved key for this connection.'; updateProvider(); }
get('provider').addEventListener('change', () => {
  if (activeProvider) connectionDrafts.set(activeProvider, { model: modelValue(), endpoint: get('endpoint').value, reasoningEffort: get('reasoningEffort').value });
  activeProvider = get('provider').value;
  const draft = connectionDrafts.get(activeProvider) || { model: '', endpoint: '', reasoningEffort: 'provider_default' };
  get('endpoint').value = draft.endpoint;
  get('reasoningEffort').value = draft.reasoningEffort;
  populateModels(draft.model);
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
      if (['enabled', 'sendScriptContents'].includes(name)) field.checked = data.values[name];
      else field.value = String(data.values[name]);
    }
    activeProvider = data.values.provider;
    connectionDrafts.clear();
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
