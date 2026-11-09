'use strict';
const crypto = require('node:crypto');
const { PRESETS, REASONING_EFFORTS, readRouterSettings } = require('./router');
const { MODEL_OPTIONS, CUSTOM_MODEL } = require('./models');
const FIELDS = { enabled: false, provider: 'openai_compatible', endpoint: '', model: '', reasoningEffort: 'provider_default', apiKeyEnv: 'auto', customApiKeyEnv: '', maxOutputTokens: 512, deadlineMs: 800, backgroundDeadlineMs: 5000, sendScriptContents: false, reviewFormat: 'severity', batchWindowMs: 0 };
function formValues(configuration) {
  const values = Object.fromEntries(Object.entries(FIELDS).map(([key, fallback]) => [key, configuration.inspect(`llm.${key}`)?.globalValue ?? fallback]));
  if (values.model === CUSTOM_MODEL) values.model = configuration.inspect('llm.customModel')?.globalValue ?? '';
  return values;
}
function validateForm(values) {
  if (!values || typeof values !== 'object' || Array.isArray(values)) throw new Error('Invalid LLM settings.');
  const result = Object.fromEntries(Object.keys(FIELDS).map(key => [key, values[key] ?? FIELDS[key]]));
  for (const [key, fallback] of Object.entries(FIELDS)) if (typeof result[key] !== typeof fallback) throw new Error('Invalid LLM setting type.');
  const router = readRouterSettings({ inspect: key => ({ globalValue: result[key.slice(4)] }) });
  return { values: result, router };
}
function settingsHtml(vscode, context, webview) {
  const nonce = crypto.randomBytes(24).toString('hex');
  const resource = name => webview.asWebviewUri(vscode.Uri.joinPath(context.extensionUri, 'media', name));
  const reasoningControl = `<label for="llm-reasoningEffort">Reasoning effort</label><select id="llm-reasoningEffort" aria-describedby="llm-reasoning-hint">${REASONING_EFFORTS.map(effort => `<option value="${effort}">${effort === 'provider_default' ? 'Provider default (omit parameter)' : effort}</option>`).join('')}</select><p id="llm-reasoning-hint">Explicit effort applies to compatible APIs. Model support varies; unsupported options return an error.</p>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';"><link rel="stylesheet" href="${resource('settings.css')}"><title>Distill LLM settings</title></head><body><h1>LLM settings</h1><p>Keys are remembered in VS Code's encrypted SecretStorage. Command history stays in memory and resets on window reload.</p><form id="llm-form"><label class="check"><input id="llm-enabled" type="checkbox">Enable advisory LLM routing</label><label for="llm-provider">Provider</label><select id="llm-provider"><option value="openai_compatible">OpenAI / compatible API</option><option value="gemini">Google Gemini</option><option value="claude">Anthropic Claude</option><option value="llama_cpp">Local llama.cpp</option><option value="vllm">Local vLLM</option></select><label for="llm-apiKeyEnv">API key variable</label><select id="llm-apiKeyEnv"><option value="auto">Provider default</option><option value="OPENAI_API_KEY">OPENAI_API_KEY</option><option value="GEMINI_API_KEY">GEMINI_API_KEY</option><option value="ANTHROPIC_API_KEY">ANTHROPIC_API_KEY</option><option value="">No key (local / compatible API)</option><option value="custom">Custom variable…</option></select><label id="llm-custom-label" for="llm-customApiKeyEnv" hidden>Custom variable name</label><input id="llm-customApiKeyEnv" type="text" placeholder="MY_PROVIDER_KEY" hidden><label for="llm-api-key">API key</label><input id="llm-api-key" type="password" autocomplete="off" spellcheck="false" maxlength="16384" placeholder="Paste your API key"><p id="llm-key-status" role="status"></p><button id="llm-forget" type="button" class="secondary">Remove saved key</button><label for="llm-model">Model</label><select id="llm-model" aria-describedby="llm-model-hint"></select><label id="llm-custom-model-label" for="llm-customModel" hidden>Custom model ID</label><input id="llm-customModel" type="text" maxlength="256" spellcheck="false" placeholder="Exact model ID or served alias" hidden><p id="llm-model-hint" class="hint">Choose a provider model or enter a custom model ID.</p>${reasoningControl}<label for="llm-endpoint">Endpoint</label><input id="llm-endpoint" type="url" maxlength="2048"><p class="hint">Empty uses the provider preset. Gemini takes a base URL; other providers take the complete request URL.</p><label for="llm-maxOutputTokens">Maximum output tokens</label><input id="llm-maxOutputTokens" type="number" min="64" max="2048"><input id="llm-deadlineMs" type="hidden"><label for="llm-backgroundDeadlineMs">Background model timeout (milliseconds)</label><input id="llm-backgroundDeadlineMs" type="number" min="100" max="15000"><p class="hint">Unresolved commands request model advice in the background. Static review requirements apply while it is pending.</p><label for="llm-reviewFormat">Model reply format</label><select id="llm-reviewFormat"><option value="severity">Severity only (semicolon separated)</option><option value="effects">Structured effects (legacy)</option></select><label for="llm-batchWindowMs">Batch window (milliseconds)</label><input id="llm-batchWindowMs" type="number" min="0" max="500"><p class="hint">0 sends immediately. Up to 500 ms groups overlapping severity reviews, adding a wait to save requests. Sequential agent commands cannot be grouped before they arrive.</p><label class="check"><input id="llm-sendScriptContents" type="checkbox">Include inspected script excerpts (up to 8 KiB)</label><p class="hint">Enabled routing sends the command and structured analysis to the selected endpoint. Disabling routing uses static analysis only.</p><div class="actions"><button id="llm-save" type="submit">Apply settings</button><button id="llm-advanced" type="button" class="secondary">Open VS Code settings</button></div><p id="llm-result" role="status" aria-live="polite"></p></form><script nonce="${nonce}" src="${resource('settings.js')}"></script></body></html>`;
}
function createRouterSettings(vscode, context, { configuration, credentials, apply, forget }) {
  let panel;
  let working = false;
  const state = async () => {
    const values = formValues(configuration());
    let hasKey = false;
    try { hasKey = await credentials.has(validateForm(values).router); } catch {}
    return { type: 'settings-state', values, presets: PRESETS, modelOptions: MODEL_OPTIONS, hasKey };
  };
  return {
    open() {
      if (panel) { panel.reveal(); return; }
      panel = vscode.window.createWebviewPanel('distill.llmSettings', 'Distill LLM settings', vscode.ViewColumn.Active, { enableScripts: true, localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'media')] });
      const current = panel;
      current.webview.html = settingsHtml(vscode, context, current.webview);
      context.subscriptions.push(current.onDidDispose(() => { if (panel === current) panel = undefined; }));
      context.subscriptions.push(current.webview.onDidReceiveMessage(async message => {
        if (panel !== current || !message || typeof message.type !== 'string') return;
        if (message.type === 'ready') { await current.webview.postMessage(await state()); return; }
        if (message.type === 'advanced') { await vscode.commands.executeCommand('workbench.action.openSettings', '@ext:distill.distill-trace llm'); return; }
        if (!['save', 'forget'].includes(message.type) || working) return;
        working = true;
        try {
          const validated = validateForm(message.values);
          if (message.type === 'save') await apply(validated.values, validated.router, message.apiKey);
          else await forget(validated.router);
          await current.webview.postMessage({ ...await state(), message: message.type === 'save' ? 'Settings applied. Saved keys stay in encrypted SecretStorage.' : 'Saved key removed. Editor service starts do not use ambient environment keys.' });
        } catch { await current.webview.postMessage({ type: 'settings-error', message: 'Could not apply settings. Check the model, endpoint and API key variable; review Distill errors for details.' }); }
        finally { working = false; }
      }));
      context.subscriptions.push(current);
    },
  };
}
module.exports = { FIELDS, formValues, validateForm, settingsHtml, createRouterSettings };
