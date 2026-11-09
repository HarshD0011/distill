'use strict';

// Curated text-model choices, checked against provider catalogs on 2026-11-08.
// These are suggestions, not an account-availability check or a fallback chain.
// https://developers.openai.com/api/docs/models
// https://developers.openai.com/api/docs/deprecations
// https://ai.google.dev/gemini-api/docs/models
// https://platform.claude.com/docs/en/models/overview
const MODEL_OPTIONS = {
  openai_compatible: [
    { id: 'gpt-6-luna', label: 'GPT-6 Luna' },
    { id: 'gpt-5.4-mini', label: 'GPT-5.4 Mini' },
    { id: 'gpt-5.4-nano', label: 'GPT-5.4 Nano (deprecated; retires 2027-04-01)' },
    { id: 'gpt-5-mini', label: 'GPT-5 Mini (deprecated; retires 2026-12-11)' },
    { id: 'gpt-5-nano', label: 'GPT-5 Nano (deprecated; retires 2026-12-11)' },
    { id: 'gpt-6.1-terra', label: 'GPT-6.1 Terra' },
    { id: 'gpt-6.1-sol', label: 'GPT-6.1 Sol' },
    { id: 'gpt-6-astra', label: 'GPT-6 Astra' },
    { id: 'gpt-6-sol', label: 'GPT-6 Sol' },
    { id: 'gpt-5.6-luna', label: 'GPT-5.6 Luna' },
    { id: 'gpt-5.6-terra', label: 'GPT-5.6 Terra' },
    { id: 'gpt-5.6-sol', label: 'GPT-5.6 Sol' },
    { id: 'gpt-5.5', label: 'GPT-5.5' },
    { id: 'gpt-5.4', label: 'GPT-5.4' },
    { id: 'gpt-5.2', label: 'GPT-5.2' },
    { id: 'gpt-5.1', label: 'GPT-5.1 (deprecated; retires 2027-04-01)' },
    { id: 'gpt-5', label: 'GPT-5 (deprecated; retires 2026-12-11)' },
    { id: 'gpt-4.1-mini', label: 'GPT-4.1 Mini (deprecated; retires 2027-01-14)' },
    { id: 'gpt-4.1', label: 'GPT-4.1 (deprecated; retires 2027-01-14)' },
    { id: 'gpt-4o-mini', label: 'GPT-4o Mini (deprecated; retires 2027-01-14)' },
    { id: 'gpt-4o', label: 'GPT-4o (deprecated; retires 2027-01-14)' },
  ],
  gemini: [
    { id: 'gemini-3.1-flash-lite', label: 'Gemini 3.1 Flash-Lite' },
    { id: 'gemini-3.5-flash-lite', label: 'Gemini 3.5 Flash-Lite' },
    { id: 'gemini-3.8-flash', label: 'Gemini 3.8 Flash' },
    { id: 'gemini-3.1-pro-preview', label: 'Gemini 3.1 Pro (preview)' },
  ],
  claude: [
    { id: 'claude-haiku-5-5', label: 'Claude Haiku 5.5' },
    { id: 'claude-sonnet-5-5', label: 'Claude Sonnet 5.5' },
    { id: 'claude-opus-5-5', label: 'Claude Opus 5.5' },
  ],
  llama_cpp: [],
  vllm: [],
};

const CUSTOM_MODEL = '__custom__';
const providers = { openai_compatible: 'OpenAI / compatible API', gemini: 'Google Gemini', claude: 'Anthropic Claude' };
function modelChoices() {
  return Object.entries(MODEL_OPTIONS).flatMap(([provider, models]) => models.map(model => ({ ...model, provider })));
}
function modelPreference(model) {
  if (typeof model !== 'string' || model === CUSTOM_MODEL) throw new Error('Enter the exact custom model ID.');
  if (model === '' || modelChoices().some(choice => choice.id === model)) return { model, customModel: '' };
  return { model: CUSTOM_MODEL, customModel: model };
}
function modelSettingSchema() {
  const choices = modelChoices();
  return {
    type: 'string',
    default: '',
    enum: ['', ...choices.map(choice => choice.id), CUSTOM_MODEL],
    enumItemLabels: ['Provider default', ...choices.map(choice => `${providers[choice.provider]} · ${choice.label}`), 'Custom model…'],
    enumDescriptions: ['Use the selected provider’s default model.', ...choices.map(choice => `Model ID: ${choice.id}. Select ${providers[choice.provider]} as the provider. Availability depends on your endpoint and account.`), 'Use the exact model ID in Distill › Llm: Custom Model.'],
    maxLength: 256,
    scope: 'machine',
    markdownDescription: 'Select a model for the configured provider. For another model or local served alias, choose **Custom model…** and set `#distill.llm.customModel#`. The **Distill: Configure LLM Router** command opens the provider-specific form and secure API key entry.',
  };
}

module.exports = { MODEL_OPTIONS, CUSTOM_MODEL, modelChoices, modelPreference, modelSettingSchema };
