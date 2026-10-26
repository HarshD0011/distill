'use strict';
function redact(text) {
  return text.replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi, '$1[REDACTED]@')
    .replace(/((?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic)?\s*)[^\s'";]+/gi, '$1[REDACTED]')
    .replace(/((?:[a-z_]*(?:token|password|passwd|secret|api_key|apikey|access_key|private_key)[a-z_]*|AWS_ACCESS_KEY_ID)\s*[=:]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s;]+)/gi, '$1[REDACTED]')
    .replace(/((?:--password|--token|--secret|--api-key|-u|--user)\s+)(?:"[^"\n]*"|'[^'\n]*'|[^\s;]+)/gi, '$1[REDACTED]')
    .replace(/\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b/g, '[REDACTED]')
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[REDACTED]');
}
function redactValue(value) {
  if (typeof value === 'string') return redact(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, /password|secret|token|api.?key|authorization/i.test(key) ? '[REDACTED]' : redactValue(item)]));
  return value;
}
module.exports = { redact, redactValue };
