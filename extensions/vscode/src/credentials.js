'use strict';
const crypto = require('node:crypto');

// Endpoint-bound slots prevent a saved provider key following an endpoint change.
// SecretStorage is the only persistence API used here. Never return keys to a view.
function credentialSlot(router) {
  return 'distill.llm.key.' + crypto.createHash('sha256').update(JSON.stringify([router.provider, router.endpoint, router.api_key_env])).digest('hex');
}
class RouterCredentials {
  constructor(secrets) { this.secrets = secrets; }
  async has(router) { return Boolean(router.api_key_env && await this.secrets.get(credentialSlot(router))); }
  async save(router, key) {
    if (!router.api_key_env) throw new Error('Select an API key variable before entering a key.');
    if (typeof key !== 'string' || !key.trim() || key.length > 16384 || /[\r\n\0]/.test(key)) throw new Error('Enter a valid API key without line breaks.');
    await this.secrets.store(credentialSlot(router), key.trim());
  }
  async forget(router) { await this.secrets.delete(credentialSlot(router)); }
  environment(_router, base = process.env) {
    return { ...(base.HOME ? { HOME: base.HOME } : {}), PATH: '/usr/bin:/bin', DISTILL_SERVICE_OWNER_PID: String(process.pid) };
  }
  async handoff(router) {
    // No environment fallback: a changed endpoint or removed key must never
    // silently pick up an ambient provider credential.
    const key = router.api_key_env ? await this.secrets.get(credentialSlot(router)) : undefined;
    return { provider: router.provider, endpoint: router.endpoint, api_key_env: router.api_key_env, key: key || null };
  }
}
module.exports = { RouterCredentials, credentialSlot };
