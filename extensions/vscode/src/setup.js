'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { promisify, isDeepStrictEqual } = require('node:util');
const execFile = promisify(require('node:child_process').execFile);

function detectHosts(home = os.homedir()) {
  // Codex is configured before its first chat; also connect existing Claude installs.
  return ['codex', ...(fs.existsSync(path.join(home, '.claude')) ? ['claude'] : [])];
}

async function configureUserHooks({ binary, extensionPath, roots, debugLog, runtime = process.execPath, env = process.env, home = env.HOME || os.homedir(), hosts = detectHosts(home), isDirty = () => false, force = false, run = execFile }) {
  if (debugLog !== undefined && debugLog !== '' && !path.isAbsolute(debugLog)) throw new Error('Hook debug log path must be absolute.');
  const results = [];
  for (const host of hosts) {
    if (!['codex', 'claude'].includes(host)) throw new Error('Unsupported Distill hook host.');
    const policies = [`hook-policy-v3-${host}.toml`, `hook-policy-v2-${host}.toml`, `hook-policy-${host}.toml`].map(name => path.join(home, '.config/distill', name));
    const stored = policies.find(file => fs.existsSync(file));
    const globalPolicies = [path.join(home, '.config/distill/config.toml'), path.join(home, 'Library/Application Support/distill/config.toml')];
    const args = ['setup', host, '--node-runtime', runtime];
    const options = { env, timeout: 10000, maxBuffer: 1024 * 1024 };
    // Activation refreshes hook pins. Retain explicitly enabled diagnostics
    // instead of silently disabling them on the next extension reload.
    let log = debugLog;
    if (log === undefined) {
      const inventory = JSON.parse((await run(binary, ['hook-sources', host], options)).stdout);
      const logs = new Set((inventory.handlers || []).filter(handler => handler.scope === 'user').flatMap(handler => {
        const flags = handler.args || [];
        return flags.flatMap((flag, index) => flag === '--debug-log' ? [flags[index + 1]] : flag.startsWith('--debug-log=') ? [flag.slice('--debug-log='.length)] : []);
      }).filter(value => typeof value === 'string' && path.isAbsolute(value)));
      if (logs.size > 1) throw new Error('Distill user hooks specify different debug logs. Choose one path before reconnecting.');
      log = [...logs][0];
    }
    if (log) args.push('--debug-log', log);
    if (host === 'codex') args.push('--labels');
    if (!stored && !globalPolicies.some(file => fs.existsSync(file))) args.push('--config', path.join(extensionPath, 'config/extension-policy.toml'));
    for (const root of roots) args.push('--workspace-root', fs.realpathSync(root));
    const preview = JSON.parse((await run(binary, [...args, '--check'], options)).stdout);
    if (isDirty(preview.path)) throw new Error('Save or revert the open user hooks file before Distill can update it.');
    let existing;
    if (fs.existsSync(preview.path)) existing = JSON.parse(fs.readFileSync(preview.path, 'utf8'));
    const launcher = path.join(home, '.config/distill/hook-launcher.js');
    if (!force && stored === preview.policy_path && fs.existsSync(launcher) && isDeepStrictEqual(existing, preview.configuration)) {
      results.push({ ...preview, host, changed: false });
      continue;
    }
    const setup = JSON.parse((await run(binary, args, options)).stdout);
    results.push({ ...setup, host });
  }
  return results;
}

module.exports = { configureUserHooks, detectHosts };
