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

async function configureUserHooks({ binary, extensionPath, roots, runtime = process.execPath, env = process.env, home = env.HOME || os.homedir(), hosts = detectHosts(home), isDirty = () => false, force = false, run = execFile }) {
  const results = [];
  for (const host of hosts) {
    if (!['codex', 'claude'].includes(host)) throw new Error('Unsupported Distill hook host.');
    const stored = path.join(home, `.config/distill/hook-policy-${host}.toml`);
    const globalPolicies = [path.join(home, '.config/distill/config.toml'), path.join(home, 'Library/Application Support/distill/config.toml')];
    const args = ['setup', host, '--node-runtime', runtime];
    if (host === 'codex') args.push('--labels');
    if (!fs.existsSync(stored) && !globalPolicies.some(file => fs.existsSync(file))) args.push('--config', path.join(extensionPath, 'config/extension-policy.toml'));
    for (const root of roots) args.push('--workspace-root', fs.realpathSync(root));
    const options = { env, timeout: 10000, maxBuffer: 1024 * 1024 };
    const preview = JSON.parse((await run(binary, [...args, '--check'], options)).stdout);
    if (isDirty(preview.path)) throw new Error('Save or revert the open user hooks file before Distill can update it.');
    let existing;
    if (fs.existsSync(preview.path)) existing = JSON.parse(fs.readFileSync(preview.path, 'utf8'));
    const launcher = path.join(home, '.config/distill/hook-launcher.js');
    if (!force && fs.existsSync(stored) && fs.existsSync(launcher) && isDeepStrictEqual(existing, preview.configuration)) {
      results.push({ ...preview, host, changed: false });
      continue;
    }
    const setup = JSON.parse((await run(binary, args, options)).stdout);
    results.push({ ...setup, host });
  }
  return results;
}

module.exports = { configureUserHooks, detectHosts };
