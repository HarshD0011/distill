'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawn, execFileSync } = require('node:child_process');
const { traceDirectory, processIdentity, endpointPath, secureDirectory, readEndpoint, rpc } = require('./transport');

function resolveBinary(configured = '') {
  if (configured && configured !== 'distill' && !path.isAbsolute(configured)) throw new Error('Set distill.binaryPath to an absolute executable path');
  const candidates = configured && configured !== 'distill' ? [configured] : [path.join(os.homedir(), '.cargo/bin/distill'), '/opt/homebrew/bin/distill', '/usr/local/bin/distill', '/usr/bin/distill'];
  for (const candidate of candidates) {
    try {
      const resolved = fs.realpathSync(candidate);
      const metadata = fs.statSync(resolved);
      if (!metadata.isFile() || metadata.mode & 0o022 || ![0, process.getuid()].includes(metadata.uid)) continue;
      fs.accessSync(resolved, fs.constants.X_OK);
      return resolved;
    } catch {}
  }
  throw new Error('Install Distill in a trusted user/system location or set distill.binaryPath to an absolute executable path');
}

const defaultClientId = crypto.randomUUID();
async function retireBroker(file, endpoint, ownerPid) {
  if (!Number.isSafeInteger(endpoint.broker_pid) || endpoint.broker_pid <= 1 || [process.pid, ownerPid].includes(endpoint.broker_pid)) throw new Error('Cannot verify the previous recorder process.');
  const lock = `${file}.lock`;
  const stat = fs.lstatSync(lock);
  if (!stat.isFile() || stat.size > 16384 || stat.uid !== process.getuid() || stat.mode & 0o077) throw new Error('Invalid recorder lock.');
  const holder = JSON.parse(fs.readFileSync(lock, 'utf8'));
  if (holder.pid !== endpoint.broker_pid || processIdentity(holder.pid) !== holder.identity) throw new Error('Previous recorder identity changed.');
  process.kill(holder.pid, 'SIGTERM');
  for (let attempt = 0; attempt < 40; attempt++) {
    if (!fs.existsSync(file) && !fs.existsSync(lock)) return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error('Previous recorder is still stopping. Reconnect Distill to retry.');
}

async function connectBroker(roots, binary = '', clientId = defaultClientId) {
  binary = resolveBinary(binary);
  const health = JSON.parse(execFileSync(binary, ['doctor', '--json'], { encoding: 'utf8', timeout: 5000 }));
  const peerBinary = health.executable;
  if (!path.isAbsolute(peerBinary || '')) throw new Error('Update Distill for authenticated Unix socket support');
  const ownerPid = Number(process.env.VSCODE_PID);
  if (!Number.isSafeInteger(ownerPid) || ownerPid <= 1) {
    throw new Error('VS Code did not expose its main process ID (VSCODE_PID). Temporary traces require desktop VS Code.');
  }
  const ownerIdentity = processIdentity(ownerPid);
  roots = [...new Set(roots.map(root => fs.realpathSync(root)))].sort();
  const directory = traceDirectory();
  secureDirectory(directory);
  const file = endpointPath(directory, ownerPid, ownerIdentity, roots);
  const register = { action: 'register', roots, clientId, clientPid: process.pid };
  try {
    const endpoint = readEndpoint(file);
    await rpc(endpoint, { action: 'ping' });
    if ((endpoint.broker_version || 1) < 9) await retireBroker(file, endpoint, ownerPid);
    else { await rpc(endpoint, register); return endpoint; }
  } catch (error) {
    if (error.code === 'DISTILL_RECORDER_UPGRADE' || fs.existsSync(file + '.lock') && /previous recorder|recorder lock|identity changed/i.test(error.message)) throw error;
  }

  const child = spawn(process.execPath, [path.join(__dirname, 'broker.js')], {
    detached: true, stdio: ['pipe', 'ignore', 'ignore'],
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
  });
  let launchError;
  child.on('error', error => { launchError = error; });
  child.stdin.on('error', error => { launchError = error; });
  child.stdin.end(JSON.stringify({ directory, ownerPid, ownerIdentity, roots, peerBinary }));
  child.unref();
  for (let attempt = 0; attempt < 50; attempt++) {
    if (launchError) throw launchError;
    try {
      const endpoint = readEndpoint(file);
      if ((endpoint.broker_version || 1) < 9) throw new Error('Recorder upgrade still pending');
      await rpc(endpoint, register, 500);
      return endpoint;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('Could not start the temporary trace broker. Run Distill: Open Chat Command Trace to retry.');
}

module.exports = { connectBroker, resolveBinary };
