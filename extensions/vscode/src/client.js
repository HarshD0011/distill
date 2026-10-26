'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
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

async function connectBroker(roots, binary = '') {
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
  try {
    const endpoint = readEndpoint(file);
    await rpc(endpoint, { action: 'register', roots });
    return endpoint;
  } catch (error) {
    if (error.code === 'DISTILL_RECORDER_UPGRADE') throw error;
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
      await rpc(endpoint, { action: 'register', roots }, 250);
      return endpoint;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error('Could not start the temporary trace broker. Run Distill: Open Chat Command Trace to retry.');
}

module.exports = { connectBroker, resolveBinary };
