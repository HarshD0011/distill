'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const MAX_BYTES = 32 * 1024 * 1024;

function traceDirectory() {
  if (process.env.DISTILL_TRACE_DIR) return process.env.DISTILL_TRACE_DIR;
  let hash = 0xcbf29ce484222325n;
  for (const byte of Buffer.from(process.env.HOME || os.homedir())) {
    hash = BigInt.asUintN(64, (hash ^ BigInt(byte)) * 0x100000001b3n);
  }
  return path.join(os.tmpdir(), `distill-vscode-${hash.toString(16).padStart(16, '0')}`);
}

function processIdentity(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 1) throw new Error('Invalid editor process ID');
  return execFileSync('/bin/ps', ['-p', String(pid), '-o', 'lstart=', '-o', 'comm='], {
    encoding: 'utf8', timeout: 1000, stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
}

function endpointPath(directory, ownerPid, ownerIdentity, roots) {
  const key = crypto.createHash('sha256').update(JSON.stringify([ownerPid, ownerIdentity])).digest('hex').slice(0, 24);
  return path.join(directory, `${key}.json`);
}

function secureDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) {
    throw new Error('Trace directory must be a private directory owned by the current user');
  }
}

function readEndpoint(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.size > 16384 || stat.uid !== process.getuid() || (stat.mode & 0o077)) throw new Error('Invalid trace endpoint permissions');
  const endpoint = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (endpoint.protocol === 1 && typeof endpoint.socket !== 'string' && Number.isInteger(endpoint.port)) {
    const error = new Error('An older Distill recorder is still running. Fully quit and reopen VS Code once to finish the upgrade; reloading a window keeps the old recorder alive. Temporary traces clear when VS Code quits.');
    error.code = 'DISTILL_RECORDER_UPGRADE';
    throw error;
  }
  if (endpoint.protocol !== 1 || typeof endpoint.socket !== 'string' || path.dirname(endpoint.socket) !== path.dirname(file)
      || typeof endpoint.token !== 'string' || endpoint.token.length !== 64) throw new Error('Invalid trace endpoint');
  return endpoint;
}

function rpc(endpoint, request, timeout = 3000) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: endpoint.socket });
    let size = 0;
    const chunks = [];
    socket.setTimeout(timeout, () => socket.destroy(new Error('Trace connection timed out')));
    socket.on('connect', () => socket.write(JSON.stringify({ ...request, token: endpoint.token }) + '\n'));
    socket.on('error', reject);
    socket.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BYTES * 2) socket.destroy(new Error('Trace response is too large'));
      else chunks.push(chunk);
    });
    socket.on('end', () => {
      try {
        const response = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!response.ok) throw new Error(response.error || 'Trace request failed');
        resolve(response);
      } catch (error) { reject(error); }
    });
  });
}

module.exports = { MAX_BYTES, traceDirectory, processIdentity, endpointPath, secureDirectory, readEndpoint, rpc };
