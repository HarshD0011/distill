'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const execFile = promisify(require('node:child_process').execFile);
const { resolveBinary } = require('./client');
const REQUIRED = ['assessments', 'completion', 'memory-only', 'workspace-context', 'hook-source-inspection', 'user-hook-setup', 'critical-hook-block', 'shell-context-coverage', 'node-hook-launcher', 'coding-workflows', 'native-critical-approval', 'foreground-critical-approval'];

function digest(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function privateDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || stat.mode & 0o022) throw new Error('Distill installation storage must be owned by you and not writable by other users.');
}
function validInstalled(binary, expected) {
  const stat = fs.lstatSync(binary);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid() || stat.mode & 0o022) throw new Error('Unsafe Distill installation file.');
  fs.accessSync(binary, fs.constants.X_OK);
  if (digest(fs.readFileSync(binary)) !== expected) throw new Error('Installed Distill checksum does not match the extension package.');
}

async function ensureBinary({ extensionPath, storagePath, configured = '', platform = process.platform, arch = process.arch, run = execFile }) {
  if (!['darwin', 'linux'].includes(platform) || !['arm64', 'x64'].includes(arch)) throw new Error('Distill supports local macOS and Linux on arm64/x64.');
  let binary;
  let managed = false;
  let sha256;
  if (configured && configured !== 'distill') {
    binary = resolveBinary(configured);
  } else {
    const manifestPath = path.join(extensionPath, 'bin/manifest.json');
    if (!fs.existsSync(manifestPath)) throw new Error('This extension package has no bundled Distill CLI. Install the platform-specific VSIX, or set Distill: Binary Path for development.');
    if (fs.statSync(manifestPath).size > 16384) throw new Error('Invalid bundled Distill manifest.');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    if (manifest.schema_version !== 1 || manifest.platform !== platform || manifest.arch !== arch || !/^[0-9a-f]{64}$/.test(manifest.sha256)) throw new Error('This Distill extension package does not match this platform or has an invalid manifest.');
    const source = path.join(extensionPath, 'bin/distill');
    const stat = fs.lstatSync(source);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 128 * 1024 * 1024) throw new Error('Invalid bundled Distill binary.');
    const bytes = fs.readFileSync(source);
    sha256 = digest(bytes);
    if (sha256 !== manifest.sha256) throw new Error('Bundled Distill checksum verification failed. Reinstall the extension.');
    if (!path.isAbsolute(storagePath || '')) throw new Error('Distill needs local extension storage to install its CLI.');
    privateDirectory(storagePath);
    const versions = path.join(storagePath, 'cli');
    privateDirectory(versions);
    const directory = path.join(versions, sha256);
    privateDirectory(directory);
    binary = path.join(directory, 'distill');
    if (!fs.existsSync(binary)) {
      const temporary = path.join(directory, `.install-${process.pid}-${crypto.randomBytes(8).toString('hex')}`);
      try {
        fs.writeFileSync(temporary, bytes, { mode: 0o700, flag: 'wx' });
        try { fs.linkSync(temporary, binary); } catch (error) { if (error.code !== 'EEXIST') throw error; }
      } finally { fs.rmSync(temporary, { force: true }); }
    }
    validInstalled(binary, sha256);
    managed = true;
  }
  const health = JSON.parse((await run(binary, ['doctor', '--json'], { timeout: 5000, maxBuffer: 1024 * 1024 })).stdout);
  if (health.trace_protocol !== 1 || !REQUIRED.every(name => health.capabilities?.includes(name))) throw new Error('This Distill CLI is missing required hook protections. Install the current extension package or update your custom CLI.');
  return { binary, managed, sha256, health };
}

module.exports = { ensureBinary, REQUIRED };
