'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { ensureBinary, REQUIRED } = require('../src/install');

function fixture(t, content = 'bundled test executable') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'distill-install-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const extensionPath = path.join(root, 'extension');
  fs.mkdirSync(path.join(extensionPath, 'bin'), { recursive: true });
  const source = path.join(extensionPath, 'bin/distill');
  const manifest = path.join(extensionPath, 'bin/manifest.json');
  fs.writeFileSync(source, content);
  fs.writeFileSync(manifest, JSON.stringify({ schema_version: 1, platform: process.platform, arch: process.arch, sha256: crypto.createHash('sha256').update(content).digest('hex') }));
  return { root, extensionPath, storagePath: path.join(root, 'storage'), source, manifest, run: async () => ({ stdout: JSON.stringify({ trace_protocol: 1, capabilities: REQUIRED }) }) };
}

test('first activation installs the bundled CLI privately; repeated activation keeps the same pin', async t => {
  const options = fixture(t);
  const first = await ensureBinary(options);
  assert.equal(first.managed, true);
  assert.equal(fs.readFileSync(first.binary, 'utf8'), 'bundled test executable');
  assert.equal(fs.statSync(first.binary).mode & 0o777, 0o700);
  const inode = fs.statSync(first.binary).ino;
  const second = await ensureBinary(options);
  assert.equal(second.binary, first.binary);
  assert.equal(fs.statSync(second.binary).ino, inode);
  // A new extension version uses another path so existing hook pins keep working.
  fs.writeFileSync(options.source, 'updated executable');
  const next = JSON.parse(fs.readFileSync(options.manifest));
  next.sha256 = crypto.createHash('sha256').update('updated executable').digest('hex');
  fs.writeFileSync(options.manifest, JSON.stringify(next));
  const updated = await ensureBinary(options);
  assert.notEqual(updated.binary, first.binary);
  assert.equal(fs.readFileSync(first.binary, 'utf8'), 'bundled test executable');
});

test('wrong platform and changed package bytes are rejected before running a binary', async t => {
  const options = fixture(t);
  options.run = async () => assert.fail('Unverified binary must never run');
  await assert.rejects(ensureBinary({ ...options, arch: process.arch === 'arm64' ? 'x64' : 'arm64' }), /does not match/);
  fs.appendFileSync(options.source, 'tampered');
  await assert.rejects(ensureBinary(options), /checksum verification failed/);
  assert.equal(fs.existsSync(options.storagePath), false);
});

test('tampered installed binaries and symlink installation directories fail closed', async t => {
  const options = fixture(t);
  const installed = await ensureBinary(options);
  fs.appendFileSync(installed.binary, 'tampered');
  await assert.rejects(ensureBinary(options), /checksum does not match/);
  fs.rmSync(options.storagePath, { recursive: true });
  fs.mkdirSync(options.storagePath, { mode: 0o700 });
  fs.symlinkSync(options.extensionPath, path.join(options.storagePath, 'cli'));
  await assert.rejects(ensureBinary(options), /installation storage/);
});

test('explicit binary overrides stay explicit and must support the current hook protections', async t => {
  const options = fixture(t);
  fs.chmodSync(options.source, 0o700);
  await assert.rejects(ensureBinary({ ...options, configured: 'relative/distill' }), /absolute/);
  const custom = await ensureBinary({ ...options, configured: options.source });
  assert.equal(custom.managed, false);
  assert.equal(fs.existsSync(options.storagePath), false);
  await assert.rejects(ensureBinary({ ...options, configured: options.source, run: async () => ({ stdout: '{"trace_protocol":1,"capabilities":[]}' }) }), /missing required hook protections/);
});
