'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
for (const directory of ['src', 'media', 'test', 'scripts']) {
  for (const file of fs.readdirSync(path.join(__dirname, '..', directory))) {
    if (file.endsWith('.js')) execFileSync(process.execPath, ['--check', path.join(__dirname, '..', directory, file)], { stdio: 'inherit' });
  }
}
const manifest = require('../package.json');
const assert = require('node:assert/strict');
assert.deepEqual(manifest.contributes.configuration.properties['distill.llm.model'], require('../src/models').modelSettingSchema(), 'Native Model dropdown must match the shared catalog.');
for (const file of [manifest.main, 'media/distill.svg', 'media/trace.js', 'media/trace.css']) {
  if (!fs.existsSync(path.join(__dirname, '..', file))) throw new Error(`Missing extension asset: ${file}`);
}
console.log('Extension syntax and assets checked.');
