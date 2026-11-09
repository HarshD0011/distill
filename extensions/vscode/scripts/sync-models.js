'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { modelSettingSchema } = require('../src/models');
const file = path.join(__dirname, '../package.json');
const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
manifest.contributes.configuration.properties['distill.llm.model'] = modelSettingSchema();
fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
