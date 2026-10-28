'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { promisify } = require('node:util');
const execFile = promisify(require('node:child_process').execFile);
const root = path.resolve(__dirname, '../../..');
const binary = process.env.DISTILL_TEST_BINARY || path.join(root, 'target/debug/distill');
test('real signed events retain rated completed or blocked rows and reject a forged label', { skip: !fs.existsSync(binary) }, async () => {
 const { stdout } = await execFile(process.execPath, [path.join(root, 'scripts/trace_label_audit.js'), binary], {timeout:10000});
 const result=JSON.parse(stdout);
 assert.equal(result.rows, 4); assert.equal(result.unknown, 1);
 assert.equal(result.unassessed, 0); assert.equal(result.proposed, 0); assert.equal(result.completed, 3); assert.equal(result.blocked, 1);
 assert.equal(result.forgedLabelKeptSeparate, true);
});
