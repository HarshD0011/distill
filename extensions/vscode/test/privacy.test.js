'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { redact, redactValue } = require('../src/privacy');
const { resolveBinary } = require('../src/client');
test('trace presentation redacts quoted credentials and nested fields', () => {
  const result = redact(`PASSWORD='two secret words' --token "another secret phrase" https://user:pass@example.com`);
  for (const secret of ['two secret words', 'another secret phrase', 'user:pass']) assert.ok(!result.includes(secret));
  assert.deepEqual(redactValue({nested: {authorization: 'opaque'}, message: 'TOKEN=hidden'}), {nested: {authorization: '[REDACTED]'}, message: 'TOKEN=[REDACTED]'});
});
test('editor rejects relative executable overrides before process launch', () => {
  for (const candidate of ['./distill', 'bin/distill', 'other-binary']) assert.throws(() => resolveBinary(candidate), /absolute/);
});
