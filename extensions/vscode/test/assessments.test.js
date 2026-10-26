'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { reportKey, normalizeDetails } = require('../src/assessments');

const report = { report_id: 'one', request_id: 'request-one', impact_severity: 'low', severity: 'low', decision: 'allow',
  explanation: 'distill LOW (3 ms; approval risk LOW): Reads an ordinary file', policy_digest: 'policy-one', coverage: { summary: 'static_accounted' }, timings_ms: { total: 3 } };
test('assessment identity ignores generated IDs and latency but retains evidence, coverage, and policy', () => {
  assert.equal(reportKey(report), reportKey({ ...report, report_id: 'two', request_id: 'two', timings_ms: { total: 12 }, explanation: 'distill LOW (12 ms; approval risk LOW): Reads an ordinary file' }));
  for (const changed of [{ decision: 'ask' }, { policy_digest: 'policy-two' }, { unknowns: ['new uncertainty'] }, { findings: [{ impact: 'new effect' }] }, { coverage: { summary: 'partial' } }]) {
    assert.notEqual(reportKey(report), reportKey({ ...report, ...changed }));
  }
});
test('existing broker details merge equivalent consecutive revisions and use plain reasons', () => {
  const first = { hook: 'PreToolUse', report };
  const command = { reason: report.explanation, assessmentCount: 2, assessments: [first, { ...first, report: { ...report, report_id: 'two' } }] };
  const normalized = normalizeDetails(command);
  assert.equal(normalized.assessments.length, 1);
  assert.equal(normalized.assessmentCount, 1);
  assert.equal(normalized.reason, 'Reads an ordinary file');
  assert.equal(normalized.assessments[0].report.explanation, normalized.reason);
  assert.equal(command.assessments.length, 2, 'Existing broker data is never mutated');
});
test('changed policy, different hooks, blocking, and returning to an earlier result remain in history', () => {
  const first = { hook: 'PreToolUse', report };
  const revisions = [first, { ...first, report: { ...report, policy_digest: 'new-policy' } }, first, { ...first, hook: 'PermissionRequest' }, { ...first, blocked: true }];
  assert.equal(normalizeDetails({ assessments: revisions, assessmentCount: 7 }).assessmentCount, 7);
  assert.equal(normalizeDetails({ assessments: revisions }).assessments.length, 5);
});
test('older broker details distinguish absent reports from unresolved verdicts without changing their rating', () => {
  const missing = normalizeDetails({ severity: 'unknown', decision: 'unavailable', assessments: [], assessmentCount: 0 });
  assert.equal(missing.assessmentState, 'missing');
  const unresolved = normalizeDetails({ severity: 'unknown', decision: 'ask', assessments: [{ hook: 'PreToolUse', report: { impact_severity: null, unknowns: ['Unproven import'], behavior_policy_version: 6 } }], assessmentCount: 1 });
  assert.equal(unresolved.assessmentState, 'unknown');
  assert.equal(unresolved.severity, 'unknown');
  assert.deepEqual(unresolved.unknowns, ['Unproven import']);
  assert.equal(unresolved.behaviorPolicyVersion, 6);
  assert.equal(normalizeDetails({ severity: 'high', decision: 'ask', assessmentCount: 1 }).assessmentState, 'rated');
});

test('retained effect evidence is recovered from the primary assessment without inventing effects for older recorders', () => {
  const behaviors = [{ kind: 'database', database: { action: 'delete', scope: 'all_rows' } }];
  const normalized = normalizeDetails({ assessments: [{ hook: 'PreToolUse', report: { behaviors, behaviorsTruncated: true } }] });
  assert.deepEqual(normalized.behaviors, behaviors);
  assert.equal(normalized.behaviorsTruncated, true);
  assert.deepEqual(normalizeDetails({ assessments: [] }).behaviors, []);
});
