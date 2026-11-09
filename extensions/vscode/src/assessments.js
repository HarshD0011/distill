'use strict';
const crypto = require('node:crypto');

function reasonText(value) {
  return String(value || '').replace(/^distill\s+\w+\s+\([^\n)]*\):\s*/i, '');
}
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
  return value;
}
function reportKey(report) {
  if (!report) return '';
  const { report_id, request_id, timings_ms, explanation, assessment_key, ...meaning } = report;
  return crypto.createHash('sha256').update(JSON.stringify(stable({ ...meaning, explanation: reasonText(explanation) }))).digest('hex');
}
function revisionKey(revision) {
  return JSON.stringify([revision.hook, !!revision.blocked, revision.report?.assessment_key || reportKey(revision.report)]);
}
const ratings = new Set(['safe', 'low', 'medium', 'high', 'critical']);
function modelFallback(report) {
  return !report?.impact_severity && report?.judge?.status === 'advisory' && ratings.has(report.judge.severity);
}
function displaySeverity(report) { return report?.impact_severity || (modelFallback(report) ? report.judge.severity : 'unknown'); }

// Also applies to retained history in older brokers, without restarting them.
function normalizeDetails(command) {
  const assessments = [];
  for (const revision of command.assessments || []) {
    if (assessments.length && revisionKey(assessments.at(-1)) === revisionKey(revision)) continue;
    assessments.push({ ...revision, report: revision.report ? { ...revision.report, explanation: reasonText(revision.report.explanation) } : null });
  }
  const omitted = Math.max(0, (command.assessmentCount || 0) - (command.assessments || []).length);
  const primary = assessments.find(revision => revision.hook === 'PreToolUse') || assessments[0];
  const report = primary?.report;
  // Older running brokers have no explicit state. Their detailed decision/report
  // identifies a missing assessment without treating an unresolved impact as absent.
  const assessmentState = command.assessmentState || (command.decision === 'unavailable' ? 'missing'
    : command.decision || report ? (command.severity && command.severity !== 'unknown' ? 'rated' : 'unknown') : undefined);
  return { ...command, reason: reasonText(command.reason), assessments, assessmentCount: assessments.length + omitted,
    assessmentState, unknowns: command.unknowns ?? report?.unknowns ?? [],
    behaviors: command.behaviors ?? report?.behaviors ?? [],
    behaviorsTruncated: command.behaviorsTruncated ?? report?.behaviorsTruncated ?? false,
    behaviorPolicyVersion: command.behaviorPolicyVersion ?? report?.behavior_policy_version,
    coverageGaps: command.coverageGaps ?? report?.coverage_gaps ?? [],
    graph: command.graph ?? report?.graph,
    contextEvidence: command.contextEvidence ?? report?.context_evidence ?? [],
    judge: command.judge ?? report?.judge,
    timings: command.timings ?? report?.timings_ms };
}

module.exports = { reasonText, reportKey, revisionKey, normalizeDetails, modelFallback, displaySeverity };
