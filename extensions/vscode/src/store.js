'use strict';
const path = require('node:path');
const { cleanTitle } = require('./titles');
const { reportKey, revisionKey, modelFallback, displaySeverity } = require('./assessments');
function contains(root, cwd) { const rel = path.relative(root, cwd); return rel === '' || (rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel)); }

function outputText(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(outputText).join('\n');
  if (typeof value !== 'object') return String(value);
  if (typeof value.stdout === 'string' || typeof value.stderr === 'string') {
    return [value.stdout || '', value.stderr ? `[stderr]\n${value.stderr}` : ''].filter(Boolean).join('\n');
  }
  if (typeof value.output === 'string') return value.output;
  if (typeof value.text === 'string') return value.text;
  if (Array.isArray(value.content)) return outputText(value.content);
  return JSON.stringify(value, null, 2);
}

function previewOutput(text, lines = 5, chars = 1800) {
  const preview = text.split('\n', lines).join('\n').slice(0, chars);
  return { text: preview, hasMore: preview.length < text.length };
}

function exitCode(response) {
  if (response && typeof response === 'object') {
    for (const key of ['exit_code', 'exitCode', 'code']) {
      if (Number.isInteger(response[key])) return response[key];
    }
  }
  // Codex may deliver model-facing output with an exit-code envelope.
  const match = typeof response === 'string' && response.match(/(?:^|\n)(?:Process exited with code|Exit code:?)\s*(-?\d+)(?:\s|$)/);
  return match ? Number(match[1]) : null;
}

// Limits bound retained text, reports, command count, and serialized pages independently.
const LIMITS = { bytes: 64 * 1024 * 1024, outputBytes: 4 * 1024 * 1024, commands: 10000, revisions: 16, pageSize: 100 };
function clipped(text, bytes) {
  const buffer = Buffer.from(text);
  if (buffer.length <= bytes) return { text, truncated: false };
  // Drop an incomplete trailing UTF-8 sequence rather than introducing replacement text.
  let end = Math.max(0, bytes);
  while (end > 0 && (buffer[end] & 0xc0) === 0x80) end--;
  return { text: buffer.subarray(0, end).toString('utf8'), truncated: true };
}
function compactReport(report) {
  if (!report) return null;
  return {
    report_id: report.report_id, assessment_key: reportKey(report), impact_severity: report.impact_severity, severity: report.severity,
    decision: report.decision, coverage: report.coverage ? { summary: report.coverage.summary } : undefined,
    explanation: String(report.explanation || '').slice(0, 4096),
    policy_digest: report.policy_digest, behavior_policy_version: report.behavior_policy_version,
    shell_dialect: report.shell_dialect, analysis_context: report.analysis_context,
    unknowns: (report.unknowns || []).slice(0, 64),
    coverage_gaps: (Array.isArray(report.coverage_gaps) ? report.coverage_gaps : []).slice(0, 64),
    graph: report.graph ? { parse_complete: !!report.graph.parse_complete, truncated: !!report.graph.truncated || report.graph.nodes?.length > 128, nodes: (report.graph.nodes || []).slice(0, 128) } : undefined,
    context_evidence: (Array.isArray(report.context_evidence) ? report.context_evidence : []).slice(0, 32),
    judge: report.judge,
    timings_ms: report.timings_ms,
    behaviors: (Array.isArray(report.behaviors) ? report.behaviors : []).slice(0, 32).filter(item => item && typeof item === 'object').map(item => ({
      kind: String(item.kind || '').slice(0, 48), operation: String(item.operation || '').slice(0, 96),
      target: item.target == null ? null : String(item.target).slice(0, 512), target_class: String(item.target_class || '').slice(0, 48),
      recursive: !!item.recursive, append: !!item.append,
      database: item.database ? { action: String(item.database.action || '').slice(0, 48), scope: String(item.database.scope || '').slice(0, 48) } : undefined,
      location: item.location ? { file: item.location.file == null ? null : String(item.location.file).slice(0, 512), line: Number(item.location.line) || null, column: Number(item.location.column) || null } : undefined,
    })),
    behaviorsTruncated: Array.isArray(report.behaviors) && report.behaviors.length > 32,
  };
}
function assessmentState(report) {
  return !report ? 'missing' : report.impact_severity ? 'rated' : modelFallback(report) ? 'advisory' : 'unknown';
}

class TraceStore {
  constructor(limits = {}) {
    this.limits = { ...LIMITS, ...limits };
    this.sessions = new Map(); this.version = 0; this.bytes = 0; this.commandCount = 0;
    this.droppedEvents = 0; this.truncatedOutputs = 0;
  }

  record(event) {
    if (!event || event.protocol !== 1 || !['codex', 'claude'].includes(event.source)
        || !['assessment', 'completion'].includes(event.kind)
        || !['session_id', 'tool_use_id', 'command', 'session_cwd'].every(key => typeof event[key] === 'string' && event[key].length)
        || !Number.isFinite(event.timestamp)) throw new Error('Invalid trace event');
    const crypto = require('node:crypto');
    const key = JSON.stringify([event.source, event.session_id]);
    let session = this.sessions.get(key);
    let id = event.tool_use_id;
    const original = session?.commands.get(id);
    // Never attach a result to an assessment for different executable text/context.
    if ((event.attempt_id != null) || (original && (original.command !== event.command || original.cwd !== event.cwd))) {
      const attempt = crypto.createHash('sha256').update(JSON.stringify([event.attempt_id, event.command, event.cwd])).digest('hex').slice(0, 16);
      id += `@${attempt}`;
    }
    let entry = session?.commands.get(id);
    const report = event.kind === 'assessment' ? compactReport(event.report) : null;
    const fingerprint = crypto.createHash('sha256').update(JSON.stringify([
      event.kind, event.hook_event_name, report, event.blocked, event.tool_response, event.error, event.failed, event.output_capture_disabled, event.exit_code, event.cancelled,
    ])).digest('hex');
    if (entry?.events.has(fingerprint)) return;
    if (event.kind === 'assessment' && entry?.revisions.length) {
      const previous = entry.revisions.at(-1);
      if (revisionKey(previous) === revisionKey({ hook: event.hook_event_name, report, blocked: event.blocked })) return;
    }
    if (!entry) {
      const size = Buffer.byteLength(JSON.stringify([key, id, event.command, event.cwd, event.session_cwd])) + 1024;
      if (this.commandCount >= this.limits.commands || this.bytes + size > this.limits.bytes) {
        this.droppedEvents++; this.version++; return;
      }
      if (!session) {
        session = { key, id: event.session_id, title: cleanTitle(event.session_title), source: event.source, cwd: event.session_cwd, commands: new Map(), startedAt: event.timestamp, updatedAt: 0 };
        this.sessions.set(key, session);
      }
      entry = { id, command: event.command, cwd: event.cwd, startedAt: event.timestamp, status: 'proposed', report: null,
        text: '', accountedBytes: size, error: null, completedAt: null, revisions: [], revisionCount: 0, events: new Set(), completionTime: -Infinity };
      session.commands.set(id, entry);
      this.bytes += size; this.commandCount++;
    }
    const title = cleanTitle(event.session_title);
    if (title) session.title = title;
    session.startedAt = Math.min(session.startedAt, event.timestamp);
    entry.version = this.version + 1;
    entry.events.add(fingerprint);
    if (entry.events.size > 64) entry.events.delete(entry.events.values().next().value);
    if (event.kind === 'assessment') {
      entry.revisionCount++;
      const revision = { timestamp: event.timestamp, hook: event.hook_event_name, report, blocked: !!event.blocked };
      const size = Buffer.byteLength(JSON.stringify(revision));
      if (entry.revisions.length < this.limits.revisions && this.bytes + size <= this.limits.bytes) {
        entry.revisions.push(revision); this.bytes += size; entry.accountedBytes += size;
        entry.revisions.sort((a, b) => a.timestamp - b.timestamp);
      } else { this.droppedEvents++; }
      const primary = entry.revisions.find(item => item.hook === 'PreToolUse') || entry.revisions[0];
      entry.report = primary?.report || null;
      entry.startedAt = Math.min(entry.startedAt, event.timestamp);
      if (entry.completedAt == null) entry.status = entry.revisions.some(item => item.blocked) ? 'blocked' : 'proposed';
    } else if (event.timestamp >= entry.completionTime) {
      entry.completionTime = event.timestamp;
      entry.completedAt = event.timestamp;
      entry.exitCode = (Number.isInteger(event.exit_code) ? event.exit_code : null) ?? exitCode(event.tool_response) ?? exitCode(event.error);
      const failed = event.failed || event.error != null || event.tool_response?.is_error || event.tool_response?.isError
        || (entry.exitCode != null && entry.exitCode !== 0);
      entry.status = event.cancelled ? 'cancelled' : failed ? 'failed' : 'completed';
      const text = [outputText(event.tool_response), outputText(event.error)].filter(Boolean).join('\n');
      const oldBytes = Buffer.byteLength(entry.text);
      const capture = clipped(text, Math.max(0, Math.min(this.limits.outputBytes, this.limits.bytes - this.bytes + oldBytes)));
      this.bytes += Buffer.byteLength(capture.text) - oldBytes;
      entry.accountedBytes += Buffer.byteLength(capture.text) - oldBytes;
      entry.text = capture.text;
      if (!entry.outputTruncated && capture.truncated) this.truncatedOutputs++;
      entry.outputTruncated = capture.truncated;
      // A failed tool may never have started a process. Only concrete evidence is shown.
      entry.executionObserved = entry.exitCode != null;
      entry.outputCaptureDisabled = !!event.output_capture_disabled;
    }
    session.updatedAt = Math.max(session.updatedAt, event.timestamp);
    this.version++;
  }

  text(entry) { return entry.text; }

  pendingAdvice() {
    return [...new Set([...this.sessions.values()].flatMap(session => [...session.commands.values()].filter(entry => entry.report?.judge?.status === 'pending').map(entry => entry.report.judge.request_digest)))].filter(key => /^[a-f0-9]{64}$/.test(key)).slice(0, 16);
  }

  applyAdvice(results) {
    if (!Array.isArray(results) || results.length > 16) throw new Error('Invalid model results');
    for (const advice of results) {
      if (!advice || !/^[a-f0-9]{64}$/.test(advice.request_digest) || !['pending', 'advisory', 'unavailable', 'expired', 'busy'].includes(advice.status) || Buffer.byteLength(JSON.stringify(advice)) > 70000) continue;
      for (const session of this.sessions.values()) for (const entry of session.commands.values()) {
        let changed = false;
        for (const revision of entry.revisions) {
          const report = revision.report;
          if (report?.judge?.status !== 'pending' || report.judge.request_digest !== advice.request_digest || JSON.stringify(report.judge) === JSON.stringify(advice)) continue;
          const delta = Buffer.byteLength(JSON.stringify(advice)) - Buffer.byteLength(JSON.stringify(report.judge));
          if (this.bytes + delta > this.limits.bytes) continue;
          report.judge = advice;
          report.assessment_key = reportKey(report);
          this.bytes += delta; entry.accountedBytes += delta; changed = true;
        }
        if (changed) { this.version++; entry.version = this.version; }
      }
    }
  }

  feedback(sessionKey, id, value) {
    const session = this.sessions.get(sessionKey); const entry = session?.commands.get(id);
    if (!entry) throw new Error('Command is no longer available');
    if (!['over', 'under'].includes(value.kind) || typeof (value.note || '') !== 'string' || (value.note || '').length > 2048) throw new Error('Invalid feedback');
    value = { ...value, note: require('./privacy').redact(value.note || '') };
    const timestamp = Number.isFinite(value.timestamp) ? value.timestamp : Date.now();
    if (entry.feedback?.some(v => v.kind === value.kind && v.note === (value.note || '') && v.timestamp === timestamp)) return { recorded: true, persistent: true, changesPolicy: false, source: session.source, sessionId: session.id, cwd: session.cwd };
    const feedback = [...(entry.feedback || []).slice(-15), { kind: value.kind, note: value.note || '', timestamp }];
    const delta = Buffer.byteLength(JSON.stringify(feedback)) - Buffer.byteLength(JSON.stringify(entry.feedback || []));
    if (this.bytes + delta > this.limits.bytes) throw new Error('Feedback capture limit reached');
    entry.feedback = feedback; this.bytes += delta; entry.accountedBytes += delta;
    entry.version = ++this.version;
    return { recorded: true, persistent: false, changesPolicy: false, source: session.source, sessionId: session.id, cwd: session.cwd };
  }

  exportSession(sessionKey) {
    const session = this.sessions.get(sessionKey);
    if (!session) throw new Error('Session is no longer available');
    const commands = []; let bytes = 0; let truncated = false;
    for (const id of session.commands.keys()) {
      const entry = this.readCommand(sessionKey, id); const size = Buffer.byteLength(JSON.stringify(entry));
      if (bytes + size > 16 * 1024 * 1024) { truncated = true; break; }
      commands.push(entry); bytes += size;
    }
    return { schema_version: 1, session: { id: session.id, title: session.title, source: session.source, cwd: session.cwd }, commands, truncated, scope: 'Retained observations; missing completion does not establish rejection. Output previews only.' };
  }

  restoreFeedback(values) {
    const crypto = require('node:crypto');
    const sessions = new Map([...this.sessions.values()].map(session => [crypto.createHash('sha256').update(JSON.stringify([session.source, session.id, session.cwd])).digest('hex'), session]));
    for (const value of values.slice(-10000)) {
      const session = sessions.get(value.session_key);
      if (session?.commands.has(value.tool_id)) { try { this.feedback(session.key, value.tool_id, value); } catch {} }
    }
  }

  coverage() {
    const commands = new Map(); const reasons = new Map(); let total = 0; let incomplete = 0;
    for (const session of this.sessions.values()) for (const entry of session.commands.values()) {
      total++; if (entry.report?.coverage?.summary === 'static_accounted') continue;
      incomplete++;
      const name = (entry.command.trim().split(/\s+/)[0] || '<unknown>').split('/').pop();
      commands.set(name, (commands.get(name) || 0) + 1);
      for (const reason of entry.report?.unknowns || []) reasons.set(reason, (reasons.get(reason) || 0) + 1);
    }
    const ranked = values => [...values].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 100).map(([name, count]) => ({ name, count }));
    return { reports: total, incomplete, commands: ranked(commands), reasons: ranked(reasons), scope: 'Retained editor events only; no accuracy estimate' };
  }

  snapshot(options = {}) {
    const allSessions = [...this.sessions.values()].filter(session => !options.roots?.length || options.roots.some(root => contains(root, session.cwd)))
      .sort((a, b) => b.updatedAt - a.updatedAt);
    const selected = allSessions.find(session => session.key === options.sessionKey) || allSessions[0];
    const offset = Math.max(0, Number.isSafeInteger(options.offset) ? options.offset : 0);
    const limit = Math.min(200, Math.max(1, Number.isSafeInteger(options.limit) ? options.limit : this.limits.pageSize));
    let remaining = limit;
    const serialize = entry => {
      const report = entry.report;
      return {
        id: entry.id, version: entry.version, command: entry.command, cwd: entry.cwd, startedAt: entry.startedAt,
        completedAt: entry.completedAt, status: entry.status, exitCode: entry.exitCode ?? null,
        executionObserved: !!entry.executionObserved, assessmentCount: entry.revisionCount,
        assessments: entry.revisions, policyDigest: report?.policy_digest, shell: report?.shell_dialect,
        assessmentState: assessmentState(report), unknowns: report?.unknowns || [], behaviorPolicyVersion: report?.behavior_policy_version,
        severity: displaySeverity(report), approvalRisk: report?.severity || null,
        decision: report?.decision || 'unavailable', coverage: report?.coverage?.summary || 'unavailable',
        reason: report?.explanation || 'No pre-command assessment was received.',
        output: previewOutput(entry.text), outputChars: entry.text.length, outputTruncated: !!entry.outputTruncated, outputCaptureDisabled: !!entry.outputCaptureDisabled,
      };
    };
    const query = String(options.query || '').toLowerCase().slice(0, 1024);
    const matching = session => [...session.commands.values()].sort((a, b) => a.startedAt - b.startedAt)
      .filter(entry => !query || [entry.command, entry.report ? displaySeverity(entry.report) : 'unassessed', entry.report?.decision, entry.status].join(' ').toLowerCase().includes(query));
    const selectedEntries = selected ? matching(selected) : [];
    return {
      version: this.version,
      capture: { droppedEvents: this.droppedEvents, truncatedOutputs: this.truncatedOutputs, bytes: this.bytes, byteLimit: this.limits.bytes },
      page: { sessionKey: selected?.key || '', offset, limit, total: selectedEntries.length, hasMore: offset + limit < selectedEntries.length },
      sessions: allSessions.map(session => {
        let entries = [];
        if (!options.paged || session === selected) {
          entries = (options.paged ? selectedEntries.slice(offset, offset + limit) : matching(session).slice(0, remaining)).map(entry => options.compact ? { id: entry.id, version: entry.version, command: entry.command, severity: displaySeverity(entry.report), assessmentState: assessmentState(entry.report) } : serialize(entry));
          remaining -= entries.length;
        }
        return { key: session.key, id: session.id, title: session.title, source: session.source, cwd: session.cwd, startedAt: session.startedAt, updatedAt: session.updatedAt,
          commandCount: session.commands.size, commands: entries };
      }),
    };
  }

  readCommand(sessionKey, id) {
    const session = this.sessions.get(sessionKey);
    const entry = session?.commands.get(id);
    if (!entry) throw new Error('Command is no longer available');
    const report = entry.report;
    return {
      id: entry.id, version: entry.version, command: entry.command, cwd: entry.cwd,
      startedAt: entry.startedAt, completedAt: entry.completedAt, status: entry.status,
      exitCode: entry.exitCode ?? null, executionObserved: !!entry.executionObserved,
      severity: displaySeverity(report), approvalRisk: report?.severity || null,
      assessmentState: assessmentState(report), unknowns: report?.unknowns || [], behaviorPolicyVersion: report?.behavior_policy_version,
      decision: report?.decision || 'unavailable', coverage: report?.coverage?.summary || 'unavailable',
      reason: report?.explanation || 'No pre-command assessment was received.',
      assessmentCount: entry.revisionCount, assessments: entry.revisions,
      policyDigest: report?.policy_digest, shell: report?.shell_dialect,
      output: previewOutput(entry.text), outputChars: entry.text.length,
      outputTruncated: !!entry.outputTruncated, outputCaptureDisabled: !!entry.outputCaptureDisabled,
      sessionId: session.id,
      behaviors: report?.behaviors || [], behaviorsTruncated: !!report?.behaviorsTruncated,
      coverageGaps: report?.coverage_gaps || [], graph: report?.graph, contextEvidence: report?.context_evidence || [],
      judge: report?.judge, timings: report?.timings_ms, feedback: entry.feedback || [],
    };
  }

  readOutput(sessionKey, id) {
    const entry = this.sessions.get(sessionKey)?.commands.get(id);
    if (!entry) throw new Error('Command is no longer available');
    return entry.text;
  }

  clear(roots) {
    if (Array.isArray(roots) && roots.length) {
      for (const [key, session] of this.sessions) if (roots.some(root => contains(root, session.cwd))) {
        for (const entry of session.commands.values()) { this.bytes -= entry.accountedBytes; this.commandCount--; }
        this.sessions.delete(key);
      }
      this.version++; return;
    }
    this.sessions.clear(); this.bytes = 0; this.commandCount = 0;
    this.droppedEvents = 0; this.truncatedOutputs = 0; this.version++;
  }
}

module.exports = { TraceStore, outputText, previewOutput, LIMITS };
