/* global acquireVsCodeApi */
'use strict';
const vscode = acquireVsCodeApi();
const chat = document.getElementById('chat');
const search = document.getElementById('search');
const commands = document.getElementById('commands');
const connection = document.getElementById('connection');
let sessions = [];
let selected = '';
let page = { offset: 0, limit: 100, total: 0, hasMore: false };
let capture = {};
let recordingWarning = '';
let routerState;
let searchTimer;
const openCommands = new Set();
const detailsCache = new Map();
const outputCache = new Map();
const pending = new Map();
const severities = ['safe', 'low', 'medium', 'high', 'critical', 'unknown'];
function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text != null) element.textContent = text;
  if (className) element.className = className;
  return element;
}
function keyFor(sessionKey, id) { return JSON.stringify([sessionKey, id]); }
function currentEntry(sessionKey, id) { return sessions.find(session => session.key === sessionKey)?.commands.find(entry => entry.id === id); }
function loadDetails(session, entry) {
  const key = keyFor(session.key, entry.id);
  if (detailsCache.get(key)?.version === entry.version || pending.has(key)) return;
  pending.set(key, entry.version);
  vscode.postMessage({ type: 'command', sessionKey: session.key, id: entry.id });
}
function commandDetails(session, entry) {
  const section = node('div', null, 'command-details');
  const key = keyFor(session.key, entry.id);
  const detail = detailsCache.get(key);
  if (!detail || detail.version !== entry.version) {
    section.append(node('p', 'Loading command details…', 'muted'));
    loadDetails(session, entry);
    return section;
  }
  section.append(node('p', detail.reason, 'reason'));
  if (detail.assessmentState === 'unknown') section.append(node('p', 'The analyzer could not establish an impact rating.', 'muted'));
  if (detail.assessmentState === 'advisory') section.append(node('p', 'Rating from model advice. Approval still required.', 'muted'));
  const meta = node('dl', null, 'metadata');
  const status = detail.status === 'proposed' ? 'No completion observed' : detail.status;
  for (const [label, value] of [
    ['Decision', detail.decision.replace(/_/g, ' ')], ['Status', status], ['Exit code', detail.exitCode],
  ]) {
    if (value == null || value === '') continue;
    meta.append(node('dt', label), node('dd', String(value)));
  }
  section.append(meta);
  const feedback = node('div', null, 'toolbar');
  for (const [kind, label] of [['over', 'Rating too high'], ['under', 'Rating too low']]) {
    const button = node('button', label, 'quiet');
    button.addEventListener('click', () => { button.disabled = true; vscode.postMessage({ type: 'feedback', sessionKey: session.key, id: entry.id, kind }); });
    feedback.append(button);
  }
  section.append(feedback);
  if (detail.feedback?.length) section.append(node('p', 'Feedback recorded. It does not change policy automatically.', 'muted small'));
  if (detail.judge) {
    const failure = String(detail.judge.detail || detail.judge.reason || '');
    const connectionFailed = /Broken pipe|Resource temporarily unavailable|Service (?:connect|write|read)|Local model service connection/i.test(failure);
    const model = node('details', null, 'provenance');
    model.append(node('summary', `Model advice · ${connectionFailed ? 'connection failed' : detail.judge.status || 'unavailable'}${detail.judge.severity ? ` · ${detail.judge.severity}` : ''}`));
    model.append(node('p', connectionFailed ? 'The local service connection failed before review completed. Update Distill and reload the window.' : detail.judge.proposal?.explanation || detail.judge.reason || 'Static policy remains in control.'));
    if (detail.judge.detail) model.append(node('p', detail.judge.detail, 'muted small'));
    if (detail.judge.source_review?.inspected_files > 0 || detail.judge.source_review?.missing_source) {
      const source = detail.judge.source_review;
      model.append(node('p', source.missing_source ? 'Script source was unavailable; file contents could not be reviewed.' : source.sharing_enabled ? `Script source: ${source.shared_files} file(s) shared${source.omitted_files ? `, ${source.omitted_files} omitted` : ''}.` : 'Script source was not shared. Enable Include inspected script excerpts to review file contents.', 'muted'));
    }
    if (detail.judge.model) model.append(node('p', `Model: ${detail.judge.model} · prompt ${detail.judge.prompt_version || 'unknown'}${detail.judge.cached ? ' · cached' : ''}`, 'muted'));
    section.append(model);
  }
  const output = node('div', null, 'output');
  output.append(node('div', 'Output', 'output-label'));
  if (detail.outputTruncated) output.append(node('p', 'Capture limit reached. Showing retained output.', 'capture-note'));
  const full = outputCache.get(key);
  if (detail.outputChars) {
    output.append(node('pre', full?.version === entry.version ? full.text : detail.output.text));
    if (detail.output.hasMore) {
      const expanded = full?.version === entry.version;
      const button = node('button', expanded ? 'Read less' : 'Read more', 'quiet');
      button.addEventListener('click', () => {
        if (expanded) { outputCache.delete(key); render(); }
        else { button.disabled = true; button.textContent = 'Loading…'; vscode.postMessage({ type: 'output', sessionKey: session.key, id: entry.id }); }
      });
      output.append(button);
    }
  } else output.append(node('p', detail.outputCaptureDisabled ? 'Output capture is disabled.' : detail.completedAt != null ? 'No output returned.' : detail.status === 'blocked' ? 'Blocked before execution.' : 'No completion event received.', 'muted'));
  section.append(output);
  const advanced = node('details', null, 'provenance');
  advanced.append(node('summary', 'More details'));
  advanced.append(node('pre', detail.command, 'command-full'));
  const context = node('dl', null, 'metadata');
  for (const [label, value] of [
    ['Analysis', detail.coverage.replace(/_/g, ' ')], ['Approval risk', detail.approvalRisk],
    ['Behavior policy', detail.behaviorPolicyVersion],
    ['Directory', detail.cwd], ['Shell', detail.shell], ['Time', new Date(detail.startedAt).toLocaleString()],
  ]) {
    if (value != null && value !== '') context.append(node('dt', label), node('dd', String(value)));
  }
  advanced.append(context);
  if (detail.coverageGaps?.length || detail.unknowns?.length) {
    advanced.append(node('p', 'Analysis limits', 'output-label'));
    const gaps = node('ul', null, 'analysis-gaps');
    if (detail.coverageGaps?.length) {
      const labels = { host_metadata: 'Host metadata', invocation: 'Invocation', dependency: 'Dependency', language: 'Language analysis', budget: 'Analysis budget', shell_semantics: 'Shell semantics', context: 'Context', runtime_environment: 'Runtime startup', unmodeled: 'Unmodeled behavior' };
      for (const gap of detail.coverageGaps) gaps.append(node('li', `${labels[gap.code] || 'Analysis'} · ${gap.message}`));
    } else for (const reason of detail.unknowns) gaps.append(node('li', reason));
    advanced.append(gaps);
  }
  if (detail.timings?.stages) {
    const timings = node('dl', null, 'metadata');
    for (const [stage, ms] of Object.entries(detail.timings.stages)) timings.append(node('dt', `${stage} (ms)`), node('dd', String(ms)));
    advanced.append(timings);
  }
  if (detail.contextEvidence?.length) {
    advanced.append(node('p', 'Context evidence', 'output-label'));
    const evidence = node('ul', null, 'analysis-gaps');
    for (const item of detail.contextEvidence) evidence.append(node('li', `${item.source}${item.value ? ` · ${item.value}` : ''} · ${item.status}`));
    advanced.append(evidence);
  }
  if (detail.graph?.nodes?.length) {
    const graph = node('details', null, 'provenance'); graph.append(node('summary', 'Parsed command structure'));
    const nodes = node('ol', null, 'analysis-gaps');
    for (const item of detail.graph.nodes) nodes.append(node('li', `${item.kind}${item.program ? ` · ${item.program}` : ''} · ${item.span?.line || '?'}:${item.span?.column || '?'} · bytes ${item.span?.start_byte ?? '?'}–${item.span?.end_byte ?? '?'}`));
    graph.append(nodes);
    if (detail.graph.truncated) graph.append(node('p', 'Additional command structure exceeded the detail limit.', 'muted'));
    advanced.append(graph);
  }
  if (detail.behaviors?.length) {
    advanced.append(node('p', 'Modeled effects', 'output-label'));
    const effects = node('ul', null, 'analysis-gaps');
    for (const effect of detail.behaviors) {
      const scope = { all_rows: 'all rows', no_rows: 'no rows selected; statement effects remain unresolved', conditional_rows: 'row-dependent condition; row count is not bounded', unresolved: 'scope unresolved' }[effect.database?.scope];
      const action = (effect.database?.action || effect.operation || effect.kind || 'effect').replace(/_/g, ' ');
      const location = effect.location ? ` · ${effect.location.file || 'source'}:${effect.location.line || '?'}:${effect.location.column || '?'}` : '';
      effects.append(node('li', `${action}${effect.target ? ` · ${effect.target}` : ''}${scope ? ` · ${scope}` : ''}${location}`));
    }
    advanced.append(effects);
    if (detail.behaviorsTruncated) advanced.append(node('p', 'Additional effects exceeded the retained detail limit.', 'muted'));
  }
  section.append(advanced);
  const provenance = node('details', null, 'provenance');
  provenance.append(node('summary', 'Assessment history'));
  if (detail.assessmentCount > (detail.assessments || []).length) provenance.append(node('p', 'Some older assessments exceeded capture limits.'));
  for (const revision of detail.assessments || []) provenance.append(node('p', `${revision.hook || 'Assessment'} · ${revision.report?.impact_severity || 'unknown'} · ${revision.report?.decision || 'unavailable'}\n${revision.report?.explanation || ''}`));
  if (detail.policyDigest) provenance.append(node('p', `Policy: ${detail.policyDigest}`));
  provenance.append(node('p', `Session ID: ${detail.sessionId}`));
  section.append(provenance);
  return section;
}
function renderRouter() {
  const label = document.getElementById('router-status');
  if (!label) return;
  label.textContent = !routerState || routerState.status === 'checking' ? 'Checking LLM router…'
    : routerState.status === 'error' ? 'LLM status unavailable · open settings'
    : !routerState.enabled ? 'Static analysis only · LLM router off'
    : !routerState.running ? `LLM service unavailable · static fallback · ${routerState.model}`
    : `Static analysis + LLM advice · ${routerState.model}`;
}
function render() {
  renderRouter();
  const historyNote = document.getElementById('history-note');
  if (historyNote) historyNote.textContent = 'Temporary · clears on window reload';
  chat.replaceChildren();
  for (const session of sessions) {
    const option = node('option', `${session.title || 'Untitled chat'} (${session.commandCount ?? session.commands.length})`);
    option.value = session.key; chat.append(option);
  }
  if (!sessions.some(session => session.key === selected)) selected = sessions[0]?.key || '';
  chat.value = selected; chat.disabled = !sessions.length;
  document.getElementById('clear').disabled = !sessions.some(session => (session.commandCount ?? session.commands.length) > 0);
  const session = sessions.find(session => session.key === selected);
  const entries = session?.commands || [];
  document.getElementById('count').textContent = page.total > page.limit ? `${page.offset + 1}–${page.offset + entries.length} of ${page.total}` : `${page.total} command${page.total === 1 ? '' : 's'}`;
  document.getElementById('empty').hidden = sessions.length > 0;
  connection.className = recordingWarning || capture.droppedEvents || capture.truncatedOutputs ? 'notice' : '';
  connection.textContent = recordingWarning || (capture.droppedEvents ? `${capture.droppedEvents} events exceeded capture limits` : capture.truncatedOutputs ? `${capture.truncatedOutputs} outputs truncated` : 'Connected · temporary history');
  commands.replaceChildren();
  if (session && !entries.length) commands.append(node('p', 'No matching commands.', 'muted'));
  for (const entry of entries) {
    const key = keyFor(session.key, entry.id);
    const row = node('details', null, 'entry');
    row.open = openCommands.has(key);
    const summary = node('summary', null, 'entry-summary');
    const severity = severities.includes(entry.severity) ? entry.severity : 'unknown';
    const cached = detailsCache.get(key);
    const assessmentState = (cached?.version === entry.version ? cached.assessmentState : null) || entry.assessmentState;
    const badge = node('span', assessmentState === 'missing' ? 'unassessed' : assessmentState === 'advisory' ? `${severity} · model` : severity, `badge severity-${severity}`);
    badge.title = assessmentState === 'missing' ? 'No pre-command assessment was received.' : assessmentState === 'advisory' ? `Model advice: ${severity}. Static analysis is unresolved.` : severity === 'unknown' ? 'The analyzer could not establish an impact rating.' : `Known impact: ${severity}`;
    summary.append(badge);
    summary.append(node('span', entry.command.replace(/\s+/g, ' ').trim(), 'command-preview'));
    summary.title = entry.command;
    row.append(summary);
    if (row.open) row.append(commandDetails(session, entry));
    row.addEventListener('toggle', () => {
      if (row.open) {
        if (openCommands.has(key)) return;
        openCommands.add(key);
        row.append(commandDetails(session, entry));
      } else { openCommands.delete(key); for (const child of [...row.children].slice(1)) child.remove(); }
    });
    commands.append(row);
  }
  if (page.total > page.limit) {
    const navigation = node('div', null, 'toolbar pagination');
    for (const [label, offset, disabled] of [['Previous', Math.max(0, page.offset - page.limit), page.offset === 0], ['Next', page.offset + page.limit, !page.hasMore]]) {
      const button = node('button', label, 'quiet'); button.disabled = disabled;
      button.addEventListener('click', () => vscode.postMessage({ type: 'page', sessionKey: selected, offset, query: search.value }));
      navigation.append(button);
    }
    commands.append(navigation);
  }
}
chat.addEventListener('change', () => { selected = chat.value; openCommands.clear(); vscode.postMessage({ type: 'page', sessionKey: selected, offset: 0, query: search.value }); });
search.addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => vscode.postMessage({ type: 'page', sessionKey: selected, offset: 0, query: search.value }), 200); });
document.getElementById('setup').addEventListener('click', () => vscode.postMessage({ type: 'setup' }));
document.getElementById('clear').addEventListener('click', () => vscode.postMessage({ type: 'clear' }));
document.getElementById('export')?.addEventListener('click', () => vscode.postMessage({ type: 'export', sessionKey: selected }));
document.getElementById('router-settings')?.addEventListener('click', () => vscode.postMessage({ type: 'configure-router' }));
window.addEventListener('message', ({ data }) => {
  if (data.type === 'router-state') {
    routerState = data.router; renderRouter();
  } else if (data.type === 'snapshot') {
    document.getElementById('clear').textContent = 'Clear logs';
    document.getElementById('clear').title = data.scopedClear ? 'Clear temporary command logs for this workspace.' : 'Clear all temporary command logs.';
    sessions = data.sessions; page = data.page; capture = { ...(data.capture || {}), historyEnabled: !!data.historyEnabled }; recordingWarning = data.recordingWarning || ''; selected = page.sessionKey;
    const valid = new Map(sessions.flatMap(session => session.commands.map(entry => [keyFor(session.key, entry.id), entry.version])));
    for (const key of openCommands) if (!valid.has(key)) openCommands.delete(key);
    for (const [key, detail] of detailsCache) if (valid.get(key) !== detail.version) detailsCache.delete(key);
    for (const [key, output] of outputCache) if (valid.get(key) !== output.version) outputCache.delete(key);
    // A model result can advance a command between a snapshot and its detail
    // reply. A request for the older version must not block the newer fetch.
    for (const [key, version] of pending) if (valid.get(key) !== version) pending.delete(key);
    render();
  } else if (data.type === 'cleared') {
    clearTimeout(searchTimer); search.value = '';
    sessions = []; selected = ''; page = { offset: 0, limit: 100, total: 0, hasMore: false };
    capture = {}; recordingWarning = '';
    openCommands.clear(); detailsCache.clear(); outputCache.clear(); pending.clear();
    render();
  } else if (data.type === 'command') {
    const key = keyFor(data.sessionKey, data.command.id);
    if (currentEntry(data.sessionKey, data.command.id)?.version !== data.command.version) return;
    pending.delete(key); detailsCache.set(key, data.command); render();
  } else if (data.type === 'output') {
    const key = keyFor(data.sessionKey, data.id);
    const detail = detailsCache.get(key);
    if (detail && detail.version === data.version) outputCache.set(key, { version: data.version, text: data.text });
    render();
  } else if (data.type === 'error') {
    if (data.sessionKey && data.id) pending.delete(keyFor(data.sessionKey, data.id));
    connection.className = 'error'; connection.textContent = data.message;
  } else if (data.type === 'connected') { render(); }
});
// Only expansion state is held in memory; no command data is persisted by the webview.
vscode.postMessage({ type: 'ready' });
