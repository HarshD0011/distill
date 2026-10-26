'use strict';
const vscode = require('vscode');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const execFile = promisify(require('node:child_process').execFile);
const { connectBroker } = require('./client');
const { rpc } = require('./transport');
const { SessionTitles } = require('./titles');
const { normalizeDetails } = require('./assessments');

function activate(context) {
  let endpointPromise;
  let view;
  let lastVersion = -1;
  let busy = false;
  let disposed = false;
  let connectionError = '';
  let selectedSession = '';
  let pageOffset = 0;
  let query = '';
  let brokerId = '';
  let recordingWarning = '';
  let requestRevision = 0;
  let lastSnapshot;
  let lastTitles = '';
  let legacyBroker = false;
  const titleHome = vscode.workspace.getConfiguration('distill').get('codexHome', '') || undefined;
  const titles = new SessionTitles(titleHome);
  const roots = () => (vscode.workspace.workspaceFolders || []).map(folder => folder.uri).filter(uri => uri.scheme === 'file').map(uri => uri.fsPath);
  const connect = () => {
    if (vscode.env.remoteName || !['darwin', 'linux'].includes(process.platform)) {
      return Promise.reject(new Error('V1 supports local desktop VS Code on macOS and Linux.'));
    }
    if (!vscode.workspace.isTrusted || !roots().length) return Promise.reject(new Error('Open a trusted local folder to record command traces.'));
    if (!endpointPromise) endpointPromise = connectBroker(roots(), vscode.workspace.getConfiguration('distill').get('binaryPath', 'distill')).then(endpoint => {
      const id = endpoint.instance_id || endpoint.token;
      if (brokerId && brokerId !== id) {
        recordingWarning = 'Recorder restarted; earlier temporary traces were lost.';
        requestRevision++; lastVersion = -1;
      }
      legacyBroker = (endpoint.broker_version || 1) < 3;
      brokerId = id; return endpoint;
    }).catch(error => { endpointPromise = null; throw error; });
    return endpointPromise;
  };
  const send = async request => {
    try { return await rpc(await connect(), request); } catch (error) { endpointPromise = null; throw error; }
  };
  const refresh = async () => {
    if (busy || disposed) return;
    busy = true;
    const revision = requestRevision;
    try {
      if (!view) { await send({ action: 'ping' }); return; }
      const snapshot = await send({ action: 'snapshot', version: view ? lastVersion : -1, paged: true, compact: true, sessionKey: selectedSession, offset: pageOffset, query, roots: roots().map(root => require('node:fs').realpathSync(root)) });
      if (revision !== requestRevision) return;
      if (!snapshot.unchanged) {
        lastSnapshot = snapshot;
        for (const session of snapshot.sessions) for (const entry of session.commands) entry.version ??= snapshot.version;
      }
      if (!lastSnapshot) return;
      const namedSessions = await titles.enrich(lastSnapshot.sessions);
      if (revision !== requestRevision) return;
      const titleStamp = JSON.stringify(namedSessions.map(session => [session.key, session.title]));
      if (connectionError && view) view.webview.postMessage({ type: 'connected' });
      connectionError = '';
      if (view && (!snapshot.unchanged || titleStamp !== lastTitles)) {
        lastVersion = lastSnapshot.version; lastTitles = titleStamp;
        selectedSession = lastSnapshot.page.sessionKey;
        view.webview.postMessage({ type: 'snapshot', ...lastSnapshot, sessions: namedSessions, recordingWarning, scopedClear: !legacyBroker });
      }
    } catch (error) {
      connectionError = error.message;
      if (view) view.webview.postMessage({ type: 'error', message: connectionError });
    } finally { busy = false; if (revision !== requestRevision) void refresh(); }
  };
  const clearLogs = async () => {
    await connect();
    requestRevision++;
    await send({ action: 'clear', roots: legacyBroker ? undefined : roots().map(root => require('node:fs').realpathSync(root)) });
    requestRevision++;
    lastVersion = -1; lastSnapshot = undefined; lastTitles = '';
    selectedSession = ''; pageOffset = 0; query = ''; recordingWarning = '';
    view?.webview.postMessage({ type: 'cleared' });
    await refresh();
  };

  context.subscriptions.push(vscode.window.registerWebviewViewProvider('distill.trace', {
    resolveWebviewView(webviewView) {
      view = webviewView;
      requestRevision++;
      lastVersion = -1;
      view.webview.options = { enableScripts: true, localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'media')] };
      const nonce = crypto.randomBytes(24).toString('hex');
      const resource = name => view.webview.asWebviewUri(vscode.Uri.joinPath(context.extensionUri, 'media', name));
      view.webview.html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${view.webview.cspSource}; script-src 'nonce-${nonce}';"><link rel="stylesheet" href="${resource('trace.css')}"><title>Distill chat trace</title></head><body><header><h1>Command trace</h1><p class="muted">Temporary · clears when VS Code quits</p></header><div id="connection" role="status">Connecting to Distill…</div><section class="controls"><label for="chat">Chat session</label><select id="chat" aria-label="Chat session"></select><label class="sr-only" for="search">Filter commands</label><input id="search" type="search" placeholder="Filter commands or severity…"><div class="toolbar"><span id="count" class="muted"></span><button id="clear" class="quiet" title="Clear temporary command logs for this workspace.">Clear logs</button></div></section><main id="commands"></main><section id="empty"><h2>No commands yet</h2><p>Connect Codex or Claude, then run a command in a chat.</p><button id="setup">Connect user hooks</button><p class="muted small">Only commands observed by the hooks are recorded.</p></section><script nonce="${nonce}" src="${resource('trace.js')}"></script></body></html>`;
      const currentView = view;
      context.subscriptions.push(view.webview.onDidReceiveMessage(async message => {
        if (!message || typeof message.type !== 'string') return;
        try {
          if (message.type === 'ready') { requestRevision++; lastVersion = -1; await refresh(); }
          if (message.type === 'page') {
            requestRevision++;
            selectedSession = typeof message.sessionKey === 'string' ? message.sessionKey : selectedSession;
            pageOffset = Number.isSafeInteger(message.offset) && message.offset >= 0 ? message.offset : 0;
            query = typeof message.query === 'string' ? message.query.slice(0, 1024) : '';
            lastVersion = -1; await refresh();
          }
          if (message.type === 'setup') await vscode.commands.executeCommand('distill.setupHooks');
          if (message.type === 'clear') await clearLogs();
          if (message.type === 'command' && typeof message.sessionKey === 'string' && typeof message.id === 'string') {
            const revision = requestRevision;
            let command;
            if (legacyBroker) {
              command = lastSnapshot?.sessions.find(session => session.key === message.sessionKey)?.commands.find(entry => entry.id === message.id);
              if (!command) throw new Error('Command is no longer available');
            } else { command = (await send({ action: 'command', sessionKey: message.sessionKey, id: message.id })).command; }
            if (revision !== requestRevision) return;
            const sessionId = command.sessionId || lastSnapshot?.sessions.find(session => session.key === message.sessionKey)?.id;
            currentView.webview.postMessage({ type: 'command', sessionKey: message.sessionKey, command: normalizeDetails({ ...command, sessionId }) });
          }
          if (message.type === 'output' && typeof message.sessionKey === 'string' && typeof message.id === 'string') {
            const revision = requestRevision;
            const output = await send({ action: 'output', sessionKey: message.sessionKey, id: message.id });
            if (revision !== requestRevision) return;
            currentView.webview.postMessage({ type: 'output', sessionKey: message.sessionKey, id: message.id, text: output.text, version: output.version ?? lastSnapshot?.sessions.find(session => session.key === message.sessionKey)?.commands.find(entry => entry.id === message.id)?.version });
          }
        } catch (error) { currentView.webview.postMessage({ type: 'error', message: error.message, sessionKey: message.sessionKey, id: message.id }); }
      }));
      context.subscriptions.push(view.onDidDispose(() => { if (view === currentView) view = null; }));
    },
  }));
  context.subscriptions.push(vscode.commands.registerCommand('distill.openTrace', async () => {
    await vscode.commands.executeCommand('workbench.view.extension.distill');
    await vscode.commands.executeCommand('distill.trace.focus');
    await refresh();
  }));
  context.subscriptions.push(vscode.commands.registerCommand('distill.clearTrace', async () => {
    try { await clearLogs(); }
    catch (error) { vscode.window.showErrorMessage(`Distill: ${error.message}`); }
  }));
  context.subscriptions.push(vscode.commands.registerCommand('distill.setupHooks', async () => {
    try {
      await connect();
      const folders = vscode.workspace.workspaceFolders || [];
      const folder = folders.length === 1 ? folders[0] : (await vscode.window.showQuickPick(folders.map(folder => ({ label: folder.name, description: folder.uri.fsPath, folder })), { title: 'Connect Distill in which workspace folder?' }))?.folder;
      if (!folder) return;
      const host = await vscode.window.showQuickPick([
        { label: 'Codex', id: 'codex', description: 'Record Bash commands and output from each Codex chat' },
        { label: 'Claude Code', id: 'claude', description: 'Record Bash commands and output from each Claude chat' },
      ], { title: 'Connect Distill command traces' });
      if (!host) return;
      const binary = require('./client').resolveBinary(vscode.workspace.getConfiguration('distill').get('binaryPath', ''));
      const health = await execFile(binary, ['doctor', '--json'], { timeout: 5000, maxBuffer: 64 * 1024 });
      const capabilities = JSON.parse(health.stdout);
      if (capabilities.trace_protocol !== 1 || !['assessments', 'completion', 'memory-only', 'workspace-context', 'hook-source-inspection'].every(name => capabilities.capabilities?.includes(name))) {
        throw new Error('This Distill CLI does not support the extension trace protocol. Build or install the current CLI before connecting.');
      }
      const workspaceRoot = require('node:fs').realpathSync(folder.uri.fsPath);
      const preview = JSON.parse((await execFile(binary, ['setup', host.id, '--check', '--workspace-root', workspaceRoot], { timeout: 10000, maxBuffer: 1024 * 1024 })).stdout);
      if (vscode.workspace.textDocuments.some(document => document.uri.fsPath === preview.path && document.isDirty)) {
        throw new Error('Save or revert the open user hooks file before connecting Distill');
      }
      const result = await execFile(binary, ['setup', host.id, '--workspace-root', workspaceRoot], { timeout: 10000, maxBuffer: 1024 * 1024 });
      const setup = JSON.parse(result.stdout);
      const file = vscode.Uri.file(setup.path);
      const document = await vscode.workspace.openTextDocument(file);
      await vscode.window.showTextDocument(document, { preview: false });
      const warnings = setup.project_handlers?.length ? ' Existing project handlers remain in place; inspect their warnings with distill doctor.' : '';
      vscode.window.showInformationMessage((host.id === 'codex'
        ? 'Pinned Distill user hooks configured. In Codex, use /hooks to review changed definitions.'
        : 'Pinned Distill user hooks configured. Restart or resume Claude Code.') + warnings);
    } catch (error) { vscode.window.showErrorMessage(`Distill: ${error.message}`); }
  }));
  context.subscriptions.push(vscode.workspace.onDidChangeWorkspaceFolders(() => { requestRevision++; endpointPromise = null; lastVersion = -1; selectedSession = ''; pageOffset = 0; void refresh(); }));
  const timer = setInterval(refresh, 1000);
  context.subscriptions.push({ dispose() { disposed = true; clearInterval(timer); } });
  // Activation starts recording even before the sidebar is opened. Deactivation does
  // not delete history: the broker follows the editor main process, not this host.
  void refresh();
}

module.exports = { activate };
