'use strict';
const vscode = require('vscode');
const crypto = require('node:crypto');
const { connectBroker } = require('./client');
const { ensureBinary } = require('./install');
const { configureUserHooks } = require('./setup');
const { rpc } = require('./transport');
const { SessionTitles } = require('./titles');
const { normalizeDetails } = require('./assessments');

function activate(context) {
  let endpointPromise;
  let runtimePromise;
  let hooksPromise;
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
  const prepare = (force = false) => {
    if (vscode.env.remoteName || !['darwin', 'linux'].includes(process.platform)) {
      return Promise.reject(new Error('V1 supports local desktop VS Code on macOS and Linux.'));
    }
    if (!vscode.workspace.isTrusted || !roots().length) return Promise.reject(new Error('Open a trusted local folder to record command traces.'));
    if (!runtimePromise) runtimePromise = ensureBinary({
      extensionPath: context.extensionPath,
      storagePath: context.globalStorageUri?.fsPath,
      configured: vscode.workspace.getConfiguration('distill').get('binaryPath', ''),
    });
    if (!hooksPromise) hooksPromise = runtimePromise.then(async runtime => {
      const setups = await configureUserHooks({
        binary: runtime.binary, extensionPath: context.extensionPath, roots: roots(), force,
        isDirty: file => vscode.workspace.textDocuments.some(document => document.uri.fsPath === file && document.isDirty),
      });
      const changed = setups.filter(setup => setup.changed);
      if (changed.length) {
        const next = changed.map(setup => setup.host === 'codex'
          ? 'Approve the Distill hooks in Codex with /hooks.'
          : 'Restart or resume Claude Code to approve the Distill hooks.').join(' ');
        void vscode.window.showInformationMessage(`Distill is installed and its hooks are configured. ${next}`);
      }
      return { ...runtime, setups };
    });
    return hooksPromise;
  };
  const connect = () => {
    if (!endpointPromise) endpointPromise = prepare().then(runtime => connectBroker(roots(), runtime.binary)).then(endpoint => {
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
      view.webview.html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${view.webview.cspSource}; script-src 'nonce-${nonce}';"><link rel="stylesheet" href="${resource('trace.css')}"><title>Distill chat trace</title></head><body><header><h1>Command trace</h1><p class="muted">Temporary · clears when VS Code quits</p></header><div id="connection" role="status">Connecting to Distill…</div><section class="controls"><label for="chat">Chat session</label><select id="chat" aria-label="Chat session"></select><label class="sr-only" for="search">Filter commands</label><input id="search" type="search" placeholder="Filter commands or severity…"><div class="toolbar"><span id="count" class="muted"></span><button id="clear" class="quiet" title="Clear temporary command logs for this workspace.">Clear logs</button></div></section><main id="commands"></main><section id="empty"><h2>No commands yet</h2><p>Approve the Distill hooks in your agent, then run a command in a chat.</p><button id="setup">Review hook setup</button><p class="muted small">Only commands observed by the hooks are recorded.</p></section><script nonce="${nonce}" src="${resource('trace.js')}"></script></body></html>`;
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
      runtimePromise = null;
      hooksPromise = null;
      endpointPromise = null;
      const runtime = await prepare(true);
      await connect();
      const file = vscode.Uri.file(runtime.setups[0].path);
      const document = await vscode.workspace.openTextDocument(file);
      await vscode.window.showTextDocument(document, { preview: false });
    } catch (error) { vscode.window.showErrorMessage(`Distill: ${error.message}`); }
  }));
  context.subscriptions.push(vscode.workspace.onDidChangeWorkspaceFolders(() => { requestRevision++; endpointPromise = null; hooksPromise = null; lastVersion = -1; selectedSession = ''; pageOffset = 0; void refresh(); }));
  context.subscriptions.push(vscode.workspace.onDidChangeConfiguration(event => {
    if (!event.affectsConfiguration('distill.binaryPath')) return;
    runtimePromise = null; hooksPromise = null; endpointPromise = null;
    void refresh();
  }));
  const timer = setInterval(refresh, 1000);
  context.subscriptions.push({ dispose() { disposed = true; clearInterval(timer); } });
  // Activation starts recording even before the sidebar is opened. Deactivation does
  // not delete history: the broker follows the editor main process, not this host.
  void refresh();
  if (vscode.workspace.isTrusted && roots().length && !vscode.env.remoteName && ['darwin', 'linux'].includes(process.platform)) {
    void prepare().catch(error => vscode.window.showErrorMessage(`Distill setup could not finish: ${error.message} Run Distill: Connect User Hooks to retry.`));
  }
  return { ready: () => prepare() };
}

module.exports = { activate };
