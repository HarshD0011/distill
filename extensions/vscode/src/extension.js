'use strict';
const vscode = require('vscode');
const crypto = require('node:crypto');
const { connectBroker } = require('./client');
const { ensureBinary, trustedBinarySetting } = require('./install');
const { configureUserHooks } = require('./setup');
const { rpc } = require('./transport');
const { SessionTitles } = require('./titles');
const { normalizeDetails } = require('./assessments');
const { exportSession } = require('./export');
const { readRouterSettings, syncRouter, runWithInput } = require('./router');
const { RouterCredentials } = require('./credentials');
const { createRouterSettings } = require('./settings');
const { modelPreference } = require('./models');
const execFile = require('node:util').promisify(require('node:child_process').execFile);
let cleanup;

function activate(context) {
  let endpointPromise;
  let runtimePromise;
  let hooksPromise;
  let setupQueue = Promise.resolve();
  const clientId = crypto.randomUUID();
  const credentials = new RouterCredentials(context.secrets);
  let restartRouter = true;
  let updatingSettings = false;
  let routerState;
  const publicRouterState = () => routerState ? { status: 'ready', enabled: routerState.enabled, running: routerState.running, model: routerState.model } : { status: 'error' };
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
  const statusBar = vscode.window.createStatusBarItem?.(vscode.StatusBarAlignment?.Left, 20);
  if (statusBar) { statusBar.command = 'distill.openTrace'; statusBar.tooltip = 'Distill observed commands'; context.subscriptions.push(statusBar); statusBar.show(); }
  const titleHome = vscode.workspace.getConfiguration('distill').get('codexHome', '') || undefined;
  const titles = new SessionTitles(titleHome);
  const roots = () => (vscode.workspace.workspaceFolders || []).map(folder => folder.uri).filter(uri => uri.scheme === 'file').map(uri => uri.fsPath);
  const prepare = (force = false) => {
    if (disposed) return Promise.reject(new Error('Distill is inactive.'));
    if (vscode.env.remoteName || !['darwin', 'linux'].includes(process.platform)) {
      return Promise.reject(new Error('V1 supports local desktop VS Code on macOS and Linux.'));
    }
    if (!vscode.workspace.isTrusted || !roots().length) return Promise.reject(new Error('Open a trusted local folder to record command traces.'));
    if (!runtimePromise) runtimePromise = ensureBinary({
      extensionPath: context.extensionPath,
      storagePath: context.globalStorageUri?.fsPath,
      configured: trustedBinarySetting(vscode.workspace.getConfiguration('distill')),
    });
    if (!hooksPromise) hooksPromise = setupQueue.catch(() => {}).then(() => runtimePromise).then(async runtime => {
      const setups = await configureUserHooks({
        binary: runtime.binary, extensionPath: context.extensionPath, roots: roots(), force,
        debugLog: '',
        isDirty: file => vscode.workspace.textDocuments.some(document => document.uri.fsPath === file && document.isDirty),
      });
      const changed = setups.filter(setup => setup.changed);
      if (changed.length) {
        const next = changed.map(setup => setup.host === 'codex'
          ? 'Approve the Distill hooks in Codex with /hooks.'
          : 'Restart or resume Claude Code to approve the Distill hooks.').join(' ');
        void vscode.window.showInformationMessage(`Distill is installed and its hooks are configured. ${next}`);
      }
      let router;
      let settingsError;
      try { router = readRouterSettings(vscode.workspace.getConfiguration('distill')); }
      catch (error) { router = { enabled: false }; settingsError = error; }
      try {
        if (disposed) throw new Error('Distill is inactive.');
        routerState = await syncRouter({ binary: runtime.binary, hosts: setups.map(setup => setup.host), router, env: credentials.environment(router), credential: router.enabled ? await credentials.handoff(router) : undefined, restart: restartRouter });
        restartRouter = false;
        if (settingsError) void vscode.window.showErrorMessage(`Distill LLM router disabled: ${settingsError.message}`);
      } catch (error) {
        routerState = undefined;
        void vscode.window.showErrorMessage(`Distill router configuration failed: ${error.stderr || error.message}. Review Distill LLM settings and reconnect hooks.`);
      }
      void view?.webview.postMessage({ type: 'router-state', router: publicRouterState() });
      return { ...runtime, setups, router: routerState };
    });
    setupQueue = hooksPromise;
    return hooksPromise;
  };
  const connect = () => {
    if (!endpointPromise) endpointPromise = prepare().then(runtime => connectBroker(roots(), runtime.binary, clientId)).then(endpoint => {
      const id = endpoint.instance_id || endpoint.token;
      if (brokerId && brokerId !== id) {
        recordingWarning = '';
        lastSnapshot = undefined; lastTitles = ''; titles.clear();
        view?.webview.postMessage({ type: 'cleared' });
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
      if (statusBar) {
        statusBar.text = `Distill: ${namedSessions.reduce((sum, session) => sum + (session.commandCount || 0), 0)} commands`;
        statusBar.tooltip = routerState ? (routerState.enabled ? `Static analysis + advisory LLM: ${routerState.model}` : 'Static analysis only · LLM router disabled') : 'Distill observed commands · check router configuration';
      }
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
    titles.clear();
    selectedSession = ''; pageOffset = 0; query = ''; recordingWarning = '';
    view?.webview.postMessage({ type: 'cleared' });
    await refresh();
  };
  const applyRouter = async () => {
    restartRouter = true;
    hooksPromise = null; requestRevision++;
    const runtime = await prepare();
    await refresh();
    if (!runtime.router) throw new Error('Router could not be configured.');
  };
  const routerSettings = createRouterSettings(vscode, context, {
    configuration: () => vscode.workspace.getConfiguration('distill'), credentials,
    apply: async (values, router, apiKey) => {
      if (apiKey !== undefined && typeof apiKey !== 'string') throw new Error('Invalid API key.');
      if (apiKey) await credentials.save(router, apiKey);
      updatingSettings = true;
      try {
        const configuration = vscode.workspace.getConfiguration('distill');
        for (const [key, value] of Object.entries({ ...values, ...modelPreference(values.model) })) await configuration.update(`llm.${key}`, value, vscode.ConfigurationTarget.Global);
      } finally { updatingSettings = false; }
      await applyRouter();
    },
    forget: async router => { await credentials.forget(router); await applyRouter(); },
  });

  context.subscriptions.push(vscode.window.registerWebviewViewProvider('distill.trace', {
    resolveWebviewView(webviewView) {
      view = webviewView;
      requestRevision++;
      lastVersion = -1;
      view.webview.options = { enableScripts: true, localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'media')] };
      const nonce = crypto.randomBytes(24).toString('hex');
      const resource = name => view.webview.asWebviewUri(vscode.Uri.joinPath(context.extensionUri, 'media', name));
      view.webview.html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${view.webview.cspSource}; script-src 'nonce-${nonce}';"><link rel="stylesheet" href="${resource('trace.css')}"><title>Distill chat trace</title></head><body><header><div class="heading-row"><h1>Command trace <span class="extension-version">v${require('../package.json').version}</span></h1><button id="router-settings" class="quiet" title="Configure the LLM router, model and endpoint" aria-label="Configure LLM router">LLM settings</button></div><p id="router-status" class="muted" role="status">Checking LLM router…</p><p id="history-note" class="muted">Temporary · clears on window reload</p></header><div id="connection" role="status">Connecting to Distill…</div><section class="controls"><label for="chat">Chat session</label><select id="chat" aria-label="Chat session"></select><label class="sr-only" for="search">Filter commands</label><input id="search" type="search" placeholder="Filter commands or severity…"><div class="toolbar"><span id="count" class="muted"></span><button id="export" class="quiet" title="Export the retained session.">Export session</button><button id="clear" class="quiet" title="Clear temporary command logs for this workspace.">Clear logs</button></div></section><main id="commands"></main><section id="empty"><h2>No commands yet</h2><p>Approve the Distill hooks in your agent, then run a command in a chat.</p><button id="setup">Review hook setup</button><p class="muted small">Only commands observed by the hooks are recorded.</p></section><script nonce="${nonce}" src="${resource('trace.js')}"></script></body></html>`;
      const currentView = view;
      context.subscriptions.push(view.webview.onDidReceiveMessage(async message => {
        if (!message || typeof message.type !== 'string') return;
        try {
          if (message.type === 'ready') {
            void currentView.webview.postMessage({ type: 'router-state', router: hooksPromise ? publicRouterState() : { status: 'checking' } });
            requestRevision++; lastVersion = -1; await refresh();
          }
          if (message.type === 'page') {
            requestRevision++;
            selectedSession = typeof message.sessionKey === 'string' ? message.sessionKey : selectedSession;
            pageOffset = Number.isSafeInteger(message.offset) && message.offset >= 0 ? message.offset : 0;
            query = typeof message.query === 'string' ? message.query.slice(0, 1024) : '';
            lastVersion = -1; await refresh();
          }
          if (message.type === 'setup') await vscode.commands.executeCommand('distill.setupHooks');
          if (message.type === 'configure-router') await vscode.commands.executeCommand('distill.configureRouter');
          if (message.type === 'clear') await clearLogs();
          if (message.type === 'feedback' && typeof message.sessionKey === 'string' && typeof message.id === 'string' && ['over', 'under'].includes(message.kind)) {
            const result = await send({ action: 'feedback', sessionKey: message.sessionKey, id: message.id, kind: message.kind, note: typeof message.note === 'string' ? message.note.slice(0, 2048) : '' });
            void vscode.window.showInformationMessage(result.persistent ? 'Distill feedback saved to your enabled history. Policy is unchanged.' : 'Distill feedback saved temporarily. Export the session to keep it. Policy is unchanged.');
            lastVersion = -1; await refresh();
          }
          if (message.type === 'export') await vscode.commands.executeCommand('distill.exportSession');
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
  context.subscriptions.push(vscode.commands.registerCommand('distill.exportSession', async () => {
    try {
      if (!selectedSession) throw new Error('Select a recorded session first.');
      const format = await vscode.window.showQuickPick(['JSON', 'Markdown'], { placeHolder: 'Export the retained session as…' });
      if (!format) return;
      const target = await vscode.window.showSaveDialog({ defaultUri: vscode.Uri.file(require('node:path').join(roots()[0], `distill-session.${format === 'JSON' ? 'json' : 'md'}`)), filters: format === 'JSON' ? { JSON: ['json'] } : { Markdown: ['md'] } });
      if (!target) return;
      const result = await send({ action: 'export', sessionKey: selectedSession });
      await vscode.workspace.fs.writeFile(target, Buffer.from(exportSession(result.export, format.toLowerCase())));
      void vscode.window.showInformationMessage('Distill session exported.');
    } catch (error) { vscode.window.showErrorMessage(`Distill: ${error.message}`); }
  }));
  context.subscriptions.push(vscode.commands.registerCommand('distill.configureServices', async () => {
    try {
      const runtime = await prepare();
      const policy = runtime.setups.find(setup => setup.host === 'codex')?.policy_path;
      if (!policy) throw new Error('The installed CLI did not report its user policy path. Update Distill and reconnect the hooks.');
      const file = vscode.Uri.file(policy);
      await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(file), { preview: false });
      void vscode.window.showInformationMessage('Distill keeps editor traces temporary. Use Distill: Configure LLM Router for models and securely saved keys.');
    } catch (error) { vscode.window.showErrorMessage(`Distill: ${error.message}`); }
  }));
  context.subscriptions.push(vscode.commands.registerCommand('distill.configureRouter', () => routerSettings.open()));
  for (const [command, action] of [['distill.startService', 'start'], ['distill.stopService', 'stop']]) context.subscriptions.push(vscode.commands.registerCommand(command, async () => {
    try {
      const runtime = await prepare();
      const router = readRouterSettings(vscode.workspace.getConfiguration('distill'));
      const response = JSON.parse((await runWithInput(runtime.binary, ['service', action, ...(action === 'start' ? ['--credential-stdin'] : [])], { env: credentials.environment(router), ...(action === 'start' ? { input: JSON.stringify(await credentials.handoff(router)) } : {}), timeout: 6000, maxBuffer: 65536 })).stdout);
      if (routerState) routerState = { ...routerState, running: action === 'start' };
      void view?.webview.postMessage({ type: 'router-state', router: publicRouterState() });
      void vscode.window.showInformationMessage(action === 'start' ? `Distill optional service started. Model judge: ${response.judge_enabled ? 'on' : 'off'}. Traces remain temporary.` : 'Distill optional service stopped.');
    } catch (error) { vscode.window.showErrorMessage(`Distill: ${error.stderr || error.message}`); }
  }));
  context.subscriptions.push(vscode.workspace.onDidChangeWorkspaceFolders(() => { requestRevision++; endpointPromise = null; hooksPromise = null; lastVersion = -1; selectedSession = ''; pageOffset = 0; void refresh(); }));
  context.subscriptions.push(vscode.workspace.onDidChangeConfiguration(event => {
    if (updatingSettings) return;
    const binaryChanged = event.affectsConfiguration('distill.binaryPath');
    if (!binaryChanged && !event.affectsConfiguration('distill.llm')) return;
    if (binaryChanged) runtimePromise = null;
    void view?.webview.postMessage({ type: 'router-state', router: { status: 'checking' } });
    hooksPromise = null; endpointPromise = null; requestRevision++;
    void refresh();
  }));
  const timer = setInterval(refresh, 1000);
  context.subscriptions.push({ dispose() { disposed = true; clearInterval(timer); } });
  cleanup = async () => {
    disposed = true; clearInterval(timer);
    await setupQueue.catch(() => {});
    try {
      if (endpointPromise) await rpc(await endpointPromise, { action: 'release', clientId });
    } catch {}
    try {
      if (runtimePromise) await execFile((await runtimePromise).binary, ['service', 'stop'], { timeout: 2000, maxBuffer: 65536 });
    } catch {}
    lastSnapshot = undefined; titles.clear();
  };
  // Each activation has a new recorder lease; reloads discard the previous lease.
  void refresh();
  if (vscode.workspace.isTrusted && roots().length && !vscode.env.remoteName && ['darwin', 'linux'].includes(process.platform)) {
    void prepare().catch(error => vscode.window.showErrorMessage(`Distill setup could not finish: ${error.message} Run Distill: Connect User Hooks to retry.`));
  }
  return { ready: async () => { const runtime = await prepare(); await connect(); return runtime; } };
}

module.exports = { activate, deactivate: () => cleanup?.() };
