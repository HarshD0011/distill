'use strict';
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { redactValue } = require('./privacy');
const { TraceStore } = require('./store');
const { advicePoller } = require('./advice');
const { MAX_BYTES, secureDirectory, processIdentity, endpointPath } = require('./transport');

function contains(root, cwd) {
  const relative = path.relative(root, cwd);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

async function startBroker(config) {
  const { directory, ownerPid, ownerIdentity } = config;
  const roots = [...(config.roots || [])];
  if (!Array.isArray(roots) || !roots.length || roots.some(root => !path.isAbsolute(root))) throw new Error('Local workspace roots required');
  if (!ownerIdentity || processIdentity(ownerPid) !== ownerIdentity) throw new Error('Editor process has exited');
  secureDirectory(directory);
  const file = endpointPath(directory, ownerPid, ownerIdentity, roots);
  const socketPath = path.join(directory, path.basename(file).slice(0, 8) + '.sock');
  if (Buffer.byteLength(socketPath) > 100) throw new Error('Trace socket path is too long; set DISTILL_TRACE_DIR to a shorter private directory');
  if (!path.isAbsolute(config.peerBinary || '')) throw new Error('An absolute Distill executable is required for Unix peer verification');
  const lock = `${file}.lock`;
  try {
    const fd = fs.openSync(lock, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, identity: processIdentity(process.pid) }));
    fs.closeSync(fd);
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const stat = fs.lstatSync(lock);
    // Another broker may still be publishing its lock. Never interpret an empty PID as 0.
    if (Date.now() - stat.mtimeMs < 5000) return null;
    let holder;
    try { holder = JSON.parse(fs.readFileSync(lock, 'utf8')); } catch {}
    if (Number.isSafeInteger(holder?.pid) && holder.pid > 1) {
      try { if (processIdentity(holder.pid) === holder.identity) return null; } catch {}
    }
    const current = fs.lstatSync(lock);
    if (current.ino !== stat.ino || current.mtimeMs !== stat.mtimeMs) return null;
    fs.unlinkSync(lock);
    return startBroker(config);
  }

  const store = new TraceStore();
  const refreshAdvice = advicePoller(store, config.peerBinary);
  const historyEnabled = false;
  const clients = new Map();
  let leased = false;
  const release = id => {
    const client = clients.get(id);
    if (!client) return;
    clients.delete(id);
    const uncovered = client.roots.filter(root => ![...clients.values()].some(other => other.roots.includes(root)));
    if (uncovered.length) store.clear(uncovered);
  };
  const token = crypto.randomBytes(32).toString('hex');
  const sockets = new Set();
  let endpoint;
  const publish = () => {
    const temporary = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(endpoint), { mode: 0o600 });
    fs.renameSync(temporary, file);
  };
  let timer;
  let stopped = false;
  const server = net.createServer(async socket => {
    socket.on('error', () => {});
    if (stopped || sockets.size >= 64) { socket.destroy(); return; }
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.pause();
    const verified = await new Promise(resolve => {
      const peer = spawn(config.peerBinary, ['peer-check', '--fd', '3'], { stdio: ['ignore', 'pipe', 'ignore', socket] });
      let output = '';
      const timeout = setTimeout(() => { peer.kill(); resolve(false); }, 1000);
      peer.stdout.on('data', chunk => { output += chunk; if (output.length > 100) peer.kill(); });
      peer.on('error', () => { clearTimeout(timeout); resolve(false); });
      peer.on('close', code => { clearTimeout(timeout); resolve(code === 0 && output.trim() === 'same-user'); });
    });
    if (stopped) { socket.destroy(); return; }
    if (!verified) { socket.end('{"ok":false,"error":"Unix peer credentials rejected"}\n'); return; }
    socket.on('error', () => {});
    socket.setTimeout(5000, () => socket.destroy());
    const chunks = [];
    let size = 0;
    let handled = false;
    socket.on('data', async chunk => {
      if (handled) return;
      size += chunk.length;
      if (size > MAX_BYTES) { handled = true; socket.end('{"ok":false,"error":"Event exceeds 32 MiB"}\n'); return; }
      chunks.push(chunk);
      if (!chunk.includes(10)) return;
      handled = true;
      try {
        const request = JSON.parse(Buffer.concat(chunks).toString('utf8').trim());
        const supplied = Buffer.from(typeof request.token === 'string' ? request.token : '');
        const expected = Buffer.from(token);
        if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) throw new Error('Unauthorized trace request');
        let response = {};
        switch (request.action) {
          case 'ping': response = { protocol: 1, capabilities: ['assessments', 'completion', 'paged-snapshots', 'memory-only', 'compact-commands', 'assessment-state', 'modeled-effects', 'structured-diagnostics', 'feedback', 'session-export'], historyEnabled }; break;
          case 'register': {
            if (!Array.isArray(request.roots) || request.roots.some(root => typeof root !== 'string' || !path.isAbsolute(root))) throw new Error('Invalid workspace roots');
            for (const root of request.roots) {
              const real = fs.realpathSync(root);
              if (!roots.includes(real)) roots.push(real);
            }
            if (request.clientId !== undefined) {
              if (typeof request.clientId !== 'string' || !/^[\w-]{1,80}$/.test(request.clientId) || !Number.isSafeInteger(request.clientPid) || request.clientPid <= 1) throw new Error('Invalid recorder session');
              const identity = processIdentity(request.clientPid);
              if (!identity) throw new Error('Editor host has exited');
              if (!clients.has(request.clientId)) {
                if (clients.size >= 64) throw new Error('Too many recorder sessions');
                // A new extension activation must never inherit old command data.
                store.clear(request.roots.map(root => fs.realpathSync(root)));
              }
              clients.set(request.clientId, { pid: request.clientPid, identity, roots: request.roots.map(root => fs.realpathSync(root)) });
              leased = true;
            }
            roots.sort(); endpoint.roots = roots; publish(); break;
          }
          case 'release': release(request.clientId); break;
          case 'record':
            if (typeof request.event?.session_cwd !== 'string'
                || !path.isAbsolute(request.event.session_cwd)
                || !roots.some(root => contains(root, request.event.session_cwd))) throw new Error('Event belongs to another workspace');
            if (request.event.editor_pid != null && request.event.editor_pid !== ownerPid) throw new Error('Event belongs to another editor instance');
            store.record(redactValue(request.event));
            break;
          case 'coverage': response = store.coverage(); break;
          case 'snapshot': response = request.version === store.version ? { unchanged: true } : { ...store.snapshot(request), historyEnabled }; break;
          case 'command': response = { command: store.readCommand(request.sessionKey, request.id) }; break;
          case 'output': response = { text: store.readOutput(request.sessionKey, request.id), version: store.readCommand(request.sessionKey, request.id).version }; break;
          case 'reload-history': response = { historyEnabled }; break;
          case 'feedback': {
            response = store.feedback(request.sessionKey, request.id, request);
            break;
          }
          case 'export': response = { export: store.exportSession(request.sessionKey) }; break;
          case 'clear': store.clear(request.roots); break;
          default: throw new Error('Unknown trace action');
        }
        socket.end(JSON.stringify({ ok: true, ...response }) + '\n');
      } catch (error) { socket.end(JSON.stringify({ ok: false, error: error.message }) + '\n'); }
    });
    socket.resume();
  });
  const stop = () => {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    store.clear();
    for (const socket of sockets) socket.destroy();
    server.close();
    for (const name of [file, lock, socketPath]) {
      try { fs.unlinkSync(name); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
  };
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(socketPath, resolve);
    });
    fs.chmodSync(socketPath, 0o600);
    endpoint = { protocol: 1, socket: socketPath, token, editor_pid: ownerPid, broker_pid: process.pid, broker_version: 9, instance_id: crypto.randomUUID(), roots };
    // Only rendezvous metadata is persisted. History lives exclusively in `store`.
    publish();
    timer = setInterval(() => {
      try {
        if (processIdentity(ownerPid) !== ownerIdentity) { stop(); return; }
        for (const [id, client] of clients) {
          try { if (processIdentity(client.pid) === client.identity) continue; } catch {}
          release(id);
        }
        if (leased && !clients.size) stop();
        if (!stopped) void refreshAdvice();
      } catch { stop(); }
    }, 500);
    return { endpoint, file, stop, store };
  } catch (error) { stop(); throw error; }
}

if (require.main === module) {
  // Configuration contains only editor identity and workspace roots, never trace data.
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', chunk => { input += chunk; if (input.length > 16384) process.exit(1); });
  process.stdin.on('end', async () => {
    try {
      const broker = await startBroker(JSON.parse(input));
      if (!broker) return;
      process.once('SIGTERM', () => broker.stop());
      process.once('SIGINT', () => broker.stop());
    } catch { process.exitCode = 1; }
  });
}

module.exports = { startBroker, contains };
