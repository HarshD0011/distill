'use strict';
// Launched with NODE_OPTIONS/loader injection removed by /usr/bin/env.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
let input = Buffer.alloc(0);
function deny(message) {
  let event = 'PreToolUse';
  try { event = JSON.parse(input.toString('utf8')).hook_event_name || event; } catch {}
  const details = event === 'PermissionRequest'
    ? { hookEventName: event, decision: { behavior: 'deny', message } }
    : { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: message };
  process.stdout.write(JSON.stringify({ systemMessage: message, hookSpecificOutput: details }) + '\n');
  process.exit(2);
}
try {
  const chunks = [];
  let bytes = 0;
  const buffer = Buffer.alloc(65536);
  for (;;) {
    const count = fs.readSync(0, buffer, 0, buffer.length, null);
    if (!count) break;
    bytes += count;
    if (bytes > 32 * 1024 * 1024) deny('Distill: hook input exceeds its size limit');
    chunks.push(Buffer.from(buffer.subarray(0, count)));
  }
  input = Buffer.concat(chunks);
  const args = process.argv.slice(2);
  if (args.length < 6 || args[0] !== '--binary' || args[2] !== '--sha256') deny('Distill: invalid pinned launcher arguments');
  const [binary, expected] = [args[1], args[3]];
  if (!path.isAbsolute(binary)) deny('Distill: executable must be absolute');
  const fd = fs.openSync(binary, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  const digest = crypto.createHash('sha256');
  try {
    if (!fs.fstatSync(fd).isFile()) deny('Distill: executable is not a regular file');
    for (;;) {
      const count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (!count) break;
      digest.update(buffer.subarray(0, count));
    }
  } finally { fs.closeSync(fd); }
  if (digest.digest('hex') !== expected) deny('Distill: pinned executable changed; reinstall trusted user hooks');
  const env = { ...process.env };
  for (const key of ['NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'PYTHONPATH', 'PYTHONHOME', 'DISTILL_ANALYSIS_WORKER', 'DISTILL_WATCHDOG_MS']) delete env[key];
  const result = spawnSync(binary, args.slice(4), { input, env, stdio: ['pipe', 'inherit', 'inherit'] });
  if (result.error || result.signal || result.status == null) deny('Distill: pinned executable unavailable');
  process.exit(result.status);
} catch { deny('Distill: pinned executable unavailable'); }
