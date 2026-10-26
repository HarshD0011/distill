'use strict';

function shellQuote(value) { return `'${value.replace(/'/g, `'"'"'`)}'`; }

function mergeHooks(existing, host, binary, workspaceRoot, coveredEvents = new Set()) {
  const workspace = workspaceRoot ? ` --workspace-root ${shellQuote(workspaceRoot)}` : '';
  if (!existing || typeof existing !== 'object' || Array.isArray(existing)) throw new Error('Hook configuration must be an object');
  const result = structuredClone(existing);
  result.hooks ??= {};
  if (!result.hooks || typeof result.hooks !== 'object' || Array.isArray(result.hooks)) throw new Error('hooks must be an object');
  const events = host === 'codex' ? ['PreToolUse', 'PermissionRequest', 'PostToolUse'] : ['PreToolUse', 'PostToolUse', 'PostToolUseFailure'];
  for (const event of events) {
    const groups = result.hooks[event] ?? [];
    if (!Array.isArray(groups)) throw new Error(`${event} hooks must be an array`);
    let found = false;
    // Update the executable while retaining policy, config, and other existing flags.
    result.hooks[event] = groups.map(group => {
      if (!Array.isArray(group.hooks)) throw new Error('Invalid hook group');
      return { ...group, hooks: group.hooks.map(handler => {
        const args = distillHookArgs(handler.command, host);
        if (args == null) return handler;
        found = true;
        if (coveredEvents.has(event)) return null;
        return { ...handler, command: `${shellQuote(binary)} hook ${host}${args}${args.includes('--workspace-root') ? '' : workspace}` };
      }).filter(Boolean) };
    }).filter(group => group.hooks.length);
    if (coveredEvents.has(event)) continue;
    if (found) continue;
    const label = host === 'codex' && event === 'PreToolUse' ? ' --label-command' : '';
    result.hooks[event].push({ matcher: host === 'codex' ? '^Bash$' : 'Bash', hooks: [{
      type: 'command', command: `${shellQuote(binary)} hook ${host} --mode advisory${label}${workspace}`, timeout: 10,
    }] });
  }
  return result;
}

function distillHookArgs(command, host) {
  if (typeof command !== 'string') return null;
  // Match the executable and hook subcommand, not mentions in another hook's arguments.
  return new RegExp(`^(?:'[^']*[/\\\\]distill'|"[^"\\n]*[/\\\\]distill"|[^\\s'"]*[/\\\\]distill|'distill'|"distill"|distill)\\s+hook\\s+${host}((?:\\s.*)?)$`).exec(command.trim())?.[1] ?? null;
}

function workspaceHookPlan(existing, host, binary, workspaceRoot, targetFile, inventory) {
  const path = require('node:path');
  const canonicalFile = file => {
    const fs = require('node:fs');
    try { return fs.realpathSync(file); } catch {}
    try { return path.join(fs.realpathSync(path.dirname(file)), path.basename(file)); } catch {}
    return path.resolve(file);
  };
  const events = host === 'codex' ? ['PreToolUse', 'PermissionRequest', 'PostToolUse'] : ['PreToolUse', 'PostToolUse', 'PostToolUseFailure'];
  const reused = new Map();
  if (inventory.warnings?.length) throw new Error(inventory.warnings.join('\n'));
  for (const handler of inventory.handlers || []) {
    if (canonicalFile(handler.path) === canonicalFile(targetFile) || !events.includes(handler.event)) continue;
    let matches;
    try { matches = !handler.matcher || handler.matcher === '*' || new RegExp(handler.matcher).test('Bash'); }
    catch { throw new Error(`Invalid matcher in ${handler.path}`); }
    if (!matches) continue;
    if (reused.has(handler.event)) throw new Error(`Multiple existing Distill ${handler.event} hooks were found outside this workspace configuration. Consolidate those sources before adding another hook.`);
    reused.set(handler.event, handler);
  }
  // Reusing a source must not silently replace a workspace's stricter policy.
  const policyArgs = args => {
    if (!Array.isArray(args)) return null;
    const result = [];
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--label-command') continue;
      if (args[i] === '--workspace-root') { i++; continue; }
      if (args[i].startsWith('--workspace-root=')) continue;
      result.push(args[i]);
    }
    return JSON.stringify(result);
  };
  for (const [event, external] of reused) {
    for (const group of existing.hooks?.[event] || []) for (const handler of group.hooks || []) {
      if (distillHookArgs(handler.command, host) == null) continue;
      const local = (inventory.handlers || []).find(item => item.event === event && canonicalFile(item.path) === canonicalFile(targetFile) && item.command.trim() === handler.command.trim());
      if (!local || policyArgs(local.args) == null || policyArgs(local.args) !== policyArgs(external.args)) {
        throw new Error(`Existing ${event} Distill hooks have different or unrecognized options. Preserve their policy by consolidating those definitions before connecting.`);
      }
    }
  }
  return {
    configuration: mergeHooks(existing, host, binary, workspaceRoot, new Set(reused.keys())),
    reused: [...reused.values()],
    installedEvents: events.filter(event => !reused.has(event)),
  };
}

module.exports = { mergeHooks, shellQuote, workspaceHookPlan };
