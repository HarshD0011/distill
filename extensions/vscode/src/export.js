'use strict';
const { redactValue } = require('./privacy');
function markdownText(value) { return String(value || '').replace(/[\\`*_[\]{}<>#!|]/g, '\\$&'); }
function exportSession(value, format = 'json') {
  const data = redactValue(structuredClone(value));
  if (format === 'json') return JSON.stringify(data, null, 2) + '\n';
  if (format !== 'markdown') throw new Error('Unsupported export format');
  const lines = ['# Distill session audit', '', markdownText(data.scope || 'Retained observations; missing completion does not establish rejection.'), '', `Session: ${markdownText(data.session?.title || data.session?.id || 'Untitled')}`, ''];
  for (const command of data.commands || []) {
    const longest = Math.max(3, ...(command.command?.match(/`+/g) || []).map(v => v.length));
    const fence = '`'.repeat(longest + 1);
    lines.push(`## ${markdownText(command.severity || 'unknown')} · ${markdownText(command.status || 'No completion observed')}`, '', fence + 'sh', command.command || '', fence, '', markdownText(command.reason), '');
    for (const gap of command.coverageGaps || []) lines.push(`- ${markdownText(gap.code)}: ${markdownText(gap.message)}`);
    for (const feedback of command.feedback || []) lines.push(`- Feedback: ${markdownText(feedback.kind)}${feedback.note ? ` · ${markdownText(feedback.note)}` : ''}`);
    lines.push('');
  }
  if (data.truncated) lines.push('Export reached its retained-detail size limit.');
  return lines.join('\n') + '\n';
}
module.exports = { exportSession };
