'use strict';
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const MAX_INDEX_BYTES = 4 * 1024 * 1024;
function cleanTitle(value) {
  return typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 240) : '';
}

// Read only Codex's small title index. Never open transcripts, history, or state DBs.
class SessionTitles {
  constructor(home = process.env.CODEX_HOME || path.join(os.homedir(), '.codex')) {
    this.file = path.join(home, 'session_index.jsonl');
    this.stamp = ''; this.checkedAt = 0; this.titles = new Map();
  }

  async refresh(wanted) {
    if (Date.now() - this.checkedAt < 1000) return;
    this.checkedAt = Date.now();
    let file;
    try {
      file = await fs.open(this.file, constants.O_RDONLY | (constants.O_NONBLOCK || 0));
      const stat = await file.stat();
      if (!stat.isFile()) return;
      const stamp = `${stat.ino}:${stat.mtimeMs}:${stat.size}:${[...wanted].sort().join(',')}`;
      if (stamp === this.stamp) return;
      const offset = Math.max(0, stat.size - MAX_INDEX_BYTES);
      const bytes = Buffer.alloc(Math.min(stat.size, MAX_INDEX_BYTES));
      const { bytesRead } = await file.read(bytes, 0, bytes.length, offset);
      const lines = bytes.subarray(0, bytesRead).toString('utf8').split('\n');
      if (offset) lines.shift(); // a tail read may start in the middle of a record
      const titles = new Map();
      for (const line of lines) {
        if (line.length > 16384) continue;
        try {
          const row = JSON.parse(line);
          const title = cleanTitle(row.thread_name);
          if (wanted.has(row.id) && title) {
            const updated = Date.parse(row.updated_at) || 0;
            const previous = titles.get(row.id);
            if (!previous || updated >= previous.updated) titles.set(row.id, { title, updated });
          }
        } catch {} // tolerate a partial append or unknown future record shapes
      }
      this.titles = titles; this.stamp = stamp;
    } catch (error) {
      if (error.code === 'ENOENT') { this.titles.clear(); this.stamp = ''; }
    } finally { await file?.close().catch(() => {}); }
  }

  async enrich(sessions) {
    await this.refresh(new Set(sessions.filter(session => session.source === 'codex').map(session => session.id)));
    return sessions.map(session => {
      const indexed = session.source === 'codex' ? this.titles.get(session.id)?.title : '';
      const supplied = cleanTitle(session.title);
      const date = new Date(session.startedAt ?? session.updatedAt).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
      return { ...session, title: indexed || supplied || `${session.source === 'codex' ? 'Codex' : 'Claude'} chat · ${date}` };
    });
  }

  clear() { this.titles.clear(); this.stamp = ''; this.checkedAt = 0; }
}

module.exports = { SessionTitles, cleanTitle };
