'use strict';
const { execFile } = require('node:child_process');

function fetchAdvice(binary, requestDigests) {
  return new Promise((resolve, reject) => {
    const child = execFile(binary, ['advice'], { timeout: 1500, maxBuffer: 2 * 1024 * 1024 }, (error, stdout) => {
      if (error) return reject(error);
      try { resolve(JSON.parse(stdout).results); } catch (error) { reject(error); }
    });
    child.stdin.on('error', () => {});
    child.stdin.end(JSON.stringify({ request_digests: requestDigests }));
  });
}
function advicePoller(store, binary, fetch = fetchAdvice) {
  let busy = false;
  let retryAt = 0;
  return async () => {
    if (busy || Date.now() < retryAt) return;
    const keys = store.pendingAdvice();
    if (!keys.length) return;
    busy = true;
    try { store.applyAdvice(await fetch(binary, keys)); }
    catch { retryAt = Date.now() + 5000; }
    finally { busy = false; }
  };
}
module.exports = { fetchAdvice, advicePoller };
