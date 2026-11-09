'use strict';

// Examples are recorded CLI reports, not a browser implementation of the analyzer.
const examples = {
  safe: { command: 'echo hello', impact: 'Safe', decision: 'Allow', coverage: 'Accounted', risk: 'Safe', symbol: '✓', index: '01', reason: 'No modeled hazardous effect was found in the supported static semantics.' },
  critical: { command: 'rm -rf /', impact: 'Critical', decision: 'Deny', coverage: 'Accounted', risk: 'Critical', symbol: '×', index: '02', reason: 'Recursive delete targets a protected path, root, or home directory.' },
  unknown: { command: './deploy.sh', impact: 'Unknown', decision: 'Review', coverage: 'Opaque', risk: 'Medium', symbol: '?', index: '03', reason: 'Unknown command definition. The executable is not in a trusted macOS system location.' }
};

const inspector = document.querySelector('.inspector');
document.querySelectorAll('[data-example]').forEach(button => {
  button.addEventListener('click', () => {
    const key = button.dataset.example;
    const example = examples[key];
    if (!example) return;
    inspector.dataset.tone = key;
    document.querySelectorAll('[data-example]').forEach(item => {
      const selected = item === button;
      item.classList.toggle('active', selected);
      item.setAttribute('aria-pressed', String(selected));
    });
    for (const [id, value] of Object.entries({ 'example-command': example.command, 'result-impact': example.impact, 'result-decision': example.decision, 'result-coverage': example.coverage, 'result-risk': example.risk, 'result-symbol': example.symbol, 'result-reason': example.reason })) {
      document.getElementById(id).textContent = value;
    }
    document.querySelector('.demo-index').textContent = `${example.index} / 03`;
  });
});

const tabs = [...document.querySelectorAll('[role="tab"]')];
function selectTab(tab, focus = false) {
  tabs.forEach(item => {
    const selected = item === tab;
    item.setAttribute('aria-selected', String(selected));
    item.tabIndex = selected ? 0 : -1;
    document.getElementById(item.getAttribute('aria-controls')).hidden = !selected;
  });
  if (focus) tab.focus();
}
tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectTab(tab));
  tab.addEventListener('keydown', event => {
    let next;
    if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = tabs.length - 1;
    if (next === undefined) return;
    event.preventDefault();
    selectTab(tabs[next], true);
  });
});

const menuToggle = document.querySelector('.menu-toggle');
const nav = document.getElementById('site-nav');
function closeMenu() {
  menuToggle.setAttribute('aria-expanded', 'false');
  nav.classList.remove('open');
}
menuToggle.addEventListener('click', () => {
  const open = menuToggle.getAttribute('aria-expanded') !== 'true';
  menuToggle.setAttribute('aria-expanded', String(open));
  nav.classList.toggle('open', open);
});
nav.querySelectorAll('a').forEach(link => link.addEventListener('click', closeMenu));
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && nav.classList.contains('open')) {
    closeMenu();
    menuToggle.focus();
  }
});

let toastTimer;
function notify(message) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.add('visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('visible'), 3000);
}
document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    const content = document.getElementById(button.dataset.copy);
    try {
      await navigator.clipboard.writeText(content.textContent);
      notify('Commands copied to clipboard');
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(content);
      selection.removeAllRanges();
      selection.addRange(range);
      notify('Select and copy the highlighted commands');
    }
  });
});
