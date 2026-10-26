'use strict';
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.listeners = {}; this.value = ''; this._text = ''; }
  set textContent(text) { this._text = String(text); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(' '); }
  append(...children) { for (const child of children) { child.parent = this; this.children.push(child); } }
  replaceChildren(...children) { this._text = ''; this.children = []; this.append(...children); }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  dispatch(name) { this.listeners[name]?.({}); }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); }
}

function app(script = path.resolve(__dirname, '../../media/trace.js')) {
  const elements = new Map(['chat', 'search', 'commands', 'connection', 'count', 'empty', 'setup', 'clear'].map(id => [id, new Element('div')]));
  const messages = []; let receive;
  const context = vm.createContext({ document: { getElementById: id => elements.get(id), createElement: tag => new Element(tag) },
    window: { addEventListener: (_, listener) => { receive = listener; } }, acquireVsCodeApi: () => ({ postMessage: message => messages.push(JSON.parse(JSON.stringify(message))) }), setTimeout, clearTimeout });
  vm.runInContext(fs.readFileSync(script, 'utf8'), context);
  return { elements, messages, receive: data => receive({ data }) };
}

module.exports = { app };
