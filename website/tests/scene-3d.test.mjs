import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import * as sceneModule from '../graphite-scene.mjs';
import { mountGraphiteScene } from '../scene-3d.mjs';

class Element extends EventTarget {
  constructor() {
    super();
    this.children = [];
    this.dataset = { phase: 'arriving' };
    this.clientWidth = this.clientHeight = 700;
    const classes = new Set();
    this.classList = { add: name => classes.add(name), remove: name => classes.delete(name), contains: name => classes.has(name) };
    const styles = new Map();
    this.style = { setProperty: (name, value) => styles.set(name, value), getPropertyValue: name => styles.get(name) || '' };
  }
  setAttribute() {}
  append(child) { this.children.push(child); child.parent = this; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); }
  getBoundingClientRect() { return { top: 0, bottom: 900, left: 0, width: 1400, height: 900 }; }
}

function environment({ reduced = false, mobile = false, webgl = true, saveData = false, failCompile = false } = {}) {
  const host = new Element();
  const stage = new Element();
  const frame = new Element();
  const journey = new Element();
  const doc = new EventTarget();
  const win = new EventTarget();
  const motion = new EventTarget();
  motion.matches = reduced;
  const observations = { resize: [], intersection: [], mutation: [] };
  const stats = { contextRequests: 0, contextsLost: 0, loads: 0, renderers: [] };
  const context = { getExtension: () => ({ loseContext: () => stats.contextsLost++ }) };
  let canvas;
  doc.hidden = false;
  doc.querySelector = selector => ({ '.journey-orbit': host, '.story-stage': stage, '.story-frame': frame }[selector]);
  doc.getElementById = () => journey;
  doc.createElement = tag => {
    const element = new Element();
    if (tag === 'canvas') {
      canvas = element;
      element.getContext = type => { assert.equal(type, 'webgl2'); stats.contextRequests++; return webgl ? context : null; };
    }
    return element;
  };
  win.innerHeight = 900;
  win.devicePixelRatio = 3;
  win.navigator = { connection: { saveData } };
  win.matchMedia = query => query.includes('reduced-motion') ? motion : { matches: query.includes('max-width') ? mobile : true };
  for (const [name, key] of [['ResizeObserver', 'resize'], ['IntersectionObserver', 'intersection'], ['MutationObserver', 'mutation']]) {
    win[name] = class {
      constructor(callback) { this.callback = callback; observations[key].push(this); }
      observe(target) { this.target = target; }
      disconnect() { this.disconnected = true; }
    };
  }
  class Renderer {
    constructor(options) { this.options = options; this.debug = {}; this.renders = 0; stats.renderers.push(this); }
    setPixelRatio(value) { this.pixelRatio = value; }
    setSize(width, height) { this.width = width; this.height = height; }
    compile() { if (failCompile) this.debug.onShaderError(); }
    render() { this.renders++; }
    setAnimationLoop(callback) { this.loop = callback; }
    dispose() { this.disposed = true; }
    forceContextLoss() { stats.contextsLost++; }
  }
  const loadScene = async () => {
    stats.loads++;
    return { ...sceneModule, Engine: { ...sceneModule.Engine, WebGLRenderer: Renderer } };
  };
  return { host, stage, frame, journey, doc, win, motion, observations, stats, loadScene,
    get canvas() { return canvas; },
    options: { windowRef: win, documentRef: doc, loadScene } };
}

test('the tested runtime and vendor files are pinned exactly to stable r180', async () => {
  assert.equal(sceneModule.Engine.REVISION, '180');
  const manifest = JSON.parse(await readFile(new URL('../vendor/three-0.180.0/manifest.json', import.meta.url)));
  const lock = JSON.parse(await readFile(new URL('../dependencies/package-lock.json', import.meta.url)));
  assert.equal(manifest.version, '0.180.0');
  assert.equal(lock.packages[''].dependencies.three, '0.180.0');
  assert.equal(lock.packages['node_modules/three'].integrity, manifest.npm_integrity);
  for (const [name, expected] of Object.entries(manifest.sha256)) {
    const bytes = await readFile(new URL('../vendor/three-0.180.0/' + name, import.meta.url));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), expected);
  }
});

test('real Three.js geometries, transforms, and materials remain finite and monochrome', () => {
  const model = sceneModule.createGraphiteScene();
  for (const phase of ['arriving', 'typing', 'checking', 'danger', 'blocked']) {
    sceneModule.updateGraphiteScene(model, { time: 2, delta: 1 / 30, progress: .2, pointer: { x: .8, y: -.6 }, phase });
    model.scene.updateMatrixWorld(true);
    model.scene.traverse(object => {
      assert.ok(object.matrixWorld.elements.every(Number.isFinite));
      if (object.geometry) {
        assert.ok(object.geometry.attributes.position.array.every(Number.isFinite));
        object.geometry.computeBoundingSphere();
        assert.ok(Number.isFinite(object.geometry.boundingSphere.radius));
      }
      if (object.material?.color) {
        assert.equal(object.material.color.r, object.material.color.g);
        assert.equal(object.material.color.g, object.material.color.b);
      }
    });
  }
  assert.equal(model.markers.count, 6);
  assert.ok(model.markers.instanceMatrix.array.every(Number.isFinite));
  assert.notEqual(model.rig.rotation.y, .12);
  sceneModule.disposeGraphiteScene(model);
});

test('shared geometry and materials are disposed once', () => {
  const model = sceneModule.createGraphiteScene();
  const resources = new Set();
  model.scene.traverse(object => {
    if (object.geometry) resources.add(object.geometry);
    if (object.material) resources.add(object.material);
  });
  let disposals = 0;
  resources.forEach(resource => resource.addEventListener('dispose', () => disposals++));
  sceneModule.disposeGraphiteScene(model);
  sceneModule.disposeGraphiteScene(model);
  assert.equal(disposals, resources.size);
  assert.equal(model.scene.children.length, 0);
});

test('unsupported WebGL, reduced motion, and data saving retain CSS without loading Three.js', async () => {
  for (const settings of [{ webgl: false }, { reduced: true }, { saveData: true }]) {
    const env = environment(settings);
    assert.equal(await mountGraphiteScene(env.options), null);
    assert.equal(env.stats.loads, 0);
    assert.equal(env.host.classList.contains('is-3d-ready'), false);
  }
});

test('successful rendering is capped, pauses offscreen/hidden, and resumes on return', async () => {
  const env = environment();
  const instance = await mountGraphiteScene(env.options);
  const renderer = env.stats.renderers[0];
  assert.equal(env.host.classList.contains('is-3d-ready'), true);
  assert.equal(renderer.pixelRatio, 1.5);
  assert.equal(renderer.options.powerPreference, 'low-power');
  const initial = renderer.renders;
  for (const time of [0, 16, 34, 48, 68]) renderer.loop(time);
  assert.equal(renderer.renders - initial, 3);
  env.doc.hidden = true;
  env.doc.dispatchEvent(new Event('visibilitychange'));
  assert.equal(renderer.loop, null);
  env.doc.hidden = false;
  env.doc.dispatchEvent(new Event('visibilitychange'));
  assert.equal(typeof renderer.loop, 'function');
  env.frame.style.setProperty('--progress', '.4');
  env.observations.mutation[0].callback();
  assert.equal(renderer.loop, null);
  env.frame.style.setProperty('--progress', '.05');
  env.observations.mutation[0].callback();
  assert.equal(typeof renderer.loop, 'function');
  env.observations.intersection[0].callback([{ isIntersecting: false }]);
  assert.equal(renderer.loop, null);
  env.observations.intersection[0].callback([{ isIntersecting: true }]);
  assert.equal(typeof renderer.loop, 'function');
  instance.dispose();
  assert.equal(renderer.loop, null);
  assert.equal(renderer.disposed, true);
  assert.equal(env.host.classList.contains('is-3d-ready'), false);
  assert.equal(env.host.children.length, 0);
  assert.ok(Object.values(env.observations).flat().every(observer => observer.disconnected));
});

test('mobile rendering uses native 1x resolution and context loss restores CSS', async () => {
  const env = environment({ mobile: true });
  const instance = await mountGraphiteScene(env.options);
  assert.equal(env.stats.renderers[0].pixelRatio, 1);
  env.canvas.dispatchEvent(new Event('webglcontextlost'));
  assert.equal(instance.disposed, true);
  assert.equal(env.host.dataset.scene3d, 'context-fallback');
  assert.equal(env.host.classList.contains('is-3d-ready'), false);
});

test('shader errors and an obsolete async load never replace the CSS backdrop', async () => {
  for (const settings of [{ failCompile: true }, {}]) {
    const env = environment(settings);
    const options = settings.failCompile ? env.options : { ...env.options, isCurrent: () => false };
    assert.equal(await mountGraphiteScene(options), null);
    assert.equal(env.host.classList.contains('is-3d-ready'), false);
    assert.equal(env.host.children.length, 0);
    assert.equal(env.stats.contextsLost, 1);
  }
});

test('enabling reduced motion releases the running renderer', async () => {
  const env = environment();
  const instance = await mountGraphiteScene(env.options);
  env.motion.matches = true;
  env.motion.dispatchEvent(new Event('change'));
  assert.equal(instance.disposed, true);
  assert.equal(env.stats.renderers[0].loop, null);
  assert.equal(env.host.classList.contains('is-3d-ready'), false);
});
