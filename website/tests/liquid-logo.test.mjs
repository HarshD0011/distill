import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { buildDistanceField, createLiquidLogo } from '../liquid-logo.mjs';

test('distance field matches brute-force nearest contours, including antialiased edges', () => {
  const width = 7, height = 5, range = 8;
  const alpha = Uint8Array.from([
    0,0,0,0,0,0,0,
    0,60,180,255,180,60,0,
    0,180,255,255,255,180,0,
    0,60,180,255,180,60,0,
    0,0,0,0,0,0,0
  ]);
  const pixels = buildDistanceField(alpha, width, height, range);
  for (let index = 0; index < alpha.length; index++) {
    const x = index % width, y = Math.floor(index / width);
    let inside = 1e12, outside = 1e12;
    for (let point = 0; point < alpha.length; point++) {
      const coverage = alpha[point] / 255;
      const squared = (x - point % width) ** 2 + (y - Math.floor(point / width)) ** 2;
      inside = Math.min(inside, squared + (coverage === 1 ? 1e12 : Math.max(0, coverage - .5) ** 2));
      outside = Math.min(outside, squared + (coverage === 0 ? 1e12 : Math.max(0, .5 - coverage) ** 2));
    }
    const expected = Math.round(255 * Math.max(0, Math.min(1, .5 + (Math.sqrt(inside) - Math.sqrt(outside)) / (range * 2))));
    assert.equal(pixels[index * 4], expected);
    assert.equal(pixels[index * 4 + 3], 255);
  }
  assert.ok(pixels[(2 * width + 3) * 4] > pixels[0]);
});

test('empty/full masks are finite and invalid sizes fail early', () => {
  for (const [value, expected] of [[0,0],[255,255]]) {
    const pixels = buildDistanceField(new Uint8Array(16).fill(value), 4, 4);
    for (let index = 0; index < 16; index++) assert.equal(pixels[index * 4], expected);
  }
  assert.throws(() => buildDistanceField(new Uint8Array(2), 3, 3), /Invalid text mask/);
  assert.throws(() => buildDistanceField(new Uint8Array(1), 1, 1, 0), /Invalid text mask/);
});

const previousDocument = globalThis.document;
const previousStyle = globalThis.getComputedStyle;
after(() => {
  if (previousDocument === undefined) delete globalThis.document; else globalThis.document = previousDocument;
  if (previousStyle === undefined) delete globalThis.getComputedStyle; else globalThis.getComputedStyle = previousStyle;
});

function setup({ initialFailure = false, renderFailure = false } = {}) {
  const frames = new Map(), canvases = [], classes = new Set();
  let time = 0, nextFrame = 1, errors = 0;
  const word = {
    dataset:{ word:'distill.' },
    classList:{ add(value) { classes.add(value); }, remove(value) { classes.delete(value); } },
    getBoundingClientRect() { return { width:84, height:32 }; },
    append(canvas) { canvas.parent = this; }
  };
  globalThis.getComputedStyle = () => ({ fontSize:'32px', fontWeight:'750', fontFamily:'Arial', letterSpacing:'-1.664px' });
  globalThis.document = { createElement() {
    const listeners = new Map();
    const canvas = { style:{}, setAttribute() {}, remove() { this.removed = true; },
      addEventListener(type, listener) { listeners.set(type, listener); },
      removeEventListener(type) { listeners.delete(type); },
      lose() { listeners.get('webglcontextlost')?.({ preventDefault() {} }); },
      getContext() { return {
        letterSpacing:'0px', measureText() { return { width:160, fontBoundingBoxAscent:58, fontBoundingBoxDescent:14 }; }, fillText() {},
        getImageData() {
          const data = new Uint8ClampedArray(canvas.width * canvas.height * 4);
          for (let y = 10; y < canvas.height - 10; y++) for (let x = 10; x < canvas.width - 10; x++) data[(y * canvas.width + x) * 4 + 3] = 255;
          return { data };
        }
      }; }
    };
    canvases.push(canvas);
    return canvas;
  } };
  const renderer = { debug:{}, renders:0, disposed:0, lost:0,
    setPixelRatio(ratio) { this.ratio = ratio; }, setSize(width, height) { this.size = [width,height]; }, setClearColor() {},
    render(scene) {
      this.renders++;
      this.mesh = scene.children[0];
      if (renderFailure && this.renders > 1) throw new Error('Lost GPU');
    },
    dispose() { this.disposed++; }, forceContextLoss() { this.lost++; }
  };
  const options = {
    rendererFactory(settings) { assert.equal(settings.powerPreference, 'low-power'); if (initialFailure) throw new Error('No WebGL'); return renderer; },
    now:() => time,
    requestFrame(callback) { const id = nextFrame++; frames.set(id, callback); return id; },
    cancelFrame(id) { frames.delete(id); }, onError() { errors++; }
  };
  return { word, options, renderer, classes, frames, canvases,
    get errors() { return errors; },
    tick(timestamp) { time = timestamp; const callbacks = [...frames.values()]; frames.clear(); callbacks.forEach(callback => callback(timestamp)); }
  };
}

test('renders one letter plane, uses elapsed time, morphs continuously, then releases the GPU', () => {
  const site = setup();
  const controller = createLiquidLogo(site.word, site.options);
  assert.equal(site.classes.has('has-glass'), true);
  assert.equal(site.frames.size, 1);
  assert.ok(site.renderer.ratio <= 1.75);
  const { geometry, material } = site.renderer.mesh;
  const texture = material.uniforms.uShape.value;
  let releases = 0;
  for (const resource of [geometry,material,texture]) resource.addEventListener('dispose', () => { releases++; });
  site.tick(450);
  assert.equal(material.uniforms.uTime.value, .45);
  controller.dock();
  site.tick(1125);
  assert.equal(material.uniforms.uDock.value, .5);
  site.tick(2300);
  assert.equal(material.uniforms.uDock.value, 1);
  controller.dispose(); controller.dispose();
  assert.equal(releases, 3);
  assert.equal(site.renderer.disposed, 1);
  assert.equal(site.renderer.lost, 1);
  assert.equal(site.frames.size, 0);
  assert.equal(site.classes.has('has-glass'), false);
  assert.equal(site.canvases[0].removed, true);
});

test('GPU failure and context loss restore the fallback and stop rendering', () => {
  const failing = setup({ initialFailure:true });
  assert.throws(() => createLiquidLogo(failing.word, failing.options), /No WebGL/);
  assert.equal(failing.classes.has('has-glass'), false);
  assert.equal(failing.canvases[0].removed, true);
  const runtime = setup({ renderFailure:true });
  createLiquidLogo(runtime.word, runtime.options);
  runtime.tick(16);
  assert.equal(runtime.errors, 1);
  assert.equal(runtime.frames.size, 0);
  assert.equal(runtime.renderer.disposed, 1);
  assert.equal(runtime.classes.has('has-glass'), false);
  const lost = setup();
  createLiquidLogo(lost.word, lost.options);
  lost.canvases[0].lose();
  assert.equal(lost.errors, 1);
  assert.equal(lost.renderer.disposed, 1);
  assert.equal(lost.frames.size, 0);
});
