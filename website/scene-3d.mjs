const loadSceneModule = () => import('./graphite-scene.mjs?v=953ab1f91506');

/** Enhance the existing CSS disc only after the first WebGL frame succeeds. */
export async function mountGraphiteScene({
  windowRef = globalThis.window,
  documentRef = globalThis.document,
  loadScene = loadSceneModule,
  isCurrent = () => true
} = {}) {
  const host = documentRef?.querySelector('.journey-orbit');
  const stage = documentRef?.querySelector('.story-stage');
  const frame = documentRef?.querySelector('.story-frame');
  const journey = documentRef?.getElementById('command-journey');
  if (!host || !stage || !frame || !journey || !windowRef) return null;
  const motion = windowRef.matchMedia('(prefers-reduced-motion: reduce)');
  if (motion.matches || windowRef.navigator?.connection?.saveData) return null;

  const canvas = documentRef.createElement('canvas');
  canvas.setAttribute('aria-hidden', 'true');
  const contextOptions = { alpha: true, antialias: true, depth: true, stencil: false, powerPreference: 'low-power' };
  let context;
  try { context = canvas.getContext('webgl2', contextOptions); } catch { /* Keep CSS fallback. */ }
  if (!context) {
    host.dataset.scene3d = 'unsupported';
    return null;
  }

  const container = documentRef.createElement('div');
  container.className = 'graphite-scene';
  container.append(canvas);
  let module;
  let renderer;
  let model;
  let disposed = false;
  let ready = false;
  let looping = false;
  let lastFrame;
  let time = 0;
  let progress = Number(frame.style.getPropertyValue('--progress')) || 0;
  const pointer = { x: 0, y: 0 };
  const bounds = stage.getBoundingClientRect();
  let inView = bounds.bottom > 0 && bounds.top < windowRef.innerHeight;
  const cleanups = [];

  function listen(target, name, callback, options) {
    target.addEventListener(name, callback, options);
    cleanups.push(() => target.removeEventListener(name, callback, options));
  }

  function dispose(reason = 'fallback') {
    if (disposed) return;
    disposed = true;
    cleanups.splice(0).forEach(cleanup => cleanup());
    if (ready) host.classList.remove('is-3d-ready');
    if (ready || !host.classList.contains('is-3d-ready')) host.dataset.scene3d = reason;
    if (renderer) {
      renderer.setAnimationLoop(null);
      if (model) module.disposeGraphiteScene(model);
      renderer.dispose();
      renderer.forceContextLoss();
    } else context.getExtension('WEBGL_lose_context')?.loseContext();
    container.remove();
  }

  function resize() {
    if (disposed) return;
    const width = Math.max(1, container.clientWidth || host.clientWidth * 1.4);
    const height = Math.max(1, container.clientHeight || width);
    const mobile = windowRef.matchMedia('(max-width: 600px)').matches;
    renderer.setPixelRatio(Math.min(windowRef.devicePixelRatio || 1, mobile ? 1 : 1.5));
    renderer.setSize(width, height, false);
    model.camera.aspect = width / height;
    model.camera.updateProjectionMatrix();
  }

  function animate(timestamp) {
    if (disposed) return;
    if (lastFrame !== undefined && timestamp - lastFrame < 1000 / 30) return;
    const delta = lastFrame === undefined ? 0 : Math.min((timestamp - lastFrame) / 1000, .05);
    lastFrame = timestamp;
    time += delta;
    try {
      module.updateGraphiteScene(model, { time, delta, progress, pointer, phase: journey.dataset.phase });
      renderer.render(model.scene, model.camera);
    } catch { dispose('render-fallback'); }
  }

  function syncVisibility() {
    if (disposed) return;
    const visible = inView && !documentRef.hidden && !motion.matches && progress < .29;
    if (visible === looping) return;
    looping = visible;
    lastFrame = undefined;
    renderer.setAnimationLoop(visible ? animate : null);
  }

  try {
    module = await loadScene();
    if (!isCurrent() || motion.matches || documentRef.hidden) {
      dispose('deferred');
      return null;
    }
    renderer = new module.Engine.WebGLRenderer({ canvas, context, ...contextOptions });
    renderer.outputColorSpace = module.Engine.SRGBColorSpace;
    renderer.toneMapping = module.Engine.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.05;
    renderer.debug.onShaderError = () => { throw new Error('Graphite shader compilation failed'); };
    model = module.createGraphiteScene();
    host.append(container);
    resize();
    renderer.compile(model.scene, model.camera);
    renderer.render(model.scene, model.camera);
    host.classList.add('is-3d-ready');
    ready = true;
    host.dataset.scene3d = 'ready';

    if (windowRef.ResizeObserver) {
      const observer = new windowRef.ResizeObserver(resize);
      observer.observe(container);
      cleanups.push(() => observer.disconnect());
    } else listen(windowRef, 'resize', resize, { passive: true });
    if (windowRef.IntersectionObserver) {
      const observer = new windowRef.IntersectionObserver(entries => {
        inView = entries.some(entry => entry.isIntersecting);
        syncVisibility();
      });
      observer.observe(stage);
      cleanups.push(() => observer.disconnect());
    }
    if (windowRef.MutationObserver) {
      const observer = new windowRef.MutationObserver(() => {
        progress = Number(frame.style.getPropertyValue('--progress')) || 0;
        syncVisibility();
      });
      observer.observe(frame, { attributes: true, attributeFilter: ['style'] });
      cleanups.push(() => observer.disconnect());
    }
    if (windowRef.matchMedia('(hover: hover) and (pointer: fine)').matches) {
      listen(stage, 'pointermove', event => {
        const rect = stage.getBoundingClientRect();
        pointer.x = Math.max(-1, Math.min(1, (event.clientX - rect.left) / Math.max(rect.width, 1) * 2 - 1));
        pointer.y = Math.max(-1, Math.min(1, (event.clientY - rect.top) / Math.max(rect.height, 1) * 2 - 1));
      }, { passive: true });
      listen(stage, 'pointerleave', () => { pointer.x = 0; pointer.y = 0; });
    }
    listen(documentRef, 'visibilitychange', syncVisibility);
    const motionChanged = () => { if (motion.matches) dispose('reduced-motion'); };
    motion.addEventListener('change', motionChanged);
    cleanups.push(() => motion.removeEventListener('change', motionChanged));
    listen(canvas, 'webglcontextlost', () => dispose('context-fallback'));
    syncVisibility();
    return { dispose, get disposed() { return disposed; } };
  } catch {
    dispose('initialization-fallback');
    return null;
  }
}

// Module lifecycle also handles reduced-motion changes and back/forward cache.
export function bootGraphiteScene(windowRef = globalThis.window, documentRef = globalThis.document) {
  if (!windowRef || !documentRef) return;
  const motion = windowRef.matchMedia('(prefers-reduced-motion: reduce)');
  let instance;
  let generation = 0;
  async function start() {
    const current = ++generation;
    instance?.dispose('restarted');
    instance = undefined;
    if (motion.matches || documentRef.hidden) return;
    const next = await mountGraphiteScene({ windowRef, documentRef, isCurrent: () => current === generation });
    if (current !== generation) next?.dispose('stale');
    else instance = next;
  }
  motion.addEventListener('change', start);
  documentRef.addEventListener('visibilitychange', () => {
    if (!documentRef.hidden && (!instance || instance.disposed)) start();
  });
  windowRef.addEventListener('pagehide', () => { generation++; instance?.dispose('page-hidden'); instance = undefined; });
  windowRef.addEventListener('pageshow', event => { if (event.persisted) start(); });
  start();
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') bootGraphiteScene();
