'use strict';

function initLogoIntro() {
  const root = document.documentElement;
  const intro = document.getElementById('logo-intro');
  if (!intro || !root.classList.contains('intro-pending')) return Promise.resolve();

  return new Promise(resolve => {
    const word = intro.querySelector('.intro-word');
    const skip = intro.querySelector('.intro-skip');
    const destination = document.querySelector('.site-header .brand-name');
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
    const surfaces = [...document.querySelectorAll('.site-header,main,.site-footer,.chapter-rail,.skip-link')];
    const inertBefore = surfaces.map(element => element.inert);
    const previousFocus = document.activeElement;
    let finished = false;
    let docking = false;
    let sweepTimer;
    let handoffTimer;
    let flight;
    let glass;

    function finish() {
      if (finished) return;
      finished = true;
      clearTimeout(sweepTimer);
      clearTimeout(handoffTimer);
      flight?.cancel();
      intro.hidden = true;
      glass?.dispose();
      root.classList.remove('intro-pending', 'intro-revealing');
      surfaces.forEach((element, index) => { element.inert = inertBefore[index]; });
      skip.removeEventListener('click', finish);
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('resize', onResize);
      window.removeEventListener('pageshow', onPageShow);
      window.removeEventListener('distill:intro-failsafe', finish);
      motion.removeEventListener('change', onMotion);
      if (document.activeElement === skip) {
        const focusTarget = previousFocus && previousFocus !== document.body && previousFocus.isConnected
          ? previousFocus : destination.closest('a');
        focusTarget?.focus({ preventScroll:true });
      }
      resolve();
    }

    function onKey(event) {
      if (event.key === 'Escape') {
        event.preventDefault();
        finish();
      } else if (event.key === 'Tab') {
        event.preventDefault();
        skip.focus({ preventScroll:true });
      }
    }
    function onMotion() { if (motion.matches) finish(); }
    function onVisibility() { if (document.hidden) finish(); }
    function onResize() {
      if (docking) finish();
      else { glass?.dispose(); glass = null; }
    }
    function onPageShow(event) { if (event.persisted) finish(); }

    function dock() {
      if (finished) return;
      try {
        const from = word.getBoundingClientRect();
        const to = destination.getBoundingClientRect();
        if (!from.width || !from.height || !to.width || !to.height) {
          finish();
          return;
        }
        docking = true;
        glass?.dock();
        word.classList.add('is-docking');
        root.classList.add('intro-revealing');
        flight = word.animate([
          { transform:'translate3d(0,0,0) scale(1,1)' },
          { transform:`translate3d(${to.left - from.left}px,${to.top - from.top}px,0) scale(${to.width / from.width},${to.height / from.height})` }
        ], { duration:1400, easing:'cubic-bezier(.65,0,.35,1)', fill:'forwards' });
        flight.finished.then(finish, finish);
        handoffTimer = setTimeout(finish, 1550);
      } catch {
        finish();
      }
    }

    // Register recovery before making the rest of the page inert.
    window.addEventListener('distill:intro-failsafe', finish);
    skip.addEventListener('click', finish);
    document.addEventListener('keydown', onKey);
    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('resize', onResize);
    window.addEventListener('pageshow', onPageShow);
    motion.addEventListener('change', onMotion);
    if (motion.matches || document.hidden || typeof word.animate !== 'function' || !destination || window.scrollY > 8) {
      finish();
      return;
    }
    surfaces.forEach(element => { element.inert = true; });
    intro.hidden = false;
    intro.classList.add('is-playing');
    skip.focus({ preventScroll:true });
    sweepTimer = setTimeout(dock, 5800);
    import('./liquid-logo.mjs?v=721148bd0e2d').then(({ createLiquidLogo }) => {
      if (finished || docking) return;
      glass = createLiquidLogo(word);
    }).catch(() => {
      // Unsupported graphics and failed module loads retain the light CSS fallback.
    });
  });
}
const logoIntroFinished = initLogoIntro();

// A presentation only: command text is never evaluated or sent anywhere.
function initCommandStory() {
  const story = document.getElementById('command-story');
  story.classList.add('story-ready');
  const stage = story.querySelector('.story-stage');
  const frame = story.querySelector('.story-frame');
  const hero = story.querySelector('.story-hero');
  const chapter = story.querySelector('.story-chapter');
  const journey = document.getElementById('command-journey');
  const command = document.getElementById('typed-command');
  const activity = document.getElementById('agent-activity');
  const execution = document.getElementById('execution-label');
  const checkText = story.querySelector('.distill-check>span:nth-child(2)');
  const checkIndicator = story.querySelector('.check-loading');
  const replay = document.getElementById('replay-story');
  const step = document.getElementById('story-step');
  const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const narrow = window.matchMedia('(max-width: 820px)');
  const fullCommand = 'rm -rf /';
  const announcement = document.createElement('p');
  announcement.className = 'story-announcement';
  announcement.setAttribute('role', 'status');
  story.append(announcement);
  let timers = [];
  let pendingFrame = false;

  function clearSequence() {
    timers.forEach(clearTimeout);
    timers = [];
  }

  function phase(name) {
    journey.dataset.phase = name;
    activity.textContent = {
      idle: 'Preparing a tool call',
      arriving: 'Preparing a tool call',
      typing: 'Proposing a shell command',
      checking: 'Requesting execution',
      danger: 'Risk detected by Distill',
      blocked: 'Waiting for your decision'
    }[name];
    const blocked = name === 'blocked';
    execution.textContent = blocked || name === 'danger' ? 'Execution paused' : 'Not executed';
    checkText.textContent = blocked ? 'distill / critical impact · deny' : 'distill is checking this command';
    checkIndicator.textContent = blocked ? '↳' : '···';
    replay.disabled = !blocked;
    if (blocked) announcement.textContent = 'Distill: this command is not safe. Recursive deletion targets a protected path. Execution paused.';
  }

  function finishSequence() {
    clearSequence();
    command.textContent = fullCommand;
    phase('blocked');
  }

  function playSequence() {
    clearSequence();
    announcement.textContent = '';
    if (motion.matches) {
      finishSequence();
      return;
    }
    command.textContent = '';
    phase('arriving');
    timers.push(setTimeout(() => phase('typing'), 650));
    [...fullCommand].forEach((_, index) => {
      timers.push(setTimeout(() => {
        command.textContent = fullCommand.slice(0, index + 1);
      }, 850 + index * 120));
    });
    timers.push(setTimeout(() => phase('checking'), 1900));
    timers.push(setTimeout(() => phase('danger'), 2700));
    timers.push(setTimeout(finishSequence, 3350));
  }

  const clamp = value => Math.max(0, Math.min(1, value));
  const range = (value, start, end) => clamp((value - start) / (end - start));
  const ease = value => value * value * (3 - 2 * value);

  function renderScroll() {
    pendingFrame = false;
    if (motion.matches) {
      hero.inert = false;
      chapter.setAttribute('aria-hidden', 'true');
      frame.classList.remove('is-light');
      step.textContent = '03';
      return;
    }
    const bounds = story.getBoundingClientRect();
    const progress = clamp(-bounds.top / Math.max(1, story.offsetHeight - stage.offsetHeight));
    const shrink = ease(range(progress, 0, .28));
    const reveal = ease(range(progress, .18, .74));
    const fade = ease(range(progress, .07, .28));
    const resolution = ease(range(progress, .68, .9));
    frame.style.setProperty('--frame-scale', (1 - shrink * (narrow.matches ? .07 : .12)).toFixed(4));
    frame.style.setProperty('--frame-radius', `${shrink * 32}px`);
    frame.style.setProperty('--hero-opacity', (1 - fade).toFixed(3));
    frame.style.setProperty('--hero-y', `${-fade * 65}px`);
    frame.style.setProperty('--chapter-y', `${103 * (1 - reveal)}%`);
    frame.style.setProperty('--journey-y', `${ease(range(progress, .12, .8)) * (narrow.matches ? 24 : 48)}px`);
    frame.style.setProperty('--journey-scale', (1 - reveal * .025).toFixed(4));
    frame.style.setProperty('--journey-tilt', `${(narrow.matches ? 0 : -Math.sin(progress * Math.PI) * 1.8).toFixed(3)}deg`);
    frame.style.setProperty('--resolution-opacity', resolution.toFixed(3));
    frame.style.setProperty('--frame-label-opacity', ease(range(progress, .62, .82)).toFixed(3));
    frame.style.setProperty('--scroll-opacity', (1 - ease(range(progress, 0, .18))).toFixed(3));
    frame.style.setProperty('--progress', progress.toFixed(3));
    frame.classList.toggle('is-light', reveal > .7);
    hero.inert = fade > .95;
    chapter.setAttribute('aria-hidden', String(reveal < .65));
    step.textContent = progress < .25 ? '01' : progress < .7 ? '02' : '03';
    // Scrolling early still leaves a complete, readable verdict in the next scene.
    if (progress > .08 && journey.dataset.phase !== 'blocked') finishSequence();
  }

  function requestScrollFrame() {
    if (pendingFrame) return;
    pendingFrame = true;
    requestAnimationFrame(renderScroll);
  }

  replay.addEventListener('click', playSequence);
  window.addEventListener('scroll', requestScrollFrame, { passive: true });
  window.addEventListener('resize', requestScrollFrame);
  motion.addEventListener('change', () => {
    finishSequence();
    renderScroll();
  });
  if (document.documentElement.classList.contains('intro-pending')) {
    command.textContent = '';
    phase('idle');
    logoIntroFinished.then(() => {
      playSequence();
      renderScroll();
    });
  } else {
    playSequence();
  }
  renderScroll();
}
initCommandStory();

const panelAnimations = new WeakMap();
function animatePanel(panel) {
  if (!panel.animate || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  panelAnimations.get(panel)?.cancel();
  panelAnimations.set(panel, panel.animate([
    { opacity: .8, transform: 'perspective(1200px) translateY(5px) rotateX(-2deg)' },
    { opacity: 1, transform: 'perspective(1200px) translateY(0) rotateX(0deg)' }
  ], { duration: 320, easing: 'cubic-bezier(.22,1,.36,1)' }));
}

// Examples are recorded CLI reports, not a browser implementation of the analyzer.
const examples = {
  safe: { command: 'echo hello', impact: 'Safe', decision: 'Allow', coverage: 'Accounted', risk: 'Safe', symbol: '✓', index: '01', reason: 'No modeled hazardous effect was found in the supported static semantics.' },
  critical: { command: 'rm -rf /', impact: 'Critical', decision: 'Deny', coverage: 'Accounted', risk: 'Critical', symbol: '×', index: '02', reason: 'Recursive delete targets a protected path, root, or home directory.' },
  unknown: { command: './deploy.sh', impact: 'Unknown', decision: 'Review', coverage: 'Opaque', risk: 'Medium', symbol: '?', index: '03', reason: 'Unknown command definition. The executable is not in a trusted macOS system location.' }
};

const inspector = document.querySelector('.inspector');
const exampleButtons = [...document.querySelectorAll('[data-example]')];
const aiReviewToggle = document.getElementById('ai-review-toggle');
// This is illustrative advice for the script context shown in the demo, not a live model response.
const illustrativeReview = { impact: 'High', risk: 'High', symbol: '!', reason: 'The example script deploys files to a production server. Its --delete option can remove remote files that are missing locally.' };
let selectedExample = 'safe';

function renderExample() {
  const previousTone = inspector.dataset.tone;
  const assisted = aiReviewToggle.checked && selectedExample === 'unknown';
  const example = assisted ? { ...examples.unknown, ...illustrativeReview } : examples[selectedExample];
  inspector.dataset.tone = assisted ? 'high' : selectedExample;
  exampleButtons.forEach(button => {
    const selected = button.dataset.example === selectedExample;
    button.classList.toggle('active', selected);
    button.setAttribute('aria-pressed', String(selected));
  });
  for (const [id, value] of Object.entries({ 'example-command': example.command, 'result-impact': example.impact, 'result-decision': example.decision, 'result-coverage': example.coverage, 'result-risk': example.risk, 'result-symbol': example.symbol, 'result-reason': example.reason })) {
    document.getElementById(id).textContent = value;
  }
  document.getElementById('result-label').textContent = assisted ? 'AI-ASSISTED SEVERITY' : 'MODELED IMPACT';
  document.getElementById('result-provenance').hidden = !assisted;
  const source = document.getElementById('review-source');
  source.hidden = !assisted;
  if (!assisted) source.open = false;
  document.getElementById('ai-review-state').textContent = aiReviewToggle.checked ? 'On' : 'Off';
  document.getElementById('ai-review-hint').textContent = assisted ? 'Illustrative advice. Static coverage stays visible.' :
    aiReviewToggle.checked ? 'AI advice is on. This command keeps its static verdict.' : 'Optional illustrative advice for the selected command.';
  document.querySelector('.demo-index').textContent = `${example.index} / 03`;
  if (previousTone && previousTone !== inspector.dataset.tone) {
    animatePanel(document.getElementById('sample-result'));
  }
}

exampleButtons.forEach(button => {
  button.addEventListener('click', () => {
    if (!examples[button.dataset.example]) return;
    selectedExample = button.dataset.example;
    renderExample();
  });
});
aiReviewToggle.addEventListener('change', () => {
  renderExample();
});
renderExample();

const tabs = [...document.querySelectorAll('[role="tab"]')];
function selectTab(tab, focus = false) {
  tabs.forEach(item => {
    const selected = item === tab;
    item.setAttribute('aria-selected', String(selected));
    item.tabIndex = selected ? 0 : -1;
    document.getElementById(item.getAttribute('aria-controls')).hidden = !selected;
  });
  animatePanel(document.getElementById(tab.getAttribute('aria-controls')));
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

function initPageJourney() {
  // Content stays visible when observers or JavaScript are unavailable.
  if (!window.IntersectionObserver) return;
  const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const targets = [...document.querySelectorAll([
    '.demo-section-copy', '.demo-wrap', '.section-intro', '.approach-row',
    '.workflow-heading>div', '.workflow-heading>p', '.trace-window',
    '.integration-list>article', '.models-heading>div', '.model-card',
    '.model-economics', '.model-setup', '.boundaries>div:first-child', '.boundary-grid>article',
    '.install-layout>div:first-child', '.install-panel',
    '.faq-section>div:first-child', '.faq-list>details'
  ].map(selector => `.chapter-shell ${selector}`).join(','))];
  let revealObserver;

  function setMotion() {
    revealObserver?.disconnect();
    if (motion.matches) {
      document.documentElement.classList.remove('motion-ready');
      targets.forEach(target => target.classList.add('is-revealed'));
      return;
    }
    revealObserver = new window.IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add('is-revealed');
        revealObserver.unobserve(entry.target);
      });
    }, { threshold: .08, rootMargin: '0px 0px -7% 0px' });
    targets.forEach((target, index) => {
      target.dataset.reveal = '';
      target.style.setProperty('--reveal-delay', `${index % 3 * 70}ms`);
      revealObserver.observe(target);
    });
    document.documentElement.classList.add('motion-ready');
  }
  setMotion();
  motion.addEventListener('change', setMotion);

  const scenes = [...document.querySelectorAll('[data-scene-theme]')];
  const railLinks = [...document.querySelectorAll('.chapter-rail a')];
  const visibleScenes = new Set();
  const sceneObserver = new window.IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) visibleScenes.add(entry.target);
      else visibleScenes.delete(entry.target);
    });
    const active = [...visibleScenes].sort((a, b) =>
      Math.abs(a.getBoundingClientRect().top) - Math.abs(b.getBoundingClientRect().top)
    )[0];
    document.body.classList.toggle('has-active-chapter', Boolean(active));
    scenes.forEach(scene => scene.classList.toggle('is-active', scene === active));
    if (active) document.body.dataset.sceneTheme = active.dataset.sceneTheme;
    railLinks.forEach(link => {
      if (active && link.getAttribute('href') === `#${active.dataset.sceneTarget}`) {
        link.setAttribute('aria-current', 'location');
      } else link.removeAttribute('aria-current');
    });
  }, { rootMargin: '-30% 0px -40% 0px', threshold: 0 });
  scenes.forEach(scene => sceneObserver.observe(scene));
}
initPageJourney();

function initReviewCounters() {
  const stats = document.querySelector('.model-test-stats');
  if (!stats || !window.IntersectionObserver) return;
  const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
  // Final figures are in the HTML for reduced motion, screen readers, and no JS.
  if (motion.matches) return;
  const counters = [...stats.querySelectorAll('[data-count-to]')].map(element => ({
    element,
    target: Number(element.dataset.countTo),
    decimals: Number(element.dataset.countDecimals)
  }));
  const duration = 2100;
  const stagger = 90;
  let started = false;
  let frameId = 0;
  let startedAt;

  function render(counter, progress) {
    const factor = 10 ** counter.decimals;
    // Floor intermediate values so the final cent is reached at the finish.
    const value = progress >= 1 ? counter.target :
      Math.floor(counter.target * (1 - (1 - progress) ** 3) * factor) / factor;
    counter.element.textContent = value.toFixed(counter.decimals);
  }

  function finish() {
    if (frameId) cancelAnimationFrame(frameId);
    frameId = 0;
    started = true;
    counters.forEach(counter => render(counter, 1));
    observer.disconnect();
  }

  function tick(timestamp) {
    if (startedAt === undefined) startedAt = timestamp;
    const elapsed = timestamp - startedAt;
    counters.forEach((counter, index) => {
      const progress = Math.max(0, Math.min(1, (elapsed - index * stagger) / duration));
      render(counter, progress);
    });
    if (elapsed < duration + (counters.length - 1) * stagger) {
      frameId = requestAnimationFrame(tick);
    } else finish();
  }

  const observer = new window.IntersectionObserver(entries => {
    if (started || !entries.some(entry => entry.isIntersecting && entry.intersectionRatio >= .55)) return;
    started = true;
    observer.disconnect();
    frameId = requestAnimationFrame(tick);
  }, { threshold: .55, rootMargin: '0px 0px -8% 0px' });
  counters.forEach(counter => render(counter, 0));
  observer.observe(stats);
  motion.addEventListener('change', () => {
    if (motion.matches) finish();
  });
}
initReviewCounters();

document.querySelectorAll('.faq-list details').forEach(details => {
  details.addEventListener('toggle', () => {
    if (details.open) animatePanel(details.querySelector('p'));
  });
});
