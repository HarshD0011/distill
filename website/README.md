# Distill website

A responsive, dependency-free product website for Distill. It is plain HTML, CSS,
and JavaScript, with relative asset paths that work at a GitHub Pages project URL
or at a domain root. Public URL: <https://harshd0011.github.io/distill/>.

## Preview

From the repository root:

```sh
make website-serve
```

Open <http://127.0.0.1:8000>. No installation or build is needed. Stylesheet, script, and favicon URLs carry
content hashes (`?v=…`) so a new deployment refreshes browser caches. Recompute
these hashes in `index.html` when the corresponding asset changes.

**Ink & Paper** is the fixed site palette, including without JavaScript. It uses
true black, crisp white, and neutral grays. The temporary theme selector has been
removed; warning colors stay distinct.

## Publish on GitHub Pages

1. Commit `website/` and `.github/workflows/pages.yml` to the repository's default
   branch. Existing application changes do not need to be included.
2. In GitHub, open **Settings → Pages → Build and deployment** and set **Source**
   to **GitHub Actions**.
3. In **Actions**, run **Deploy website to GitHub Pages**. Later pushes changing
   the website on `main`, `master`, or this checkout's `init` branch deploy
   automatically when that branch is the repository's default branch.
4. The deployment job reports the published URL. For a different default branch,
   update the workflow's `push.branches` list, or use its manual dispatch.

The workflow validates pull requests without deploying them. It deploys only
from the default branch, requests Pages/OIDC permissions only in the deployment
job, and uploads only `website/`, not the Rust repository.

For a dedicated `<username>.github.io` repository, put the contents of this
directory at the repository root, and change the workflow's artifact path to
`.` and validation paths accordingly. No custom domain is configured.

Official reference:
<https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages>

## Content and interactions

- On an ordinary arrival at the top of the page, the original chrome `distill.`
  wordmark plays on black, following `logo.mp4`. Three overlapping gradient layers
  turn, stretch, and change direction independently across the letters. Sharp
  light folds alternate with a soft haze whose blur and intensity breathe through
  the animation. The silhouette stays sharp. The light motion keeps its original
  5.8-second pace; after 2.2 seconds, it starts shrinking into the real header
  wordmark over 0.75 seconds as the site fades into view. The intro lasts
  2.95 seconds total, capped at 3 seconds by the fail-open watchdog. Highlight
  opacity fades independently during the handoff so the slow animation can end
  smoothly before its full cycle completes. The command animation starts afterward.
  The finish uses CSS gradients and a measured Web Animations transform, with
  no new dependencies. Skip intro and Escape reveal the site immediately.
  Reduced motion, anchor links, history returns, unsupported animation APIs,
  and disabled JavaScript open the site directly. A three-second fail-open
  watchdog protects access if initialization fails. `logo-intro.css` contains
  the finish and reveal styles; resizing during the handoff ends it cleanly.
- A dark opening shows an AI agent proposing a command. The command types in,
  shakes and turns red, then a warning appears. Scrolling contracts the scene
  into a rounded frame with a monochrome backdrop and carries the command panel down
  into a light section, following the supplied `inspiration.mp4` reference.
  The sequence can be replayed. Reduced-motion preferences show the final
  warning without animation or a pinned scroll section; without JavaScript,
  the opening still displays the command and warning. Scene styles live in
  `story.css`; timing and scroll progress are handled in `app.js`.
  The command scene sits on a lighter graphite disc with defined concentric
  edges and a soft halo, carrying the reference's glow into the monochrome
  palette. The static backdrop stays visible with reduced motion enabled.
  Depth is limited to small CSS perspective tilts: up to 1.8 degrees during
  desktop scrolling, one degree on panel entry, and two degrees on verdict/tab
  changes. There is no WebGL scene or Three.js dependency. Reduced-motion users
  keep the static presentation.
- The rest of the page continues the opening's Ink & Paper palette
  in rounded chapters. Panels enter in stages as they reach the viewport; the
  surrounding color follows the active chapter. Verdict changes, installation
  tabs, FAQ answers, and copy notifications use the same motion language.
  `palette.css` defines the neutral Ink & Paper scale for surfaces, text, borders,
  and accents. `journey.css` contains the shared chapter and panel styles. Intersection
  observers reveal each panel once; reduced motion and missing observer support
  keep all content visible. A desktop chapter rail tracks the current section.
- Three recorded command examples, installation tabs with arrow-key support,
  copy buttons, mobile navigation, and native FAQ disclosures.
- The **AI-assisted review** demo switch keeps the currently selected command.
  Safe and critical examples retain their static verdicts when toggled. For the
  unknown-script example, advice changes the displayed severity from **Unknown**
  to **High**; turning it off restores **Unknown**. The illustrative
  AI rating refers to the displayed production deployment script context; it is
  not a captured or live model response. Coverage stays opaque and the policy
  decision remains review.
- A model support section covering OpenAI-compatible APIs, Anthropic Claude,
  and local servers through llama.cpp, vLLM, or compatible endpoints. It includes
  VS Code router setup and describes disabled-by-default routing, provider data
  sharing, opt-in script excerpts, and encrypted API key storage. The website
  itself does not connect to model providers or collect credentials.
- A model-cost note recommends a small, capable model for high-volume command
  review. The maintainer reports a real-world GPT-6 Luna test of 1,000 requests for
  $0.15 USD. The page shows the request count and total spend without a redundant
  normalized-cost metric. These are observed costs, not a quoted API tariff. The official
  model page is linked for context. Sub-second responses are reported as observed
  cases, not a universal latency guarantee; checked-in live samples also include
  slower replies. The speed summary reflects compact severity-only prompts,
  bounded context, matching-result caching and deduplication, reusable provider
  connections, and background model work in the current service implementation.
  The request count and total spend count up once when the statistics enter the
  viewport, easing to their final values over roughly 2.3 seconds. Reduced motion,
  missing observer support, and disabled JavaScript show final values immediately;
  screen readers receive stable final figures throughout the animation. The
  observed latency bound remains static.
- **Extension install guide** links to the public VSIX build and installation
  instructions. The Marketplace listing and release packages were unavailable
  when checked on 2026-11-09, so the site describes the source-build path.
- The installation section and editor FAQ list macOS and Windows as supported,
  with Linux coming soon pending runtime testing, following the maintainer's
  release status. Native critical-command approval dialogs remain macOS-only;
  the FAQ states that other platforms retain their denial fallback. This website
  copy update does not perform new platform runtime testing.
- Examples are actual CLI 0.4.6 reports recorded on macOS with explicit Bash
  context and `/tmp` as the working directory. The page does not execute or
  analyze user-supplied commands. See `assets/example-reports.json` for their
  selected source fields. Policy and environment affect real verdicts.
- Installation and capability copy comes from the repository's root and
  extension READMEs and the CLI subcommand definitions. Links use the actual
  Git remote (`HarshD0011/distill`), rather than the stale Cargo repository URL.
- No external fonts, libraries, analytics, runtime network requests, or cookies.
- The existing Distill extension SVG mark is reused for the wordmark and favicon.

Check after changes:

```sh
make website-check
make website-check-links
python3 website/validate.py --online --base-url https://harshd0011.github.io/distill/
```

The default check is offline and runs in the Pages workflow. The online check
verifies public HTTP destinations and linked documentation anchors. With
`--base-url`, it also verifies deployed assets and compares the served HTML to
the local source. Run the deployment check after Pages has finished publishing.
These checks require Python 3.9+ and Node.js; they do not require Rust or Cargo.

Keep the version text, captured examples, and setup instructions aligned with
the CLI when releasing. `analyze` and hook assessment do not execute commands;
the opt-in `run` gate is a separate feature.
