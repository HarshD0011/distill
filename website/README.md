# Distill website

A responsive, dependency-free product website for Distill. It is plain HTML, CSS,
and JavaScript, with relative asset paths that work at a GitHub Pages project URL
or at a domain root. Public URL: <https://harshd0011.github.io/distill/>.

## Preview

From the repository root:

```sh
make website-serve
```

Open <http://127.0.0.1:8000>. No installation or build is needed.

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

- Three recorded command examples, installation tabs with arrow-key support,
  copy buttons, mobile navigation, and native FAQ disclosures.
- A model support section covering OpenAI-compatible APIs, Anthropic Claude,
  and local servers through llama.cpp, vLLM, or compatible endpoints. It includes
  VS Code router setup and describes disabled-by-default routing, provider data
  sharing, opt-in script excerpts, and encrypted API key storage. The website
  itself does not connect to model providers or collect credentials.
- **Extension install guide** links to the public VSIX build and installation
  instructions. The Marketplace listing and release packages were unavailable
  when checked on 2026-11-09, so the site describes the source-build path.
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
