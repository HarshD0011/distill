# Distill website

A responsive, dependency-free product website for Distill. It is plain HTML, CSS,
and JavaScript, with relative asset paths that work at a GitHub Pages project URL
such as `https://HarshD0011.github.io/distill/` or at a domain root.

## Preview

From the repository root:

```sh
python3 -m http.server 8000 --directory website --bind 127.0.0.1
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
- **Get extension** uses `vscode:extension/distill.distill-trace`, matching the
  extension manifest. The click asks the browser to open the extension in desktop
  VS Code. The browser controls its external-app confirmation and may remember a
  prior choice; the website does not create a fake confirmation dialog. Installing
  for new users requires the extension to be published under that Marketplace ID.
  The public Marketplace query returned no listing for this ID on 2026-11-07;
  publish the extension before promising Marketplace installs to new visitors.
  A VSIX installation guide remains available as a fallback.
  Official URL format: <https://code.visualstudio.com/docs/configure/command-line#_opening-vs-code-with-urls>.
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
node --check website/app.js
python3 website/validate.py
```

Keep the version text, captured examples, and setup instructions aligned with
the CLI when releasing. `analyze` and hook assessment do not execute commands;
the opt-in `run` gate is a separate feature.
