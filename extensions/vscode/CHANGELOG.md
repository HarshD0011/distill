# Changelog

## 0.5.14

- Treat shared home roots and complete user-home directories as protected deletion targets across Python, shell and Node analysis, including `/home` when it is not the current user's home.
- Preserve bounded project deletions and component boundaries. Cache home-root aliases within each analysis, and advance the behavior-policy version so prior assessments cannot be reused under the new classification.

## 0.5.13

- Share an explicit effect rubric across Decisions and text severity reviews, distinguishing printed text, secret reads, bounded downloads and downloaded code execution.
- Version the review prompts and bind background cache entries to that revision. Static uncertainty and approval requirements remain unchanged.
- Add frozen command corpora and an analysis-only live evaluator for comparing prompt revisions without executing candidate commands.

## 0.5.12

- Add an API mode dropdown to LLM settings with opt-in OpenAI Decisions for GPT-6 Luna severity classifications. Keep existing provider behavior as the default.
- Disable inapplicable Decisions controls, preserve chat/provider drafts, and clarify the None reasoning option. Saved keys remain bound to the selected endpoint.
- Match typed answers by name, reject refused or malformed batches, and retain all static coverage and approval requirements. No automatic retries or fallback model calls are added.

## 0.5.11

- Ask once before connecting Distill to Codex and existing Claude Code installations. Choosing Not Now leaves user hook files untouched; Connect User Hooks retries setup.
- Name generated handlers “Distill for Codex” or “Distill for Claude Code” so the agent can identify the service during trust review. Preserve safety, permission, and completion events while consolidating duplicate Distill handlers for each event.
- Package the verified CLI and optional service using the official VS Code packager, with Marketplace README and license assets. No separate tool download is required.
- Update bundled SQLite to a patched release and refresh the pinned packager dependencies, including the minimatch security override.
