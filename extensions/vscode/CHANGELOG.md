# Changelog

## 0.5.11

- Ask once before connecting Distill to Codex and existing Claude Code installations. Choosing Not Now leaves user hook files untouched; Connect User Hooks retries setup.
- Name generated handlers “Distill for Codex” or “Distill for Claude Code” so the agent can identify the service during trust review. Preserve safety, permission, and completion events while consolidating duplicate Distill handlers for each event.
- Package the verified CLI and optional service using the official VS Code packager, with Marketplace README and license assets. No separate tool download is required.
- Update bundled SQLite to a patched release and refresh the pinned packager dependencies, including the minimatch security override.
