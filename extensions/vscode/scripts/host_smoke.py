"""Exercise the package and extension in an isolated desktop VS Code instance."""
import os
import json
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
code = os.environ.get("VSCODE_BIN", "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code")
with tempfile.TemporaryDirectory(prefix="distill-vscode-host-", dir="/tmp") as temporary:
    temporary = Path(temporary)
    workspace = temporary / "workspace"
    workspace.mkdir()
    common = ["--user-data-dir", str(temporary / "user"), "--extensions-dir", str(temporary / "extensions")]
    result_file = temporary / "result.txt"
    codex_home = temporary / "codex"
    codex_home.mkdir()
    (codex_home / "session_index.jsonl").write_text(json.dumps({"id": "extension-host-smoke", "thread_name": "Reload smoke chat", "updated_at": "2026-10-18T00:00:00Z"}) + "\n")
    binary = str(root.parents[1] / "target/debug/distill")
    settings = temporary / "user/User"
    settings.mkdir(parents=True)
    (settings / "settings.json").write_text(json.dumps({"distill.binaryPath": binary}))
    environment = {**os.environ, "DISTILL_TEST_BINARY": binary, "CODEX_HOME": str(codex_home), "DISTILL_TRACE_DIR": str(temporary / "trace"), "DISTILL_HOST_TEST_RESULT": str(result_file)}
    version = json.loads((root / "package.json").read_text())["version"]
    environment["DISTILL_HOST_TEST_EXTENSION"] = str(temporary / "extensions" / f"distill.distill-trace-{version}")
    package = root / f"distill-trace-{version}.vsix"
    install = subprocess.run([code, *common, "--install-extension", str(package), "--force"], env=environment, text=True, capture_output=True, timeout=30)
    print(install.stdout, end="", flush=True)
    if install.returncode:
        raise SystemExit(install.stderr)
    # A tiny isolated driver extension activates again after a real window reload.
    # VS Code's --extensionTestsPath runner exits during reload and cannot test this.
    driver = temporary / "driver"
    driver.mkdir(parents=True)
    (driver / "package.json").write_text(json.dumps({"name": "lifecycle-driver", "publisher": "distill", "version": "0.0.1", "engines": {"vscode": "^1.95.0"}, "activationEvents": ["onStartupFinished"], "main": "driver.js"}))
    (driver / "driver.js").write_text("exports.activate = async () => { try { await require(" + json.dumps(str(root / "test/host")) + ").run(); } finally { await require('vscode').commands.executeCommand('workbench.action.quit'); } };\n")
    result = subprocess.run([
        code, *common, "--new-window", "--wait", "--verbose", "--disable-workspace-trust", "--skip-welcome", "--skip-release-notes",
        "--extensionDevelopmentPath=" + str(driver), str(workspace),
    ], env=environment, text=True, capture_output=True, timeout=90)
    for line in result.stdout.splitlines():
        if "Distill extension-host smoke" in line:
            print(line, flush=True)
    if result.returncode:
        raise SystemExit(result.stderr[-4000:] or result.returncode)
    if not result_file.exists():
        raise SystemExit("VS Code exited without running the extension smoke test")
    if result_file.read_text() != "passed":
        raise SystemExit(result_file.read_text())
    # The test runner exits the application. Its broker must remove its endpoint.
    import time
    for _ in range(40):
        if not list((temporary / "trace").glob("*.json")):
            break
        time.sleep(0.05)
    if list((temporary / "trace").glob("*.json")):
        raise SystemExit("Trace broker endpoint remained after VS Code quit")
    print("VSIX installation and real VS Code quit cleanup passed.", flush=True)
