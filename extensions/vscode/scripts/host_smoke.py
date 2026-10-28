"""Exercise the package and extension in an isolated desktop VS Code instance."""
import os
import json
import subprocess
import tempfile
import platform
import signal
from pathlib import Path

root = Path(__file__).resolve().parents[1]
code = os.environ.get("VSCODE_BIN", "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code")
with tempfile.TemporaryDirectory(prefix="distill-vscode-host-", dir="/tmp") as temporary:
    temporary = Path(temporary)
    workspace = temporary / "workspace"
    workspace.mkdir()
    common = ["--user-data-dir", str(temporary / "user"), "--extensions-dir", str(temporary / "extensions")]
    result_file = temporary / "result.txt"
    home = temporary / "home"
    home.mkdir(mode=0o700)
    codex_home = home / ".codex"
    codex_home.mkdir()
    (codex_home / "session_index.jsonl").write_text(json.dumps({"id": "extension-host-smoke", "thread_name": "Reload smoke chat", "updated_at": "2026-10-18T00:00:00Z"}) + "\n")
    settings = temporary / "user/User"
    settings.mkdir(parents=True)
    (settings / "settings.json").write_text('{}')
    environment = {**os.environ, "HOME": str(home), "CODEX_HOME": str(codex_home), "DISTILL_TRACE_DIR": str(temporary / "trace"), "DISTILL_HOST_TEST_RESULT": str(result_file)}
    environment.pop('DISTILL_TEST_BINARY', None)
    environment.pop('VSCODE_IPC_HOOK_CLI', None)
    version = json.loads((root / "package.json").read_text())["version"]
    arch = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'x64', 'amd64': 'x64'}[platform.machine().lower()]
    package = root / f"distill-trace-{version}-{platform.system().lower()}-{arch}.vsix"
    install = subprocess.run([code, *common, "--install-extension", str(package), "--force"], env=environment, text=True, capture_output=True, timeout=30)
    print(install.stdout, end="", flush=True)
    if install.returncode:
        raise SystemExit(install.stderr)
    installed = list((temporary / 'extensions').glob(f'distill.distill-trace-{version}*'))
    if len(installed) != 1:
        raise SystemExit('Could not identify the installed platform-specific extension')
    environment['DISTILL_HOST_TEST_EXTENSION'] = str(installed[0])
    # A tiny isolated driver extension activates again after a real window reload.
    # VS Code's --extensionTestsPath runner exits during reload and cannot test this.
    driver = temporary / "driver"
    driver.mkdir(parents=True)
    (driver / "package.json").write_text(json.dumps({"name": "lifecycle-driver", "publisher": "distill", "version": "0.0.1", "engines": {"vscode": "^1.95.0"}, "activationEvents": ["onStartupFinished"], "main": "driver.js"}))
    (driver / "driver.js").write_text("exports.activate = async () => { try { await require(" + json.dumps(str(root / "test/host")) + ").run(); } finally { await require('vscode').commands.executeCommand('workbench.action.quit'); } };\n")
    try:
        result = subprocess.run([
            code, *common, "--new-window", "--wait", "--verbose", "--disable-workspace-trust", "--skip-welcome", "--skip-release-notes",
            # Disposable profiles must not wait for a macOS keychain prompt.
            "--use-inmemory-secretstorage",
            "--extensionDevelopmentPath=" + str(driver), str(workspace),
        ], env=environment, text=True, capture_output=True, timeout=90)
    except subprocess.TimeoutExpired as error:
        if result_file.exists():
            print('Isolated host test result: ' + result_file.read_text(), flush=True)
        for label, output in [('stdout', error.stdout), ('stderr', error.stderr)]:
            if output:
                if isinstance(output, bytes): output = output.decode(errors='replace')
                print(f'{label}: {output[-6000:]}', flush=True)
        # Only the disposable profile belongs to this test. Never terminate the
        # user's existing editor process or a process selected just by its name.
        processes = subprocess.check_output(['/bin/ps', '-axo', 'pid=,command='], text=True)
        for line in processes.splitlines():
            if f'--user-data-dir {temporary / "user"}' in line and '/Contents/MacOS/Electron' in line:
                try: os.kill(int(line.split(None, 1)[0]), signal.SIGTERM)
                except ProcessLookupError: pass
        raise SystemExit('Isolated VS Code host test timed out; its test instance was stopped.')
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
