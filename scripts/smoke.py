"""Fixture checks for the local distill binary. Exits 0 on success."""

import json
import subprocess
import sys
import tempfile
import os
from pathlib import Path

TEST_CONFIG = None


def analyze(binary: str, command: str) -> dict:
    output = subprocess.check_output(
        [binary, "analyze", "--config", TEST_CONFIG, "--cwd", "/tmp", "--command", command]
    )
    return json.loads(output)


def hook(binary: str, host: str, path: str, mode: str = "strict", label: bool = False) -> dict:
    with open(path, "rb") as handle:
        payload = handle.read()
    args = [binary, "hook", host, "--no-prompt", "--mode", mode, "--config", TEST_CONFIG]
    if label:
        args.append("--label-command")
    output = subprocess.check_output(args, input=payload)
    return json.loads(output)


def permission(report: dict):
    return report.get("hookSpecificOutput", {}).get("permissionDecision")


def main() -> None:
    global TEST_CONFIG
    directory = tempfile.TemporaryDirectory(prefix="distill-smoke-")
    root = Path(directory.name)
    key = root / "key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    TEST_CONFIG = str(root / "config.toml")
    Path(TEST_CONFIG).write_text(f'[ledger]\nenabled=false\n[security]\nlabel_key_path="{key}"\n')
    binary = sys.argv[1]
    subprocess.check_call([binary, "config", "validate", "--path", "config.example.toml"])

    echo = analyze(binary, "echo hello")
    if echo["decision"] != "allow" or echo["severity"] != "safe":
        raise SystemExit(f"echo hello: {echo['severity']} {echo['decision']}")

    root = analyze(binary, "rm -rf /")
    if root["decision"] != "deny" or root["severity"] != "critical":
        raise SystemExit(f"rm -rf /: {root['severity']} {root['decision']}")

    checks = [
        ("claude", "corpus/hooks/pretooluse-echo.json", None),
        ("claude", "corpus/hooks/pretooluse-unknown.json", "ask"),
        ("codex", "corpus/hooks/pretooluse-unknown.json", "deny"),
        ("claude", "corpus/hooks/pretooluse-rm-root.json", "deny"),
        ("codex", "corpus/hooks/pretooluse-rm-root.json", "deny"),
    ]
    for host, path, expected in checks:
        got = permission(hook(binary, host, path))
        if got != expected:
            raise SystemExit(f"{host} {path}: expected {expected}, got {got}")

    approval = hook(
        binary, "codex", "corpus/hooks/permissionrequest-high.json", "advisory"
    )
    if "Severity: UNKNOWN" not in approval.get("systemMessage", "") or "Approval risk: HIGH" not in approval.get("systemMessage", ""):
        raise SystemExit("PermissionRequest hook response is missing separate unknown impact and HIGH approval risk")
    if "hookSpecificOutput" in approval:
        raise SystemExit("advisory approval must leave the native prompt in control")

    for host in ["codex", "claude"]:
        critical = hook(
            binary, host, "corpus/hooks/pretooluse-rm-root.json", "advisory"
        )
        if "Severity: CRITICAL" not in critical.get("systemMessage", ""):
            raise SystemExit(f"{host}: hook response is missing CRITICAL severity")
        if permission(critical) != "deny":
            raise SystemExit(f"{host}: critical verdict must block even in advisory mode")

    labeled = hook(binary, "codex", "corpus/hooks/pretooluse-echo.json", "advisory", label=True)
    rewrite = labeled.get("hookSpecificOutput", {})
    if rewrite.get("hookEventName") != "PreToolUse" or rewrite.get("permissionDecision") != "allow":
        raise SystemExit("command label must use the supported PreToolUse rewrite shape")
    label, _, body = rewrite.get("updatedInput", {}).get("command", "").partition("\n")
    if not label.startswith("# Distill severity: SAFE 🟢 | Analysis: modeled") or " | HMAC-SHA256: " not in label or body != "echo hello":
        raise SystemExit("command label rewrite is missing the computed severity comment")

    print("smoke ok")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: smoke.py <distill-binary>")
    main()
