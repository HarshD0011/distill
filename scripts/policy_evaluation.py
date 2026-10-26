"""Evaluate an independently labeled policy corpus. Candidate commands are never run."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def main(binary: str) -> None:
    binary = str(Path(binary).resolve())
    cases = json.loads((Path(__file__).resolve().parent.parent / "corpus/behavior-policy.json").read_text())
    failures = []
    wrong_impacts = unsafe_allows = unnecessary_reviews = 0
    with tempfile.TemporaryDirectory(prefix="distill-policy-evaluation-") as directory:
        root = Path(directory)
        config = root / "policy.toml"
        config.write_text('[policy]\nprotected_paths = ["/srv/production"]\n')
        env = dict(os.environ, HOME=str(root / "home"))
        for index, case in enumerate(cases):
            if "source" in case:
                source = root / f"case-{index}.{case['extension']}"
                source.write_text(case["source"])
                command = f"{case['tool']} {shlex.quote(str(source))} {case.get('arguments', '')}"
            else:
                command = case["command"]
            report = json.loads(subprocess.check_output([
                binary, "analyze", "--config", str(config), "--cwd", directory,
                "--command", command,
            ], env=env))
            if report["impact_severity"] != case["impact"]:
                wrong_impacts += 1
                failures.append(f"{case['name']}: impact expected {case['impact']}, got {report['impact_severity']}")
            allowed = report["decision"] == "allow"
            if case["review"] and allowed:
                unsafe_allows += 1
                failures.append(f"{case['name']}: review required but allowed")
            if not case["review"] and not allowed:
                unnecessary_reviews += 1
                failures.append(f"{case['name']}: expected allow but got {report['decision']}")
            if "effect" in case:
                matches = [behavior for behavior in report["behaviors"] if behavior["kind"] == case["effect"]]
                if not matches:
                    failures.append(f"{case['name']}: missing {case['effect']} behavior")
                if "target" in case and not any(behavior["target"] == case["target"] for behavior in matches):
                    failures.append(f"{case['name']}: incorrect target propagation")
            if any(behavior["kind"] == case.get("forbidden_effect") for behavior in report["behaviors"]):
                failures.append(f"{case['name']}: spurious {case['forbidden_effect']} behavior")
    print(f"policy evaluation: {len(cases)} cases; wrong impacts={wrong_impacts}; unsafe allows={unsafe_allows}; unnecessary reviews={unnecessary_reviews}")
    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: policy_evaluation.py <distill-binary>")
    main(sys.argv[1])
