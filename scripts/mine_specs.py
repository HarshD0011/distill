"""Extract reviewable syntax drafts from saved --help/man text. Never invokes a tool or an LLM.

Capabilities must be annotated and reviewed by a person before inclusion in the embedded catalog.
An offline model may produce the same JSON schema; its output is subject to identical validation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9+_.-]*", args.tool):
        parser.error("tool must be a plain executable name")
    raw = args.source.read_bytes()
    if len(raw) > 1024 * 1024:
        parser.error("source exceeds 1 MiB")
    text = raw.decode("utf-8")
    flags = sorted(set(re.findall(r"(?<![\w-])--[a-zA-Z][a-zA-Z0-9-]*|(?<![\w-])-[a-zA-Z](?![a-zA-Z])", text)))
    args.output.write_text(json.dumps({"version": 1, "reviewed": False,
        "provenance": f"syntax-only extraction; source_sha256={hashlib.sha256(raw).hexdigest()}",
        "commands": {args.tool: [{"flag": flag, "kind": "unresolved"} for flag in flags]}}, indent=2) + "\n")
    print(f"Drafted {len(flags)} options. Review capabilities before merging into the shipped catalog.")


if __name__ == "__main__":
    main()
