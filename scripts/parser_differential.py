"""Offline second-parser syntax comparison; candidate commands never execute."""
import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', type=Path)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/distill'))
    parser.add_argument('--bash', type=Path, default=Path('/bin/bash'))
    args = parser.parse_args()
    mismatches = []
    count = 0
    with tempfile.TemporaryDirectory(prefix='distill-parser-') as d:
        config = Path(d) / 'config.toml'
        config.write_text('[judge]\nenabled=false\n[service]\nhistory_enabled=false\n[ledger]\nenabled=false\n')
        for line in args.corpus.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get('shell', 'bash') != 'bash':
                continue
            source = row['command']
            # Empty environment removes BASH_ENV, exported functions and loaders.
            result = subprocess.run([str(args.bash), '--noprofile', '--norc', '-n'], input=source, capture_output=True, text=True, timeout=2, cwd=d, env={'PATH': '/usr/bin:/bin', 'HOME': d})
            report = json.loads(subprocess.run([str(args.binary.resolve()), 'analyze', '--stdin', '--cwd', d, '--config', str(config)], input=source, capture_output=True, text=True, timeout=8, check=True).stdout)
            count += 1
            if (result.returncode == 0) != bool(report.get('graph', {}).get('parse_complete')):
                mismatches.append({'id': row.get('id'), 'bash_accepts': result.returncode == 0, 'static_decision': report['decision'], 'static_coverage': report['coverage']['summary']})
    print(json.dumps({'cases': count, 'syntax_disagreements': mismatches, 'scope': 'Offline syntax oracle only; no equivalence proof or runtime safety claim'}))


if __name__ == '__main__':
    main()
