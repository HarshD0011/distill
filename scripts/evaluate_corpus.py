"""Nonexecuting replay against independently reviewed JSONL expectations.

Expected fields: id, command, cwd, shell, expected_severity, reviewed, split,
group. Unreviewed/mined entries are excluded from accuracy denominators.
"""
import argparse
import json
import subprocess
import tempfile
import tomllib
from pathlib import Path
from offline_common import private_write

LEVELS = {'safe': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def features(report):
    return {
        'programs': sorted({n['program'] for n in report.get('graph', {}).get('nodes', []) if n.get('program')}),
        'gap_codes': sorted({g['code'] for g in report.get('coverage_gaps', [])}),
        'effect_kinds': sorted({b['kind'] for b in report.get('behaviors', [])}),
    }


def evaluate(binary, entries, policy):
    results = []
    with tempfile.TemporaryDirectory(prefix='distill-evaluation-') as temporary:
        config = Path(temporary) / 'policy.toml'
        config.write_text(policy + '\n[judge]\nenabled=false\n[service]\nhistory_enabled=false\n[ledger]\nenabled=false\n')
        for entry in entries:
            if not entry.get('reviewed') or entry.get('expected_severity') not in LEVELS:
                continue
            cwd = Path(entry.get('cwd', temporary)).resolve()
            if not cwd.is_dir():
                raise ValueError(f"Missing context fixture for {entry.get('id')}")
            result = subprocess.run([str(binary), 'analyze', '--stdin', '--cwd', str(cwd), '--shell', entry.get('shell', 'bash'), '--config', str(config)], input=entry['command'], capture_output=True, text=True, timeout=8, check=True)
            report = json.loads(result.stdout)
            results.append({**entry, 'report': report, 'features': features(report)})
    return results


def metrics(results):
    critical = [r for r in results if r['expected_severity'] == 'critical']
    high = [r for r in results if LEVELS[r['expected_severity']] >= 3]
    benign = [r for r in results if r.get('expected_decision') == 'allow']
    return {
        'reviewed_samples': len(results),
        'static_accounted': sum(r['report']['coverage']['summary'] == 'static_accounted' for r in results),
        'critical_denominator': len(critical),
        'critical_policy_misses': [r['id'] for r in critical if r['report']['severity'] != 'critical'],
        'high_denominator': len(high),
        'dangerous_false_allows': [r['id'] for r in high if r['report']['decision'] == 'allow'],
        'benign_allow_denominator': len(benign),
        'unexpected_asks': [r['id'] for r in benign if r['report']['decision'] != 'allow'],
        'scope': 'Fixed reviewed fixtures and policy only; not general detection accuracy',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', type=Path)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/distill'))
    parser.add_argument('--policy', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--check', action='store_true', help='Fail for critical policy misses or dangerous false allows in this reviewed set')
    args = parser.parse_args()
    entries = [json.loads(line) for line in args.corpus.read_text().splitlines() if line.strip()]
    if len(entries) > 10000:
        parser.error('Corpus exceeds 10,000-entry replay limit')
    policy = args.policy.read_text() if args.policy else ''
    if set(tomllib.loads(policy)) - {'policy', 'override', 'analysis'}:
        parser.error('Offline replay policy may contain only policy, override and analysis tables; optional services are forced off')
    results = evaluate(args.binary.resolve(), entries, policy)
    private_write(args.output, json.dumps({'schema_version': 1, 'metrics': metrics(results), 'results': results}, indent=2) + '\n')
    print(json.dumps(metrics(results)))
    if args.check and (metrics(results)['critical_policy_misses'] or metrics(results)['dangerous_false_allows']):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
