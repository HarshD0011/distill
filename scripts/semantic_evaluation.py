"""Recheck the semantic design's fixed expectation corpora; never run candidates."""
import argparse
import json
from pathlib import Path
import tempfile
from verdict_audit import ROOT, phase


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--before', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    suites = {
        'regression': 'corpus/verdict-audit.json',
        'challenge': 'corpus/verdict-challenge-20261022.json',
        'generalization': 'corpus/semantic-generalization.json',
    }
    report = {'method': 'Targeted authored regression, challenge and variation expectations. Candidate commands were analyzed only; no accuracy estimate is inferred. Counts across suites can overlap.',
              'candidate_execution': False, 'suites': {}}
    failures = 0
    with tempfile.TemporaryDirectory(prefix='distill-semantic-evaluation-', dir='/tmp') as directory:
        fixture = Path(directory)
        (fixture / 'home').mkdir()
        (fixture / 'input.txt').write_text('needle\nsecond\nthird\n')
        (fixture / '.env').write_text('fake_sensitive_fixture=needle\n')
        (fixture / 'input.sql').write_text('DELETE FROM orders;\n')
        for name, filename in suites.items():
            cases = json.loads((ROOT / filename).read_text())
            result = {'expectations': filename}
            if args.before:
                result['before'] = phase(args.before.resolve(), cases, fixture)
            result['after'] = phase(args.binary.resolve(), cases, fixture)
            report['suites'][name] = result
            failures += result['after']['metrics']['cases_with_discrepancy']
            print(name, json.dumps(result['after']['metrics']))
            for case in result['after']['cases']:
                if case['issues']:
                    print(json.dumps(case))
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    if failures:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
