"""Challenge current verdicts; candidates are analyzed, never executed.

The separate effect probes below use only disposable files, harmless printf,
and private in-memory tables. A nonzero exit means expectations did not match.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from verdict_audit import ROOT, phase


def effect_probes(fixture):
    env = {
        'PATH': '/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin',
        'HOME': str(fixture / 'home'), 'LANG': 'C',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
    }
    git, sqlite = shutil.which('git'), shutil.which('sqlite3')
    if not git or not sqlite:
        raise RuntimeError('Git and the SQLite CLI are required for effect probes')
    subprocess.run([git, 'init', '-q', str(fixture)], env=env, check=True, capture_output=True)
    checks = []
    compared = subprocess.run([git, 'diff', '--no-index', '.env', 'input.txt'], cwd=fixture, env=env, text=True, capture_output=True, timeout=5)
    assert compared.returncode == 1 and 'fake_sensitive_fixture=needle' in compared.stdout, compared
    checks.append({'name': 'git no-index reads explicit credential-path contents', 'passed': True})
    written = subprocess.run([git, 'diff', '--output=.env'], cwd=fixture, env=env, text=True, capture_output=True, timeout=5)
    assert written.returncode == 0 and (fixture / '.env').read_text() == '', written
    checks.append({'name': 'git output option truncates a credential-path fixture', 'passed': True})
    shell = subprocess.run([sqlite, ':memory:', '.shell printf distill-controlled-shell-probe'], cwd=fixture, env=env, text=True, capture_output=True, timeout=5)
    assert shell.returncode == 0 and shell.stdout == 'distill-controlled-shell-probe', shell
    checks.append({'name': 'SQLite .shell executes a controlled printf payload', 'passed': True})
    for predicate in ('true', '1=1'):
        sql = f'CREATE TABLE accounts(id); INSERT INTO accounts VALUES(1),(2),(3); DELETE FROM accounts WHERE {predicate}; SELECT COUNT(*) FROM accounts;'
        query = subprocess.run([sqlite, ':memory:', sql], cwd=fixture, env=env, text=True, capture_output=True, timeout=5)
        assert query.returncode == 0 and query.stdout == '0\n', query
        checks.append({'name': f'WHERE {predicate} deletes all three private in-memory fixture rows', 'passed': True})
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    cases = json.loads((ROOT / 'corpus/verdict-challenge-20261022.json').read_text())
    with tempfile.TemporaryDirectory(prefix='distill-verdict-challenge-', dir='/tmp') as directory:
        fixture = Path(directory).resolve()
        (fixture / 'home').mkdir()
        (fixture / 'input.txt').write_text('ordinary fixture\n')
        (fixture / '.env').write_text('fake_sensitive_fixture=needle\n')
        result = phase(args.binary.resolve(), cases, fixture)
        probes = effect_probes(fixture)
    report = {
        'date': '2026-10-22',
        'method': '32 targeted authored challenge expectations recorded before their first evaluation. All candidate commands were analyzed only. Separate effect probes used private disposable files, harmless printf, and private in-memory tables. This is not an unbiased accuracy estimate.',
        'expected': cases, 'installed': result, 'effect_probes': probes,
        'semantic_references': [
            'https://git-scm.com/docs/git-diff',
            'https://www.postgresql.org/docs/current/queries-with.html#QUERIES-WITH-MODIFYING',
            'https://www.postgresql.org/docs/current/app-psql.html',
            'https://www.sqlite.org/cli.html',
            'https://www.sqlite.org/loadext.html',
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'metrics': result['metrics'], 'effect_probes_passed': len(probes)}, indent=2))
    for expected, actual in zip(cases, result['cases']):
        if actual['issues']:
            print(f"{expected['name']}: expected {expected['impact']}; got {actual['impact'] or 'UNKNOWN'}; risk={actual['risk']}; decision={actual['decision']}")
    if result['metrics']['cases_with_discrepancy']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
