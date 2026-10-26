"""Compare authored semantic expectations; never execute the assessment corpus.

Only benign, fixed oracle probes run in a disposable fixture directory. Their
source is explicitly separate from the corpus containing hazardous commands.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LEVELS = ['safe', 'low', 'medium', 'high', 'critical']


def phase(binary, cases, fixture):
    env = dict(os.environ, HOME=str(fixture / 'home'), DISTILL_TRACE_DIR=str(fixture / 'no-recorder'))
    policy = fixture / 'policy.toml'
    policy.write_text('[ledger]\nenabled=false\n')
    rows = []
    for case in cases:
        output = subprocess.check_output([str(binary), 'analyze', '--config', str(policy), '--cwd', str(fixture), '--command', case['command']], env=env)
        report = json.loads(output)
        issues = []
        if report['impact_severity'] != case['impact']: issues.append('wrong_impact')
        allowed = report['decision'] == 'allow'
        if case['review'] and allowed: issues.append('unsafe_allow')
        if not case['review'] and not allowed: issues.append('unnecessary_review')
        if case.get('risk_min') and LEVELS.index(report['severity']) < LEVELS.index(case['risk_min']): issues.append('understated_risk')
        rows.append({'name':case['name'], 'impact':report['impact_severity'], 'risk':report['severity'], 'decision':report['decision'], 'coverage':report['coverage']['summary'], 'unknowns':report['unknowns'], 'issues':issues})
    metrics = {'cases':len(rows),'cases_with_discrepancy':sum(bool(row['issues']) for row in rows),'unknown':sum(row['impact'] is None for row in rows)}
    for kind in ['wrong_impact','unsafe_allow','unnecessary_review','understated_risk']: metrics[kind]=sum(kind in row['issues'] for row in rows)
    return {'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'metrics':metrics,'cases':rows}


def benign_oracle(fixture):
    env={'PATH':'/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin','HOME':str(fixture/'home'),'LANG':'C'}
    probes=[('legacy head count',['/usr/bin/head','-2','input.txt'],'needle\nsecond\n'),('legacy tail count',['/usr/bin/tail','-2','input.txt'],'second\nthird\n'),('sed print',['/usr/bin/sed','-n','1,2p','input.txt'],'needle\nsecond\n'),('metadata listing',['/bin/ls','.env'],'.env\n'),('literal braces',['/bin/bash','--noprofile','--norc','-c',"printf '%s\\n' -I{} '{literal}'"],'-I{}\n{literal}\n')]
    rg=shutil.which('rg')
    if rg: probes.append(('ripgrep ordinary content',[rg,'needle','input.txt'],'needle\n'))
    checks=[]
    for name,argv,expected in probes:
        completed=subprocess.run(argv,cwd=fixture,env=env,text=True,capture_output=True,timeout=5)
        assert completed.returncode==0 and completed.stdout==expected,(name,completed)
        checks.append({'name':name,'passed':True})
    if rg:
        provider=fixture/'provider.sh'
        provider.write_text('#!/bin/sh\nprintf invoked > helper-marker\nprintf fixture-host\\n\n')
        provider.chmod(0o700)
        marker=fixture/'helper-marker'
        completed=subprocess.run([rg,'--hostname-bin',str(provider),'--hyperlink-format','file://{host}{path}','needle','input.txt'],cwd=fixture,env=env,text=True,capture_output=True,timeout=5)
        assert completed.returncode==0 and marker.exists(),completed
        checks.append({'name':'hostname option invokes a controlled helper','passed':True})
        marker.unlink()
        completed=subprocess.run([rg,'--pre',str(provider)+' ignored','needle','input.txt'],cwd=fixture,env=env,text=True,capture_output=True,timeout=5)
        assert completed.returncode!=0 and not marker.exists(),completed
        checks.append({'name':'preprocessor option is an executable path, not shell text','passed':True})
    (fixture/'json.py').write_text("open('import-marker','w').write('imported')\n")
    python=shutil.which('python3')
    subprocess.run([python,'-c','import json'],cwd=fixture,env=env,check=True,timeout=5)
    assert (fixture/'import-marker').exists()
    checks.append({'name':'local import can execute code despite a print-only-looking caller','passed':True})
    return checks


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--before',type=Path,required=True);parser.add_argument('--after',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    cases=json.loads((ROOT/'corpus/verdict-audit.json').read_text())
    with tempfile.TemporaryDirectory(prefix='distill-semantic-audit-',dir='/tmp') as directory:
        fixture=Path(directory).resolve();(fixture/'home').mkdir();(fixture/'input.txt').write_text('needle\nsecond\nthird\n');(fixture/'.env').write_text('needle=fake-credential-fixture\n')
        before=phase(args.before.resolve(),cases,fixture);after=phase(args.after.resolve(),cases,fixture);oracle=benign_oracle(fixture)
    result={'date':'2026-10-22','method':'65 authored semantic/policy cases, independently stated expectations; candidate commands were analyzed only. Fixed benign oracle probes ran in a disposable directory. No database statements or hazardous commands were executed.','limitations':['Targeted regression corpus, selected after inspecting gaps; not an unbiased accuracy benchmark','Known impact and incomplete coverage are distinct','No full SQL, shell, or arbitrary-program soundness claim'], 'expected':cases,'before':before,'after':after,'benign_oracle':oracle}
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'before':before['metrics'],'after':after['metrics'],'benign_oracle_passed':len(oracle)},indent=2))
    if after['metrics']['cases_with_discrepancy']:raise SystemExit('Audit expectations failed')


if __name__=='__main__':main()
