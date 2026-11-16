"""Evaluate labeled command reviews through an existing local service.

Candidate commands are data: they are never executed. Live mode uses the saved
service route and its internal credentials; it never exports a provider API key.
Use frozen JSONL labels and --expect-prompt for reproducible prompt comparisons.
Python 3.11+ is required.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from benchmark_reviews import rpc, encoded


def percentiles(values):
    values = sorted(values)
    if not values:
        return None
    return {'n': len(values), 'p50_ms': round(statistics.median(values), 3),
            'p95_ms': round(values[math.ceil(.95 * len(values)) - 1], 3),
            'min_ms': round(values[0], 3), 'max_ms': round(values[-1], 3)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, default=Path.home() / '.config/distill/hook-policy-v3-codex.toml')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=2)
    parser.add_argument('--limit', type=int)
    parser.add_argument('--corpus', type=Path, action='append', required=True)
    parser.add_argument('--expect-prompt')
    parser.add_argument('--static-only', action='store_true')
    parser.add_argument('--binary', type=Path, default=ROOT / 'target/release/distill')
    args = parser.parse_args()
    if not 1 <= args.repeats <= 5:
        parser.error('Repeats must be 1..5')
    config = tomllib.loads(args.config.read_text())
    judge, service = config['judge'], config.get('service', {})
    digest = hashlib.sha256(encoded([judge, service.get('classifier_path'), service.get('classifier_min_support', 20), service.get('classifier_min_probability', .99)])).hexdigest()
    endpoint = Path(service.get('directory', str(args.config.parent / 'service'))) / 'endpoint.json'
    hello = None if args.static_only else rpc(endpoint, 'hello', {})
    rows = [json.loads(line) for path in args.corpus for line in path.read_text().splitlines() if line.strip()][:args.limit]
    if not 1 <= len(rows) <= 64 or len({r['id'] for r in rows}) != len(rows):
        parser.error('Supply 1..64 uniquely named cases')
    levels = {'safe', 'low', 'medium', 'high', 'critical'}
    for row in rows:
        if row.get('expected_severity') not in levels or not row.get('accepted_model_severities') or not set(row['accepted_model_severities']) <= levels:
            parser.error('Each case needs a known expected severity and nonempty accepted labels')
    data = {'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'kind': 'live_existing_service' if hello else 'static_only',
            'service': hello, 'configuration': {k:v for k,v in judge.items() if k in ('enabled','provider','api_mode','model','endpoint','reasoning_effort','review_format','batch_window_ms','background_deadline_ms','send_script_contents')},
            'methodology': ['Only distill analyze and authenticated local-service RPCs run; candidate commands are data, never executed.',
                            'Expectations come from the supplied frozen JSONL corpus; accepted labels are not inferred from static or model output.',
                            'Exact labels reported separately from accepted-model-label checks; safe/low both accepted for benign seed cases.',
                            'Unique nonce outside the prompt forces cache misses without changing the model evidence.',
                            'Sequential live requests include network/provider time; polling interval is 10 ms; p95 is nearest rank.',
                            'No inspected script excerpts are supplied; inline code remains in the command. No API keys exported. Fixed synthetic set, not population accuracy.'],
            'results': []}

    def save():
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd,'w') as file:
            json.dump(data, file, indent=2)
            file.write('\n')

    with tempfile.TemporaryDirectory(prefix='distill-verdict-fixtures-', dir='/tmp') as directory:
        cwd = Path(directory)
        (cwd/'ordinary.txt').write_text('fixture\n')
        (cwd/'artifact.tmp').write_text('fixture\n')
        (cwd/'README.txt').write_text('fixture\n')
        (cwd/'notes.txt').write_text('fixture\n')
        (cwd/'cache-entry.tmp').write_text('fixture\n')
        (cwd/'.env').write_text('DISTILL_TEST_FIXTURE=synthetic\n')
        policy = cwd/'static.toml'
        policy.write_text('[judge]\nenabled=false\n[service]\nhistory_enabled=false\n[ledger]\nenabled=false\n')
        binary = args.binary.resolve()
        for entry in rows:
            static = []
            for repeat in range(3):
                start = time.perf_counter()
                result = subprocess.run([str(binary),'analyze','--stdin','--cwd',str(cwd),'--shell','bash','--config',str(policy)], input=entry['command'], text=True, capture_output=True, timeout=10, check=True)
                static.append({'wall_ms': round((time.perf_counter()-start)*1000,3), 'report': json.loads(result.stdout)})
            report = static[0]['report']
            row = {**entry, 'static': {'severity': report['severity'], 'impact_severity': report.get('impact_severity'), 'decision': report['decision'], 'coverage': report['coverage'], 'unknowns': report['unknowns'], 'wall_ms': [s['wall_ms'] for s in static], 'reported_total_ms': [s['report']['timings_ms']['total'] for s in static], 'exact_severity_match': report['severity']==entry['expected_severity'], 'exact_decision_match': report['decision']==entry['expected_decision']}, 'live': []}
            data['results'].append(row)
            save()
            if args.static_only:
                print(json.dumps({'id':entry['id'], 'static':row['static']['severity'], 'decision':row['static']['decision']}),flush=True)
                continue
            for repeat in range(args.repeats):
                payload = {'command': entry['command'], 'cwd': str(cwd), 'shell': 'bash', 'coverage_gaps': report['coverage_gaps'][:16], 'coverage_gaps_omitted': max(0,len(report['coverage_gaps'])-16), 'model_policy_digest': digest,
                           'source_review': {'sharing_enabled':judge.get('send_script_contents',False), 'inspected_files':len(report['inspected_files']), 'shared_files':0, 'omitted_files':len(report['inspected_files']), 'missing_source':any('source is unavailable' in s.lower() for s in report['unknowns'])},
                           'benchmark_nonce': uuid.uuid4().hex}
                start = time.perf_counter()
                value = rpc(endpoint,'judge_enqueue',payload)
                enqueue_ms = (time.perf_counter()-start)*1000
                key = value.get('request_digest')
                deadline = time.perf_counter()+max(12,judge.get('background_deadline_ms',5000)/1000+3)
                while value['status']=='pending' and time.perf_counter()<deadline:
                    time.sleep(.01)
                    value = rpc(endpoint,'judge_results',{'model_policy_digest':digest,'request_digests':[key]})['results'][0]
                live = {'repeat':repeat+1, 'enqueue_ms':round(enqueue_ms,3), 'wall_ms':round((time.perf_counter()-start)*1000,3), 'result':value,
                        'exact_severity_match':value.get('severity')==entry['expected_severity'], 'accepted_severity_match':value.get('severity') in entry['accepted_model_severities']}
                row['live'].append(live)
                save()
                print(json.dumps({'id':entry['id'], 'repeat':repeat+1, 'static':row['static']['severity'], 'decision':row['static']['decision'], 'model':value.get('severity'), 'status':value['status'], 'ms':live['wall_ms'], 'accepted':live['accepted_severity_match'], 'cached':value.get('cached',False)}),flush=True)
                if value['status']!='advisory':
                    raise RuntimeError('Live service review failed; see private output (no automatic retries).')
                if value.get('cached'):
                    raise RuntimeError('Unexpected cache hit invalidates cold latency measurements')
                if args.expect_prompt and value.get('prompt_version') != args.expect_prompt:
                    raise RuntimeError('Unexpected prompt revision; stop comparison')
                if repeat==0:
                    cache_start=time.perf_counter()
                    cached=rpc(endpoint,'judge_enqueue',payload)
                    row['cache_check']={'wall_ms':round((time.perf_counter()-cache_start)*1000,3),'cached':cached.get('cached',False),'same_severity':cached.get('severity')==value.get('severity')}
        data['summary'] = {
            'static_wall': percentiles([v for r in data['results'] for v in r['static']['wall_ms']]),
            'static_reported': percentiles([v for r in data['results'] for v in r['static']['reported_total_ms']]),
            'static_exact_severity': sum(r['static']['exact_severity_match'] for r in data['results']),
            'static_exact_decision': sum(r['static']['exact_decision_match'] for r in data['results']),
            'live_wall': percentiles([v['wall_ms'] for r in data['results'] for v in r['live']]),
            'live_enqueue': percentiles([v['enqueue_ms'] for r in data['results'] for v in r['live']]),
            'live_service': percentiles([v['result']['elapsed_ms'] for r in data['results'] for v in r['live'] if 'elapsed_ms' in v['result']]),
            'live_exact_labels': sum(v['exact_severity_match'] for r in data['results'] for v in r['live']),
            'live_accepted_labels': sum(v['accepted_severity_match'] for r in data['results'] for v in r['live']),
            'cache_wall': percentiles([r['cache_check']['wall_ms'] for r in data['results'] if 'cache_check' in r]),
            'static_dangerous_false_allows': [r['id'] for r in data['results'] if r['expected_severity'] in ('high','critical') and r['static']['decision']=='allow'],
            'static_critical_misses': [r['id'] for r in data['results'] if r['expected_severity']=='critical' and r['static']['severity']!='critical'],
            'unstable_cases': [r['id'] for r in data['results'] if len(set(v['result'].get('severity') for v in r['live']))>1],
        }
        save()
        print(json.dumps(data['summary']),flush=True)


if __name__ == '__main__':
    main()
