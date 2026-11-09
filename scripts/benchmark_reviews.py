"""Measure command analysis and review batching without executing candidates.

Default: real local IPC/HTTP with a deterministic mock, not model inference.
--live-config: use an already-running configured service; keys never leave it.
Outputs contain timings/configuration only, never credentials or source text.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import random
import socket
import statistics
import subprocess
import tempfile
import threading
import time
import tomllib
import uuid


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def rpc(endpoint_file, method, params):
    endpoint = json.loads(endpoint_file.read_text())
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(2)
        stream.connect(endpoint['socket'])
        stream.sendall(encoded({'v': 1, 'id': uuid.uuid4().hex, 'method': method, 'params': params, 'token': endpoint['token']}) + b'\n')
        data = b''
        while b'\n' not in data:
            chunk = stream.recv(8192)
            if not chunk or len(data) > 2097152:
                break
            data += chunk
    response = json.loads(data)
    if not response.get('ok'):
        raise RuntimeError('Service rejected benchmark request: ' + response.get('error', 'unknown error'))
    return response['result']


class Mock(http.server.BaseHTTPRequestHandler):
    calls = []
    lock = threading.Lock()
    active = 0
    peak = 0
    base_delay_ms = 120

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        request = json.loads(body)
        items = json.loads(request['messages'][1]['content'])
        compact = isinstance(items, list)
        # Synthetic input processing cost; explicitly not a provider estimate.
        delay = Mock.base_delay_ms / 1000 + len(body) / 1024 * 0.002
        content = ';'.join(['low'] * len(items)) if compact else json.dumps({'effects': [{'kind': 'file_read', 'target': '/tmp/fixture', 'recursive': False}], 'intent_match': 'unavailable', 'explanation': 'Deterministic local fixture.'})
        response = encoded({'choices': [{'finish_reason': 'stop', 'message': {'content': content}}]})
        with self.lock:
            self.calls.append({'input_bytes': len(body), 'output_bytes': len(response), 'synthetic_delay_ms': delay * 1000})
            Mock.active += 1
            Mock.peak = max(Mock.peak, Mock.active)
        try:
            time.sleep(delay)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(response)
        except BrokenPipeError:
            pass
        finally:
            with self.lock:
                Mock.active -= 1


def trial(endpoint, digest, cwd, count, gap, source_bytes, serial=False):
    keys, arrivals, submit = [], {}, []
    finished, advice = {}, {}
    started = time.perf_counter()

    def collect():
        result = rpc(endpoint, 'judge_results', {'model_policy_digest': digest, 'request_digests': keys})
        for value in result['results']:
            key = value['request_digest']
            if value['status'] != 'pending' and key not in finished:
                finished[key] = time.perf_counter()
                advice[key] = value
        if time.perf_counter() - started > 17:
            raise RuntimeError('Benchmark exceeded review deadline')
        time.sleep(0.005)

    for i in range(count):
        target = started + i * gap / 1000
        time.sleep(max(0, target - time.perf_counter()))
        command = 'node scripts/test.js # benchmark-' + uuid.uuid4().hex
        params = {'command': command, 'cwd': str(cwd), 'shell': 'bash', 'model_policy_digest': digest, 'coverage_gaps': [{'code': 'unresolved_program'}]}
        if source_bytes:
            prefix = "require('unmodeled_fixture'); //"
            source = prefix + 'x' * (source_bytes - len(prefix))
            params['scripts'] = [{'path': str(cwd / 'scripts/test.js'), 'source': source, 'sha256': hashlib.sha256(source.encode()).hexdigest()}]
        arrived = time.perf_counter()
        result = rpc(endpoint, 'judge_enqueue', params)
        submit.append((time.perf_counter() - arrived) * 1000)
        if 'request_digest' not in result:
            raise RuntimeError('Benchmark admission failed: ' + str(result.get('status')))
        keys.append(result['request_digest'])
        arrivals[keys[-1]] = arrived
        if serial:
            while len(finished) < len(keys):
                collect()
    while len(finished) < len(keys):
        collect()
    return {'commands': count, 'arrival_gap_ms': gap, 'script_bytes_per_command': source_bytes, 'submit_ms': submit,
            'advice_ms': [round((finished[key] - arrivals[key]) * 1000, 3) for key in keys],
            'service_advice_ms': [advice[key].get('elapsed_ms') for key in keys],
            'submission': 'serial' if serial else 'parallel',
            'completion_ms': round((max(finished.values()) - started) * 1000, 3),
            'statuses': [advice[key]['status'] for key in keys], 'cached': [advice[key].get('cached', False) for key in keys]}


def launch(root, binary, provider_url, review_format, window):
    policy = root / 'policy.toml'
    state = root / 'state'
    policy.write_text(f'[ledger]\nenabled=false\n[service]\ndirectory={json.dumps(str(state))}\nhistory_enabled=false\n[judge]\nenabled=true\nendpoint={json.dumps(provider_url)}\nmodel="mock-fixture"\napi_key_env=""\nreview_format="{review_format}"\nbatch_window_ms={window}\nsend_script_contents=true\nbackground_deadline_ms=5000\n')
    env = {'HOME': str(root), 'PATH': '/usr/bin:/bin'}
    digest = json.loads(subprocess.check_output([str(binary), 'doctor', '--config', str(policy), '--json'], env=env))['model_policy_digest']
    child = subprocess.Popen([str(binary.with_name('distill-service')), '--config', str(policy), '--credential-stdin'], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=(root / 'service-stderr.log').open('wb'), env=env)
    child.stdin.write(encoded({'provider': 'openai_compatible', 'endpoint': provider_url, 'api_key_env': '', 'key': None}))
    child.stdin.close()
    endpoint = state / 'endpoint.json'
    deadline = time.perf_counter() + 4
    while time.perf_counter() < deadline:
        if endpoint.exists():
            return child, endpoint, digest
        if child.poll() is not None:
            raise RuntimeError('Benchmark service exited')
        time.sleep(0.01)
    child.kill()
    child.wait()
    raise RuntimeError('Benchmark service did not start')


def static_bench(binary, root, repeats):
    policy = root / 'static.toml'
    policy.write_text('[ledger]\nenabled=false\n[judge]\nenabled=false\n')
    (root / 'scripts').mkdir()
    (root / 'scripts/test.js').write_text("require('unmodeled_fixture');\n")
    rows = []
    for command in ['echo hello', 'cat README.md', 'node scripts/test.js', 'rm -rf /']:
        samples, internal = [], []
        for _ in range(repeats):
            start = time.perf_counter()
            result = json.loads(subprocess.check_output([str(binary), 'analyze', '--command', command, '--config', str(policy), '--cwd', str(root), '--shell', '/bin/bash', '--workspace-root', str(root)]))
            samples.append((time.perf_counter() - start) * 1000)
            internal.append(result['timings_ms']['total'])
        rows.append({'command': command, 'samples': repeats, 'process_median_ms': round(statistics.median(samples), 3), 'process_p95_ms': round(sorted(samples)[int((len(samples)-1)*.95)], 3), 'analysis_median_ms': statistics.median(internal), 'coverage': result['coverage']['summary'], 'approval_risk': result['severity']})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/distill'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=3)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--live-config', type=Path, help='Use the existing service without extracting its key, restarting it, or changing its settings')
    mode.add_argument('--parallel', action='store_true', help='Compare serial versus up-to-five parallel requests with batching disabled')
    parser.add_argument('--commands', type=int, choices=[1, 2, 4, 5], default=1, help='Commands per live trial')
    parser.add_argument('--arrival-gap-ms', type=int, choices=[0, 100, 300], default=0)
    parser.add_argument('--script-bytes', type=int, choices=[0, 1024, 4096, 8192], default=0)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 20:
        parser.error('Repeats must be 1..20')
    binary = args.binary.resolve()
    rows = []
    if args.live_config:
        config = tomllib.loads(args.live_config.read_text())
        judge, service = config['judge'], config.get('service', {})
        if args.script_bytes and not judge.get('send_script_contents', False):
            parser.error('Live source-size tests require send_script_contents in the service policy')
        # The installed service may predate new optional fields. Use exactly its
        # serialized judge policy; do not ask it to loosen the policy binding.
        digest = hashlib.sha256(encoded([judge, service.get('classifier_path'), service.get('classifier_min_support', 20), service.get('classifier_min_probability', .99)])).hexdigest()
        endpoint = Path(service.get('directory', str(Path.home() / '.config/distill/service'))) / 'endpoint.json'
        for _ in range(args.repeats):
            row = trial(endpoint, digest, Path.cwd(), args.commands, args.arrival_gap_ms, args.script_bytes)
            row.update(review_format=judge.get('review_format', 'effects'), window_ms=judge.get('batch_window_ms', 0))
            rows.append(row)
        report = {'kind': 'live_existing_service', 'model': judge['model'], 'provider': judge['provider'], 'source_contents_enabled': judge.get('send_script_contents', False), 'limitations': 'Current configured route only; compare files from different configured formats/windows at identical model/effort. No candidate execution; cache misses required.', 'trials': rows}
    else:
        if args.parallel:
            Mock.base_delay_ms = 400
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Mock)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory(prefix='distill-bench-', dir='/tmp') as temporary:
                root = Path(temporary)
                static = static_bench(binary, root, 20)
                routes = [('effects', 0), ('severity', 0)] if args.parallel else [('effects', 0), ('severity', 0), ('severity', 50), ('severity', 100), ('severity', 500)]
                for review_format, window in routes:
                    child, endpoint, digest = launch(root, binary, f'http://127.0.0.1:{server.server_port}/v1/chat/completions', review_format, window)
                    cases = [(count, 0, size, serial) for count in [1, 2, 5] for size in [0, 8192] for serial in [True, False] for _ in range(args.repeats)] if args.parallel else [(count, gap, size, False) for count in [1, 2, 4] for gap in ([0] if count == 1 else [0, 100]) for size in [0, 8192] for _ in range(args.repeats)]
                    random.Random(42).shuffle(cases)
                    print(json.dumps({'review_format': review_format, 'window_ms': window}), flush=True)
                    try:
                        for count, gap, size, serial in cases:
                            with Mock.lock:
                                if Mock.active:
                                    raise RuntimeError('Previous fixture request has not finished')
                                Mock.peak = 0
                                before = len(Mock.calls)
                            try:
                                row = trial(endpoint, digest, root, count, gap, size, serial=serial)
                            except Exception as error:
                                raise RuntimeError(f'Case format={review_format} window={window} count={count} gap={gap} bytes={size} service_exit={child.poll()} stderr={(root / "service-stderr.log").read_text()[:1000]}') from error
                            calls = Mock.calls[before:]
                            row.update(review_format=review_format, window_ms=window, api_calls=len(calls), input_bytes=sum(v['input_bytes'] for v in calls), output_bytes=sum(v['output_bytes'] for v in calls), max_in_flight=Mock.peak)
                            if args.parallel and (row['statuses'] != ['advisory'] * count or len(calls) != count or Mock.peak != (1 if serial else count)):
                                raise RuntimeError('Parallel benchmark failed its response/count/overlap invariants')
                            rows.append(row)
                    finally:
                        rpc(endpoint, 'stop', {})
                        child.wait(timeout=3)
                report = {'kind': 'local_mock_parallel' if args.parallel else 'local_mock', 'model': 'deterministic fixture, no inference', 'mock_delay': f'{Mock.base_delay_ms} ms + 2 ms per KiB input; synthetic, not a provider estimate', 'repeats_per_case': args.repeats, 'static_commands': static, 'trials': rows, 'limitations': 'Pipeline compatibility, timings, concurrency, batching and payload sizes only. Does not measure model accuracy, token usage, billing, or real provider latency. Debug binaries; polling adds <= 5 ms and later submissions can delay observing earlier results.'}
        finally:
            server.shutdown()
            server.server_close()
    # Private output even if invoked outside the repository.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as file:
        json.dump(report, file, indent=2)
        file.write('\n')
    print(json.dumps({'kind': report['kind'], 'trials': len(rows), 'successful_reviews': sum(row['statuses'].count('advisory') for row in rows), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
