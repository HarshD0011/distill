"""Explicit offline trace collection inside a preinstalled, pinned container.

Never mounts the project, credentials, container socket, or host filesystem.
An image with /usr/bin/strace, /bin/sh, timeout and head must already be present.
Observed syscalls cover one exercised path, not all possible program behavior.
"""
import argparse
import json
import re
import shlex
import subprocess
import uuid
from pathlib import Path
from offline_common import private_write


def docker_args(image, name, source):
    traced = shlex.quote(source + '\n')
    runner = f"timeout -k 1 5 /usr/bin/strace -f -s 256 -o /tmp/trace /bin/sh -c {shlex.quote('/bin/sh -c ' + traced + ' >/dev/null 2>&1')}; head -c 1048576 /tmp/trace"
    return ['docker', 'run', '--pull=never', '--rm', '--name', name, '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=256m', '--cpus=1', '--user=65534:65534', '--tmpfs=/work:rw,nosuid,nodev,size=32m,mode=1777', '--tmpfs=/tmp:rw,nosuid,nodev,size=32m,mode=1777', '--workdir=/work', image, '/bin/sh', '-c', runner]


def observed_effects(trace):
    effects = set()
    attempts = set()
    for line in trace.splitlines():
        match = re.search(r'\b(openat|open|unlinkat|unlink|rmdir|renameat|rename|connect|execve)\(', line)
        if not match:
            continue
        call = match.group(1)
        kind = 'file_delete' if call in {'unlink', 'unlinkat', 'rmdir'} else 'file_write' if call.startswith('rename') or (call.startswith('open') and re.search(r'O_WRONLY|O_RDWR|O_CREAT|O_TRUNC', line)) else 'connect' if call == 'connect' else 'execute' if call == 'execve' else 'file_read'
        attempts.add(kind)
        if re.search(r'= -1\b', line) is None and re.search(r'= \d+', line):
            effects.add(kind)
    return sorted(effects), sorted(attempts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', type=Path)
    parser.add_argument('--image', required=True)
    parser.add_argument('--execute-isolated', action='store_true', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}', args.image):
        parser.error('A preinstalled image pinned by SHA-256 is required')
    rows = [json.loads(line) for line in args.corpus.read_text().splitlines() if line.strip()]
    if len(rows) > 1000:
        parser.error('Trace corpus exceeds 1,000 entries')
    results = []
    for row in rows:
        if not row.get('reviewed') or not row.get('trace_allowed'):
            continue
        source = row['command']
        if len(source) > 16384:
            raise ValueError('Trace source exceeds limit')
        name = 'distill-trace-' + uuid.uuid4().hex
        try:
            result = subprocess.run(docker_args(args.image, name, source), capture_output=True, text=True, timeout=12, check=False)
            if not result.stdout or 'execve(' not in result.stdout:
                raise RuntimeError('Isolated trace unavailable; verify the pinned image and container tracing support')
            effects, attempts = observed_effects(result.stdout)
            results.append({'id': row['id'], 'image': args.image, 'observed_effects': effects, 'attempted_effects': attempts, 'reviewed': False, 'scope': 'One isolated execution path; not a complete safety label'})
        finally:
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
    private_write(args.output, '\n'.join(json.dumps(row) for row in results) + '\n')


if __name__ == '__main__':
    main()
