"""Explicit-consent local usage sampler. Mined entries are never gold labels."""
import argparse
import collections
import hashlib
import json
import re
import shlex
from pathlib import Path
from offline_common import private_write


def redact(text):
    text = re.sub(r'(?i)(https?://)[^\s/@:]+:[^\s/@]+@', r'\1[REDACTED]@', text)
    text = re.sub(r'(?i)((?:token|password|secret|api_key|authorization)\s*[=:]\s*)(?:"[^"\n]*"|\S+)', r'\1[REDACTED]', text)
    return re.sub(r'\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b', '[REDACTED]', text)


def commands(row):
    payload = row.get('payload', row)
    if payload.get('type') == 'function_call':
        try:
            args = json.loads(payload.get('arguments', '{}'))
            if isinstance(args.get('cmd') or args.get('command'), str):
                yield args.get('cmd') or args['command']
        except (ValueError, TypeError):
            return
    if payload.get('type') == 'custom_tool_call':
        # Only decode literal JSON strings; never evaluate surrounding JS.
        for match in re.finditer(r'(?:"cmd"|\bcmd|"command"|\bcommand)\s*:\s*("(?:\\.|[^"\\])*")', payload.get('input', '')):
            try:
                yield json.loads(match.group(1))
            except ValueError:
                continue
    for item in row.get('message', {}).get('content', []):
        if isinstance(item, dict) and item.get('type') == 'tool_use' and item.get('name') == 'Bash':
            command = item.get('input', {}).get('command')
            if isinstance(command, str):
                yield command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', type=Path, nargs='+')
    parser.add_argument('--allow-transcript-read', action='store_true', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    corpus = []
    counts = collections.Counter()
    for path in args.paths:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 32 * 1024 * 1024:
            parser.error('Each input must be an explicit regular transcript file of at most 32 MiB')
        group = hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:16]
        for line in path.read_text().splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            for command in commands(row):
                if len(command) > 65536 or len(corpus) >= 10000:
                    continue
                try:
                    words = shlex.split(command)
                    program = Path(words[0]).name if words else '<empty>'
                except ValueError:
                    program = '<unparsed>'
                counts[program] += 1
                corpus.append({'id': hashlib.sha256((group + command).encode()).hexdigest(), 'group': group, 'command': redact(command), 'context_required': True, 'reviewed': False, 'expected_severity': None, 'source': 'local_transcript', 'shell_metadata': 'not_inferred'})
    private_write(args.output, '\n'.join(json.dumps(v) for v in corpus) + '\n')
    print(json.dumps({'samples': len(corpus), 'programs': counts.most_common(100), 'scope': 'Usage frequencies; redaction is best effort; labels and context need independent review'}))


if __name__ == '__main__':
    main()
