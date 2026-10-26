"""Strict build-time validation for the authored capability catalog."""
import json
from pathlib import Path
import re
import sys


def validate(path):
    data = json.loads(Path(path).read_text())
    assert set(data) == {"version", "reviewed", "provenance", "commands"}
    assert data["version"] == 1 and data["reviewed"] is True
    assert isinstance(data["provenance"], str) and data["provenance"]
    for tool, entries in data["commands"].items():
        assert re.fullmatch(r"[a-z0-9][a-z0-9+_.-]*", tool)
        for entry in entries:
            assert set(entry) <= {"flag", "kind", "prefix"}
            assert re.fullmatch(r"--?[a-zA-Z][a-zA-Z0-9-]*", entry["flag"])
            assert entry["kind"] in {"exec", "unresolved", "file-read", "file-write", "net-send", "net-fetch", "priv", "persist"}
    print("Reviewed capability catalog validated")


def validate_arguments(path):
    data = json.loads(Path(path).read_text())
    assert set(data) == {'version', 'commands'} and data['version'] == 1
    for name, grammar in data['commands'].items():
        assert name and set(grammar) == {'options'}
        seen = set()
        for option in grammar['options']:
            assert set(option) <= {'names', 'role', 'forms', 'mode', 'last_wins', 'before_program', 'append', 'pipe'}
            assert option['role'] in {'flag', 'value', 'read', 'write', 'program', 'script'}
            assert option['names'] and len(option['names']) == len(set(option['names']))
            assert not (seen & set(option['names']))
            seen.update(option['names'])
            assert all(name.startswith('-') and len(name) > 1 for name in option['names'])
            assert all(form in {'separate', 'equals', 'attached'} for form in option.get('forms', []))
            assert (option['role'] == 'flag') == (not option.get('forms'))
            for key in ('last_wins', 'before_program', 'append', 'pipe'):
                assert isinstance(option.get(key, False), bool)
            assert not option.get('append') or option['role'] == 'write'
            assert not option.get('pipe') or option['role'] == 'write'
    print('Argument grammars validated; semantic roles contain no verdict fields')


def validate_languages(path):
    data = json.loads(Path(path).read_text())
    assert set(data) == {'version', 'functions', 'clients'} and data['version'] == 1
    kinds = {'native_load', 'file_read', 'file_write', 'shell', 'script'}
    for dialect, functions in data['functions'].items():
        assert dialect in {'sqlite', 'postgres', 'mysql'}
        for name, spec in functions.items():
            assert name and set(spec) == {'kind', 'argument'}
            assert spec['kind'] in kinds - {'shell', 'script'}
            assert type(spec['argument']) is int and 0 <= spec['argument'] <= 16
    for client, commands in data['clients'].items():
        assert client in {'sqlite3', 'psql'}
        for name, spec in commands.items():
            assert name.startswith(('.', '\\'))
            assert set(spec) <= {'kind', 'syntax', 'pipe'}
            assert spec['kind'] in kinds
            assert spec['syntax'] in {'rest', 'sqlite_join', 'sqlite_words', 'psql_path'}
            assert isinstance(spec.get('pipe', False), bool)
    print('Language capabilities validated; argument bindings contain no verdict fields')


if __name__ == "__main__":
    validate(sys.argv[1] if len(sys.argv) > 1 else "crates/distill-interp/rules/capabilities.json")
    if len(sys.argv) == 1:
        validate_arguments('crates/distill-interp/rules/arguments.json')
        validate_languages('crates/distill-interp/rules/languages.json')
