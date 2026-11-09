#!/usr/bin/env python3
"""Check deployable static assets, links, and accessible control relationships."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit
import json

ROOT = Path(__file__).resolve().parent


class Document(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = []
        self.relationships = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if 'id' in attrs:
            if attrs['id'] in self.ids:
                self.errors.append(f"Duplicate ID: {attrs['id']}")
            self.ids.add(attrs['id'])
        for attr in ('href', 'src'):
            if attrs.get(attr):
                self.links.append(attrs[attr])
        for attr in ('aria-controls', 'aria-labelledby', 'data-copy'):
            if attrs.get(attr):
                self.relationships.extend(attrs[attr].split())


page = Document()
page.feed((ROOT / 'index.html').read_text())
for link in page.links:
    parts = urlsplit(link)
    if parts.scheme or parts.netloc:
        continue
    if parts.path:
        target = (ROOT / unquote(parts.path)).resolve()
        if not target.is_relative_to(ROOT) or not target.is_file():
            page.errors.append(f'Missing or escaping asset: {link}')
    if parts.fragment and not parts.path and unquote(parts.fragment) not in page.ids:
        page.errors.append(f'Missing anchor: {link}')
for identifier in page.relationships:
    if identifier not in page.ids:
        page.errors.append(f'Missing control target: {identifier}')
reports = json.loads((ROOT / 'assets/example-reports.json').read_text())
expected = {'safe': ('safe', 'allow'), 'critical': ('critical', 'deny'),
            'unknown': (None, 'ask')}
for name, (impact, decision) in expected.items():
    report = reports['examples'][name]
    if (report['impact_severity'], report['decision']) != (impact, decision):
        page.errors.append(f'Example report does not match its displayed behavior: {name}')
    if report['analysis_context']['shell'] != 'bash':
        page.errors.append(f'Unexpected shell in example: {name}')
if page.errors:
    raise SystemExit('\n'.join(page.errors))
print(f'Validated {len(page.ids)} IDs, {len(page.links)} links/assets, accessible control targets, and 3 captured CLI examples.')
