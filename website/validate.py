#!/usr/bin/env python3
"""Check deployable static assets, links, and accessible control relationships."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urldefrag, urljoin, urlsplit
from urllib.request import Request, urlopen
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
import re

ROOT = Path(__file__).resolve().parent
VOID_ELEMENTS = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
                 'link', 'meta', 'param', 'source', 'track', 'wbr'}


class Document(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = []
        self.relationships = []
        self.errors = []
        self.open_tags = []

    def handle_starttag(self, tag, attrs):
        if tag not in VOID_ELEMENTS:
            self.open_tags.append(tag)
        attrs = dict(attrs)
        if 'id' in attrs:
            if attrs['id'] in self.ids:
                self.errors.append(f"Duplicate ID: {attrs['id']}")
            self.ids.add(attrs['id'])
        for attr in ('href', 'src'):
            if attrs.get(attr):
                self.links.append(attrs[attr])
        for attr in ('aria-controls', 'aria-labelledby', 'aria-describedby', 'data-copy'):
            if attrs.get(attr):
                self.relationships.extend(attrs[attr].split())

    def handle_endtag(self, tag):
        if not self.open_tags or self.open_tags[-1] != tag:
            self.errors.append(f'Misnested closing tag: </{tag}>')
        else:
            self.open_tags.pop()


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--online', action='store_true', help='also check public HTTP links and their anchors')
parser.add_argument('--base-url', help='also verify the deployed page and assets at this URL (requires --online)')
args = parser.parse_args()
if args.base_url and not args.online:
    parser.error('--base-url requires --online')
if args.base_url and (urlsplit(args.base_url).scheme not in ('http', 'https') or
                      not args.base_url.endswith('/')):
    parser.error('--base-url must be an HTTP(S) URL ending in /')

page = Document()
page.feed((ROOT / 'index.html').read_text())
page.close()
if page.open_tags:
    page.errors.append('Unclosed HTML elements: ' + ', '.join(page.open_tags))
for stylesheet in ROOT.glob('*.css'):
    for asset in re.findall(r'url\(\s*[\'\"]?([^\s\)\'\"]+)', stylesheet.read_text()):
        page.links.append(asset)
for link in page.links:
    parts = urlsplit(link)
    if parts.scheme or parts.netloc:
        if parts.scheme not in ('http', 'https', 'data'):
            page.errors.append(f'Unsupported public link scheme: {link}')
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

if args.online:
    destinations = {}
    for link in page.links:
        parts = urlsplit(link)
        if parts.scheme in ('http', 'https') or parts.netloc:
            destination = link if parts.scheme else 'https:' + link
        elif args.base_url and parts.path:
            destination = urljoin(args.base_url, link)
        else:
            continue
        url, fragment = urldefrag(destination)
        destinations.setdefault(url, set())
        if fragment:
            destinations[url].add(unquote(fragment))
    if args.base_url:
        destinations.setdefault(args.base_url, set())

    def check_destination(item):
        url, fragments = item
        try:
            request = Request(url, headers={'User-Agent': 'Distill-Website-Link-Check/1.0'})
            with urlopen(request, timeout=30) as response:
                if response.status != 200:
                    return f'HTTP {response.status}: {url}'
                if fragments or url == args.base_url:
                    body = response.read().decode('utf-8')
                    remote = Document()
                    remote.feed(body)
                    for fragment in fragments:
                        if fragment not in remote.ids and 'user-content-' + fragment not in remote.ids:
                            return f'Missing remote anchor: {url}#{fragment}'
                    if url == args.base_url and body != (ROOT / 'index.html').read_text():
                        return f'Deployed page differs from local index.html: {url}'
            return None
        except Exception as error:
            return f'Cannot reach {url}: {error}'

    with ThreadPoolExecutor(max_workers=4) as executor:
        failures = [error for error in executor.map(check_destination, destinations.items()) if error]
    if failures:
        raise SystemExit('\n'.join(failures))
    print(f'Verified {len(destinations)} public HTTP destinations and their linked anchors.' +
          (' Deployed page matches local source.' if args.base_url else ''))
