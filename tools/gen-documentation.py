#!/usr/bin/env python3
"""Render docs/manual into the static GitHub Pages manual.

Requires Python-Markdown (python3 -m pip install 'Markdown>=3.5,<4').
Run from any directory: python3 tools/gen-documentation.py [--check]
The Markdown files, not the generated HTML, are the source of truth.
"""
from __future__ import annotations

import argparse
import html
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree as ET

try:
    import markdown
    from markdown.extensions import Extension
    from markdown.treeprocessors import Treeprocessor
except ImportError:
    sys.exit("Install the build-time dependency with: python3 -m pip install 'Markdown>=3.5,<4'")

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / 'docs'
MANUAL = DOCS / 'manual'
OUT = DOCS / 'documentation'
SECTION = re.compile(r'^## (\d+\.\d+)\s+(.+?)\s*$', re.M)
NUMBERED_HEADING = re.compile(r'^(\d+\.\d+(?:\.\d+)*)\s+')
REF = re.compile(r'§\s*(\d+\.\d+(?:\.\d+)*)\b')


@dataclass
class Page:
    number: str
    title: str
    part: str
    source: str
    filename: str
    body: str


def collect():
    front = (MANUAL / '00-front-matter.md').read_text(encoding='utf-8')
    pages = [Page('', 'Introduction', 'Field manual', '00-front-matter.md', 'documentation.html', front)]
    for path in sorted(MANUAL.glob('part[0-9]*-*.md')):
        text = path.read_text(encoding='utf-8')
        found = list(SECTION.finditer(text))
        if not found:
            raise ValueError(f'{path}: no numbered sections found')
        part = text.splitlines()[0].removeprefix('# ').strip()
        intro = text[:found[0].start()]
        for index, match in enumerate(found):
            end = found[index + 1].start() if index + 1 < len(found) else len(text)
            # Retain the part title and its introductory prose on its first section.
            content = (intro if index == 0 else '') + text[match.start():end]
            number, title = match.groups()
            pages.append(Page(number, title, part, path.name, f'documentation/{number.replace(".", "-")}.html', content))
    return pages


def numbered_headings(pages):
    targets = {}
    for page in pages:
        # Restrict to real headings outside fenced code.
        fence = False
        for line in page.body.splitlines():
            if re.match(r'^\s*```', line):
                fence = not fence
                continue
            if fence:
                continue
            match = re.match(r'^#{2,6}\s+(\d+\.\d+(?:\.\d+)*)\s+', line)
            if match:
                number = match.group(1)
                if number in targets:
                    raise ValueError(f'duplicate heading {number}')
                targets[number] = page.filename
    return targets


def relative_link(source, destination):
    import posixpath
    return posixpath.relpath(destination, posixpath.dirname(source) or '.')


class CrossReferences(Treeprocessor):
    def __init__(self, md, page, targets):
        super().__init__(md)
        self.page = page
        self.targets = targets
        # First sections retain their part-level h1 and introduction. Later
        # sections begin with an h2, so promote their heading hierarchy by one.
        self.promote_headings = bool(page.number and not re.match(r'^#\s', page.body))
        self.ids = set()

    def inject(self, parent, child_index, text, is_tail):
        matches = [m for m in REF.finditer(text or '') if m.group(1) in self.targets]
        if not matches:
            return
        before = text[:matches[0].start()]
        if is_tail:
            parent[child_index].tail = before
            insert_at = child_index + 1
        else:
            parent.text = before
            insert_at = 0
        for i, match in enumerate(matches):
            number = match.group(1)
            link = ET.Element('a', {'href': relative_link(self.page.filename, self.targets[number]) + '#section-' + number.replace('.', '-')})
            link.text = match.group(0)
            link.tail = text[match.end():matches[i + 1].start() if i + 1 < len(matches) else len(text)]
            parent.insert(insert_at + i, link)

    def visit(self, element):
        if element.tag in ('pre', 'code', 'a'):
            return
        if re.fullmatch(r'h[1-6]', element.tag):
            if self.promote_headings and element.tag != 'h1':
                element.tag = f'h{int(element.tag[1]) - 1}'
            heading = ''.join(element.itertext()).strip()
            number = NUMBERED_HEADING.match(heading)
            base = 'section-' + number.group(1).replace('.', '-') if number else re.sub(r'[^\w-]+', '-', heading.lower(), flags=re.UNICODE).strip('-')
            base = base or 'heading'
            slug = base
            i = 2
            while slug in self.ids:
                slug = f'{base}-{i}'
                i += 1
            self.ids.add(slug)
            element.set('id', slug)
        for child in list(element):
            self.visit(child)
        # Insert links only after walking the original children.
        for child in reversed(list(element)):
            index = list(element).index(child)
            self.inject(element, index, child.tail, True)
        self.inject(element, -1, element.text, False)

    def run(self, root):
        self.visit(root)
        return root


class CrossReferenceExtension(Extension):
    def __init__(self, page, targets):
        super().__init__()
        self.page, self.targets = page, targets

    def extendMarkdown(self, md):
        md.treeprocessors.register(CrossReferences(md, self.page, self.targets), 'manual-refs', 1)


def nav(pages, current):
    def href(page):
        return relative_link(current.filename, page.filename)
    result = ['<a class="manual-home' + (' active' if current is pages[0] else '') + '" href="' + href(pages[0]) + '"' + (' aria-current="page"' if current is pages[0] else '') + '>Introduction <span>↗</span></a>']
    for part in dict.fromkeys(p.part for p in pages[1:]):
        members = [p for p in pages[1:] if p.part == part]
        opened = ' open' if current in members else ''
        result.append(f'<details{opened}><summary>{html.escape(part)}</summary><ul>')
        for p in members:
            active = ' aria-current="page"' if p is current else ''
            result.append(f'<li><a href="{href(p)}"{active}><span>{p.number}</span>{html.escape(p.title)}</a></li>')
        result.append('</ul></details>')
    return '\n'.join(result)


def render(page, pages, targets):
    body = markdown.markdown(page.body, extensions=['tables', 'fenced_code', CrossReferenceExtension(page, targets)], output_format='html5')
    base = '../' if page.number else ''
    position = pages.index(page)
    def adjacent(other, label, arrow):
        return f'<a href="{relative_link(page.filename, other.filename)}"><small>{label}</small><span>{arrow} {html.escape((other.number + " " if other.number else "") + other.title)}</span></a>'
    previous = adjacent(pages[position - 1], 'PREVIOUS', '←') if position else '<span></span>'
    following = adjacent(pages[position + 1], 'NEXT', '→') if position + 1 < len(pages) else '<span></span>'
    title = (page.number + ' ' if page.number else '') + page.title
    return f'''<!doctype html>
<!-- Generated by tools/gen-documentation.py from docs/manual/{html.escape(page.source)}. Do not edit. -->
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0b1017"><meta name="description" content="IMSISting field manual: {html.escape(title, quote=True)}">
<title>{html.escape(title)} — IMSIsting documentation</title><link rel="icon" href="{base}imsisting-icon.png"><link rel="stylesheet" href="{base}documentation.css"></head>
<body><a class="skip-link" href="#main">Skip to content</a>
<header class="site-header"><div class="header-inner"><a class="brand" href="{base}index.html"><img src="{base}imsisting-icon.png" alt="" width="40" height="40"><span>IMSI<span>sting</span><small>CELLULAR SECURITY TOOLKIT</small></span></a>
<nav aria-label="Main navigation"><a href="{base}index.html">Overview</a><a href="{base}modules.html">Modules</a><a href="{base}documentation.html" aria-current="page">Documentation</a><a href="{base}install.html">Install</a></nav><a class="header-link" href="https://github.com/yslxotwod/IMSIsting">GitHub ↗</a></div></header>
<div class="manual-layout"><aside class="sidebar"><div class="sidebar-top"><span class="indicator"></span> FIELD MANUAL <span class="sidebar-tag">REFERENCE / 01</span></div><nav aria-label="Manual contents">{nav(pages, page)}</nav><p class="sidebar-foot">SOURCE / <code>docs/manual</code></p></aside>
<main id="main" class="manual-main"><div class="document-meta"><span>DOCUMENTATION <b>/</b> {html.escape(page.part.upper())}</span><span>{html.escape(page.number or 'INTRODUCTION')}</span></div>
<article class="manual-content">{body}</article><nav class="page-turn" aria-label="Previous and next sections">{previous}{following}</nav>
<footer>IMSIsting <span>·</span> FIELD MANUAL <a href="{base}index.html">PROJECT OVERVIEW ↗</a></footer></main></div></body></html>\n'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='check that generated pages are up to date without writing')
    args = parser.parse_args()
    pages = collect()
    targets = numbered_headings(pages)
    stale = []
    for page in pages:
        destination = DOCS / page.filename
        output = render(page, pages, targets)
        if args.check:
            if not destination.exists() or destination.read_text(encoding='utf-8') != output:
                stale.append(page.filename)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(output, encoding='utf-8')
    if stale:
        print('Stale or missing pages: ' + ', '.join(stale), file=sys.stderr)
        return 1
    print(f'{"Checked" if args.check else "Generated"} {len(pages)} pages from {len(set(p.source for p in pages))} manual files; {len(targets)} section anchors.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
