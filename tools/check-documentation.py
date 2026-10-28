#!/usr/bin/env python3
"""Check generated manual pages, content, local links, and anchors."""
import importlib.util
import re
import sys
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

import markdown

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('manual_generator', ROOT / 'tools/gen-documentation.py')
generator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = generator
spec.loader.exec_module(generator)


class Document(HTMLParser):
    def __init__(self, article_only=False):
        super().__init__(convert_charrefs=True)
        self.article_only = article_only
        self.in_article = not article_only
        self.in_pre = False
        self.text = []
        self.codes = []
        self.ids = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'article' and attrs.get('class') == 'manual-content':
            self.in_article = True
        if 'id' in attrs:
            self.ids.append(attrs['id'])
        if tag == 'a' and 'href' in attrs:
            self.links.append(attrs['href'])
        if tag == 'pre' and self.in_article:
            self.in_pre = True
            self.codes.append([])

    def handle_endtag(self, tag):
        if tag == 'pre':
            self.in_pre = False
        if tag == 'article' and self.article_only:
            self.in_article = False

    def handle_data(self, data):
        if self.in_article:
            self.text.append(data)
            if self.in_pre:
                self.codes[-1].append(data)


def parse(text, article_only=False):
    document = Document(article_only)
    document.feed(text)
    return document


def normalized(document):
    return re.sub(r'\s+', ' ', ''.join(document.text)).strip()


def main():
    pages = generator.collect()
    targets = generator.numbered_headings(pages)
    for source in sorted((ROOT / 'docs/manual').glob('*.md')):
        combined = ''.join(page.body for page in pages if page.source == source.name)
        assert combined == source.read_text(encoding='utf-8'), f'{source.name}: source coverage differs'
    documents = {}
    for page in pages:
        path = (ROOT / 'docs' / page.filename).resolve()
        expected_html = generator.render(page, pages, targets)
        actual_html = path.read_text(encoding='utf-8')
        assert expected_html == actual_html, f'{page.filename}: generated page is stale'
        actual = parse(actual_html, article_only=True)
        reference = parse(markdown.markdown(page.body, extensions=['tables', 'fenced_code']))
        assert normalized(actual) == normalized(reference), f'{page.filename}: rendered text differs from source'
        assert [''.join(c) for c in actual.codes] == [''.join(c) for c in reference.codes], f'{page.filename}: code differs from source'
        duplicates = [key for key, count in Counter(actual.ids).items() if count > 1]
        assert not duplicates, f'{page.filename}: duplicate IDs {duplicates}'
        documents[path] = actual
    links = 0
    for path, document in documents.items():
        for href in document.links:
            link = urlsplit(href)
            if link.scheme or link.netloc:
                continue
            destination = (path.parent / unquote(link.path)).resolve() if link.path else path
            assert destination.exists(), f'{path}: missing {href}'
            if link.fragment:
                assert destination in documents and unquote(link.fragment) in documents[destination].ids, f'{path}: missing anchor {href}'
            links += 1
    print(f'PASS: {len(pages)} up-to-date pages, source text and code verified, {links} local links checked.')


if __name__ == '__main__':
    main()
