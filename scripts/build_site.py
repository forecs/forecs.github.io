#!/usr/bin/env python3
"""Build an approved-content-only learning blog using the Python standard library.

Usage: python3 scripts/build_site.py --output _site
API: build(repo: Path, output: Path); a relative output is relative to repo.

The shared scripts/content.py validator is REQUIRED (there is no fallback):
validate_articles(repo / 'publish_articles') -> list of dictionaries containing
slug, title, body, sha256. Sources are flat UTF-8 {slug}.md body-only files and
strict {slug}.json approval objects {"title": str, "sha256": exact-byte digest}.
The shared validator owns approval/JSON/frontmatter validation; this builder
also checks returned types, safe slugs, unique routes, and exact body digests.

Markdown is deliberately small: ATX headings, flat unordered/ordered lists,
blank-line paragraphs, triple-backtick fenced code, and single-backtick inline
code. All other syntax is literal text, including raw HTML, links, images,
frontmatter and Liquid. No templates, network requests, user-generated links,
JavaScript, external assets, or syntax highlighters run on new pages. The wiki
index includes full article text for the browser's Find (Ctrl/Cmd+F).

Legacy content is a separate TRUSTED historical snapshot, not sanitized new
content. Only explicitly listed site/legacy-files.txt files are copied, with
no globbing or recursive repository copy. Existing URLs remain at their old
paths except index.html, which moves to legacy/index.html with a base URL of
'/' so its relative resource/article links retain their old root semantics.
Same-document fragment links are retargeted to /legacy/index.html so the base
URL does not send heading anchors to the new homepage. Its Home link can
return to the new homepage. Deploy at the origin root, not
under a URL subdirectory. Old missing dependencies (e.g. atom.xml) are not
invented. Legacy HTML/JS can retain historical scripts and external requests;
the strict CSP on new pages does not apply to those historical documents.

All inputs and output path components must be non-symlinks. Output must be
absent or an empty directory, never the repository or a source location.
All validation/rendering precedes output creation; writes are exclusive and
never overwrite existing files. Run against a quiescent, trusted checkout:
this is not a sandbox against concurrent hostile filesystem mutation.
"""

from __future__ import annotations

import argparse
import hashlib
import html
from html.parser import HTMLParser
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


class BuildError(ValueError):
    """Unsafe input or output; no existing files should be overwritten."""


SLUG = re.compile(r"[a-z0-9-]{1,80}\Z", re.ASCII)
DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
LEGACY_PART = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.@-]*\Z", re.ASCII)
LEGACY_SUFFIXES = frozenset({
    '.html', '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.webp', '.avif', '.woff', '.woff2', '.ttf', '.otf', '.eot',
})
RESERVED = frozenset({
    'wiki', 'legacy', 'scripts', 'tests', 'site', 'publish_articles',
    'draft', 'drafts', 'pending', 'artifacts', 'node_modules',
})
CSP = "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'"
STYLE = b"""/* Trusted site style; never derived from article text. */
:root { color-scheme: light dark; font: 18px/1.7 system-ui, sans-serif; }
body { max-width: 52rem; margin: 3rem auto; padding: 0 1.2rem; }
nav { font-size: .9rem; padding-bottom: 1.2rem; border-bottom: 1px solid #8886; }
a { color: light-dark(#1559a8, #8ac1ff); text-underline-offset: .2em; }
h1,h2,h3 { line-height: 1.25; margin-top: 1.6em; }
pre { overflow-x: auto; padding: 1rem; background: #8881; border: 1px solid #8884; }
code { font-size: .85em; overflow-wrap: anywhere; }
article { border-top: 1px solid #8886; padding: 1rem 0; }
li { margin: .4rem 0; } p { overflow-wrap: anywhere; }
"""


def validate_articles(root: Path) -> list[dict]:
    """Load the shared validator lazily, also supporting direct CLI execution."""
    try:
        if __package__:
            from .content import validate_articles as validate
        else:
            from content import validate_articles as validate
    except ImportError as exc:
        raise BuildError(
            'Shared validator scripts/content.py is required; '
            'refusing to publish unvalidated articles'
        ) from exc
    return validate(root)


def _checked_path(path: Path) -> Path:
    """Make absolute without resolving away symlinks; inspect every component."""
    path = Path(path)
    if '..' in path.parts:
        raise BuildError(f'Parent traversal is not allowed: {path}')
    path = path.absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise BuildError(f'Symlink is not allowed: {current}')
    return path


def _regular_file(path: Path) -> Path:
    path = _checked_path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise BuildError(f'Expected a regular file: {path}')
    return path


def _read_bytes(path: Path) -> bytes:
    """Reject special files and final-component symlinks again when opening."""
    path = _regular_file(path)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, flags), 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise BuildError(f'Expected a regular file: {path}')
        return source.read()


def _inside(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _check_output(repo: Path, output: Path) -> None:
    _checked_path(output)
    if _inside(repo, output):
        raise BuildError('Output cannot contain or replace the repository')
    if _inside(output, repo):
        first = output.relative_to(repo).parts[0]
        if first.lower() in RESERVED or first.startswith('.'):
            raise BuildError('Output cannot be in a source or protected directory')
    if output.exists():
        if not output.is_dir() or any(output.iterdir()):
            raise BuildError('Output must be absent or an empty directory')


def _approved(repo: Path) -> list[dict]:
    root = _checked_path(repo / 'publish_articles')
    if not root.is_dir():
        raise BuildError('publish_articles must be an existing directory')
    # The source contract is flat. Check names/types without consuming drafts.
    for entry in root.iterdir():
        _regular_file(entry)
    articles = validate_articles(root)
    if not isinstance(articles, list):
        raise BuildError('Validator must return a list of approved articles')
    seen = set()
    result = []
    for article in articles:
        if not isinstance(article, dict) or set(article) != {'slug', 'title', 'body', 'sha256'}:
            raise BuildError('Invalid validated article shape')
        if not all(isinstance(article[key], str) for key in article):
            raise BuildError('Validated article values must be strings')
        slug, body, digest = article['slug'], article['body'], article['sha256']
        if not SLUG.fullmatch(slug) or slug in seen:
            raise BuildError('Invalid or duplicate approved slug')
        if not DIGEST.fullmatch(digest):
            raise BuildError('Invalid approved SHA-256 digest')
        seen.add(slug)
        _regular_file(root / f'{slug}.json')
        raw = _read_bytes(root / f'{slug}.md')
        if raw.decode('utf-8') != body or hashlib.sha256(raw).hexdigest() != digest:
            raise BuildError(f'Approved body or exact-byte digest mismatch: {slug}')
        result.append(dict(article))
    return sorted(result, key=lambda article: article['slug'])


def _inline(text: str) -> str:
    """Escape everything, allowing only balanced single-backtick code spans."""
    parts = re.split(r'(`[^`\n]+`)', text)
    return ''.join(
        '<code>' + html.escape(part[1:-1]) + '</code>'
        if part.startswith('`') and part.endswith('`') and len(part) > 2
        else html.escape(part)
        for part in parts
    )


def render_markdown(body: str) -> str:
    """Render the documented inert Markdown subset, never raw HTML."""
    blocks = []
    paragraph = []
    items = []
    list_kind = None
    code = None

    def flush_paragraph():
        if paragraph:
            blocks.append('<p>' + _inline('\n'.join(paragraph)) + '</p>')
            paragraph.clear()

    def flush_list():
        nonlocal list_kind
        if items:
            blocks.append(f'<{list_kind}>' + ''.join(
                '<li>' + _inline(item) + '</li>' for item in items
            ) + f'</{list_kind}>')
            items.clear()
        list_kind = None

    for line in body.splitlines():
        if code is not None:
            if line.strip() == '```':
                blocks.append('<pre><code>' + html.escape('\n'.join(code)) + '</code></pre>')
                code = None
            else:
                code.append(line)
            continue
        if re.fullmatch(r'```[^`]*', line):
            flush_paragraph()
            flush_list()
            code = []  # Fence language labels are ignored, never attributes.
            continue
        heading = re.fullmatch(r'(#{1,6})[ \t]+(.+)', line)
        item = re.fullmatch(r'(?:[-+*]|[0-9]+\.)[ \t]+(.+)', line)
        if heading:
            flush_paragraph()
            flush_list()
            level = len(heading[1])
            blocks.append(f'<h{level}>' + _inline(heading[2]) + f'</h{level}>')
        elif item:
            flush_paragraph()
            kind = 'ol' if line[0].isdigit() else 'ul'
            if list_kind != kind:
                flush_list()
            list_kind = kind
            items.append(item[1])
        elif not line.strip():
            flush_paragraph()
            flush_list()
        else:
            flush_list()
            paragraph.append(line)
    flush_paragraph()
    flush_list()
    if code is not None:
        blocks.append('<pre><code>' + html.escape('\n'.join(code)) + '</code></pre>')
    return '\n'.join(blocks)


def _page(title: str, content: str) -> bytes:
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
        '<meta http-equiv="Content-Security-Policy" content="' + html.escape(CSP, quote=True) + '">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<link rel="stylesheet" href="/wiki/style.css">\n'
        '<title>' + html.escape(title) + '</title></head><body>\n'
        '<nav aria-label="Main"><a href="/">Learning blog</a> | '
        '<a href="/wiki/">Wiki</a> | <a href="/archives/">Old archives</a> | '
        '<a href="/legacy/index.html">Legacy home</a></nav>\n<main>\n'
        + content + '\n</main></body></html>\n'
    ).encode('utf-8')


def _root_fragments(text: str) -> str:
    """Keep old in-page anchors on the relocated page despite its root base."""
    offsets = [0] + [match.end() for match in re.finditer('\n', text)]
    edits = []

    class FragmentLinks(HTMLParser):
        def handle_starttag(self, tag, attrs):
            self.rewrite(tag, attrs, False)

        def handle_startendtag(self, tag, attrs):
            self.rewrite(tag, attrs, True)

        def rewrite(self, tag, attrs, closed):
            if tag not in {'a', 'area'} or not any(
                    key == 'href' and value is not None
                    and (not value or value.startswith('#')) for key, value in attrs):
                return
            rewritten = []
            for key, value in attrs:
                if key == 'href' and value is not None and (not value or value.startswith('#')):
                    value = '/legacy/index.html' + value
                rewritten.append(key if value is None else key + '="' + html.escape(value, quote=True) + '"')
            start = offsets[self.getpos()[0] - 1] + self.getpos()[1]
            replacement = '<' + tag + ' ' + ' '.join(rewritten) + (' />' if closed else '>')
            edits.append((start, start + len(self.get_starttag_text()), replacement))

    parser = FragmentLinks(convert_charrefs=True)
    parser.feed(text)
    parser.close()
    for start, end, replacement in reversed(edits):
        text = text[:start] + replacement + text[end:]
    return text


def _legacy(repo: Path, output: Path) -> dict[str, bytes]:
    manifest = _read_bytes(repo / 'site' / 'legacy-files.txt').decode('utf-8')
    paths = []
    seen = set()
    for line in manifest.splitlines():
        if not line or line.startswith('#'):
            continue
        # Validate before PurePosixPath can normalize away '.', empty parts etc.
        parts = line.split('/')
        if (any(not LEGACY_PART.fullmatch(part) or part in {'.', '..'} for part in parts)
                or any(part.lower() in RESERVED for part in parts)
                or PurePosixPath(line).suffix.lower() not in LEGACY_SUFFIXES):
            raise BuildError(f'Unsafe legacy path: {line!r}')
        if line in seen:
            raise BuildError(f'Duplicate legacy path: {line}')
        if len(parts) > 1 and _inside(output, repo / parts[0]):
            raise BuildError('Output cannot be inside a legacy input directory')
        seen.add(line)
        paths.append(line)
    copied = {}
    for name in sorted(paths):
        data = _read_bytes(repo.joinpath(*name.split('/')))
        if name == 'index.html':
            text = _root_fragments(data.decode('utf-8'))
            # A prior base has its own URL semantics and must be reviewed first.
            if re.search(r'<base\b', text, flags=re.IGNORECASE):
                raise BuildError('Legacy root already has a base element; review relocation first')
            base = '<base href="/">'
            text, count = re.subn(r'(<head\b[^>]*>)', lambda match: match[0] + base,
                                  text, count=1, flags=re.IGNORECASE)
            if not count:
                # HTML fragments are also accepted as historical input.
                text = base + '\n' + text
            data = text.encode('utf-8')
            name = 'legacy/index.html'
        copied[name] = data
    return copied


def build(repo: Path, output: Path) -> None:
    """Build into an absent/empty output, failing closed on unsafe inputs."""
    try:
        repo = _checked_path(Path(repo))
        if not repo.is_dir():
            raise BuildError('Repository must be a directory')
        output = Path(output)
        if not output.is_absolute():
            output = repo / output
        output = _checked_path(output)
        _check_output(repo, output)
        articles = _approved(repo)
        files = _legacy(repo, output)
        links = ''.join(
            '<li><a href="/wiki/' + article['slug'] + '/">'
            + html.escape(article['title']) + '</a></li>\n' for article in articles
        )
        files['index.html'] = _page('Learning blog',
            '<h1>Learning blog</h1>\n<p>Approved learning notes. '
            '<a href="/wiki/">Browse and search the wiki</a>.</p>\n'
            + ('<ul>' + links + '</ul>' if articles else '<p>No published articles yet.</p>'))
        wiki = ['<h1>Wiki</h1><p>Search titles and full text with your browser’s Find '
                '(Ctrl+F or Cmd+F). No scripts or network search are used.</p>', '<ul>' + links + '</ul>']
        for article in articles:
            rendered = '<h1>' + html.escape(article['title']) + '</h1>\n' + render_markdown(article['body'])
            files[f"wiki/{article['slug']}/index.html"] = _page(article['title'], rendered)
            wiki.append('<article><h2><a href="/wiki/' + article['slug'] + '/">'
                        + html.escape(article['title']) + '</a></h2>\n'
                        + render_markdown(article['body']) + '</article>')
        files['wiki/index.html'] = _page('Wiki', '\n'.join(wiki))
        files['wiki/style.css'] = STYLE
        # Detect file/directory collisions before creating any output.
        for name in files:
            if any(str(parent) in files for parent in PurePosixPath(name).parents):
                raise BuildError(f'Output file/directory collision: {name}')
        # Inputs can have changed while the validator ran. Recheck the target.
        _check_output(repo, output)
        output.mkdir(parents=True, exist_ok=True)
        for name, data in sorted(files.items()):
            target = _checked_path(output.joinpath(*name.split('/')))
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as destination:
                destination.write(data)
    except (OSError, UnicodeError) as exc:
        raise BuildError(str(exc)) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', required=True, type=Path, help='Absent or empty output directory')
    args = parser.parse_args(argv)
    # The checkout is determined by this script, not the caller's cwd.
    try:
        build(Path(__file__).absolute().parent.parent, args.output)
    except ValueError as exc:
        print(f'Build refused: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
