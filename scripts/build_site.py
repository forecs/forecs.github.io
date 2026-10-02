#!/usr/bin/env python3
"""Standard-library safety and inert-rendering helpers for modern_site.py.

This module is not a publisher or fallback CLI. VitePress is the sole site
builder. Shared public-content validation remains mandatory; no legacy inputs
are read, copied, relocated, or linked. Operate on a trusted quiescent checkout.
"""
from __future__ import annotations

import hashlib
import html
import os
from pathlib import Path
import re
import stat


class BuildError(ValueError):
    """Unsafe input or output; no existing files should be overwritten."""


SLUG = re.compile(r"[a-z0-9-]{1,80}\Z", re.ASCII)
DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
RESERVED = frozenset({
    'wiki', 'legacy', 'scripts', 'tests', 'site', 'publish_articles',
    'draft', 'drafts', 'pending', 'artifacts', 'node_modules',
    'docs', 'workflow-templates', 'archives', 'archive', '2016', 'css', 'js', 'fancybox',
})

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


def _table_cells(line: str) -> list[str]:
    """Split a pipe-table row; cells remain inert and are escaped by _inline."""
    value = line.strip()
    if value.startswith('|'):
        value = value[1:]
    if value.endswith('|'):
        value = value[:-1]
    return [cell.strip() for cell in value.split('|')]


def _is_table_separator(line: str, columns: int) -> bool:
    cells = _table_cells(line)
    return len(cells) == columns and all(
        re.fullmatch(r':?-{3,}:?', cell) for cell in cells
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

    lines = body.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if code is not None:
            if line.strip() == '```':
                blocks.append('<pre><code>' + html.escape('\n'.join(code)) + '</code></pre>')
                code = None
            else:
                code.append(line)
            index += 1
            continue
        if re.fullmatch(r'```[^`]*', line):
            flush_paragraph()
            flush_list()
            code = []  # Fence language labels are ignored, never attributes.
            index += 1
            continue
        header = _table_cells(line) if '|' in line else []
        if (header and index + 1 < len(lines)
                and _is_table_separator(lines[index + 1], len(header))):
            flush_paragraph()
            flush_list()
            rows = []
            index += 2
            while index < len(lines) and '|' in lines[index] and lines[index].strip():
                cells = _table_cells(lines[index])
                if len(cells) != len(header):
                    break
                rows.append(cells)
                index += 1
            head_html = ''.join('<th scope="col">' + _inline(cell) + '</th>' for cell in header)
            body_html = ''.join(
                '<tr>' + ''.join('<td>' + _inline(cell) + '</td>' for cell in row) + '</tr>'
                for row in rows
            )
            blocks.append(
                '<div class="markdown-table-scroll" tabindex="0" '
                'aria-label="可横向滚动的表格"><table><thead><tr>' + head_html
                + '</tr></thead><tbody>' + body_html + '</tbody></table></div>'
            )
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
        index += 1
    flush_paragraph()
    flush_list()
    if code is not None:
        blocks.append('<pre><code>' + html.escape('\n'.join(code)) + '</code></pre>')
    return '\n'.join(blocks)
