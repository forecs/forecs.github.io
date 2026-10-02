#!/usr/bin/env python3
"""Isolated standard-library validation/staging and exact-allowlist finalization.

The original build_site.build(repo, output) remains the script-free compatibility
builder. This pipeline never sends article Markdown to VitePress: trusted Vue
receives only public data and Python-rendered inert HTML. Review/export and the
shared validator remain mandatory. Run against a quiescent trusted checkout;
this is not a sandbox against concurrent hostile filesystem or toolchain edits.

CLI stage --output EMPTY_DIRECTORY; finalize --dist DIR --receipt FILE
--output EMPTY_DIRECTORY; build --output _site. Only build may replace its own
previous output, after verifying every previous byte against an external receipt.
No Git operations, network access, or approval generation occurs here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

try:
    from . import build_site as old
except ImportError:
    import build_site as old

BuildError = old.BuildError
BASE_COMMIT = '8b9d85c82f47146a27668a3536a118dfc4a2fc47'
DOWNLOADS = ('Demo-Enable-SoftAP-WinRT.exe', 'Demo-IOCP-WinRT.exe',
             'Demo-QOSAddSocketToFlow.cpp', 'Demo-QOSAddSocketToFlow.exe', 'main.cpp')
# Reviewed trusted frontend inputs, not a glob over site/ or the checkout.
FRONTEND = (
    'index.md', 'wiki/index.md', 'archive/index.md',
    '.vitepress/config.mjs', '.vitepress/theme/index.js',
    '.vitepress/theme/style.css', '.vitepress/shared.mjs', '.vitepress/theme/data.js',
    '.vitepress/theme/components/HomeOverview.vue', '.vitepress/theme/components/ArticleIndex.vue',
    '.vitepress/theme/components/ArchiveIndex.vue', '.vitepress/theme/components/ApprovedArticle.vue',
)
FIXED_OUTPUT = {'index.html', 'wiki/index.html', 'archive/index.html',
                '404.html', 'hashmap.json', 'vp-icons.css'}
ASSET = re.compile(r'assets/(?:chunks/)?[A-Za-z0-9_@.-]+\.(?:js|css|woff2?|ttf|otf|png|svg|webp|jpg)\Z')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BuildError('Duplicate receipt key')
            result[key] = value
        return result
    return json.loads(old._read_bytes(path), object_pairs_hook=unique)


def target_path(repo, output):
    output = Path(output)
    return old._checked_path(output if output.is_absolute() else repo / output)


def write_files(output, files):
    # Complete in-memory preflight, including file/directory collisions.
    for name in files:
        if any(str(p) in files for p in PurePosixPath(name).parents):
            raise BuildError('Output file/directory collision')
    output.mkdir(parents=True, exist_ok=True)
    for name, data in sorted(files.items()):
        target = old._checked_path(output / name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)


def public_data(articles, legacy):
    """Canonical public projection; also binds finalization to the approved version."""
    return {
        'articles': [{
            'slug': a['slug'], 'title': a['title'], 'body': a['body'],
            'html': old.render_markdown(a['body']),
        } for a in articles],
        'legacy': [{'path': '/' + name, 'title': {
            '2016/08/02/hello-world/index.html': 'Hello World',
            '2016/08/02/rabbitmq-troubleshooting/index.html': 'RabbitMQ troubleshooting',
        }.get(name, name)} for name in legacy if name.startswith('2016/') and name.endswith('.html')],
        'downloads': [{'name': name, 'url': f'https://github.com/forecs/forecs.github.io/blob/{BASE_COMMIT}/{name}'}
                      for name in DOWNLOADS],
    }


def stage(repo: Path, output: Path) -> None:
    """Validate approved pairs and write ONLY trusted templates + inert public data."""
    repo = old._checked_path(repo)
    output = target_path(repo, output)
    old._check_output(repo, output)
    articles = old._approved(repo)
    legacy = old._legacy(repo, output)
    files = {name: old._read_bytes(repo / 'site/frontend' / name) for name in FRONTEND}
    files['.vitepress/public-data.json'] = json_bytes(public_data(articles, legacy))
    for a in articles:
        files[f"wiki/{a['slug']}/index.md"] = (
            '<!-- Trusted generated wrapper: article text is data, never Vue source. -->\n'
            f'<ApprovedArticle slug="{a["slug"]}" />\n'
        ).encode()
    old._check_output(repo, output)
    write_files(output, files)


def tree(root):
    """Read all files without following symlinks; reject special/hidden entries."""
    root = old._checked_path(root)
    if not root.is_dir():
        raise BuildError('Expected build directory')
    files = {}
    def visit(directory):
        for item in directory.iterdir():
            old._checked_path(item)
            if item.name.startswith('.'):
                raise BuildError('Hidden artifact entry')
            if item.is_dir():
                # Empty directories are also pollution, not ignored.
                if not any(item.iterdir()):
                    raise BuildError('Empty artifact directory')
                visit(item)
            else:
                files[item.relative_to(root).as_posix()] = old._read_bytes(item)
    visit(root)
    return files


def check_receipt(files, receipt):
    if not isinstance(receipt, dict) or not receipt:
        raise BuildError('Invalid generated file receipt')
    if set(files) != set(receipt):
        raise BuildError(f'Artifact inventory mismatch: {sorted(set(files) ^ set(receipt))}')
    for name, data in files.items():
        if not isinstance(receipt[name], str) or digest(data) != receipt[name]:
            raise BuildError(f'Artifact digest mismatch: {name}')


def finalized_files(repo, dist, receipt, output):
    articles = old._approved(repo)
    expected = FIXED_OUTPUT | {f"wiki/{a['slug']}/index.html" for a in articles}
    record = read_json(receipt)
    if not isinstance(record, dict) or set(record) != {'files', 'publicDataSha256'}:
        raise BuildError('Expected content-bound Rollup output inventory')
    legacy = old._legacy(repo, output)
    if record['publicDataSha256'] != digest(json_bytes(public_data(articles, legacy))):
        raise BuildError('Staged public content no longer matches the approved version')
    inventory = record['files']
    if not isinstance(inventory, dict):
        raise BuildError('Expected Rollup output inventory')
    assets = set(inventory) - expected
    if not expected <= set(inventory) or any(not ASSET.fullmatch(name) for name in assets):
        raise BuildError('Unexpected generated route or non-asset output')
    files = tree(dist)
    check_receipt(files, inventory)
    if set(files) & set(legacy):
        raise BuildError('Generated route collides with historical URL')
    files.update(legacy)
    files['.nojekyll'] = b''
    return files


def finalize(repo, dist, receipt, output):
    repo = old._checked_path(repo)
    output = target_path(repo, output)
    old._check_output(repo, output)
    files = finalized_files(repo, dist, receipt, output)
    old._check_output(repo, output)
    write_files(output, files)


def published_tree(root):
    # .nojekyll is the sole explicitly permitted hidden output.
    marker = old._read_bytes(root / '.nojekyll')
    if marker:
        raise BuildError('Invalid .nojekyll marker')
    def visit(directory):
        result = {}
        for item in directory.iterdir():
            old._checked_path(item)
            if item.is_dir():
                if not any(item.iterdir()):
                    raise BuildError('Empty artifact directory')
                result.update(visit(item))
            else:
                result[item.relative_to(root).as_posix()] = old._read_bytes(item)
        return result
    return visit(root)


def build(repo, output):
    repo = old._checked_path(repo)
    output = target_path(repo, output)
    receipt = old._checked_path(output.with_name(output.name + '.build-receipt.json'))
    # Check protected paths even when replacing an existing output.
    if old._inside(repo, output) or (old._inside(output, repo) and
            (output.relative_to(repo).parts[0].lower() in old.RESERVED or
             output.relative_to(repo).parts[0].startswith('.'))):
        raise BuildError('Unsafe output location')
    old._legacy(repo, output)  # Also reject output nested inside a historical source directory.
    previous = None
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        previous = read_json(receipt)
        check_receipt(published_tree(output), previous)
    else:
        old._check_output(repo, output)
        if receipt.exists():
            raise BuildError('Receipt exists without a verified prior artifact; move it aside explicitly')
    # Under repo only for npm module resolution; sources remain a closed allowlist.
    with tempfile.TemporaryDirectory(prefix='_build-temp-', dir=repo) as temporary:
        scratch = Path(temporary)
        source, dist, result = scratch / 'src', scratch / 'dist', scratch / 'final'
        rollup_receipt = scratch / 'rollup-output.json'
        before = old._approved(repo)
        stage(repo, source)
        if before != old._approved(repo):
            raise BuildError('Articles changed during staging')
        subprocess.run(['node', str(repo / 'scripts/vitepress_build.mjs'),
                        str(source), str(dist), str(rollup_receipt)], check=True, cwd=repo)
        if before != old._approved(repo):
            raise BuildError('Articles changed during build; obtain fresh review')
        finalize(repo, dist, rollup_receipt, result)
        final_receipt = json_bytes({name: digest(data) for name, data in published_tree(result).items()})
        new_receipt = scratch / 'final-receipt.json'
        new_receipt.write_bytes(final_receipt)
        # Recheck immediately before swapping. Never recursively delete arbitrary _site.
        if previous is not None:
            check_receipt(published_tree(output), previous)
        elif output.exists() and any(output.iterdir()):
            raise BuildError('Output changed during build')
        old._checked_path(receipt)
        backup = scratch / 'previous'
        existed = output.exists()
        if existed:
            output.rename(backup)
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            result.rename(output)
        except OSError:
            if existed:
                backup.rename(output)
            raise
        os.replace(new_receipt, receipt)
        print(f'Published {len(json.loads(final_receipt))} allowlisted files to {output}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('stage', 'finalize', 'build'))
    parser.add_argument('--repo', type=Path, default=Path(__file__).absolute().parent.parent)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--dist', type=Path)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.mode == 'stage':
            stage(args.repo, args.output)
        elif args.mode == 'finalize':
            if args.dist is None or args.receipt is None:
                parser.error('finalize requires --dist and --receipt')
            finalize(args.repo, args.dist, args.receipt, args.output)
        else:
            build(args.repo, args.output)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f'Modern build refused: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
