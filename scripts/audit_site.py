#!/usr/bin/env python3
"""Audit the isolated modern artifact against its external receipt and route policy.

Run after build, before upload. The receipt is integrity evidence from the trusted
build, not a signature or a defense against a malicious build-tool maintainer.
"""
import argparse
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

try:
    from . import modern_site as modern
except ImportError:
    import modern_site as modern


class PublicLinks(HTMLParser):
    """Inspect real SSR href/src attributes, not escaped article/code examples."""
    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key not in {'href', 'src'} or not value:
                continue
            path = unquote(urlsplit(value).path)
            first = path.lstrip('/').split('/')[0]
            if (first in {'legacy', 'archive', 'archives', '2016', 'css', 'js', 'fancybox'}
                    or PurePosixPath(path).suffix.lower() in {'.exe', '.cpp'}):
                raise modern.BuildError('Retired route or historical download linked')

    handle_startendtag = handle_starttag


def audit(repo, output):
    repo = modern.core._checked_path(repo)
    output = modern.target_path(repo, output)
    files = modern.published_tree(output)
    receipt = modern.read_json(output.with_name(output.name + '.build-receipt.json'))
    modern.check_receipt(files, receipt)
    expected = modern.FIXED_OUTPUT | {'.nojekyll'} | {
        f"wiki/{a['slug']}/index.html" for a in modern.core._approved(repo)
    }
    if not expected <= set(files) or any(
            name not in expected and not modern.ASSET.fullmatch(name) for name in files):
        raise modern.BuildError('Artifact contains an unexpected route or source file')
    for name, data in files.items():
        if name.endswith(('.html', '.js', '.css', '.json')):
            if str(repo).encode() in data or b'_build-temp-' in data:
                raise modern.BuildError(f'Build path leaked: {name}')
        if name.endswith('.html'):
            parser = PublicLinks(convert_charrefs=True)
            parser.feed(data.decode('utf-8'))
            parser.close()
    return {
        'files': len(files),
        'pages': sorted(name for name in files if name.endswith('.html')),
        'extensions': dict(sorted(Counter(Path(name).suffix or '(marker)' for name in files).items())),
    }


def main():
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('_site'))
    args = parser.parse_args()
    repo = Path(__file__).absolute().parent.parent
    try:
        print(json.dumps(audit(repo, args.output), sort_keys=True, indent=2))
    except (ValueError, OSError) as exc:
        parser.exit(1, f'Artifact audit refused: {exc}\n')


if __name__ == '__main__':
    main()
