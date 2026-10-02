"""Security tests for the isolated VitePress boundary (no npm needed)."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from html.parser import HTMLParser
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

modern = importlib.import_module('scripts.modern_site')
core = importlib.import_module('scripts.build_site')


class Document(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.elements = []
        self.text = ''
        self.feed(source)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text += data


def tree_snapshot(root):
    entries = {}
    for item in root.rglob('*'):
        name = item.relative_to(root).as_posix()
        entries[name] = ('symlink', os.readlink(item)) if item.is_symlink() else (
            ('directory',) if item.is_dir() else ('file', item.read_bytes()))
    return entries


class ModernSiteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='modern-test-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.repo = self.base / 'repo'
        self.repo.mkdir()
        (self.repo / 'publish_articles').mkdir()
        (self.repo / 'site').mkdir()
        shutil.copytree(ROOT / 'site/frontend', self.repo / 'site/frontend')
        self.output = self.base / 'output'

    def put(self, name, text):
        target = self.repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def article(self, body='A searchable synthetic fixture.\n', title='Fixture', slug='fixture'):
        self.put(f'publish_articles/{slug}.md', body)
        self.put(f'publish_articles/{slug}.json', json.dumps({'title': title, 'sha256': hashlib.sha256(body.encode()).hexdigest()}))

    def staged(self):
        modern.stage(self.repo, self.output)
        return json.loads((self.output / '.vitepress/public-data.json').read_text())

    def fake_dist(self):
        dist = self.base / 'dist'
        dist.mkdir()
        names = (modern.FIXED_OUTPUT | {'assets/app.abcdef.js', 'assets/chunks/search.123.js'} |
                 {f"wiki/{a['slug']}/index.html" for a in core._approved(self.repo)})
        for name in names:
            p = dist / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b'fixture')
        receipt = self.base / 'receipt.json'
        receipt.write_bytes(modern.json_bytes({
            'files': {name: modern.digest((dist / name).read_bytes()) for name in names},
            'publicDataSha256': modern.digest(modern.json_bytes(modern.public_data(
                core._approved(self.repo)))),
        }))
        return dist, receipt

    def test_empty_approved_state_is_real_empty(self):
        data = self.staged()
        self.assertEqual(data['articles'], [])
        self.assertEqual(set(data), {'articles'})
        self.assertFalse((self.output / 'archive').exists())

    def test_article_payload_only_in_data_never_compiled_source(self):
        body = ('# Synthetic\n\n{{ globalThis.__articleAttack = 49 }}\n'
                '<script setup>import x from "../../private.md"</script>\n'
                '<img src=x onerror="globalThis.__articleAttack=1">\n'
                '<!-- @include: ../../private.md -->\n\n---\nlayout: home\n---\n'
                '[run](javascript:alert(1))\n::: raw\n{{ 7 * 7 }}\n:::\n')
        self.article(body, '</script><script>alert(1)</script> {{ 7 * 7 }}')
        data = self.staged()
        self.assertEqual(data['articles'][0]['body'], body)
        self.assertNotIn('sha256', data['articles'][0])
        self.assertNotIn('<script', data['articles'][0]['html'])
        self.assertNotIn('<img', data['articles'][0]['html'])
        for md in self.output.rglob('*.md'):
            self.assertNotIn('__articleAttack', md.read_text())
            self.assertNotIn('private.md', md.read_text())
        self.assertEqual((self.output / 'wiki/fixture/index.md').read_text().splitlines()[-1], '<ApprovedArticle slug="fixture" />')

    def test_rendered_data_has_no_active_tags_or_attributes(self):
        self.article('<iframe src="https://invalid.test"></iframe>\n<svg onload="alert(1)"></svg>\n')
        data = self.staged()
        document = Document(data['articles'][0]['html'])
        self.assertEqual({tag for tag, _ in document.elements}, {'p'})
        self.assertIn('<iframe', document.text)

    def test_frontmatter_is_rejected_not_compiled(self):
        self.article('---\nlayout: home\n---\nBody\n')
        with self.assertRaises(ValueError): self.staged()
        self.assertFalse(self.output.exists())

    def test_changed_approval_fails_before_writes(self):
        self.article()
        self.put('publish_articles/fixture.md', 'Changed\n')
        with self.assertRaises(ValueError): self.staged()
        self.assertFalse(self.output.exists())

    def test_raw_sidecar_private_fields_rejected(self):
        self.article()
        self.put('publish_articles/fixture.json', '{"title":"x","sha256":"x","private_path":"secret"}')
        with self.assertRaises(ValueError): self.staged()

    def test_source_symlink_refused(self):
        p = self.repo / 'site/frontend/index.md'
        p.unlink()
        p.symlink_to(ROOT / 'site/frontend/index.md')
        with self.assertRaises(ValueError): self.staged()
        self.assertFalse(self.output.exists())

    def test_article_symlink_refused(self):
        (self.repo / 'publish_articles/fixture.md').symlink_to(self.put('unapproved.txt', 'Not approved'))
        with self.assertRaises(ValueError): self.staged()

    def test_output_parent_symlink_refused(self):
        link = self.base / 'link'
        link.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValueError): modern.stage(self.repo, link / 'out')

    def test_extra_frontend_checkout_files_not_staged(self):
        self.put('site/frontend/public/leak.json', '{"secret":1}')
        self.put('site/frontend/leak.md', 'Private content')
        self.staged()
        files = {p.relative_to(self.output).as_posix() for p in self.output.rglob('*') if p.is_file()}
        self.assertEqual(files, set(modern.FRONTEND) | {'.vitepress/public-data.json'})

    def test_finalizer_only_exact_generated_outputs(self):
        self.article()
        dist, receipt = self.fake_dist()
        modern.finalize(self.repo, dist, receipt, self.output)
        self.assertEqual(modern.published_tree(self.output), {**modern.tree(dist), '.nojekyll': b''})
        self.assertTrue((self.output / 'wiki/fixture/index.html').is_file())
        self.assertFalse((self.output / 'publish_articles').exists())

    def test_artifact_pollution_fails_without_writes(self):
        for extra in ('test.py', 'private.json', 'Demo.exe', 'main.cpp', 'assets/hidden.js', '.git/config',
                      'legacy/index.html', 'archive/index.html', '2016/post/index.html', 'css/style.css'):
            with self.subTest(extra=extra):
                dist, receipt = self.fake_dist()
                p = dist / extra
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b'pollution')
                with self.assertRaises(ValueError): modern.finalize(self.repo, dist, receipt, self.output)
                self.assertFalse(self.output.exists())
                shutil.rmtree(dist)

    def test_receipt_cannot_authorize_checkout_or_legacy_files(self):
        dist, receipt = self.fake_dist()
        original = json.loads(receipt.read_text())
        for name in ('private.json', 'scripts/tool.js', 'assets/main.cpp', 'assets/tool.exe',
                     'unexpected.html', 'legacy/index.html', 'archive/index.html',
                     '2016/post/index.html', 'css/style.css', 'js/script.js', 'downloads/tool.exe'):
            with self.subTest(name=name):
                inventory = {**original, 'files': {**original['files'], name: modern.digest(b'pollution')}}
                receipt.write_text(json.dumps(inventory))
                p = dist / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b'pollution')
                with self.assertRaisesRegex(ValueError, 'Unexpected generated route'):
                    modern.finalize(self.repo, dist, receipt, self.output)
                self.assertFalse(self.output.exists())
                p.unlink()

    def test_artifact_file_and_directory_symlinks_rejected(self):
        dist, receipt = self.fake_dist()
        p = dist / 'assets/app.abcdef.js'
        p.unlink()
        p.symlink_to(self.repo / 'site/frontend/index.md')
        with self.assertRaises(ValueError): modern.finalize(self.repo, dist, receipt, self.output)
        p.unlink()
        (dist / 'link').symlink_to(self.repo, target_is_directory=True)
        with self.assertRaises(ValueError): modern.finalize(self.repo, dist, receipt, self.output)

    def test_empty_directory_pollution_rejected(self):
        dist, receipt = self.fake_dist()
        (dist / 'private').mkdir()
        with self.assertRaises(ValueError): modern.finalize(self.repo, dist, receipt, self.output)

    def test_asset_changed_after_rollup_refused(self):
        dist, receipt = self.fake_dist()
        (dist / 'assets/app.abcdef.js').write_text('changed')
        with self.assertRaises(ValueError): modern.finalize(self.repo, dist, receipt, self.output)

    def test_output_protection_preserves_existing_files(self):
        self.output.mkdir()
        (self.output / 'mine').write_text('keep')
        before = tree_snapshot(self.base)
        with self.assertRaises(ValueError): self.staged()
        self.assertEqual(before, tree_snapshot(self.base))

    def test_npm_builder_refuses_unowned_existing_output(self):
        self.output.mkdir()
        (self.output / 'mine').write_text('keep')
        with self.assertRaises((ValueError, OSError)): modern.build(self.repo, self.output)
        self.assertEqual((self.output / 'mine').read_text(), 'keep')

    def test_npm_builder_preserves_orphan_or_unowned_receipt(self):
        receipt = self.output.with_name(self.output.name + '.build-receipt.json')
        receipt.write_text('Do not overwrite this unrelated file')
        with self.assertRaisesRegex(ValueError, 'Receipt exists'):
            modern.build(self.repo, self.output)
        self.assertEqual(receipt.read_text(), 'Do not overwrite this unrelated file')
        self.assertFalse(self.output.exists())

    def test_npm_builder_refuses_protected_source_targets(self):
        for path in (self.repo, self.repo / 'site/out', self.repo / '.git/out', self.repo.parent):
            with self.subTest(path=path), self.assertRaises(ValueError): modern.build(self.repo, path)

    def test_stale_staged_content_refused_even_with_same_approved_slug(self):
        self.article()
        dist, receipt = self.fake_dist()
        self.article('A new explicitly approved version.\n')
        with self.assertRaisesRegex(ValueError, 'approved version'):
            modern.finalize(self.repo, dist, receipt, self.output)
        self.assertFalse(self.output.exists())

    def test_changed_approved_title_also_invalidates_stage(self):
        self.article(title='Original title')
        dist, receipt = self.fake_dist()
        self.article(title='New approved title')
        with self.assertRaisesRegex(ValueError, 'approved version'):
            modern.finalize(self.repo, dist, receipt, self.output)
        self.assertFalse(self.output.exists())

    def test_receipt_bound_to_removed_legacy_projection_is_rejected(self):
        dist, receipt = self.fake_dist()
        record = json.loads(receipt.read_text())
        record['publicDataSha256'] = modern.digest(modern.json_bytes({
            'articles': [], 'legacy': [], 'downloads': [],
        }))
        receipt.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, 'approved version'):
            modern.finalize(self.repo, dist, receipt, self.output)
        self.assertFalse(self.output.exists())

    def test_receipt_cannot_omit_approved_article_route(self):
        self.article()
        dist, receipt = self.fake_dist()
        record = json.loads(receipt.read_text())
        del record['files']['wiki/fixture/index.html']
        receipt.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, 'Unexpected generated route'):
            modern.finalize(self.repo, dist, receipt, self.output)
        self.assertFalse(self.output.exists())

    def test_finalize_cannot_write_into_protected_source_directory(self):
        dist, receipt = self.fake_dist()
        with self.assertRaises(ValueError):
            modern.finalize(self.repo, dist, receipt, self.repo / 'site/output')
        self.assertFalse((self.repo / 'site/output').exists())

    def test_duplicate_receipt_keys_fail_closed(self):
        dist, receipt = self.fake_dist()
        receipt.write_text('{"files":{},"files":{}}')
        with self.assertRaisesRegex(ValueError, 'Duplicate receipt key'):
            modern.finalize(self.repo, dist, receipt, self.output)

    def test_fifo_artifact_refused_without_opening_or_blocking(self):
        dist, receipt = self.fake_dist()
        os.mkfifo(dist / 'fifo')
        with self.assertRaises(ValueError):
            modern.finalize(self.repo, dist, receipt, self.output)

    def test_dist_root_symlink_refused(self):
        dist, receipt = self.fake_dist()
        link = self.base / 'linked-dist'
        link.symlink_to(dist, target_is_directory=True)
        with self.assertRaises(ValueError):
            modern.finalize(self.repo, link, receipt, self.output)

    def test_repo_inputs_are_never_changed(self):
        before = tree_snapshot(self.repo)
        self.staged()
        self.assertEqual(before, tree_snapshot(self.repo))


if __name__ == '__main__':
    unittest.main()
