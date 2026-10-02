"""Independent post-build audit rejects even receipt-authorized source pollution."""
import json
from pathlib import Path
import tempfile
import unittest
from scripts import audit_site, modern_site as modern


class ArtifactAuditTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name)
        (self.repo / 'publish_articles').mkdir()
        self.out = self.repo / 'output'
        self.out.mkdir()
        self.files = {name: b'fixture' for name in modern.FIXED_OUTPUT}
        self.files['.nojekyll'] = b''
        self.files['assets/app.123.js'] = b'public runtime'

    def write(self):
        for name, data in self.files.items():
            p = self.out / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        self.out.with_name('output.build-receipt.json').write_text(json.dumps({
            name: modern.digest(data) for name, data in self.files.items()
        }))

    def test_exact_modern_output(self):
        self.write()
        self.assertEqual(audit_site.audit(self.repo, self.out)['pages'],
                         ['404.html', 'index.html', 'wiki/index.html'])

    def test_receipt_cannot_authorize_retired_routes_or_raw_sources(self):
        for name in ('legacy/index.html', 'archive/index.html', 'archives/index.html',
                     '2016/post/index.html', 'main.cpp', 'Demo.exe', 'scripts/tool.py',
                     'tests/test.py', 'publish_articles/a.json', 'raw.md', 'assets/source.map'):
            with self.subTest(name=name):
                self.files[name] = b'pollution'
                self.write()
                with self.assertRaises(ValueError): audit_site.audit(self.repo, self.out)
                (self.out / name).unlink()
                # Remove directories left empty by this synthetic case.
                parent = (self.out / name).parent
                while parent != self.out and not any(parent.iterdir()):
                    parent.rmdir()
                    parent = parent.parent
                del self.files[name]

    def test_digest_tampering(self):
        self.write()
        (self.out / 'index.html').write_bytes(b'changed')
        with self.assertRaises(ValueError): audit_site.audit(self.repo, self.out)

    def test_private_build_path_and_retired_links(self):
        for data in (str(self.repo).encode(), b'_build-temp-private',
                     b'<a href="/legacy/">old</a>', b'<a href="/archive/">old</a>',
                     b'<a href=/main.cpp>source</a>', b'<a href=/Demo.exe>exe</a>',
                     b'<a href="https://github.com/forecs/forecs.github.io/blob/old/main.cpp">old</a>'):
            self.files['index.html'] = data
            self.write()
            with self.assertRaises(ValueError): audit_site.audit(self.repo, self.out)

    def test_symlink_output_is_rejected(self):
        self.write()
        link = self.repo / 'link'
        link.symlink_to(self.out)
        with self.assertRaises(ValueError): audit_site.audit(self.repo, link)

    def test_escaped_article_examples_are_not_links(self):
        self.files['index.html'] = b'<pre>&lt;a href="/archives/"&gt;example&lt;/a&gt;</pre>'
        self.files['assets/app.123.js'] = b"const approvedText = 'href=\"/archives/\"';"
        self.write()
        audit_site.audit(self.repo, self.out)
