"""Adversarial tests for the shared modern-site safety/renderer helpers."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from html.parser import HTMLParser
from unittest import mock


CHECKOUT = Path(__file__).resolve().parents[1]
# Support both unittest discovery and direct execution without installing scripts.
if str(CHECKOUT) not in sys.path:
    sys.path.insert(0, str(CHECKOUT))
build_site = importlib.import_module("scripts.build_site")


class Document(HTMLParser):
    """Inspect HTML semantically, without depending on whitespace or templates."""

    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.elements = []
        self.text_parts = []
        self.feed(source)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_data(self, data):
        self.text_parts.append(data)

    @property
    def text(self):
        return "".join(self.text_parts)

    def attributes(self, tag):
        return [attrs for name, attrs in self.elements if name == tag]


class Fixture:
    def __init__(self, base):
        self.base = base
        self.repo = base / "repo"
        self.repo.mkdir()
        (self.repo / "publish_articles").mkdir()
        (self.repo / "site").mkdir()
        self.output = base / "output"
        self.articles = []
        self.article("hello-world", "Hello world", "A searchable body needle.\n")

    def put(self, relative, data):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            data = data.encode("utf-8")
        path.write_bytes(data)
        return path

    def article(self, slug, title, body):
        raw = body.encode("utf-8")
        self.put("publish_articles/" + slug + ".md", raw)
        row = {
            "slug": slug,
            "title": title,
            "body": body,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        self.put(
            "publish_articles/" + slug + ".json",
            json.dumps({"title": title, "sha256": row["sha256"]}),
        )
        self.articles.append(row)
        return row



def tree_snapshot(root):
    """Compare all fixture bytes and directory entries, without following links."""
    entries = {}

    def visit(directory):
        for child in directory.iterdir():
            key = child.relative_to(root).as_posix()
            if child.is_symlink():
                entries[key] = ("symlink", os.readlink(child))
            elif child.is_dir():
                entries[key] = ("directory",)
                visit(child)
            else:
                entries[key] = ("file", child.read_bytes())

    visit(root)
    return entries


class CoreTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='site-core-')
        self.addCleanup(temp.cleanup)
        self.f = Fixture(Path(temp.name))

    def test_validated_projection_and_exact_bytes(self):
        self.assertEqual(build_site._approved(self.f.repo), self.f.articles)
        self.f.put('publish_articles/hello-world.md', 'Changed without review')
        with self.assertRaises(ValueError):
            build_site._approved(self.f.repo)

    def test_invalid_validator_shapes_and_digests(self):
        mutations = [{'slug': s} for s in ('../escape', 'a/b', 'a\\b', 'UPPER', '中文', '', 'a'*81, 'a%2fb')]
        mutations += [{'title': None}, {'body': 42}, {'sha256': 'bad'}, {'sha256': '0'*64}, {'unexpected': 'metadata'}]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                row = dict(self.f.articles[0], **mutation)
                with mock.patch.object(build_site, 'validate_articles', return_value=[row]):
                    with self.assertRaises(ValueError): build_site._approved(self.f.repo)
        for value in (None, {}, ['bad'], [self.f.articles[0]]*2):
            with mock.patch.object(build_site, 'validate_articles', return_value=value):
                with self.assertRaises(ValueError): build_site._approved(self.f.repo)

    def test_body_mismatch_rejected_even_with_matching_digest(self):
        row = dict(self.f.articles[0], body='not the disk body')
        with mock.patch.object(build_site, 'validate_articles', return_value=[row]):
            with self.assertRaises(ValueError): build_site._approved(self.f.repo)

    def test_empty_approved_directory(self):
        for p in (self.f.repo/'publish_articles').iterdir(): p.unlink()
        self.assertEqual(build_site._approved(self.f.repo), [])

    def test_required_article_directory(self):
        root=self.f.repo/'publish_articles'
        shutil.rmtree(root)
        with self.assertRaises(ValueError): build_site._approved(self.f.repo)
        root.write_text('not a directory')
        with self.assertRaises(ValueError): build_site._approved(self.f.repo)

    def test_article_and_unreturned_symlinks_rejected(self):
        for name in ('hello-world.md', 'hello-world.json', 'unreturned.md'):
            with self.subTest(name=name):
                p=self.f.repo/'publish_articles'/name
                raw=p.read_bytes() if p.exists() else None
                if p.exists(): p.unlink()
                p.symlink_to(self.f.base/'absent')
                with self.assertRaises(ValueError): build_site._approved(self.f.repo)
                p.unlink()
                if raw is not None: p.write_bytes(raw)

    def test_article_directory_symlink_rejected(self):
        root=self.f.repo/'publish_articles'; target=self.f.base/'moved'; root.rename(target); root.symlink_to(target)
        with self.assertRaises(ValueError): build_site._approved(self.f.repo)

    def test_directory_and_fifo_article_inputs_rejected(self):
        p=self.f.repo/'publish_articles/unreturned.md'; p.mkdir()
        with self.assertRaises(ValueError): build_site._approved(self.f.repo)
        p.rmdir(); os.mkfifo(p)
        with self.assertRaises(ValueError): build_site._approved(self.f.repo)

    def test_special_and_symlink_reads_fail(self):
        fifo=self.f.base/'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): build_site._read_bytes(fifo)
        with self.assertRaises(ValueError): build_site._read_bytes(self.f.repo)
        link=self.f.base/'link'; link.symlink_to(self.f.repo/'publish_articles/hello-world.md')
        with self.assertRaises(ValueError): build_site._read_bytes(link)

    def test_output_protected_paths(self):
        paths=[self.f.repo,self.f.base,*[self.f.repo/name/'out' for name in build_site.RESERVED], self.f.repo/'.git/out']
        for path in paths:
            with self.subTest(path=path):
                with self.assertRaises(ValueError): build_site._check_output(self.f.repo,path)

    def test_output_symlink_and_parent_traversal(self):
        link=self.f.base/'link'; link.symlink_to(self.f.base)
        for path in (link/'out', self.f.base/'x/../out'):
            with self.assertRaises(ValueError): build_site._check_output(self.f.repo,path)

    def test_output_nonempty_file_or_hidden_directory(self):
        for kind in ('file','hidden','directory'):
            out=self.f.base/kind
            if kind=='file': out.write_text('keep')
            else:
                out.mkdir()
                if kind=='hidden': (out/'.keep').write_text('keep')
                else: (out/'empty').mkdir()
            before=tree_snapshot(self.f.base)
            with self.assertRaises(ValueError): build_site._check_output(self.f.repo,out)
            self.assertEqual(before,tree_snapshot(self.f.base))

    def test_output_absent_or_empty(self):
        build_site._check_output(self.f.repo,self.f.output)
        self.f.output.mkdir()
        build_site._check_output(self.f.repo,self.f.output)

    def test_markdown_supported_formatting(self):
        body='# Heading\n\n## Second\n\n- One\n- Two\n\n1. First\n2. Next\n\nInline `x < y`.\n\n```html\n<script>alert(1)</script>\n```\n'
        doc=Document(build_site.render_markdown(body))
        for tag in ('h1','h2','ul','ol','li','pre','code'):
            self.assertIn(tag,[t for t,_ in doc.elements])
        self.assertIn('<script>alert(1)</script>',doc.text)
        self.assertNotIn('script',[t for t,_ in doc.elements])

    def test_all_active_syntax_is_literal(self):
        literals=['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<iframe src="https://evil.invalid"></iframe>',
                  '<svg onload=alert(1)></svg>', '[link](javascript:alert(1))', '![pixel](https://evil.invalid)',
                  '{{ site.secret }}', '{% include private.html %}', '<!-- @include: ../../private.md -->',
                  '::: raw', 'layout: home', 'Literal &amp; entity']
        doc=Document(build_site.render_markdown('\n\n'.join(literals)))
        for literal in literals: self.assertIn(literal,doc.text)
        self.assertEqual({t for t,_ in doc.elements},{'p'})

    def test_unclosed_code_is_inert(self):
        doc=Document(build_site.render_markdown('```\n<svg onload=alert(1)>'))
        self.assertEqual([t for t,_ in doc.elements],['pre','code'])
        self.assertIn('<svg',doc.text)

    def test_module_is_not_an_alternative_publisher(self):
        self.assertFalse(hasattr(build_site,'build'))
        self.assertFalse(hasattr(build_site,'_legacy'))
        self.assertFalse(hasattr(build_site,'main'))

    def test_import_is_lazy_and_missing_validator_fails_closed(self):
        scripts=self.f.base/'isolated/scripts'; scripts.mkdir(parents=True)
        shutil.copyfile(CHECKOUT/'scripts/build_site.py',scripts/'build_site.py')
        result=subprocess.run([sys.executable,'-B','-I','-c',
            'import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); '
            'import build_site as b; assert "content" not in sys.modules; '
            'b.validate_articles(Path(sys.argv[2]))',str(scripts),str(self.f.repo/'publish_articles')],
            capture_output=True,text=True,timeout=20)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Shared validator scripts/content.py is required',result.stderr)
        self.assertFalse(list(scripts.rglob('__pycache__')))

if __name__ == '__main__':
    unittest.main()
