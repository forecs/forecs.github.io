"""Adversarial, filesystem-isolated tests for the public static-site builder.

Run from the checkout with::

    PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p test_build_site.py

Unit tests use validator doubles with matching on-disk bodies and sidecars.
Optional integration tests use the shared validator when available, still with
only temporary fixture articles. No repository articles are used. Subprocess
tests also explicitly disable bytecode writes.
"""

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
from urllib.parse import urljoin


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
        self.allowlist = self.repo / "site" / "legacy-files.txt"
        self.allowlist.write_text("", encoding="utf-8")
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

    def allow(self, *paths):
        self.allowlist.write_text("".join(path + "\n" for path in paths), encoding="utf-8")


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


class BuildSiteTests(unittest.TestCase):
    def setUp(self):
        self.fixture = self.new_fixture()

    def new_fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="build-site-test-")
        self.addCleanup(temporary.cleanup)
        return Fixture(Path(temporary.name))

    def build(self, fixture=None, repo=None, output=None):
        fixture = fixture or self.fixture
        with mock.patch.object(
            build_site, "validate_articles", return_value=fixture.articles
        ) as validator:
            result = build_site.build(
                repo if repo is not None else fixture.repo,
                output if output is not None else fixture.output,
            )
        return result, validator

    def reject(self, fixture=None, repo=None, output=None, validator_error=None):
        """Every rejected build must leave the *whole* fixture tree untouched."""
        fixture = fixture or self.fixture
        before = tree_snapshot(fixture.base)
        with mock.patch.object(
            build_site,
            "validate_articles",
            return_value=fixture.articles,
            side_effect=validator_error,
        ):
            with self.assertRaises(ValueError):
                build_site.build(
                    repo if repo is not None else fixture.repo,
                    output if output is not None else fixture.output,
                )
        self.assertEqual(before, tree_snapshot(fixture.base), "failed preflight wrote files")

    def document(self, relative, fixture=None):
        fixture = fixture or self.fixture
        path = fixture.output / relative
        self.assertTrue(path.is_file(), str(path))
        return Document(path.read_text(encoding="utf-8"))

    def assert_csp(self, document):
        policies = [
            attrs.get("content", "")
            for attrs in document.attributes("meta")
            if attrs.get("http-equiv", "").lower() == "content-security-policy"
        ]
        self.assertTrue(policies, "generated HTML lacks a CSP meta element")
        directives = [
            directive.strip().split()
            for policy in policies
            for directive in policy.split(";")
        ]
        self.assertIn(["default-src", "'none'"], directives)

    def test_build_error_is_a_value_error(self):
        self.assertTrue(issubclass(build_site.BuildError, ValueError))

    def test_build_creates_home_wiki_and_articles_and_uses_validator(self):
        f = self.fixture
        f.article("second", "Second article", "Second body unique phrase.\n")
        result, validator = self.build()
        self.assertIsNone(result)
        validator.assert_called_once()
        home = self.document("index.html")
        listing = self.document("wiki/index.html")
        self.assertIn("Hello world", listing.text)
        self.assertIn("Second article", listing.text)
        self.assertIn("A searchable body needle.", listing.text)
        self.assertIn("Second body unique phrase.", listing.text)
        self.assertTrue(home.attributes("a"), "home should link to site content")
        for slug, title in (("hello-world", "Hello world"), ("second", "Second article")):
            page = self.document("wiki/" + slug + "/index.html")
            self.assertIn(title, page.text)
            self.assertTrue(
                any(slug in attrs.get("href", "") for attrs in listing.attributes("a")),
                "wiki listing must link to each article",
            )
        for path in f.output.rglob("*.html"):
            self.assert_csp(Document(path.read_text(encoding="utf-8")))

    def test_listing_contains_full_body_not_a_summary(self):
        f = self.fixture
        body = "Early search marker.\n\n" + ("Long middle paragraph.\n\n" * 400)
        body += "Final full-text sentinel 中文検索.\n"
        f.articles.clear()
        f.article("long-body", "Long article", body)
        self.build()
        for relative in ("wiki/index.html", "wiki/long-body/index.html"):
            text = self.document(relative).text
            self.assertIn("Early search marker.", text)
            self.assertIn("Final full-text sentinel 中文検索.", text)

    def test_empty_articles_and_empty_allowlist_are_valid(self):
        self.fixture.articles.clear()
        (self.fixture.repo / "publish_articles/hello-world.md").unlink()
        (self.fixture.repo / "publish_articles/hello-world.json").unlink()
        self.build()
        self.assert_csp(self.document("index.html"))
        self.assert_csp(self.document("wiki/index.html"))
        self.assertFalse((self.fixture.output / "legacy/index.html").exists())

    def test_existing_empty_output_is_accepted(self):
        self.fixture.output.mkdir()
        self.build()
        self.document("wiki/hello-world/index.html")

    def test_markdown_headings_lists_and_code_are_rendered_safely(self):
        f = self.fixture
        f.articles.clear()
        body = (
            "# First heading\n\n## Second heading\n\n"
            "- First bullet\n- Second bullet\n\n"
            "1. First ordered item\n2. Second ordered item\n\n"
            "Inline `x < y && y > z` code.\n\n"
            "```html\n<script>fenced_attack()</script>\n<a href=\"https://evil.invalid\">x</a>\n```\n"
        )
        f.article("formatting", "Formatting", body)
        self.build()
        page = self.document("wiki/formatting/index.html")
        tags = [tag for tag, _ in page.elements]
        for tag in ("h1", "h2", "ul", "ol", "li", "pre", "code"):
            self.assertIn(tag, tags)
        self.assertGreaterEqual(tags.count("li"), 4)
        self.assertIn("x < y && y > z", page.text)
        self.assertIn("<script>fenced_attack()</script>", page.text)
        self.assertNotIn("script", tags)
        self.assertFalse(any("evil.invalid" in a.get("href", "") for a in page.attributes("a")))

    def test_title_and_body_attacks_remain_text_on_all_generated_pages(self):
        f = self.fixture
        f.articles.clear()
        title = '</title><script>title_attack()</script> & "quoted" <b>bold</b>'
        body = (
            '<script>body_attack()</script>\n\n'
            '<img src="https://evil.invalid/pixel" onerror="image_attack()">\n\n'
            '<a href="javascript:anchor_attack()">raw anchor</a>\n\n'
            '<svg onload="svg_attack()"></svg>\n\n'
            '<iframe src="https://evil.invalid/frame"></iframe>\n\n'
            '</main><form action="https://evil.invalid/post">form attack</form>\n\n'
            'Literal &amp; entity, < and > and "quotes".\n'
        )
        f.article("attacks", title, body)
        self.build()
        for relative in ("index.html", "wiki/index.html", "wiki/attacks/index.html"):
            with self.subTest(page=relative):
                page = self.document(relative)
                self.assert_csp(page)
                tags = [tag for tag, _ in page.elements]
                for forbidden in ("script", "img", "svg", "iframe"):
                    self.assertNotIn(forbidden, tags)
                for _, attrs in page.elements:
                    self.assertFalse(any(key.lower().startswith("on") for key in attrs))
                    for name in ("href", "src", "action", "srcdoc"):
                        value = attrs.get(name, "")
                        self.assertNotIn("evil.invalid", value)
                        self.assertNotIn("javascript:", value.lower())
        for relative in ("wiki/index.html", "wiki/attacks/index.html"):
            page = self.document(relative)
            self.assertIn(title, page.text)
            self.assertIn('<script>body_attack()</script>', page.text)
            self.assertIn('Literal &amp; entity, < and > and "quotes".', page.text)

    def test_markdown_links_images_liquid_and_frontmatter_are_inert(self):
        f = self.fixture
        f.articles.clear()
        literals = [
            '[external](https://evil.invalid/link "hover")',
            '[javascript](javascript:alert(1))',
            '[local](../../private.txt)',
            '![pixel](https://evil.invalid/image.png)',
            '[reference][secret]',
            '[secret]: https://evil.invalid/reference',
            '<https://evil.invalid/autolink>',
            '{{ site.secret }}',
            '{% include private.html %}',
            '{% raw %}<script>liquid_attack()</script>{% endraw %}',
            'layout: secret-layout',
            'redirect_to: https://evil.invalid/redirect',
        ]
        body = "---\n" + "\n".join(literals[-2:]) + "\n---\n\n"
        body += "\n\n".join(literals[:-2]) + "\n"
        f.article("inert", "Inert syntax", body)
        self.build()
        for relative in ("wiki/inert/index.html", "wiki/index.html"):
            with self.subTest(page=relative):
                page = self.document(relative)
                for literal in literals:
                    self.assertIn(literal, page.text)
                self.assertFalse(page.attributes("img"))
                self.assertFalse(page.attributes("script"))
                for attrs in page.attributes("a"):
                    self.assertNotIn("evil.invalid", attrs.get("href", ""))
                    self.assertNotIn("javascript:", attrs.get("href", "").lower())
                    self.assertNotIn("private.txt", attrs.get("href", ""))
                self.assertFalse(
                    any(a.get("http-equiv", "").lower() == "refresh" for a in page.attributes("meta"))
                )

    def test_only_validated_bodies_and_rows_are_published(self):
        f = self.fixture
        f.articles.clear()
        body = "Approved public text.\n"
        f.article("approved", "Approved title", body)
        f.put("publish_articles/unvalidated.md", "UNVALIDATED_ARTICLE_SENTINEL")
        f.put("drafts/secret.md", "DRAFT_SENTINEL")
        f.put("pending/private.md", "PENDING_SENTINEL")
        f.put("artifacts/metadata.json", '{"secret": "METADATA_SENTINEL"}')
        f.put("publish_articles/review.json", '{"secret": "REVIEW_SENTINEL"}')
        f.put("Demo.exe", b"MZ\x00EXECUTABLE_SENTINEL")
        f.put("main.cpp", "CPP_SENTINEL")
        f.put("unlisted.html", "UNLISTED_HTML_SENTINEL")
        f.put("css/unlisted.css", "UNLISTED_CSS_SENTINEL")
        self.build()
        output_files = [p for p in f.output.rglob("*") if p.is_file()]
        combined = b"\n".join(p.read_bytes() for p in output_files)
        self.assertIn(body.strip().encode(), combined)
        for marker in (
            "UNVALIDATED_ARTICLE_SENTINEL",
            "DRAFT_SENTINEL", "PENDING_SENTINEL", "METADATA_SENTINEL",
            "REVIEW_SENTINEL", "EXECUTABLE_SENTINEL", "CPP_SENTINEL",
            "UNLISTED_HTML_SENTINEL", "UNLISTED_CSS_SENTINEL",
        ):
            self.assertNotIn(marker.encode(), combined)
        for path in output_files:
            self.assertNotIn(path.suffix, (".md", ".json", ".exe", ".cpp"))
        self.assertFalse((f.output / "wiki/unvalidated").exists())

    def test_allowlisted_assets_are_copied_byte_for_byte_at_original_paths(self):
        f = self.fixture
        extensions = (
            "html", "css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico",
            "webp", "avif", "woff", "woff2", "ttf", "otf", "eot",
        )
        payloads = {}
        for extension in extensions:
            path = "assets/nested/file." + extension
            payloads[path] = b"\x00\xff\r\nEXACT BYTES " + extension.encode() + b"\n"
            f.put(path, payloads[path])
        f.allow(*payloads)
        self.build()
        for path, data in payloads.items():
            with self.subTest(path=path):
                self.assertEqual(data, (f.output / path).read_bytes())
        self.assertFalse((f.output / "legacy/index.html").exists())

    def test_root_legacy_index_is_relocated_and_gets_root_base(self):
        f = self.fixture
        old = (
            '<!doctype html><html><head><title>Old site</title></head>'
            '<body><p>UNIQUE_LEGACY_CONTENT</p><a href="archives/old.html">old</a>'
            '<script src="js/old.js"></script></body></html>'
        )
        f.put("index.html", old)
        f.put("archives/old.html", b"old archive\r\n")
        f.put("js/old.js", b"old_script();\r\n")
        f.allow("index.html", "archives/old.html", "js/old.js")
        self.build()
        legacy = self.document("legacy/index.html")
        self.assertIn("UNIQUE_LEGACY_CONTENT", legacy.text)
        self.assertEqual(["/"], [a.get("href") for a in legacy.attributes("base")])
        self.assertIn({"src": "js/old.js"}, legacy.attributes("script"))
        self.assertEqual(b"old archive\r\n", (f.output / "archives/old.html").read_bytes())
        self.assertEqual(b"old_script();\r\n", (f.output / "js/old.js").read_bytes())
        home = self.document("index.html")
        self.assertNotIn("UNIQUE_LEGACY_CONTENT", home.text)
        self.assert_csp(home)
        self.assert_csp(self.document("wiki/index.html"))

    def test_legacy_fragment_links_stay_on_relocated_root(self):
        f = self.fixture
        old = (
            '<html><head><title>Old</title></head><body>\n'
            '<a href="#heading" title="A &amp; B">jump</a>'
            '<area href=#map /><a href="">same page</a>'
            '<a href="archives/">archives</a><a href="/">home</a>'
            '<!-- <a href="#comment"> -->'
            '<script>var example = \'<a href="#script">\';</script>'
            '</body></html>'
        )
        f.put('index.html', old)
        f.allow('index.html')
        self.build()
        legacy = self.document('legacy/index.html')
        hrefs = [a.get('href') for a in legacy.attributes('a')]
        self.assertIn('/legacy/index.html#heading', hrefs)
        self.assertIn('/legacy/index.html', hrefs)
        self.assertIn({'href': '/legacy/index.html#map'}, legacy.attributes('area'))
        base = urljoin('https://example.test/legacy/index.html', legacy.attributes('base')[0]['href'])
        self.assertEqual('https://example.test/archives/', urljoin(base, 'archives/'))
        self.assertEqual('https://example.test/legacy/index.html#heading', urljoin(base, hrefs[0]))
        result = (f.output / 'legacy/index.html').read_text(encoding='utf-8')
        self.assertIn('<!-- <a href="#comment"> -->', result)
        self.assertIn('var example = \'<a href="#script">\';', result)
        self.assertEqual(old, (f.repo / 'index.html').read_text(encoding='utf-8'))

    def test_existing_legacy_base_requires_explicit_review(self):
        self.fixture.put('index.html', '<html><head><BASE href="/other/"></head></html>')
        self.fixture.allow('index.html')
        self.reject()

    def test_invalid_validator_results_fail_before_output(self):
        invalid_slugs = ('../escape', 'a/b', 'a\\b', 'UPPER', '中文', '', 'a' * 81, 'a%2fb')
        mutations = [{'slug': slug} for slug in invalid_slugs]
        mutations += [{'title': None}, {'body': 42}, {'sha256': 'bad'},
                      {'sha256': '0' * 64}, {'unexpected': 'metadata'}]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                f = self.new_fixture()
                f.articles[0].update(mutation)
                self.reject(f)
        for value in (None, {}, ['not an article']):
            with self.subTest(result=value):
                f = self.new_fixture()
                f.articles = value
                self.reject(f)
        f = self.new_fixture()
        f.articles.append(dict(f.articles[0]))
        self.reject(f)

    @unittest.skipUnless((CHECKOUT / 'scripts/content.py').is_file(), 'shared validator not supplied yet')
    def test_real_shared_validator_approval_and_tamper_rejection(self):
        f = self.fixture
        build_site.build(f.repo, f.output)
        self.assertIn('A searchable body needle.', self.document('wiki/hello-world/index.html').text)
        f.put('publish_articles/hello-world.md', 'Changed without fresh approval.\n')
        before = tree_snapshot(f.base)
        with self.assertRaises(ValueError):
            build_site.build(f.repo, f.base / 'tampered-output')
        self.assertEqual(before, tree_snapshot(f.base))

    def test_unlisted_root_index_is_not_published(self):
        self.fixture.put("index.html", "UNLISTED_OLD_ROOT")
        self.build()
        self.assertFalse((self.fixture.output / "legacy/index.html").exists())
        self.assertNotIn("UNLISTED_OLD_ROOT", self.document("index.html").text)

    def test_required_input_directory_and_allowlist_file(self):
        for kind in ("missing_articles", "articles_file", "missing_allowlist", "allowlist_directory"):
            with self.subTest(kind=kind):
                f = self.new_fixture()
                if kind in ("missing_articles", "articles_file"):
                    shutil.rmtree(f.repo / "publish_articles")
                    if kind == "articles_file":
                        f.put("publish_articles", "not a directory")
                else:
                    f.allowlist.unlink()
                    if kind == "allowlist_directory":
                        f.allowlist.mkdir()
                self.reject(f)

    def test_missing_or_file_repository_is_rejected_without_writes(self):
        f = self.fixture
        file_repo = f.base / "file-repo"
        file_repo.write_text("not a repo", encoding="utf-8")
        for repo in (f.base / "missing-repo", file_repo):
            with self.subTest(repo=repo.name):
                self.reject(repo=repo)

    def test_validator_failure_is_preflighted_before_any_writes(self):
        for existing in (False, True):
            with self.subTest(existing_output=existing):
                f = self.new_fixture()
                f.put("assets/good.css", "good")
                f.allow("assets/good.css")
                if existing:
                    f.output.mkdir()
                self.reject(f, validator_error=ValueError("invalid published article"))

    def test_nonempty_output_including_hidden_entries_is_rejected(self):
        for entry in ("keep.txt", ".keep", "empty-directory"):
            with self.subTest(entry=entry):
                f = self.new_fixture()
                f.output.mkdir()
                if entry == "empty-directory":
                    (f.output / entry).mkdir()
                else:
                    (f.output / entry).write_bytes(b"DO NOT OVERWRITE")
                self.reject(f)

    def test_output_file_and_file_ancestor_are_rejected(self):
        f = self.fixture
        obstacle = f.base / "obstacle"
        obstacle.write_bytes(b"DO NOT OVERWRITE")
        for output in (obstacle, obstacle / "child"):
            with self.subTest(output=str(output)):
                self.reject(output=output)

    def test_late_invalid_allowlist_entry_leaves_no_partial_output(self):
        for existing in (False, True):
            with self.subTest(existing_output=existing):
                f = self.new_fixture()
                f.put("assets/first.css", "first valid entry")
                f.put("assets/second.png", b"second valid entry")
                f.allow("assets/first.css", "assets/second.png", "assets/missing.js")
                if existing:
                    f.output.mkdir()
                self.reject(f)

    def test_allowlist_strict_posix_path_spellings(self):
        bad_paths = (
            "/absolute.html", "../escape.html", "assets/../escape.html",
            "./index.html", "assets/./ok.css", "assets//ok.css", "assets/ok.css/",
            "assets\\ok.css", "C:/assets/ok.css", "assets/name:part.css",
            "assets/%2e%2e/ok.css", "assets/100%real.css", "assets/ok.css?x=1",
            "assets/ok.css#fragment", "assets/.hidden/ok.css", ".cache/ok.css",
            "assets/.hidden.css", ".", "..",
        )
        for path in bad_paths:
            with self.subTest(path=path):
                f = self.new_fixture()
                # Supply the would-be target wherever possible so path validation,
                # rather than merely a nonexistent file, is exercised.
                if not path.startswith("/") and "\\" not in path:
                    candidate = f.repo / path
                    try:
                        candidate.parent.mkdir(parents=True, exist_ok=True)
                        if not candidate.is_dir():
                            candidate.write_bytes(b"forbidden spelling")
                    except (OSError, ValueError):
                        pass
                if path == "assets\\ok.css":
                    f.put(path, b"literal backslash filename")
                    f.put("assets/ok.css", b"normalized target")
                f.allow(path)
                self.reject(f)

    def test_existing_absolute_allowlist_target_is_rejected(self):
        f = self.fixture
        outside = f.base / "outside.html"
        outside.write_bytes(b"PRIVATE OUTSIDE FILE")
        f.allow(str(outside))
        self.reject()

    def test_allowlist_protected_directories_at_root_and_nested(self):
        protected = (
            "wiki", "legacy", "scripts", "tests", "site", "publish_articles",
            ".git", "drafts", "pending", "artifacts",
        )
        for directory in protected:
            for prefix in ("", "assets/"):
                with self.subTest(directory=directory, prefix=prefix):
                    f = self.new_fixture()
                    path = prefix + directory + "/leak.html"
                    f.put(path, "SHOULD NOT BE PUBLISHED")
                    f.allow(path)
                    self.reject(f)

    def test_nonallowlisted_extensions_are_rejected_even_when_files_exist(self):
        for name in ("app.exe", "source.cpp", "secret.md", "state.json", "config.yml", "run.py", "archive.zip", "noextension", "image.png.exe"):
            with self.subTest(name=name):
                f = self.new_fixture()
                path = "assets/" + name
                f.put(path, b"not public")
                f.allow(path)
                self.reject(f)

    def test_duplicate_allowlist_paths_are_rejected(self):
        f = self.fixture
        f.put("assets/same.css", "same")
        f.allow("assets/same.css", "assets/same.css")
        self.reject()

    def test_allowlisted_directory_is_not_a_file(self):
        f = self.fixture
        (f.repo / "assets/directory.html").mkdir(parents=True)
        f.allow("assets/directory.html")
        self.reject()

    def test_output_cannot_overlap_input_directories(self):
        f = self.fixture
        f.put("assets/approved.css", "approved")
        f.allow("assets/approved.css")
        outputs = (
            f.repo, f.base,
            f.repo / "publish_articles", f.repo / "publish_articles/generated",
            f.repo / "site", f.repo / "site/generated",
            f.repo / "assets", f.repo / "assets/generated",
        )
        for output in outputs:
            with self.subTest(output=str(output)):
                self.reject(output=output)

    def test_symlink_repository_and_repository_ancestor_are_rejected(self):
        f = self.fixture
        alias = f.base / "repo-link"
        alias.symlink_to(f.repo, target_is_directory=True)
        self.reject(repo=alias)
        parent_alias = f.base / "parent-link"
        parent_alias.symlink_to(f.base, target_is_directory=True)
        self.reject(repo=parent_alias / "repo")
        dangling = f.base / "missing-repo-link"
        dangling.symlink_to(f.base / "absent", target_is_directory=True)
        self.reject(repo=dangling)

    def test_symlink_required_inputs_and_allowlist_are_rejected(self):
        for name in ("publish_articles", "site", "site/legacy-files.txt"):
            for dangling in (False, True):
                with self.subTest(name=name, dangling=dangling):
                    f = self.new_fixture()
                    path = f.repo / name
                    is_directory = path.is_dir()
                    target = f.base / "relocated-input"
                    path.rename(target)
                    path.symlink_to(
                        f.base / "absent" if dangling else target,
                        target_is_directory=is_directory,
                    )
                    self.reject(f)

    def test_symlink_published_article_is_rejected_even_with_fake_validator(self):
        for suffix in ("md", "json"):
            for dangling in (False, True):
                with self.subTest(suffix=suffix, dangling=dangling):
                    f = self.new_fixture()
                    article = f.repo / ("publish_articles/hello-world." + suffix)
                    target = f.base / ("outside-article." + suffix)
                    article.rename(target)
                    article.symlink_to(f.base / "absent" if dangling else target)
                    self.reject(f)

    def test_unreturned_published_input_symlinks_are_also_rejected(self):
        for dangling in (False, True):
            with self.subTest(dangling=dangling):
                f = self.new_fixture()
                target = f.base / "outside.md"
                if not dangling:
                    target.write_text("Not approved", encoding="utf-8")
                (f.repo / "publish_articles/unreturned.md").symlink_to(target)
                self.reject(f)

    def test_changed_approved_bytes_are_rejected_without_partial_output(self):
        f = self.fixture
        f.article("second", "Second article", "Approved second body.\n")
        # The digest was correct when validation returned; simulate changed input.
        f.put("publish_articles/second.md", "Unapproved replacement body.\n")
        self.reject()

    def test_non_utf8_text_inputs_are_preflighted_before_output_creation(self):
        for kind in ("manifest", "legacy_root"):
            with self.subTest(kind=kind):
                f = self.new_fixture()
                if kind == "manifest":
                    f.allowlist.write_bytes(b"assets/\xff.css\n")
                else:
                    f.put("index.html", b"<html>\xff</html>")
                    f.allow("index.html")
                self.reject(f)

    def test_symlink_output_and_output_ancestors_are_rejected(self):
        for kind in ("empty_directory", "file", "dangling", "ancestor", "dangling_ancestor"):
            with self.subTest(kind=kind):
                f = self.new_fixture()
                target = f.base / "target"
                if kind in ("empty_directory", "ancestor"):
                    target.mkdir()
                elif kind == "file":
                    target.write_bytes(b"DO NOT TOUCH")
                link = f.base / "output-link"
                link.symlink_to(target, target_is_directory=(kind != "file"))
                output = link / "nested/output" if "ancestor" in kind else link
                self.reject(f, output=output)

    def test_symlink_allowlisted_file_and_path_component_are_rejected(self):
        for kind in ("file", "dangling_file", "directory", "dangling_directory", "root_index"):
            with self.subTest(kind=kind):
                f = self.new_fixture()
                if "directory" in kind:
                    target = f.base / "outside-assets"
                    target.mkdir()
                    (target / "approved.css").write_bytes(b"outside asset")
                    link = f.repo / "assets"
                    link.symlink_to(
                        f.base / "absent" if kind.startswith("dangling") else target,
                        target_is_directory=True,
                    )
                    f.allow("assets/approved.css")
                else:
                    target = f.base / "outside.html"
                    target.write_bytes(b"outside file")
                    relative = "index.html" if kind == "root_index" else "assets/approved.html"
                    link = f.repo / relative
                    link.parent.mkdir(parents=True, exist_ok=True)
                    link.symlink_to(f.base / "absent" if kind.startswith("dangling") else target)
                    f.allow(relative)
                self.reject(f)


class IsolatedImportAndCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="build-site-cli-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.checkout = self.base / "checkout"
        scripts = self.checkout / "scripts"
        scripts.mkdir(parents=True)
        # Deliberately copy only the builder, never content.py or real articles.
        self.builder = scripts / "build_site.py"
        shutil.copyfile(CHECKOUT / "scripts/build_site.py", self.builder)
        self.env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        self.env.pop("PYTHONPATH", None)

    def run_python(self, *args):
        return subprocess.run(
            [sys.executable, "-B", "-I", *args],
            cwd=self.checkout,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    def test_module_import_does_not_require_content_validator(self):
        code = (
            "import sys; "
            "sys.path.insert(0, sys.argv[1]); "
            "import scripts.build_site as builder; "
            "assert callable(builder.build); "
            "assert callable(builder.validate_articles); "
            "assert issubclass(builder.BuildError, ValueError); "
            "assert 'content' not in sys.modules; "
            "assert 'scripts.content' not in sys.modules"
        )
        result = self.run_python("-c", code, str(self.checkout))
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertFalse(list(self.base.rglob("__pycache__")))

    @unittest.skipUnless((CHECKOUT / 'scripts/content.py').is_file(), 'shared validator not supplied yet')
    def test_standalone_cli_with_real_validator_from_another_working_directory(self):
        shutil.copyfile(CHECKOUT / 'scripts/content.py', self.builder.parent / 'content.py')
        (self.checkout / 'publish_articles').mkdir()
        (self.checkout / 'site').mkdir()
        (self.checkout / 'site/legacy-files.txt').write_text('', encoding='utf-8')
        body = '# CLI article\n\nApproved body.\n'
        (self.checkout / 'publish_articles/cli.md').write_bytes(body.encode('utf-8'))
        (self.checkout / 'publish_articles/cli.json').write_text(json.dumps({
            'title': 'CLI article', 'sha256': hashlib.sha256(body.encode('utf-8')).hexdigest()
        }), encoding='utf-8')
        result = subprocess.run(
            [sys.executable, '-B', str(self.builder), '--output', 'cli-output'],
            cwd=self.base, env=self.env, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertTrue((self.checkout / 'cli-output/wiki/cli/index.html').is_file())
        self.assertFalse((self.base / 'cli-output').exists())
        self.assertFalse(list(self.base.rglob('__pycache__')))

    def test_standalone_cli_reports_missing_validator_without_creating_output(self):
        (self.checkout / "publish_articles").mkdir()
        (self.checkout / "site").mkdir()
        (self.checkout / "site/legacy-files.txt").write_text("", encoding="utf-8")
        (self.checkout / "publish_articles/sample.md").write_text("Sample body.\n", encoding="utf-8")
        output = self.base / "cli-output"
        before = tree_snapshot(self.base)
        result = self.run_python(str(self.builder), "--output", str(output))
        self.assertNotEqual(0, result.returncode, "CLI unexpectedly succeeded without its validator")
        diagnostic = (result.stdout + result.stderr).lower()
        self.assertRegex(diagnostic, r"content(?:\.py)?|validator|validate_articles")
        self.assertNotIn("unrecognized arguments", diagnostic, "CLI interface mismatch")
        self.assertFalse(output.exists())
        self.assertEqual(before, tree_snapshot(self.base), "failed CLI wrote files or bytecode")


if __name__ == "__main__":
    unittest.main()
