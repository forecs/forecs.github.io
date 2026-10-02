import argparse
import base64
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import content
import wiki_intake as intake


class FakeGitHubAPI:
    """In-memory Git Data/PR contract; no token, network, or real approval."""
    def __init__(self):
        self.private = True
        self.ref = None
        self.prs = []
        self.files = {}
        self.writes = []
        self.diff = None
        self.master_files = {}

    def __call__(self, endpoint, data=None, missing=False):
        path = endpoint.removeprefix(f"repos/{intake.REPO}").lstrip("/")
        if data is not None:
            self.writes.append(path)
        if path == "":
            return {"private": self.private, "default_branch": "master"}
        if path == "git/ref/heads/master":
            return {"object": {"sha": "base"}}
        if path.startswith("git/ref/heads/wiki-review/"):
            return self.ref
        if path.startswith("contents/"):
            filename, ref = path[9:].split("?ref=")
            value = (self.master_files if ref == "base" else self.files).get(filename)
            return None if value is None else {"type": "file", "encoding": "base64", "content": base64.b64encode(value).decode()}
        if path == "git/commits/base":
            return {"tree": {"sha": "base-tree"}}
        if path == "git/trees":
            self.files = {item["path"]: item["content"].encode() for item in data["tree"]}
            return {"sha": "new-tree"}
        if path == "git/commits":
            return {"sha": "head"}
        if path == "git/refs":
            self.ref = {"object": {"sha": "head"}}
            return self.ref
        if path == "git/commits/head":
            return {"parents": [{"sha": "base"}]}
        if path == "compare/base...head":
            return {"files": self.diff if self.diff is not None else [{"filename": f, "status": "added"} for f in self.files]}
        if path.startswith("pulls?"):
            return self.prs
        if path == "pulls":
            self.prs = [{"html_url": "https://github.com/forecs/forecs.github.io/pull/1", "state": "open", "head": {"sha": "head"}}]
            return self.prs[0]
        raise AssertionError(f"unexpected fake API path {path}")


class ContentTests(unittest.TestCase):
    def test_frontmatter_is_discarded_not_executed(self):
        raw = b'---\ntitle: public\nsource: /home/private\nsecret: hidden\nx: !!python/object/apply:os.system [touch /tmp/no]\n---\n# Hello\n'
        self.assertEqual(content.public_body(raw), b"# Hello\n")

    def test_malformed_and_local_paths_rejected(self):
        for body in (b"---\nsecret: bad", b"file:///etc/passwd", b"/home/user/secret", b"\x00", b" ", b"x" * 262145):
            with self.subTest(body=body[:30]), self.assertRaises(ValueError):
                content.public_body(body)

    def test_slug_restrictions(self):
        for slug in ("../escape", "/abs", "UPPER", "a/b", "a--b", "", "a" * 81):
            with self.subTest(slug=slug), self.assertRaises(ValueError):
                content.validate_slug(slug)

    def test_digest_and_schema_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            body = b"# Public\n"
            (root / "test.md").write_bytes(body)
            (root / "test.json").write_bytes(content.metadata_bytes("Title", body))
            self.assertEqual(len(content.validate_articles(root)), 1)
            (root / "test.md").write_text("Changed\n")
            with self.assertRaises(ValueError):
                content.validate_articles(root)
            (root / "test.md").write_bytes(body)
            (root / "test.json").write_text(json.dumps({**content.metadata("Title", body), "source": "private"}))
            with self.assertRaises(ValueError):
                content.validate_articles(root)

    def test_symlink_and_unpaired_files_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.md").write_text("Data\n")
            with self.assertRaises(ValueError):
                content.validate_articles(root)
            (root / "a.json").symlink_to(root / "a.md")
            with self.assertRaises(ValueError):
                content.validate_articles(root)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.repo = self.root / "repo"
        (self.repo / ".git").mkdir(parents=True)
        self.patch = patch.object(intake, "CHECKOUT", self.repo)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.api = FakeGitHubAPI()
        self.github = lambda: intake.GitHub(self.api)
        (self.source / "old.md").write_text("---\ntitle: Old\nprivate: hidden\n---\n# old\n")

    def args(self, command="submit", **kwargs):
        return argparse.Namespace(command=command, source_root=self.source, dry_run=False,
                                  select=kwargs.get("select"), slug=kwargs.get("slug"), title=kwargs.get("title"), limit=kwargs.get("limit", 1))

    def execute(self, args):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            intake.execute(args, self.github)
        return stream.getvalue()

    def test_no_implicit_backfill(self):
        with self.assertRaises(ValueError):
            self.execute(self.args())
        self.assertEqual(self.api.writes, [])

    def test_baseline_no_upload_existing_edits_ignored_new_incremental(self):
        self.execute(self.args("baseline"))
        self.assertEqual(self.api.writes, [])
        (self.source / "old.md").write_text("Modified historic file\n")
        self.assertIn("no-new-content", self.execute(self.args()))
        (self.source / "new.md").write_text("# New\n")
        self.assertIn('"status": "open"', self.execute(self.args()))
        writes = len(self.api.writes)
        self.assertIn("no-new-content", self.execute(self.args()))
        self.assertEqual(len(self.api.writes), writes)

    def test_dry_run_neither_network_nor_state_writes(self):
        args = self.args(select="old.md", slug="explicit", title="Public title")
        args.dry_run = True
        with patch.object(self, "github", side_effect=AssertionError("no network")):
            self.assertIn("dry-run", self.execute(args))
        self.assertEqual(list((self.repo / ".git").iterdir()), [])
        self.assertEqual(self.api.writes, [])

    def test_explicit_selection_no_metadata_leak_and_repeat_idempotent(self):
        args = self.args(select="old.md", slug="explicit", title="Public title")
        self.execute(args)
        writes = len(self.api.writes)
        self.execute(args)
        self.assertEqual(len(self.api.writes), writes)
        uploaded = b"".join(self.api.files.values())
        for private in (b"hidden", b"old.md", str(self.source).encode()):
            self.assertNotIn(private, uploaded)
        self.assertEqual(len(self.api.files), 2)

    def test_failure_does_not_advance_and_retry_reuses_orphan_ref(self):
        args = self.args(select="old.md")
        real_api = self.api
        def failure(endpoint, data=None, missing=False):
            if endpoint.endswith("/pulls") and data:
                raise RuntimeError("simulated failure after branch creation")
            return real_api(endpoint, data, missing)
        with self.assertRaises(RuntimeError), contextlib.redirect_stdout(io.StringIO()):
            intake.execute(args, lambda: intake.GitHub(failure))
        self.assertEqual(list((self.repo / ".git").glob("*.json")), [])
        refs = self.api.writes.count("git/refs")
        self.execute(args)
        self.assertEqual(self.api.writes.count("git/refs"), refs)

    def test_private_frontmatter_never_supplies_title(self):
        for header in ("# PRIVATE_COMMENT", "title: Public # PRIVATE_COMMENT", "title: |\n  PRIVATE_COMMENT"):
            raw = f"---\n{header}\n---\n# Public heading\nPublic body.\n".encode()
            [item] = intake.candidates({"test.md": raw}, {"baseline": [], "tracked": {}})
            self.assertEqual(json.loads(item["meta"])["title"], "Public heading")
            self.assertNotIn(b"PRIVATE_COMMENT", item["meta"] + item["body"])

    def test_unmergeable_delimiter_body_is_rejected_before_network_or_state(self):
        (self.source / "old.md").write_text("---\ntitle: Public\n---\n---\nPublic body.\n")
        with self.assertRaises(ValueError):
            self.execute(self.args(select="old.md"))
        self.assertEqual(self.api.writes, [])
        self.assertEqual(list((self.repo / ".git").glob("*.json")), [])

    def test_tracked_edits_retain_explicit_public_slug_and_title(self):
        self.execute(self.args(select="old.md", slug="chosen-slug", title="Chosen title"))
        (self.source / "old.md").write_text("# New source title\nChanged body\n")
        state_path = next((self.repo / ".git").glob("*.json"))
        state = json.loads(state_path.read_text())
        _, files = intake.source_files(self.source)
        batch = intake.candidates(files, state)
        self.assertEqual(len(batch), 1)
        self.assertEqual(batch[0]["slug"], "chosen-slug")
        self.assertEqual(json.loads(batch[0]["meta"])["title"], "Chosen title")

    def test_baseline_cannot_be_reset(self):
        self.execute(self.args("baseline"))
        with self.assertRaises(ValueError):
            self.execute(self.args("baseline"))

    def test_source_symlinks_and_traversal_rejected(self):
        (self.source / "evil.md").symlink_to(self.source / "old.md")
        with self.assertRaises(ValueError):
            self.execute(self.args("baseline"))
        (self.source / "evil.md").unlink()
        with self.assertRaises(ValueError):
            self.execute(self.args(select="../outside.md"))

    def test_bounded_batch(self):
        files = {f"{n}.md": b"x\n" for n in range(10)}
        state = {"baseline": [], "tracked": {}}
        self.assertEqual(len(intake.candidates(files, state)), 1)
        self.assertEqual(len(intake.candidates(files, state, limit=5)), 5)
        with self.assertRaises(ValueError):
            intake.candidates(files, state, limit=6)


class GitHubTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeGitHubAPI()
        self.item = {"slug": "test", "body": b"# Test\n", "meta": content.metadata_bytes("Test", b"# Test\n")}

    def test_public_repo_refused(self):
        self.api.private = False
        with self.assertRaises(ValueError):
            intake.GitHub(self.api)
        self.assertEqual(self.api.writes, [])

    def test_amended_branch_refused(self):
        gh = intake.GitHub(self.api)
        gh.submit(self.item)
        self.api.files["publish_articles/test.md"] = b"amended\n"
        with self.assertRaises(ValueError):
            gh.submit(self.item)

    def test_extra_file_refused(self):
        gh = intake.GitHub(self.api)
        gh.submit(self.item)
        self.api.files[".github/workflows/evil.yml"] = b"malicious\n"
        with self.assertRaises(ValueError):
            gh.submit(self.item)

    def test_closed_pr_not_reopened(self):
        gh = intake.GitHub(self.api)
        gh.submit(self.item)
        self.api.prs[0]["state"] = "closed"
        writes = len(self.api.writes)
        self.assertEqual(gh.submit(self.item)["status"], "closed")
        self.assertEqual(len(self.api.writes), writes)

    def test_already_published_no_branch(self):
        self.api.master_files = {"publish_articles/test.md": self.item["body"], "publish_articles/test.json": self.item["meta"]}
        self.assertEqual(intake.GitHub(self.api).submit(self.item)["status"], "already-on-default")
        self.assertEqual(self.api.writes, [])

    def test_title_only_update_supported(self):
        self.api.diff = [{"filename": "publish_articles/test.json", "status": "modified"}]
        self.assertEqual(intake.GitHub(self.api).submit(self.item)["status"], "open")

    def test_changed_body_or_title_changes_review_version(self):
        first = intake.GitHub(self.api).submit(self.item)["version"]
        other = dict(self.item, meta=content.metadata_bytes("New title", self.item["body"]))
        second = intake.GitHub(FakeGitHubAPI()).submit(other)["version"]
        self.assertNotEqual(first, second)
        other = dict(self.item, body=b"New body\n", meta=content.metadata_bytes("Test", b"New body\n"))
        third = intake.GitHub(FakeGitHubAPI()).submit(other)["version"]
        self.assertNotEqual(first, third)


if __name__ == "__main__":
    unittest.main()
