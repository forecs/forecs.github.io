"""End-to-end isolated content state machine and deployment boundary regressions."""
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from modern_site import stage as build
import shutil
from content import metadata_bytes, validate_articles
from wiki_intake import candidates

REPO = Path(__file__).resolve().parents[1]


class PipelineTests(unittest.TestCase):
    def test_candidate_stays_private_until_approved_export_and_public_merge(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_branch, default = root / "private-branch", root / "default"
            for repo in (private_branch, default):
                (repo / "publish_articles").mkdir(parents=True)
                shutil.copytree(REPO / "site/frontend", repo / "site/frontend")
            raw = b'---\ntitle: Public\nsource: /home/private/wiki\nsecret: PRIVATE_META_SENTINEL\n---\n# NEW_NOTE_SENTINEL\n<script>alert(1)</script>\n'
            [item] = candidates({"private/note.md": raw}, {"baseline": [], "tracked": {}}, selected="private/note.md", slug="public-note")
            proposed = private_branch / "publish_articles"
            (proposed / "public-note.md").write_bytes(item["body"])
            (proposed / "public-note.json").write_bytes(item["meta"])
            # The public builder sees default, never a private review branch.
            build(default, root / "before")
            before = (root / "before/.vitepress/public-data.json").read_bytes()
            self.assertNotIn(b"NEW_NOTE_SENTINEL", before)
            self.assertEqual(validate_articles(default / "publish_articles"), [])
            # Simulate approved pair export plus a separate public human merge.
            # The mock API export suite tests the actual private merge/export gate.
            for name in ("public-note.md", "public-note.json"):
                (default / "publish_articles" / name).write_bytes((proposed / name).read_bytes())
            build(default, root / "after")
            data = json.loads((root / "after/.vitepress/public-data.json").read_text())
            after = data["articles"][0]["html"].encode()
            self.assertIn(b"NEW_NOTE_SENTINEL", after)
            self.assertIn(b"&lt;script&gt;", after)
            for secret in (b"PRIVATE_META_SENTINEL", b"/home/private", b"private/note.md", b"<script>"):
                self.assertNotIn(secret, after)
            self.assertEqual(set(data), {"articles"})
            self.assertEqual(set(data["articles"][0]), {"slug", "title", "body", "html"})
            # Amending only a body cannot silently retain the old integrity proof.
            (default / "publish_articles/public-note.md").write_text("Amended\n")
            with self.assertRaises(ValueError):
                build(default, root / "amended")
            self.assertFalse((root / "amended").exists())

    def test_workflows_do_not_publish_prs_or_enable_implicitly(self):
        workflows = REPO / ".github/workflows"
        checks = (workflows / "wiki-checks.yml").read_text()
        pages = (workflows / "wiki-pages.yml").read_text()
        self.assertIn("pull_request:", checks)
        for forbidden in ("upload-pages-artifact@", "deploy-pages@", "scripts/build_site.py", "secrets."):
            self.assertNotIn(forbidden, checks)
        for forbidden in ("pull_request:", "pull_request_target:", "workflow_run:", "schedule:", "issue_comment:", "secrets."):
            self.assertNotIn(forbidden, pages)
        self.assertIn("vars.WIKI_PAGES_ENABLED == 'true'", pages)
        self.assertIn("github.ref == 'refs/heads/master'", pages)
        self.assertIn("github.event.repository.default_branch == 'master'", pages)
        self.assertIn("ref: ${{ github.sha }}", pages)
        self.assertIn("path: _site", pages)
        self.assertNotIn("contents: write", pages + checks)
        for workflow in (pages, checks):
            uses = re.findall(r"uses: (\S+)", workflow)
            self.assertTrue(uses)
            self.assertTrue(all(re.fullmatch(r"actions/[a-z-]+@[a-f0-9]{40}", action) for action in uses))
            self.assertIn("persist-credentials: false", workflow)


if __name__ == "__main__":
    unittest.main()
