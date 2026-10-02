"""Post-merge regressions; synthetic fixtures only, never real GitHub writes."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import content
import wiki_export
import wiki_intake
import test_export
import test_intake
from build_site import build


class MetadataRegressions(unittest.TestCase):
    def check_rejected(self, raw):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.md").write_bytes(b"Example\n")
            (root / "a.json").write_text(raw)
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                content.validate_articles(root)

    def test_duplicate_title(self):
        for discarded in ("Hidden", "Visible"):
            with self.subTest(discarded=discarded):
                self.check_rejected('{"title":' + json.dumps(discarded) +
                    ',"title":"Visible","sha256":"' + content.digest(b"Example\n") + '"}')

    def test_duplicate_digest(self):
        digest = content.digest(b"Example\n")
        for discarded in ("wrong", digest):
            with self.subTest(discarded=discarded):
                self.check_rejected('{"title":"Visible","sha256":"' + discarded +
                    '","sha256":"' + digest + '"}')

    def test_escaped_duplicate_title(self):
        self.check_rejected('{"title":"Hidden","ti\\u0074le":"Visible","sha256":"' +
                            content.digest(b"Example\n") + '"}')

    def test_unique_metadata_formatting_remains_valid(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.md").write_bytes(b"Example\n")
            (root / "a.json").write_text(json.dumps(content.metadata("Visible", b"Example\n")))
            self.assertEqual(len(content.validate_articles(root)), 1)

    def test_builder_rejects_duplicate_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "publish_articles").mkdir()
            (root / "site").mkdir()
            (root / "site/legacy-files.txt").write_text("")
            (root / "publish_articles/a.md").write_bytes(b"Example\n")
            (root / "publish_articles/a.json").write_text(
                '{"title":"Hidden","title":"Visible","sha256":"' + content.digest(b"Example\n") + '"}')
            with self.assertRaises(ValueError):
                build(root, root / "output")
            self.assertFalse((root / "output").exists())


class RetargetedPRRegressions(unittest.TestCase):
    def test_export_retargeted_open_and_closed_refused_without_writes(self):
        for state in ("open", "closed"):
            with self.subTest(state=state):
                api = test_export.FakeGitHubREST()
                wiki_export.ExportGitHub(api).export(7, api.review_head)
                pr = next(iter(api.prs[test_export.DST].values()))
                pr["base"]["ref"] = "another-base"
                pr["state"] = state
                api.writes.clear()
                with self.assertRaises(ValueError):
                    wiki_export.ExportGitHub(api).export(7, api.review_head)
                self.assertEqual(api.writes, [])
                self.assertEqual(len(api.prs[test_export.DST]), 1)

    def intake_fixture(self):
        api = test_intake.FakeGitHubAPI()
        def filtered(endpoint, data=None, missing=False):
            result = api(endpoint, data, missing)
            if "/pulls?" in endpoint:
                query = parse_qs(urlsplit(endpoint).query)
                return [p for p in result if "base" not in query or p["base"]["ref"] == query["base"][0]]
            return result
        bridge = wiki_intake.GitHub(filtered)
        candidate = {"slug": "test", "body": b"Example\n", "meta": content.metadata_bytes("Visible", b"Example\n")}
        bridge.submit(candidate)
        api.writes.clear()
        return api, bridge, candidate

    def test_intake_retargeted_open_and_closed_refused_without_writes(self):
        for state in ("open", "closed"):
            with self.subTest(state=state):
                api, bridge, candidate = self.intake_fixture()
                api.prs[0]["base"]["ref"] = "another-base"
                api.prs[0]["state"] = state
                with self.assertRaises(ValueError):
                    bridge.submit(candidate)
                self.assertEqual(api.writes, [])

    def test_intake_deleted_branch_with_history_not_recreated(self):
        api, bridge, candidate = self.intake_fixture()
        api.ref = None
        with self.assertRaises(ValueError):
            bridge.submit(candidate)
        self.assertEqual(api.writes, [])

    def test_export_ambiguous_history_across_bases_refused(self):
        api = test_export.FakeGitHubREST()
        wiki_export.ExportGitHub(api).export(7, api.review_head)
        pr = copy.deepcopy(next(iter(api.prs[test_export.DST].values())))
        pr.update(number=42)
        pr["base"]["ref"] = "another-base"
        api.prs[test_export.DST][42] = pr
        api.writes.clear()
        with self.assertRaises(ValueError):
            wiki_export.ExportGitHub(api).export(7, api.review_head)
        self.assertEqual(api.writes, [])

    def test_intake_ambiguous_history_across_bases_refused(self):
        api, bridge, candidate = self.intake_fixture()
        pr = copy.deepcopy(api.prs[0])
        pr["base"]["ref"] = "another-base"
        api.prs.append(pr)
        with self.assertRaises(ValueError):
            bridge.submit(candidate)
        self.assertEqual(api.writes, [])

    def test_intake_malformed_history_refused_before_writes(self):
        api = test_intake.FakeGitHubAPI()
        def malformed(endpoint, data=None, missing=False):
            return {} if "/pulls?" in endpoint else api(endpoint, data, missing)
        with self.assertRaises(ValueError):
            wiki_intake.GitHub(malformed).submit({"slug": "test", "body": b"Example\n",
                "meta": content.metadata_bytes("Visible", b"Example\n")})
        self.assertEqual(api.writes, [])
