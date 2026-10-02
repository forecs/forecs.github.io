"""Synthetic integration tests for the real exporter; never contact GitHub/wiki.

Run: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_export.py -v
The fake implements Git object hashing, recursive trees, ancestry, refs and PRs.
Only the transport is replaced: ExportGitHub's approval/export/guard methods run
unchanged. Regression tests deliberately fail while the documented bugs remain.
"""
import base64
import contextlib
import copy
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import content
import wiki_export as export

SRC = export.SOURCE_REPO
DST = export.DESTINATION_REPO
DATE = "2026-09-01T00:00:00Z"
REVIEW_DATE = "2026-09-02T00:00:00Z"
MERGE_DATE = "2026-09-03T00:00:00Z"
LATER_DATE = "2026-09-04T00:00:00Z"
BODY = b"# Synthetic public note\n\nOnly approved public prose.\n"
SLUG = "synthetic-note"
MD = f"publish_articles/{SLUG}.md"
META = f"publish_articles/{SLUG}.json"
SAFE_ERRORS = (ValueError, RuntimeError, OSError, UnicodeError, KeyError, TypeError, AttributeError)


def git_oid(kind, value):
    return hashlib.sha1(kind.encode() + b" " + str(len(value)).encode() + b"\0" + value).hexdigest()


def canonical_meta(body=BODY, title="Synthetic public note"):
    # Intentionally independent of the production serializer.
    return (json.dumps({"title": title, "sha256": hashlib.sha256(body).hexdigest()},
                       sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()


class FakeGitHubREST:
    """Strict, in-memory GitHub subset with genuinely content-addressed objects.

    Unknown endpoints/methods are assertions, never fallback network requests.
    before/after hooks inject mutable-state races or malformed REST responses.
    """
    def __init__(self):
        self.calls = []
        self.writes = []
        self.before = None
        self.after = None
        self.fail_post = None
        self.pr_listing = None
        self.repos = {
            SRC: {"id": 101, "full_name": SRC, "private": True, "fork": False, "default_branch": "main"},
            DST: {"id": 202, "full_name": DST, "private": False, "fork": False, "default_branch": "master"},
        }
        self.blobs = {r: {} for r in (SRC, DST)}
        self.trees = {r: {} for r in (SRC, DST)}
        self.commits = {r: {} for r in (SRC, DST)}
        self.refs = {r: {} for r in (SRC, DST)}
        self.prs = {r: {} for r in (SRC, DST)}
        private = {
            "private/SECRET_SOURCE_FILE.md": self.entry(SRC, b"PRIVATE_BODY_SENTINEL\n"),
            "private/config.json": self.entry(SRC, b'{"secret":"PRIVATE_CONFIG_SENTINEL"}\n'),
        }
        self.review_parent = self.add_commit(SRC, private, message="PRIVATE_PARENT_MESSAGE")
        public = {
            "README.md": self.entry(DST, b"Existing public README\n"),
            "legacy/unchanged.txt": self.entry(DST, b"Keep this legacy data\n"),
            "legacy/executable": self.entry(DST, b"#!/bin/sh\n", "100755"),
            "legacy/link": self.entry(DST, b"unchanged.txt", "120000"),
            "legacy/submodule": ("160000", "commit", "a" * 40),
        }
        self.public_base = self.add_commit(DST, public, message="Existing public history")
        self.refs[DST]["master"] = self.public_base
        self.install_review()

    def entry(self, repo, value, mode="100644"):
        oid = git_oid("blob", value)
        self.blobs[repo][oid] = {
            "sha": oid, "encoding": "base64", "size": len(value),
            "content": base64.b64encode(value).decode(),
        }
        return (mode, "blob", oid)

    def add_tree(self, repo, files):
        nested = {}
        for path, entry in files.items():
            pieces = path.split("/")
            node = nested
            for piece in pieces[:-1]:
                node = node.setdefault(piece, {})
                if not isinstance(node, dict):
                    raise AssertionError("fake Git tree path collision")
            if isinstance(node.get(pieces[-1]), dict):
                raise AssertionError("fake Git tree directory collision")
            node[pieces[-1]] = entry

        def build(node):
            entries, raw = [], b""
            for name in sorted(node, key=lambda n: (n + ("/" if isinstance(node[n], dict) else "")).encode()):
                value = node[name]
                if isinstance(value, dict):
                    child_sha, children = build(value)
                    mode, kind, oid = "040000", "tree", child_sha
                else:
                    mode, kind, oid = value
                    children = []
                raw += mode.lstrip("0").encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid)
                entries.append({"path": name, "mode": mode, "type": kind, "sha": oid})
                entries.extend({**e, "path": name + "/" + e["path"]} for e in children)
            oid = git_oid("tree", raw)
            self.trees[repo][oid] = {"sha": oid, "truncated": False, "tree": entries}
            return oid, entries
        return build(nested)[0]

    def add_commit(self, repo, files=None, parents=(), message="PRIVATE_COMMIT_MESSAGE",
                   date=DATE, tree=None, author=None, committer=None):
        tree = tree or self.add_tree(repo, files)
        identity = {"name": "PRIVATE_AUTHOR_SENTINEL", "email": "private-sentinel@example.invalid", "date": date}
        author, committer = copy.deepcopy(author or identity), copy.deepcopy(committer or identity)
        def person(kind, who):
            seconds = int(datetime.fromisoformat(who["date"].replace("Z", "+00:00")).timestamp())
            return f'{kind} {who["name"]} <{who["email"]}> {seconds} +0000\n'
        raw = (f"tree {tree}\n" + "".join(f"parent {p}\n" for p in parents)
               + person("author", author) + person("committer", committer) + "\n" + message).encode()
        oid = git_oid("commit", raw)
        self.commits[repo][oid] = {"sha": oid, "tree": {"sha": tree},
                                  "parents": [{"sha": p} for p in parents], "message": message,
                                  "author": author, "committer": committer}
        return oid

    def files(self, repo, commit):
        tree = self.commits[repo][commit]["tree"]["sha"]
        return {e["path"]: (e["mode"], e["type"], e["sha"])
                for e in self.trees[repo][tree]["tree"] if e["type"] != "tree"}

    def install_review(self, body=BODY, meta=None, parent=None, files=None, merge_parent=None):
        parent = parent or self.review_parent
        self.payload = {MD: body, META: canonical_meta(body) if meta is None else meta}
        version_bytes = SLUG.encode() + b"\0" + self.payload[META] + b"\0" + body
        self.version = hashlib.sha256(version_bytes).hexdigest()
        self.review_branch = "wiki-review/" + self.version
        self.export_branch = "wiki-export/" + self.version
        old = self.files(SRC, parent)
        new = {**old, **{p: self.entry(SRC, v) for p, v in self.payload.items()}}
        if files is not None:
            new = files
        self.review_head = self.add_commit(SRC, new, [parent], date=REVIEW_DATE)
        merge_parent = merge_parent or parent
        merged_files = self.files(SRC, merge_parent)
        changed = {p for p in old.keys() | new.keys() if old.get(p) != new.get(p)}
        for p in changed:
            if p in new:
                merged_files[p] = new[p]
            else:
                merged_files.pop(p, None)
        self.merged = self.add_commit(SRC, merged_files, [merge_parent], date=MERGE_DATE,
                                      message="PRIVATE_SQUASH_MESSAGE")
        self.refs[SRC][self.review_branch] = self.review_head
        self.refs[SRC]["main"] = self.merged
        self.prs[SRC][7] = {
            "number": 7, "state": "closed", "merged": True, "draft": False, "auto_merge": None,
            "commits": 1, "changed_files": len(changed), "merge_commit_sha": self.merged,
            "merged_at": MERGE_DATE, "merged_by": {"type": "User", "login": "private-human", "id": 303},
            "title": "PRIVATE_PR_TITLE", "body": "PRIVATE_PR_BODY", "html_url": "https://evil.invalid/source",
            "head": {"ref": self.review_branch, "sha": self.review_head, "repo": copy.deepcopy(self.repos[SRC])},
            "base": {"ref": "main", "sha": parent, "repo": copy.deepcopy(self.repos[SRC])},
        }

    def advance(self, repo, branch, changes, date=LATER_DATE):
        parent = self.refs[repo][branch]
        files = self.files(repo, parent)
        for path, value in changes.items():
            if value is None:
                files.pop(path, None)
            else:
                files[path] = value if isinstance(value, tuple) else self.entry(repo, value)
        head = self.add_commit(repo, files, [parent], date=date)
        self.refs[repo][branch] = head
        return head

    def is_ancestor(self, repo, earlier, later):
        pending, seen = [later], set()
        while pending:
            head = pending.pop()
            if head == earlier:
                return True
            if head in seen:
                continue
            seen.add(head)
            pending.extend(p["sha"] for p in self.commits[repo].get(head, {}).get("parents", []))
        return False

    def __call__(self, endpoint, data=None, missing=False):
        call = (endpoint, copy.deepcopy(data), missing)
        self.calls.append(call)
        if self.before:
            self.before(endpoint, data, missing)
        prefix = next((f"repos/{r}" for r in (SRC, DST)
                       if endpoint == f"repos/{r}" or endpoint.startswith(f"repos/{r}/")), None)
        if prefix is None:
            raise AssertionError(f"unapproved endpoint: {endpoint}")
        repo = prefix[6:]
        path = endpoint[len(prefix):].lstrip("/")
        if data is not None:
            if repo != DST or path not in ("git/trees", "git/commits", "git/refs", "pulls"):
                raise AssertionError(f"unapproved write: {endpoint}")
            if self.fail_post == path:
                raise RuntimeError("synthetic transport failure; no retry")
            self.writes.append((path, copy.deepcopy(data)))
            result = self.post(repo, path, data)
        else:
            result = self.get(repo, path, missing)
        result = copy.deepcopy(result)
        if self.after:
            result = self.after(endpoint, data, result)
        return result

    def get(self, repo, path, missing):
        if not path:
            return self.repos[repo]
        if path.startswith("git/ref/heads/"):
            branch = path[len("git/ref/heads/"):]
            oid = self.refs[repo].get(branch)
            if oid is None:
                if missing:
                    return None
                raise RuntimeError("synthetic ref missing")
            return {"ref": "refs/heads/" + branch, "object": {"type": "commit", "sha": oid}}
        if path.startswith("git/commits/"):
            return self.commits[repo][path[len("git/commits/"):]]
        if path.startswith("git/trees/"):
            oid, query = path[len("git/trees/"):].split("?")
            if query != "recursive=1":
                raise AssertionError("complete recursive tree required")
            return self.trees[repo][oid]
        if path.startswith("git/blobs/"):
            return self.blobs[repo][path[len("git/blobs/"):]]
        if path.startswith("compare/"):
            earlier, later = path[len("compare/"):].split("...")
            ahead = earlier != later and self.is_ancestor(repo, earlier, later)
            return {"status": "ahead" if ahead else "diverged", "behind_by": 0 if ahead else 1,
                    "ahead_by": 1 if ahead else 0, "merge_base_commit": {"sha": earlier if ahead else "0" * 40},
                    # A capped compare-files list is not proof; exporter must use full trees.
                    "files": []}
        if path.startswith("pulls?"):
            query = parse_qs(urlsplit(path).query)
            if query.get("state") != ["all"] or query.get("per_page") != ["100"]:
                raise AssertionError("all-state bounded PR lookup required")
            branch = query["head"][0].removeprefix("forecs:")
            if self.pr_listing is not None:
                return self.pr_listing
            return [p for p in self.prs[repo].values()
                    if p["head"]["ref"] == branch
                    and ("base" not in query or p["base"]["ref"] == query["base"][0])]
        if path.startswith("pulls/"):
            return self.prs[repo][int(path[len("pulls/"):])]
        raise AssertionError(f"unexpected GET {repo}/{path}")

    def post(self, repo, path, data):
        if path == "git/trees":
            base = self.trees[repo][data["base_tree"]]
            files = {e["path"]: (e["mode"], e["type"], e["sha"])
                     for e in base["tree"] if e["type"] != "tree"}
            for item in data["tree"]:
                files[item["path"]] = self.entry(repo, item["content"].encode(), item["mode"])
            return {"sha": self.add_tree(repo, files)}
        if path == "git/commits":
            return {"sha": self.add_commit(repo, tree=data["tree"], parents=data["parents"],
                                          message=data["message"], author=data["author"], committer=data["committer"])}
        if path == "git/refs":
            branch = data["ref"].removeprefix("refs/heads/")
            if branch in self.refs[repo]:
                raise RuntimeError("synthetic HTTP 422: reference already exists")
            self.refs[repo][branch] = data["sha"]
            return {"ref": data["ref"], "object": {"type": "commit", "sha": data["sha"]}}
        if path == "pulls":
            number = max(self.prs[repo], default=40) + 1
            pr = {"number": number, "state": "open", "merged": False, "draft": False,
                  "auto_merge": None, "maintainer_can_modify": data["maintainer_can_modify"],
                  "title": data["title"], "body": data["body"], "html_url": "https://evil.invalid/redirect",
                  "head": {"ref": data["head"], "sha": self.refs[repo][data["head"]], "repo": copy.deepcopy(self.repos[repo])},
                  "base": {"ref": data["base"], "sha": self.refs[repo][data["base"]], "repo": copy.deepcopy(self.repos[repo])}}
            self.prs[repo][number] = pr
            return pr
        raise AssertionError(f"unexpected POST {path}")


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeGitHubREST()
        # A missing fake boundary must fail, not accidentally invoke gh/network.
        for target in ("subprocess.run", "socket.create_connection", "socket.socket.connect"):
            p = patch(target, side_effect=AssertionError("real process/network forbidden in export tests"))
            p.start()
            self.addCleanup(p.stop)

    def run_export(self, dry_run=False, api=None):
        return export.ExportGitHub(api or self.api).export(7, self.api.review_head, dry_run)

    def assert_rejected(self, action=None, writes=0):
        with self.assertRaises(SAFE_ERRORS):
            (action or self.run_export)()
        self.assertEqual(len(self.api.writes), writes, "rejection must occur before the next public write")

    def source_pr(self):
        return self.api.prs[SRC][7]

    def public_pr(self):
        return next(iter(self.api.prs[DST].values()))

    def response_mutation(self, suffix, change, repo=SRC):
        endpoint = f"repos/{repo}/{suffix}"
        def after(ep, data, result):
            if ep == endpoint and data is None:
                changed = change(result)
                return result if changed is None else changed
            return result
        self.api.after = after

    def test_happy_pair_only_public_writes_and_metadata_nonleak(self):
        original = self.api.files(DST, self.api.public_base)
        result = self.run_export()
        self.assertEqual(result, {"status": "open", "url": f"https://github.com/{DST}/pull/41",
                                  "version": self.api.version, "dry_run": False})
        self.assertEqual([p for p, _ in self.api.writes], ["git/trees", "git/commits", "git/refs", "pulls"])
        tree_data = self.api.writes[0][1]
        self.assertEqual(tree_data["base_tree"], self.api.commits[DST][self.api.public_base]["tree"]["sha"])
        self.assertEqual({e["path"]: e["content"].encode() for e in tree_data["tree"]}, self.api.payload)
        self.assertTrue(all(e["type"] == "blob" and e["mode"] == "100644" for e in tree_data["tree"]))
        head = self.api.refs[DST][self.api.export_branch]
        files = self.api.files(DST, head)
        self.assertEqual({p: files[p] for p in original}, original)
        self.assertEqual(set(files) - set(original), {MD, META})
        commit = self.api.commits[DST][head]
        self.assertEqual(commit["parents"], [{"sha": self.api.public_base}])
        identity = {**export.IDENTITY, "date": DATE}
        self.assertEqual(commit["author"], identity)
        self.assertEqual(commit["committer"], identity)
        self.assertFalse(self.public_pr()["maintainer_can_modify"])
        encoded = json.dumps(self.api.writes)
        for secret in ("PRIVATE_", "private-sentinel", "private-human", SRC,
                       self.api.review_head, self.api.review_parent, self.api.merged,
                       REVIEW_DATE, MERGE_DATE, "SECRET_SOURCE_FILE"):
            self.assertNotIn(secret, encoded)
        self.assertFalse(any("contents/" in ep for ep, _, _ in self.api.calls))

    def test_dry_run_reads_only_no_files_stdout_or_subprocess(self):
        out = io.StringIO()
        with patch("builtins.open", side_effect=AssertionError("no local IO")), contextlib.redirect_stdout(out):
            result = self.run_export(dry_run=True)
        self.assertEqual(result["status"], "would-create-pr")
        self.assertTrue(result["dry_run"])
        self.assertEqual(self.api.writes, [])
        self.assertTrue(self.api.calls)
        self.assertEqual(out.getvalue(), "")

    def test_deleted_private_review_ref_is_allowed(self):
        del self.api.refs[SRC][self.api.review_branch]
        self.assertEqual(self.run_export()["status"], "open")

    def test_source_default_is_server_advertised_not_hardcoded(self):
        self.api.repos[SRC]["default_branch"] = "release/notes"
        self.api.refs[SRC]["release/notes"] = self.api.refs[SRC].pop("main")
        self.source_pr()["base"]["ref"] = "release/notes"
        self.assertEqual(self.run_export()["status"], "open")

    def test_unrelated_private_default_advance_is_allowed(self):
        self.api.advance(SRC, "main", {"private/later.txt": b"PRIVATE_LATER"})
        self.assertEqual(self.run_export()["status"], "open")

    def test_unrelated_changes_before_squash_are_allowed(self):
        files = self.api.files(SRC, self.api.review_parent)
        files["private/concurrent.txt"] = self.api.entry(SRC, b"PRIVATE_CONCURRENT")
        parent = self.api.add_commit(SRC, files, [self.api.review_parent])
        self.api.install_review(merge_parent=parent)
        self.assertEqual(self.run_export()["status"], "open")

    def test_single_metadata_change_exports_complete_pair(self):
        old = self.api.files(SRC, self.api.review_parent)
        old.update({MD: self.api.entry(SRC, BODY), META: self.api.entry(SRC, canonical_meta(title="Old title"))})
        parent = self.api.add_commit(SRC, old, [self.api.review_parent])
        self.api.install_review(parent=parent)
        self.assertEqual(self.source_pr()["changed_files"], 1)
        self.assertEqual(self.run_export()["status"], "open")
        self.assertEqual(len(self.api.writes[0][1]["tree"]), 2)

    def test_default_article_changed_since_approval_rejected(self):
        self.api.advance(SRC, "main", {MD: b"Different default bytes\n"})
        self.assert_rejected()

    def test_default_not_descended_from_merge_rejected(self):
        self.api.refs[SRC]["main"] = self.api.review_head
        self.assert_rejected()

    def test_stale_pair_at_squash_base_rejected(self):
        old = self.api.files(SRC, self.api.review_parent)
        old[MD] = self.api.entry(SRC, b"Concurrent article version\n")
        parent = self.api.add_commit(SRC, old, [self.api.review_parent])
        self.api.install_review(merge_parent=parent)
        self.assert_rejected()

    def test_squash_parent_unrelated_rejected_even_if_tree_matches(self):
        parent = self.api.add_commit(SRC, self.api.files(SRC, self.api.review_parent), message="unrelated root")
        self.api.install_review(merge_parent=parent)
        self.assert_rejected()

    def test_merge_delta_extra_private_change_not_hidden_by_compare_files(self):
        merged = self.api.files(SRC, self.api.merged)
        merged["private/hidden-delta"] = self.api.entry(SRC, b"UNAPPROVED")
        oid = self.api.add_commit(SRC, merged, [self.api.review_parent], date=MERGE_DATE)
        self.source_pr()["merge_commit_sha"] = oid
        self.api.refs[SRC]["main"] = oid
        self.assert_rejected()

    def test_merge_bytes_differ_from_review_rejected(self):
        files = self.api.files(SRC, self.api.merged)
        files[MD] = self.api.entry(SRC, b"Different squash body\n")
        oid = self.api.add_commit(SRC, files, [self.api.review_parent], date=MERGE_DATE)
        self.source_pr()["merge_commit_sha"] = oid
        self.api.refs[SRC]["main"] = oid
        self.assert_rejected()

    def test_review_ref_amended_after_approval_rejected(self):
        self.api.advance(SRC, self.api.review_branch, {MD: b"Amended\n"})
        self.assert_rejected()

    def test_ref_moves_during_private_default_verification_rejected(self):
        reads = 0
        def before(endpoint, data, missing):
            nonlocal reads
            if endpoint == f"repos/{SRC}/git/ref/heads/main":
                reads += 1
                if reads == 2:
                    self.api.advance(SRC, "main", {"private/race": b"race"})
        self.api.before = before
        self.assert_rejected()

    def test_repeat_open_is_read_only(self):
        self.run_export()
        self.api.writes.clear()
        self.assertEqual(self.run_export()["status"], "open")
        self.assertEqual(self.api.writes, [])

    def test_repeat_closed_pr_is_not_reopened(self):
        self.run_export()
        self.public_pr()["state"] = "closed"
        self.api.writes.clear()
        self.assertEqual(self.run_export()["status"], "closed")
        self.assertEqual(self.api.writes, [])

    def test_repeat_merged_pr_with_later_public_edit_fails_closed(self):
        self.run_export()
        self.public_pr().update(state="closed", merged=True)
        self.api.advance(DST, "master", {MD: b"Another approved public version\n", META: canonical_meta(b"Another approved public version\n")})
        self.api.writes.clear()
        self.assert_rejected()

    def test_merged_pair_on_default_with_deleted_branch_is_read_only(self):
        self.run_export()
        self.public_pr().update(state="closed", merged=True)
        self.api.advance(DST, "master", self.api.payload)
        del self.api.refs[DST][self.api.export_branch]
        self.api.writes.clear()
        self.assertEqual(self.run_export()["status"], "already-on-default")
        self.assertEqual(self.api.writes, [])

    def test_merged_pr_when_default_no_longer_contains_pair_reports_merged(self):
        self.run_export()
        # GitHub merged-state evidence is returned; exporter does not re-open it.
        self.public_pr().update(state="closed", merged=True)
        self.api.writes.clear()
        self.assertEqual(self.run_export()["status"], "merged")
        self.assertEqual(self.api.writes, [])

    def test_already_public_pair_without_export_history_needs_no_writes(self):
        self.api.advance(DST, "master", self.api.payload)
        self.assertEqual(self.run_export()["status"], "already-on-default")
        self.assertEqual(self.api.writes, [])

    def test_deleted_unmerged_branch_is_not_recreated(self):
        self.run_export()
        del self.api.refs[DST][self.api.export_branch]
        self.api.writes.clear()
        self.assert_rejected()

    def test_deleted_unmerged_branch_rejected_even_if_pair_on_master(self):
        self.run_export()
        self.api.advance(DST, "master", self.api.payload)
        del self.api.refs[DST][self.api.export_branch]
        self.api.writes.clear()
        self.assert_rejected()

    def test_deleted_merged_branch_missing_default_pair_rejected(self):
        self.run_export()
        self.public_pr().update(state="closed", merged=True)
        del self.api.refs[DST][self.api.export_branch]
        self.api.writes.clear()
        self.assert_rejected()

    def test_orphan_ref_recovery_posts_only_pr(self):
        self.api.fail_post = "pulls"
        with self.assertRaises(RuntimeError):
            self.run_export()
        self.assertIn(self.api.export_branch, self.api.refs[DST])
        self.api.fail_post = None
        self.api.writes.clear()
        self.assertEqual(self.run_export()["status"], "open")
        self.assertEqual([p for p, _ in self.api.writes], ["pulls"])

    def test_dry_run_orphan_ref_does_not_finish_pr(self):
        self.api.fail_post = "pulls"
        with self.assertRaises(RuntimeError):
            self.run_export()
        self.api.fail_post = None
        self.api.writes.clear()
        self.assertEqual(self.run_export(dry_run=True)["status"], "would-create-pr")
        self.assertEqual(self.api.writes, [])

    def test_deterministic_retry_reuses_same_objects_after_ref_failure(self):
        self.api.fail_post = "git/refs"
        with self.assertRaises(RuntimeError):
            self.run_export()
        before = set(self.api.commits[DST]), set(self.api.trees[DST])
        self.api.fail_post = None
        self.run_export()
        self.assertEqual(before, (set(self.api.commits[DST]), set(self.api.trees[DST])))

    def test_new_review_revision_gets_new_branch_and_pr(self):
        self.run_export()
        first_branch, first_version = self.api.export_branch, self.api.version
        self.api.install_review(body=b"# Revised public note\n", parent=self.api.merged)
        self.api.writes.clear()
        result = self.run_export()
        self.assertNotEqual(first_version, result["version"])
        self.assertNotEqual(first_branch, self.api.export_branch)
        self.assertEqual(len(self.api.prs[DST]), 2)
        self.assertEqual(len(self.api.writes), 4)

    def test_repeat_after_unrelated_master_advance_is_allowed(self):
        self.run_export()
        self.api.advance(DST, "master", {"legacy/new.txt": b"Other public work"})
        self.api.writes.clear()
        self.assertEqual(self.run_export()["status"], "open")
        self.assertEqual(self.api.writes, [])

    def test_concurrent_pr_completion_does_not_create_duplicate(self):
        fired = False
        def before(endpoint, data, missing):
            nonlocal fired
            if not fired and endpoint == f"repos/{DST}/git/ref/heads/{self.api.export_branch}" and len(self.api.writes) == 3:
                fired = True
                self.api.post(DST, "pulls", {"head": self.api.export_branch, "base": "master",
                    "title": export.ExportGitHub.message(self.api.version), "body": export.ExportGitHub.pr_body(self.api.version),
                    "maintainer_can_modify": False})
        self.api.before = before
        self.assertEqual(self.run_export()["status"], "open")
        self.assertTrue(fired)
        self.assertEqual([p for p, _ in self.api.writes], ["git/trees", "git/commits", "git/refs"])

    def test_api_supplied_urls_are_neither_followed_nor_returned(self):
        def after(endpoint, data, result):
            if isinstance(result, dict):
                result.update(url="https://evil.invalid/api", html_url="file:///secret", links={"next": "https://evil.invalid"})
            return result
        self.api.after = after
        result = self.run_export()
        self.assertEqual(result["url"], f"https://github.com/{DST}/pull/41")
        self.assertTrue(all(ep.startswith((f"repos/{SRC}", f"repos/{DST}")) for ep, _, _ in self.api.calls))
        self.assertNotIn("evil.invalid", json.dumps(self.api.writes))

    def test_get_disallows_arbitrary_repository(self):
        client = export.ExportGitHub(self.api)
        for repo in ("evil/project", "https://evil.invalid", SRC + "-evil", DST + "/../evil"):
            with self.subTest(repo=repo), self.assertRaises(ValueError):
                client.get(repo)
        self.assertEqual(self.api.calls, [])

    def test_cli_dry_run_summary_contains_no_article_or_private_fields(self):
        client = export.ExportGitHub(self.api)
        out, err = io.StringIO(), io.StringIO()
        with patch.object(export, "ExportGitHub", return_value=client), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = export.main(["--private-pr", "7", "--reviewed-sha", self.api.review_head, "--dry-run"])
        self.assertEqual(status, 0)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(json.loads(out.getvalue())["status"], "would-create-pr")
        self.assertNotIn("Synthetic public", out.getvalue())
        self.assertNotIn("PRIVATE_", out.getvalue())
        self.assertEqual(self.api.writes, [])

    def test_cli_failure_is_generic_and_does_not_echo_server_secret(self):
        client = export.ExportGitHub(lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("PRIVATE_SERVER_SECRET")))
        out, err = io.StringIO(), io.StringIO()
        with patch.object(export, "ExportGitHub", return_value=client), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(export.main(["--private-pr", "7", "--reviewed-sha", self.api.review_head]), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn("PRIVATE_SERVER_SECRET", err.getvalue())
        self.assertIn("stopped safely", err.getvalue())


# Matrix cases are distinct unittest tests (rather than one misleading subtest
# count). Every negative full-export case also asserts zero public writes.
def add_case(name, body):
    body.__name__ = "test_" + name
    setattr(ExportTests, body.__name__, body)


def pr_case(name, keys, value):
    def test(self):
        item = self.source_pr()
        for key in keys[:-1]:
            item = item[key]
        item[keys[-1]] = value(self) if callable(value) else copy.deepcopy(value)
        self.assert_rejected()
    add_case(name, test)


for name, keys, value in [
    ("approval_open_pr", ("state",), "open"),
    ("approval_unmerged", ("merged",), False),
    ("approval_draft", ("draft",), True),
    ("approval_auto_merge", ("auto_merge",), {"enabled_by": "bot"}),
    ("approval_multiple_commits", ("commits",), 2),
    ("approval_wrong_number", ("number",), 8),
    ("approval_bot_merger", ("merged_by", "type"), "Bot"),
    ("approval_no_merger", ("merged_by",), None),
    ("approval_blank_merger", ("merged_by", "login"), "  "),
    ("approval_invalid_merger_id", ("merged_by", "id"), True),
    ("approval_wrong_exact_head", ("head", "sha"), "b" * 40),
    ("approval_wrong_branch_digest", ("head", "ref"), "wiki-review/" + "0" * 64),
    ("approval_arbitrary_head_url", ("head", "ref"), "https://evil.invalid/branch"),
    ("approval_nondefault_base", ("base", "ref"), "other"),
    ("approval_bad_base_sha", ("base", "sha"), "main"),
    ("approval_bad_merge_sha", ("merge_commit_sha",), "short"),
    ("approval_same_head_and_merge", ("merge_commit_sha",), lambda s: s.api.review_head),
    ("approval_merge_timestamp_before_commit", ("merged_at",), DATE),
    ("approval_invalid_merge_timestamp", ("merged_at",), "yesterday"),
    ("approval_wrong_changed_files", ("changed_files",), 1),
    ("approval_boolean_changed_files", ("changed_files",), True),
]:
    pr_case(name, keys, value)

for side in ("head", "base"):
    for field, value in (("fork", True), ("private", False), ("id", 999), ("id", True), ("full_name", DST)):
        pr_case(f"approval_{side}_repo_{field}_{str(value).replace('/', '_')}", (side, "repo", field), value)

for repo_name, repo in (("source", SRC), ("destination", DST)):
    for field, value in (("fork", True), ("private", repo == DST), ("id", True), ("id", 0), ("full_name", "evil/repo")):
        def test(self, repo=repo, field=field, value=value):
            self.api.repos[repo][field] = value
            self.assert_rejected()
        add_case(f"repository_{repo_name}_{field}_{str(value).replace('/', '_')}", test)

for name, branch in (("url", "https://evil.invalid"), ("query", "main?ref=evil"),
                     ("dotdot", "../evil"), ("empty", ""), ("double_slash", "main//evil"),
                     ("fragment", "main#evil"), ("encoded_slash", "main%2fevil")):
    def test(self, branch=branch):
        self.api.repos[SRC]["default_branch"] = branch
        self.assert_rejected()
    add_case("source_default_rejects_" + name, test)


def test_destination_default(self):
    self.api.repos[DST]["default_branch"] = "main"
    self.assert_rejected()
add_case("destination_requires_master", test_destination_default)

for name, number, oid in (("zero_number", 0, None), ("bool_number", True, None), ("str_number", "7", None),
                          ("negative_number", -1, None), ("short_sha", 7, "abc"), ("branch_sha", 7, "main"),
                          ("uppercase_sha", 7, "A" * 40), ("none_sha", 7, False),
                          ("url_sha", 7, "https://evil.invalid")):
    def test(self, number=number, oid=oid):
        self.assert_rejected(lambda: export.ExportGitHub(self.api).export(number, self.api.review_head if oid is None else oid))
        self.assertEqual(self.api.calls, [])
    add_case("explicit_input_" + name, test)

for name, value in (("integer", 1), ("string", "false"), ("none", None)):
    def test(self, value=value):
        self.assert_rejected(lambda: self.run_export(dry_run=value))
        self.assertEqual(self.api.calls, [])
    add_case("dry_run_requires_bool_" + name, test)

for name, body in (("frontmatter", b"---\nsecret: private\n---\nPublic\n"), ("bom", b"\xef\xbb\xbfPublic\n"),
                   ("crlf", b"Public\r\n"), ("empty", b"\n"), ("nul", b"Public\x00\n"),
                   ("invalid_utf8", b"\xff\n"), ("missing_newline", b"Public"),
                   ("local_path", b"See /home/private/note\n"), ("oversize", b"x" * (content.MAX_BYTES + 1))):
    def test(self, body=body):
        self.api.install_review(body=body)
        self.assert_rejected()
    add_case("noncanonical_body_" + name, test)

for name, meta in (
    ("extra_private_field", json.dumps({"title": "Public", "sha256": hashlib.sha256(BODY).hexdigest(), "source": "PRIVATE_SOURCE"}).encode()),
    ("duplicate_key", b'{"title":"Hidden","title":"Public","sha256":"x"}\n'),
    ("wrong_digest", canonical_meta(b"Wrong body\n")),
    ("not_object", b"[]\n"), ("invalid_json", b"{bad"), ("invalid_utf8", b"\xff"),
    ("missing_key", b'{"title":"Public"}\n'), ("noncanonical_spacing", json.dumps(json.loads(canonical_meta())).encode()),
    ("nonstring_title", b'{"title":3,"sha256":"x"}\n'), ("empty_title", canonical_meta(title="")),
    ("multiline_title", canonical_meta(title="Public\nprivate")), ("oversize_title", canonical_meta(title="x" * 201)),
):
    def test(self, meta=meta):
        self.api.install_review(meta=meta)
        self.assert_rejected()
    add_case("malformed_metadata_" + name, test)

for name, mode, kind in (("executable", "100755", "blob"), ("symlink", "120000", "blob"),
                         ("submodule", "160000", "commit")):
    for location in ("review", "destination"):
        def test(self, mode=mode, kind=kind, location=location):
            if location == "review":
                files = self.api.files(SRC, self.api.review_head)
                files[MD] = (mode, kind, files[MD][2])
                self.api.install_review(files=files)
            else:
                entry = self.api.entry(DST, b"unsafe")
                self.api.advance(DST, "master", {MD: (mode, kind, entry[2])})
            self.assert_rejected()
        add_case(f"unsafe_{location}_{name}", test)

for mode, kind in (("120000", "blob"), ("100644", "blob"), ("160000", "commit")):
    def test(self, mode=mode, kind=kind):
        entry = self.api.entry(DST, b"unsafe root")
        self.api.advance(DST, "master", {"publish_articles": (mode, kind, entry[2])})
        self.assert_rejected()
    add_case("unsafe_public_article_root_" + mode, test)

for name in ("no_change", "missing_pair", "extra_file", "two_slugs", "deletion", "old_symlink"):
    def test(self, name=name):
        old = self.api.files(SRC, self.api.review_parent)
        new = self.api.files(SRC, self.api.review_head)
        if name == "no_change":
            self.api.install_review(files=old)
        elif name == "missing_pair":
            del new[META]
            self.api.install_review(files=new)
        elif name == "extra_file":
            new["private/unreviewed"] = self.api.entry(SRC, b"UNAPPROVED")
            self.api.install_review(files=new)
        elif name == "two_slugs":
            del new[META]
            new["publish_articles/another.json"] = self.api.entry(SRC, canonical_meta())
            self.api.install_review(files=new)
        elif name == "deletion":
            parent = self.api.add_commit(SRC, new, [self.api.review_parent])
            del new[META]
            self.api.install_review(parent=parent, files=new)
        else:
            old[MD] = self.api.entry(SRC, b"target", "120000")
            parent = self.api.add_commit(SRC, old, [self.api.review_parent])
            self.api.install_review(parent=parent)
        self.assert_rejected()
    add_case("review_scope_" + name, test)

for target in ("review", "merge"):
    for name, parents in (("root", []), ("multiple_parents", [{"sha": "a" * 40}, {"sha": "b" * 40}])):
        def test(self, target=target, parents=parents):
            oid = self.api.review_head if target == "review" else self.api.merged
            self.response_mutation(f"git/commits/{oid}", lambda r: r.update(parents=parents))
            self.assert_rejected()
        add_case(f"{target}_commit_{name}", test)

for name, change in (
    ("truncated", lambda r: r.update(truncated=True)),
    ("missing_truncated", lambda r: r.pop("truncated") and None),
    ("wrong_sha", lambda r: r.update(sha="0" * 40)),
    ("nonlist", lambda r: r.update(tree={})),
    ("duplicate", lambda r: r["tree"].append(copy.deepcopy(r["tree"][0]))),
    ("absolute_path", lambda r: r["tree"][0].update(path="/absolute")),
    ("traversal", lambda r: r["tree"][0].update(path="../escape")),
    ("bad_sha", lambda r: r["tree"][0].update(sha="bad")),
    ("bad_mode", lambda r: r["tree"][0].update(mode="999999")),
    ("bad_type", lambda r: r["tree"][0].update(type="unknown")),
    ("missing_directory", lambda r: r.update(tree=[e for e in r["tree"] if e["type"] != "tree"])),
):
    def test(self, change=change):
        tree = self.api.commits[SRC][self.api.review_head]["tree"]["sha"]
        self.response_mutation(f"git/trees/{tree}?recursive=1", change)
        self.assert_rejected()
    add_case("malformed_tree_" + name, test)

for name, change in (
    ("wrong_sha", lambda r: r.update(sha="0" * 40)),
    ("wrong_encoding", lambda r: r.update(encoding="utf-8")),
    ("invalid_base64", lambda r: r.update(content="!?")),
    ("size_mismatch", lambda r: r.update(size=r["size"] + 1)),
    ("negative_size", lambda r: r.update(size=-1)),
    ("boolean_size", lambda r: r.update(size=True)),
    ("oversized", lambda r: r.update(size=content.MAX_BYTES + 1)),
    ("encoded_oversized", lambda r: r.update(content="A" * (2 * content.MAX_BYTES + 1))),
    ("nonstring_content", lambda r: r.update(content=[])),
    ("hash_mismatch", lambda r: r.update(content=base64.b64encode(b"!" * r["size"]).decode())),
):
    def test(self, change=change):
        oid = self.api.files(SRC, self.api.review_head)[MD][2]
        self.response_mutation(f"git/blobs/{oid}", change)
        self.assert_rejected()
    add_case("malformed_blob_" + name, test)

for name, change in (("wrong_sha", lambda r: r.update(sha="0" * 40)),
                     ("bad_tree_sha", lambda r: r["tree"].update(sha="x")),
                     ("bad_parent_sha", lambda r: r["parents"][0].update(sha="x")),
                     ("bad_date", lambda r: r["committer"].update(date="invalid"))):
    def test(self, change=change):
        self.response_mutation(f"git/commits/{self.api.review_head}", change)
        self.assert_rejected()
    add_case("malformed_commit_" + name, test)

for name, field, value in (("behind", "behind_by", 1), ("not_ahead", "status", "identical"),
                           ("zero_ahead", "ahead_by", 0), ("bool_ahead", "ahead_by", True),
                           ("wrong_merge_base", "merge_base_commit", {"sha": "0" * 40})):
    def test(self, field=field, value=value):
        self.api.advance(SRC, "main", {"private/later": b"later"})
        base = self.api.refs[SRC]["main"]
        self.response_mutation(f"compare/{self.api.merged}...{base}", lambda r: r.update({field: value}))
        self.assert_rejected()
    add_case("ancestor_proof_" + name, test)

for name, field, value in (("title", "title", "PRIVATE_TITLE"), ("body", "body", "tampered"),
                           ("draft", "draft", True), ("auto_merge", "auto_merge", {}),
                           ("maintainer_write", "maintainer_can_modify", True),
                           ("invalid_state", "state", "unknown"), ("invalid_merged", "merged", "false")):
    def test(self, field=field, value=value):
        self.run_export()
        self.public_pr()[field] = value
        self.api.writes.clear()
        self.assert_rejected()
    add_case("repeat_public_pr_rejects_" + name, test)

for side in ("head", "base"):
    for field, value in (("fork", True), ("private", True), ("id", 999), ("full_name", SRC)):
        def test(self, side=side, field=field, value=value):
            self.run_export()
            self.public_pr()[side]["repo"][field] = value
            self.api.writes.clear()
            self.assert_rejected()
        add_case(f"repeat_public_pr_{side}_repo_{field}", test)

for count in (2, 100):
    def test(self, count=count):
        self.run_export()
        self.api.pr_listing = [copy.deepcopy(self.public_pr()) for _ in range(count)]
        self.api.writes.clear()
        self.assert_rejected()
    add_case(f"ambiguous_or_truncated_pr_history_{count}", test)

for name in ("extra_delta", "wrong_payload", "wrong_author", "wrong_message", "foreign_parent"):
    def test(self, name=name):
        self.run_export()
        head = self.api.refs[DST][self.api.export_branch]
        original = self.api.commits[DST][head]
        files = self.api.files(DST, head)
        author, message, parents = original["author"], original["message"], [self.api.public_base]
        if name == "extra_delta":
            files["unapproved.txt"] = self.api.entry(DST, b"unapproved")
        elif name == "wrong_payload":
            files[MD] = self.api.entry(DST, b"tampered\n")
        elif name == "wrong_author":
            author = {**author, "name": "PRIVATE_LEAK"}
        elif name == "wrong_message":
            message = "PRIVATE_LEAK"
        else:
            parents = [self.api.add_commit(DST, self.api.files(DST, self.api.public_base), message="unrelated")]
        new_head = self.api.add_commit(DST, files, parents, message, author=author, committer=original["committer"])
        self.api.refs[DST][self.api.export_branch] = new_head
        self.public_pr()["head"]["sha"] = new_head
        self.api.writes.clear()
        self.assert_rejected()
    add_case("public_commit_rejects_" + name, test)

# Mutations happen at the start of a guard (not after its final read). The next
# write must be blocked; prior approved writes may already exist remotely.
def race_mutation(api, kind):
    if kind == "source_visibility":
        api.repos[SRC]["private"] = False
    elif kind == "source_id":
        api.repos[SRC]["id"] += 1
    elif kind == "source_default":
        api.repos[SRC]["default_branch"] = "other"
    elif kind == "destination_visibility":
        api.repos[DST]["private"] = True
    elif kind == "destination_id":
        api.repos[DST]["id"] += 1
    elif kind == "destination_default":
        api.repos[DST]["default_branch"] = "other"
    elif kind == "review_head":
        api.prs[SRC][7]["head"]["sha"] = "0" * 40
    elif kind == "review_unmerged":
        api.prs[SRC][7]["merged"] = False
    elif kind == "review_ref":
        api.refs[SRC][api.review_branch] = api.review_parent
    elif kind == "source_payload":
        api.advance(SRC, "main", {MD: b"Different default body\n"})
    elif kind == "public_base":
        api.advance(DST, "master", {"concurrent.txt": b"other"})
    else:
        raise AssertionError(kind)


for stage, endpoint in enumerate(("trees", "commits", "refs", "pulls")):
    for kind in ("source_visibility", "source_id", "source_default", "destination_visibility", "destination_id",
                 "destination_default", "review_head", "review_unmerged", "review_ref", "source_payload", "public_base"):
        def test(self, stage=stage, kind=kind):
            reads, fired = 0, False
            def before(ep, data, missing):
                nonlocal reads, fired
                if ep == f"repos/{SRC}" and data is None:
                    reads += 1
                    if not fired and reads >= 2 and len(self.api.writes) == stage:
                        fired = True
                        race_mutation(self.api, kind)
            self.api.before = before
            self.assert_rejected(writes=stage)
            self.assertTrue(fired, "race injection must execute")
        add_case(f"guard_before_{endpoint}_{kind}", test)

for stage, path in enumerate(("git/trees", "git/commits", "git/refs", "pulls")):
    def test(self, stage=stage, path=path):
        self.api.fail_post = path
        self.assert_rejected(writes=stage)
        attempts = [ep for ep, data, _ in self.api.calls if data is not None and ep.endswith("/" + path)]
        self.assertEqual(len(attempts), 1, "no automatic retry")
    add_case("transport_failure_no_retry_" + path.replace("/", "_"), test)


class NativeTransportTests(unittest.TestCase):
    def test_native_gh_pins_host_and_disables_debug_without_shell(self):
        result = subprocess.CompletedProcess([], 0, '{"ok": true}', "")
        with patch.dict("os.environ", {"GH_DEBUG": "api"}), patch.object(export.subprocess, "run", return_value=result) as run:
            self.assertEqual(export.run_api(f"repos/{DST}/git/trees", {"tree": []}), {"ok": True})
        args, kwargs = run.call_args
        cmd = args[0]
        self.assertEqual(cmd[:4], ["gh", "api", "--hostname", "github.com"])
        self.assertEqual(cmd[cmd.index("--method") + 1], "POST")
        self.assertNotIn("GH_DEBUG", kwargs["env"])
        self.assertFalse(kwargs.get("shell", False))
        self.assertTrue(kwargs["capture_output"])
        self.assertEqual(json.loads(kwargs["input"]), {"tree": []})

    def test_missing_404_only_get_is_optional(self):
        failure = subprocess.CompletedProcess([], 1, "", "not found (HTTP 404)")
        with patch.object(export.subprocess, "run", return_value=failure):
            self.assertIsNone(export.run_api(f"repos/{SRC}/git/ref/heads/missing", missing=True))
            with self.assertRaises(RuntimeError):
                export.run_api(f"repos/{DST}/git/refs", {"ref": "x"}, missing=True)

    def test_rate_limit_is_not_missing_or_retried_or_echoed(self):
        failure = subprocess.CompletedProcess([], 1, "PRIVATE_BODY", "PRIVATE_ERROR (HTTP 429)")
        with patch.object(export.subprocess, "run", return_value=failure) as run:
            with self.assertRaisesRegex(RuntimeError, "GitHub request failed") as caught:
                export.run_api(f"repos/{SRC}", missing=True)
        self.assertEqual(run.call_count, 1)
        self.assertNotIn("PRIVATE", str(caught.exception))

    def test_duplicate_json_response_keys_rejected(self):
        response = subprocess.CompletedProcess([], 0, '{"sha":"one","sha":"two"}', "")
        with patch.object(export.subprocess, "run", return_value=response), self.assertRaises(ValueError):
            export.run_api(f"repos/{SRC}")

    def test_arbitrary_host_or_repository_rejected_before_subprocess(self):
        with patch.object(export.subprocess, "run") as run:
            for endpoint in ("https://evil.invalid/repos/" + SRC, "//evil.invalid", "repos/evil/project",
                             "repos/" + SRC + "-evil", "repos/" + DST + "-evil", "--hostname=evil.invalid"):
                with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                    export.run_api(endpoint)
            run.assert_not_called()


# These are assertions of the intended fail-closed contract, NOT expectedFailure
# decorators: they must turn green when the parent fixes the implementation.
def regression_boolean_commit_count(self):
    self.source_pr()["commits"] = True  # Python True == 1 is not a valid API count.
    self.assert_rejected()
add_case("regression_boolean_commit_count_rejected", regression_boolean_commit_count)


def regression_branch_race_inside_final_post_guard(self):
    # Arm after the last explicit branch check, then mutate during the approval
    # work in post('pulls'). There is time to re-read the branch AFTER that work;
    # this is distinct from an unavoidable change after the very last read.
    armed, fired = False, False
    reads_after_ref = 0
    def before(ep, data, missing):
        nonlocal armed, fired, reads_after_ref
        if len(self.api.writes) != 3:
            return
        if ep == f"repos/{DST}/git/ref/heads/{self.api.export_branch}":
            reads_after_ref += 1
            if reads_after_ref == 2:
                armed = True
        if armed and not fired and ep == f"repos/{SRC}" and data is None:
            fired = True
            self.api.advance(DST, self.api.export_branch, {"unapproved.txt": b"Unapproved public delta\n"})
    self.api.before = before
    with self.assertRaises(SAFE_ERRORS):
        self.run_export()
    self.assertTrue(fired)
    self.assertNotIn("pulls", [p for p, _ in self.api.writes],
                     "must not create a PR for a branch changed during the final guard")
add_case("regression_branch_race_inside_final_post_guard", regression_branch_race_inside_final_post_guard)


def regression_repeat_rechecks_live_head_after_guard(self):
    self.run_export()
    self.api.writes.clear()
    reads, fired = 0, False
    def before(ep, data, missing):
        nonlocal reads, fired
        if ep == f"repos/{SRC}" and data is None:
            reads += 1
            if reads == 2:
                fired = True
                self.api.advance(DST, self.api.export_branch, {"unapproved.txt": b"Unapproved delta\n"})
    self.api.before = before
    with self.assertRaises(SAFE_ERRORS):
        self.run_export()
    self.assertTrue(fired)
    self.assertEqual(self.api.writes, [])
add_case("regression_repeat_rechecks_live_head_after_guard", regression_repeat_rechecks_live_head_after_guard)


for name, endpoint in (
    ("source_prefix_collision", f"repos/{SRC}-attacker/git/trees"),
    ("destination_prefix_collision", f"repos/{DST}-attacker/git/trees"),
    ("source_parent_traversal", f"repos/{SRC}/../unapproved/git/trees"),
    ("destination_parent_traversal", f"repos/{DST}/../unapproved/git/trees"),
):
    def test(self, endpoint=endpoint):
        response = subprocess.CompletedProcess([], 0, "{}", "")
        with patch.object(export.subprocess, "run", return_value=response) as run:
            # Capture acceptance without losing the stronger no-process assertion.
            rejected = False
            try:
                export.run_api(endpoint, {"tree": []})
            except ValueError:
                rejected = True
            self.assertEqual(run.call_count, 0, "unapproved repository/path reached authenticated gh")
            self.assertTrue(rejected)
    test.__name__ = "test_regression_endpoint_" + name
    setattr(NativeTransportTests, test.__name__, test)


if __name__ == "__main__":
    unittest.main()
