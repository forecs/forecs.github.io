#!/usr/bin/env python3
"""Local, explicit, exact-version export from private review to a public PR.

Trust boundary: a HUMAN must review the complete private diff and deliberately run
  gh pr merge NUMBER --repo forecs/wiki-review --squash \
      --match-head-commit REVIEWED_40_HEX_SHA
without --auto/--admin. Then supply that SAME number and SHA to this program.
Labels, comments, reviews, CI and a newly fetched head are not approval. GitHub's
shared native-gh credential cannot distinguish the human from an agent/admin;
merged_by and hashes are evidence of a merge/byte identity, NOT proof of humanity
or proof that --match-head-commit was used. REST does not attest the merge method;
we enforce the resulting single-parent squash-compatible shape and exact reviewed
delta. Equivalent single-commit rebase and historical auto-merge cannot be inferred.
A hostile writer/admin can bypass this cooperative boundary. Do not automate the
human merge. Strong separation needs separately permissioned identities and rules.

Only the canonical, reviewed public article pair crosses the boundary. No private
commit, parent, author, title, PR text, source filename or history is copied. Public
branch/message/PR identifiers use a digest of public slug + JSON + Markdown only.
Public commits use a fixed exporter identity and the PUBLIC parent's timestamp,
so concurrent identical exports have identical objects, without private metadata.
The public parent's unrelated files are preserved; export changes only its approved pair. No merge, push,
force update, delete, checkout, arbitrary repository option or local state exists.

API assumptions: authenticated github.com REST Git Data, repository and PR APIs;
full non-truncated recursive trees (never a capped compare-files list) prove the
complete delta. Commit comparisons are used ONLY for ancestry with explicit SHAs.
Source PR base must equal its repository's currently advertised default (pinned
for this run); destination default must be master. Deleted private review refs
are allowed after merge, but any surviving ref must still match the reviewed SHA.
Missing/unknown shape, oversized/truncated responses and ambiguous PR history fail
closed. The injected API callable makes all integration tests synthetic.

Every public POST revalidates private visibility, merge/head/payload/default, and
public identity/visibility/default. Immutable objects are cached only by SHA.
GitHub has no cross-repository transaction: visibility/ref changes AFTER the last
read cannot be atomically prevented. Concurrent mutations stop this run; rerun to
verify/reuse an orphan branch. No automatic retries (including rate limits). A
public object POST already exposes its approved bytes, even before a PR exists.
Human review is also the DLP boundary: no program can prove that approved prose
contains no confidential facts. --dry-run DOES authenticated read-only API checks,
never creates remote objects, and never writes local files or prints article text.
"""
import argparse
import base64
from datetime import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from urllib.parse import unquote, urlencode

from content import MAX_BYTES, digest, metadata_bytes, public_body, validate_slug, validate_title

SOURCE_REPO = "forecs/wiki-review"
DESTINATION_REPO = "forecs/forecs.github.io"
DESTINATION_DEFAULT = "master"
IDENTITY = {"name": "Wiki export", "email": "wiki-export@users.noreply.github.com"}
SHA = re.compile(r"[0-9a-f]{40}\Z")
ARTICLE = re.compile(r"publish_articles/([a-z0-9]+(?:-[a-z0-9]+)*)\.(md|json)\Z")


def require(condition, message="export verification failed"):
    if not condition:
        raise ValueError(message)


def sha(value):
    require(isinstance(value, str) and SHA.fullmatch(value), "expected exact 40-hex SHA")
    return value


def number(value):
    require(type(value) is int and value > 0, "explicit positive PR number required")
    return value


def timestamp(value):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value),
            "invalid commit/merge date")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def run_api(endpoint, data=None, missing=False):
    """Native gh only; pinned host, no shell, no payload/server-error logging."""
    require(any(endpoint == f"repos/{repo}" or endpoint.startswith(f"repos/{repo}/")
                for repo in (SOURCE_REPO, DESTINATION_REPO)))
    path = unquote(endpoint.split("?", 1)[0])
    require(all(part not in ("", ".", "..") for part in path.split("/"))
            and "\\" not in path and not any(ord(c) < 32 for c in path), "unsafe API path")
    command = ["gh", "api", "--hostname", "github.com", endpoint, "--method",
               "GET" if data is None else "POST", "-H", "Accept: application/vnd.github+json",
               "-H", "X-GitHub-Api-Version: 2022-11-28"]
    if data is not None:
        command += ["--input", "-"]
    env = os.environ.copy()
    env.pop("GH_DEBUG", None)
    result = subprocess.run(command, input=None if data is None else json.dumps(data),
                            text=True, capture_output=True, check=False, env=env)
    if result.returncode:
        if missing and data is None and "(HTTP 404)" in result.stderr:
            return None
        raise RuntimeError("GitHub request failed; stop and inspect gh access/rate limits before retrying")
    return json.loads(result.stdout, object_pairs_hook=unique_json)


class ExportGitHub:
    """Independent export implementation; no intake repo-selection assumptions."""

    def __init__(self, api=run_api):
        self.api = api
        self.commits = {}
        self.trees = {}
        self.blobs = {}
        self.source_identity = None
        self.destination_identity = None

    def get(self, repo, path="", missing=False):
        require(repo in (SOURCE_REPO, DESTINATION_REPO))
        return self.api(f"repos/{repo}" + ("/" + path if path else ""), missing=missing)

    @staticmethod
    def repo_identity(info, repo, private):
        require(isinstance(info, dict) and info.get("full_name") == repo
                and info.get("private") is private and info.get("fork") is False
                and type(info.get("id")) is int and info["id"] > 0,
                "wrong repository identity/visibility or fork")
        return info["id"]

    def repositories(self):
        source = self.get(SOURCE_REPO)
        source_id = self.repo_identity(source, SOURCE_REPO, True)
        default = source.get("default_branch")
        # Only a server-returned default, never a caller/content-supplied ref.
        require(isinstance(default, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", default)
                and ".." not in default and "//" not in default and not default.endswith("/"))
        require(self.source_identity in (None, (source_id, default)), "private default/identity changed")
        self.source_identity = (source_id, default)
        destination = self.get(DESTINATION_REPO)
        dest_id = self.repo_identity(destination, DESTINATION_REPO, False)
        require(destination.get("default_branch") == DESTINATION_DEFAULT, "unexpected public default")
        require(self.destination_identity in (None, dest_id), "public repository identity changed")
        self.destination_identity = dest_id
        return default

    def ref(self, repo, branch, missing=False):
        item = self.get(repo, f"git/ref/heads/{branch}", missing=missing)
        if item is None:
            require(missing)
            return None
        require(item.get("ref") == f"refs/heads/{branch}" and item["object"].get("type") == "commit",
                "unexpected ref")
        return sha(item["object"]["sha"])

    def commit(self, repo, oid):
        key = (repo, sha(oid))
        if key not in self.commits:
            item = self.get(repo, f"git/commits/{oid}")
            require(item.get("sha") == oid and isinstance(item.get("parents"), list))
            sha(item["tree"]["sha"])
            for parent in item["parents"]:
                sha(parent["sha"])
            timestamp(item["committer"]["date"])
            self.commits[key] = item
        return self.commits[key]

    def tree(self, repo, tree_sha):
        key = (repo, sha(tree_sha))
        if key not in self.trees:
            item = self.get(repo, f"git/trees/{tree_sha}?recursive=1")
            require(item.get("sha") == tree_sha and item.get("truncated") is False
                    and isinstance(item.get("tree"), list), "incomplete tree")
            leaves, names, directories = {}, set(), set()
            for entry in item["tree"]:
                path = entry["path"]
                require(isinstance(path, str) and path and not path.startswith("/")
                        and all(p not in ("", ".", "..") for p in path.split("/"))
                        and path not in names, "invalid tree path")
                names.add(path)
                oid, mode, kind = sha(entry["sha"]), entry["mode"], entry["type"]
                if kind == "tree":
                    require(mode == "040000")
                    directories.add(path)
                else:
                    require((kind == "blob" and mode in ("100644", "100755", "120000"))
                            or (kind == "commit" and mode == "160000"), "unknown tree entry")
                    leaves[path] = (mode, kind, oid)
            for path in names:
                ancestors = path.split("/")[:-1]
                require(all("/".join(ancestors[:i]) in directories for i in range(1, len(ancestors) + 1)),
                        "incomplete recursive tree")
            self.trees[key] = leaves
        return self.trees[key]

    def files(self, repo, oid):
        return self.tree(repo, self.commit(repo, oid)["tree"]["sha"])

    @staticmethod
    def difference(before, after):
        return {path for path in before.keys() | after.keys() if before.get(path) != after.get(path)}

    def blob(self, repo, entry):
        require(entry is not None and entry[:2] == ("100644", "blob"), "article must be a regular file")
        oid = sha(entry[2])
        key = (repo, oid)
        if key not in self.blobs:
            item = self.get(repo, f"git/blobs/{oid}")
            require(item.get("sha") == oid and item.get("encoding") == "base64"
                    and type(item.get("size")) is int and 0 <= item["size"] <= MAX_BYTES)
            encoded = item["content"]
            require(isinstance(encoded, str) and len(encoded) <= 2 * MAX_BYTES)
            value = base64.b64decode(encoded.replace("\n", ""), validate=True)
            require(len(value) == item["size"])
            # Verify API data is really the requested immutable Git blob.
            actual = hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest()
            require(actual == oid, "blob identity mismatch")
            self.blobs[key] = value
        return self.blobs[key]

    def ancestor(self, repo, earlier, later):
        if earlier == later:
            return
        comparison = self.get(repo, f"compare/{sha(earlier)}...{sha(later)}")
        require(comparison.get("status") == "ahead" and comparison.get("behind_by") == 0
                and type(comparison.get("ahead_by")) is int and comparison["ahead_by"] > 0
                and comparison.get("merge_base_commit", {}).get("sha") == earlier,
                "required ancestor relationship absent")

    def pair(self, repo, files, paths):
        return {path: self.blob(repo, files.get(path)) for path in sorted(paths)}

    def approval(self, pr_number, reviewed_sha):
        default = self.repositories()
        pr = self.get(SOURCE_REPO, f"pulls/{pr_number}")
        require(pr.get("number") == pr_number and pr.get("state") == "closed"
                and pr.get("merged") is True and pr.get("draft") is False
                and pr.get("auto_merge") is None
                and type(pr.get("commits")) is int and pr["commits"] == 1,
                "deliberate single-commit merged PR required")
        merged_by = pr.get("merged_by")
        require(isinstance(merged_by, dict) and merged_by.get("type") == "User"
                and isinstance(merged_by.get("login"), str) and merged_by["login"].strip()
                and type(merged_by.get("id")) is int and merged_by["id"] > 0,
                "missing human-account merge record")
        for side in ("head", "base"):
            require(self.repo_identity(pr[side]["repo"], SOURCE_REPO, True) == self.source_identity[0])
        require(pr["head"]["sha"] == reviewed_sha and pr["base"]["ref"] == default,
                "wrong reviewed head or private base")
        sha(pr["base"]["sha"])
        head = self.commit(SOURCE_REPO, reviewed_sha)
        require(len(head["parents"]) == 1, "review must be an immutable single-parent commit")
        parent = head["parents"][0]["sha"]
        old, new = self.files(SOURCE_REPO, parent), self.files(SOURCE_REPO, reviewed_sha)
        changed = self.difference(old, new)
        require(1 <= len(changed) <= 2 and type(pr.get("changed_files")) is int
                and pr["changed_files"] == len(changed), "review is not pair-only")
        matches = [ARTICLE.fullmatch(path) for path in changed]
        require(all(matches), "non-article change in private review")
        slugs = {match[1] for match in matches}
        require(len(slugs) == 1, "one article per export")
        slug = validate_slug(slugs.pop())
        paths = {f"publish_articles/{slug}.md", f"publish_articles/{slug}.json"}
        for path in changed:
            require(path in new and (path not in old or old[path][:2] == ("100644", "blob")),
                    "deletion/type change is not approved export")
        payload = self.pair(SOURCE_REPO, new, paths)
        body, meta = payload[f"publish_articles/{slug}.md"], payload[f"publish_articles/{slug}.json"]
        require(public_body(body) == body, "noncanonical public body")
        info = json.loads(meta.decode("utf-8"), object_pairs_hook=unique_json)
        require(isinstance(info, dict) and set(info) == {"title", "sha256"}, "invalid public metadata")
        validate_title(info["title"])
        require(meta == metadata_bytes(info["title"], body), "noncanonical metadata/content digest")
        version = digest(slug.encode() + b"\0" + meta + b"\0" + body)
        branch = f"wiki-review/{version}"
        require(pr["head"]["ref"] == branch, "review branch version mismatch")
        current_head = self.ref(SOURCE_REPO, branch, missing=True)
        require(current_head in (None, reviewed_sha), "review branch amended after approval")
        merged_sha = sha(pr["merge_commit_sha"])
        require(merged_sha != reviewed_sha, "distinct merged commit record required")
        merged = self.commit(SOURCE_REPO, merged_sha)
        require(len(merged["parents"]) == 1, "single-parent squash-compatible merge required")
        require(timestamp(head["committer"]["date"]) <= timestamp(merged["committer"]["date"])
                <= timestamp(pr["merged_at"]), "merge predates reviewed commit")
        merge_parent = merged["parents"][0]["sha"]
        self.ancestor(SOURCE_REPO, parent, merge_parent)
        before, after = self.files(SOURCE_REPO, merge_parent), self.files(SOURCE_REPO, merged_sha)
        require(self.difference(before, after) == changed, "merge changed a different scope")
        require(all(before.get(path) == old.get(path) for path in paths), "reviewed base pair became stale")
        require(self.pair(SOURCE_REPO, after, paths) == payload, "merge differs from reviewed bytes")
        base = self.ref(SOURCE_REPO, default)
        self.ancestor(SOURCE_REPO, merged_sha, base)
        require(self.pair(SOURCE_REPO, self.files(SOURCE_REPO, base), paths) == payload,
                "private default pair changed since approval")
        require(self.ref(SOURCE_REPO, default) == base, "private default moved during verification")
        return {"slug": slug, "payload": payload, "version": version, "merge": merged_sha}

    def public_commit(self, head, base, approved):
        commit = self.commit(DESTINATION_REPO, head)
        require(len(commit["parents"]) == 1, "public branch changed")
        parent = commit["parents"][0]["sha"]
        self.ancestor(DESTINATION_REPO, parent, base)
        old, new = self.files(DESTINATION_REPO, parent), self.files(DESTINATION_REPO, head)
        paths = set(approved["payload"])
        changes = self.difference(old, new)
        require(1 <= len(changes) <= 2 and changes <= paths, "unexpected public branch delta")
        require(self.pair(DESTINATION_REPO, new, paths) == approved["payload"], "altered public branch bytes")
        # Never silently overwrite another public version that advanced on master.
        current = self.files(DESTINATION_REPO, base)
        require(all(current.get(path) in (old.get(path), new.get(path)) for path in paths),
                "public article changed since branch creation")
        parent_date = self.commit(DESTINATION_REPO, parent)["committer"]["date"]
        expected_identity = {**IDENTITY, "date": parent_date}
        require(commit.get("message") == self.message(approved["version"])
                and commit.get("author") == expected_identity and commit.get("committer") == expected_identity,
                "unexpected public commit metadata")

    @staticmethod
    def message(version):
        return f"Publish learning note {version}"

    @staticmethod
    def pr_body(version):
        return ("Publish the validated public article pair.\n\n"
                f"Public content version: `{version}`\n\n"
                "Review this public diff before merging. No automatic merge.\n")

    def public_prs(self, branch):
        # Discover by head across ALL bases; filtering by the expected base
        # would hide retargeted PRs before public_pr can reject the change.
        query = urlencode({"head": f"forecs:{branch}", "state": "all", "per_page": 100})
        items = self.get(DESTINATION_REPO, f"pulls?{query}")
        require(isinstance(items, list) and len(items) < 100 and len(items) <= 1,
                "ambiguous or truncated public PR history")
        return items

    def public_pr(self, item, branch, head, version):
        pr_number = number(item["number"])
        pr = self.get(DESTINATION_REPO, f"pulls/{pr_number}")
        require(pr.get("number") == pr_number)
        for side in ("head", "base"):
            require(self.repo_identity(pr[side]["repo"], DESTINATION_REPO, False) == self.destination_identity)
        require(pr["head"]["ref"] == branch and pr["head"]["sha"] == head
                and pr["base"]["ref"] == DESTINATION_DEFAULT and pr.get("state") in ("open", "closed")
                and type(pr.get("merged")) is bool and pr.get("draft") is False
                and pr.get("auto_merge") is None and pr.get("maintainer_can_modify") is False
                and pr.get("title") == self.message(version) and pr.get("body") == self.pr_body(version),
                "unexpected/altered public PR")
        sha(pr["base"]["sha"])
        require(not pr["merged"] or pr["state"] == "closed")
        # Construct, rather than trust an API-supplied redirect/injected URL.
        return {"status": "merged" if pr["merged"] else pr["state"],
                "url": f"https://github.com/{DESTINATION_REPO}/pull/{pr_number}", "version": version}

    def export(self, pr_number, reviewed_sha, dry_run=False):
        number(pr_number)
        sha(reviewed_sha)
        require(type(dry_run) is bool)
        approved = self.approval(pr_number, reviewed_sha)
        version, payload = approved["version"], approved["payload"]
        paths = set(payload)
        branch = f"wiki-export/{version}"
        base = self.ref(DESTINATION_REPO, DESTINATION_DEFAULT)
        base_commit = self.commit(DESTINATION_REPO, base)
        base_files = self.files(DESTINATION_REPO, base)
        # Ancestor path must be a directory; never follow a symlink/submodule.
        require("publish_articles" not in base_files, "unsafe public article root")
        for path in paths:
            require(path not in base_files or base_files[path][:2] == ("100644", "blob"),
                    "unsafe existing public article")
        already = all(path in base_files and self.blob(DESTINATION_REPO, base_files[path]) == value
                      for path, value in payload.items())
        head = self.ref(DESTINATION_REPO, branch, missing=True)
        pulls = self.public_prs(branch)
        if head is None and pulls:
            # A deleted merged branch is recoverable only if default has the pair.
            require(already, "public PR exists but its branch disappeared")
            detail = self.get(DESTINATION_REPO, f"pulls/{number(pulls[0]['number'])}")
            require(detail.get("merged") is True, "deleted unmerged public branch")
            head = sha(detail["head"]["sha"])
        if head is not None:
            self.public_commit(head, base, approved)
        result = self.public_pr(pulls[0], branch, head, version) if pulls else None

        def guard():
            require(self.approval(pr_number, reviewed_sha) == approved, "approval changed")
            require(self.ref(DESTINATION_REPO, DESTINATION_DEFAULT) == base, "public default moved")

        def post(path, data):
            require(not dry_run, "dry-run cannot write")
            guard()  # Includes source visibility immediately before EVERY public write.
            if path == "pulls":
                require(self.ref(DESTINATION_REPO, branch) == head, "public branch moved inside final guard")
            return self.api(f"repos/{DESTINATION_REPO}/{path}", data=data)

        guard()
        if head is not None:
            live_head = self.ref(DESTINATION_REPO, branch, missing=True)
            require(live_head == head or (live_head is None and already and result
                                         and result["status"] == "merged"),
                    "public branch moved during final verification")
        if already:
            return {"status": "already-on-default", "version": version, "dry_run": dry_run}
        if result:
            return {**result, "dry_run": dry_run}
        if dry_run:
            return {"status": "would-create-pr", "version": version, "dry_run": True}
        if head is None:
            tree = post("git/trees", {"base_tree": base_commit["tree"]["sha"], "tree": [
                {"path": path, "mode": "100644", "type": "blob", "content": value.decode("utf-8")}
                for path, value in sorted(payload.items())]})
            tree_sha = sha(tree["sha"])
            created = self.tree(DESTINATION_REPO, tree_sha)
            require(self.difference(base_files, created) <= paths
                    and self.pair(DESTINATION_REPO, created, paths) == payload, "public tree not preserved")
            identity = {**IDENTITY, "date": base_commit["committer"]["date"]}
            commit = post("git/commits", {"message": self.message(version), "tree": tree_sha,
                                         "parents": [base], "author": identity, "committer": identity})
            head = sha(commit["sha"])
            self.public_commit(head, base, approved)
            post("git/refs", {"ref": f"refs/heads/{branch}", "sha": head})
        require(self.ref(DESTINATION_REPO, branch) == head, "public branch moved")
        self.public_commit(head, base, approved)
        # A competing process may have completed the PR while we made objects.
        pulls = self.public_prs(branch)
        if not pulls:
            guard()
            require(self.ref(DESTINATION_REPO, branch) == head, "public branch moved before PR")
            pulls = [post("pulls", {"title": self.message(version), "head": branch,
                                    "base": DESTINATION_DEFAULT, "body": self.pr_body(version),
                                    "maintainer_can_modify": False})]
        result = self.public_pr(pulls[0], branch, head, version)
        guard()
        require(self.ref(DESTINATION_REPO, branch) == head, "public branch moved after PR")
        return {**result, "dry_run": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Export one exact, human-squash-merged private article to a public PR.")
    parser.add_argument("--private-pr", required=True, type=int, help="explicit merged private review PR number")
    parser.add_argument("--reviewed-sha", required=True, help="the exact 40-hex head the human reviewed and merged")
    parser.add_argument("--dry-run", action="store_true", help="authenticated read-only verification; no writes")
    args = parser.parse_args(argv)
    try:
        result = ExportGitHub().export(args.private_pr, args.reviewed_sha, args.dry_run)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, RuntimeError, OSError, UnicodeError, KeyError, TypeError, AttributeError):
        print("Export stopped safely. Verify the exact human merge, repository visibility, payload and gh access; "
              "no automatic retry or merge.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
