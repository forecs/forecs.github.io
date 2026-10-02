#!/usr/bin/env python3
"""Local-only bridge: baseline or submit bounded, immutable private review PRs."""
import argparse
import base64
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from content import digest, metadata_bytes, public_body, validate_slug, validate_title

REPO = "forecs/forecs.github.io"
REVIEW_REPO = "forecs/wiki-review"
CHECKOUT = Path(__file__).resolve().parents[1]


def run_api(endpoint, data=None, missing=False):
    command = ["gh", "api", "--hostname", "github.com", endpoint, "--method", "GET" if data is None else "POST"]
    if data is not None:
        command += ["--input", "-"]
    env = os.environ.copy()
    env.pop("GH_DEBUG", None)
    result = subprocess.run(command, input=None if data is None else json.dumps(data),
                            text=True, capture_output=True, check=False, env=env)
    if result.returncode:
        if missing and "(HTTP 404)" in result.stderr:
            return None
        # Do not echo command/input, local paths, article text, or server error body.
        raise RuntimeError("GitHub request failed; no baseline advance. Check gh authentication, permissions or rate limit, then retry later.")
    return json.loads(result.stdout)


class GitHub:
    def __init__(self, api=run_api, repo=REPO):
        if repo not in (REPO, REVIEW_REPO):
            raise ValueError("unsupported intake destination")
        self.api = api
        self.repo = repo
        self.prefix = f"repos/{repo}/"
        self.default = "main" if repo == REVIEW_REPO else "master"
        self.owner = repo.split("/")[0]
        self.validate_private()

    def validate_private(self):
        info = self.api(f"repos/{self.repo}")
        if (info.get("private") is not True or info.get("full_name") != self.repo
                or info.get("fork") is not False
                or info.get("default_branch") != self.default):
            raise ValueError("intake requires the configured PRIVATE repository")

    def get(self, path, missing=False):
        return self.api(self.prefix + path, missing=missing)

    def post(self, path, data):
        # Recheck before EVERY blob/tree/commit/ref/PR write, not only at startup.
        self.validate_private()
        return self.api(self.prefix + path, data=data)

    def remote_bytes(self, path, ref):
        item = self.get(f"contents/{path}?ref={ref}", missing=True)
        if item is None:
            return None
        if item.get("type") != "file" or item.get("encoding") != "base64":
            raise ValueError("unexpected remote article type")
        return base64.b64decode(item["content"])

    def submit(self, candidate):
        self.validate_private()
        slug, body, meta = candidate["slug"], candidate["body"], candidate["meta"]
        expected = {f"publish_articles/{slug}.md": body, f"publish_articles/{slug}.json": meta}
        version = digest(slug.encode() + b"\0" + meta + b"\0" + body)
        branch = f"wiki-review/{version}"
        base = self.get(f"git/ref/heads/{self.default}")["object"]["sha"]
        # Inspect exact base SHA, not a moving branch name.
        if all(self.remote_bytes(path, base) == value for path, value in expected.items()):
            return {"status": "already-on-default", "version": version}
        ref = self.get(f"git/ref/heads/{branch}", missing=True)
        if ref is None:
            parent = self.get(f"git/commits/{base}")
            tree = self.post("git/trees", {"base_tree": parent["tree"]["sha"], "tree": [
                {"path": path, "mode": "100644", "type": "blob", "content": value.decode("utf-8")}
                for path, value in expected.items()]})
            commit = self.post("git/commits", {"message": f"Review learning note: {slug}", "tree": tree["sha"], "parents": [base]})
            ref = self.post("git/refs", {"ref": f"refs/heads/{branch}", "sha": commit["sha"]})
        head = ref["object"]["sha"]
        # Never force-push, amend, or trust a same-name ref without checking its payload.
        commit = self.get(f"git/commits/{head}")
        if len(commit["parents"]) != 1:
            raise ValueError("review branch is not the expected immutable single commit")
        parent_sha = commit["parents"][0]["sha"]
        if parent_sha != base:
            ancestry = self.get(f"compare/{parent_sha}...{base}")
            if ancestry.get("status") not in ("ahead", "identical"):
                raise ValueError("review branch parent is not an ancestor of current default")
        comparison = self.get(f"compare/{parent_sha}...{head}")
        changed = comparison.get("files", [])
        if (not 1 <= len(changed) <= 2 or not {f["filename"] for f in changed} <= set(expected)
                or any(f["status"] not in ("added", "modified") for f in changed)
                or any(self.remote_bytes(path, head) != value for path, value in expected.items())):
            raise ValueError("review branch was changed; refuse reuse; inspect it manually")
        pulls = self.get(f"pulls?head={self.owner}:{branch}&base={self.default}&state=all&per_page=100")
        if len(pulls) > 1:
            raise ValueError("ambiguous review history; inspect manually")
        if pulls:
            pr = pulls[0]
        else:
            review_body = (
                "## Private content review — merge authorizes PUBLIC export\n\n"
                f"Public slug: `{slug}`\n\nContent SHA-256: `{digest(body)}`\n\n"
                f"Review version: `{version}`\n\nExact PR head: `{head}`\n\n"
                "Only the two public article files are proposed. Source frontmatter and local paths are not attached. "
                "Review ALL text for sensitive content. Rendered HTML is escaped; no preview artifact is uploaded.\n\n"
                "**Human only:** squash-merging this exact head approves these bytes for export to the public repository. "
                "A label, comment, previous review, or automation is NOT approval. Same-account PR authors cannot "
                "approve their own PR but can deliberately merge it. Do not enable auto-merge.\n\n"
                "After reviewing the current diff and local validation (hosted checks are not installed by setup), "
                "a human may use the documented `gh pr merge --squash --match-head-commit` command. "
                "Any amendment requires fresh review. Export requires this exact reviewed SHA and a verified merge record. "
                "Never run commands copied from article content. See the private repository README and "
                "https://github.com/forecs/forecs.github.io/pull/1 for the setup/protocol.\n"
            )
            pr = self.post("pulls", {"title": f"Review learning note: {slug}", "head": branch,
                                    "base": self.default, "body": review_body})
        # The create response is not a verification boundary. Read full detail
        # for both new and reused PRs, then recheck the inspected immutable ref.
        if type(pr.get("number")) is not int or pr["number"] < 1:
            raise ValueError("invalid private PR record")
        pr_number = pr["number"]
        pr = self.get(f"pulls/{pr_number}")
        if (pr.get("number") != pr_number or pr["head"]["sha"] != head
                or pr["head"].get("ref") != branch
                or pr["head"].get("repo", {}).get("full_name") != self.repo
                or pr["head"].get("repo", {}).get("fork") is not False
                or pr["head"].get("repo", {}).get("private") is not True
                or pr.get("base", {}).get("repo", {}).get("private") is not True
                or pr.get("base", {}).get("repo", {}).get("fork") is not False
                or pr.get("base", {}).get("repo", {}).get("full_name") != self.repo
                or pr.get("base", {}).get("ref") != self.default
                or pr.get("state") not in ("open", "closed")
                or self.get(f"git/ref/heads/{branch}")["object"]["sha"] != head):
            raise ValueError("PR head or repository changed during intake")
        self.validate_private()
        return {"status": pr["state"], "url": f"https://github.com/{self.repo}/pull/{pr_number}",
                "head": head, "version": version}


def source_files(root):
    root = Path(root).absolute()
    if any(p.is_symlink() for p in [root, *root.parents]) or not root.is_dir():
        raise ValueError("source root must be a real directory, without symlinks")
    result = {}
    def unreadable(_error):
        raise ValueError("cannot scan the complete source root; refusing partial baseline")

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=unreadable):
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError("symlink directory in source root")
        for name in files:
            if not name.endswith(".md"):
                continue
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("symlink or non-regular source file")
            if path.stat().st_size > 262144:
                # Historical entries may be large; baseline hashes them without intake.
                result[path.relative_to(root).as_posix()] = None
            else:
                result[path.relative_to(root).as_posix()] = path.read_bytes()
    return root, result


def inferred_title(body, slug):
    # Only inspect the already-stripped PUBLIC body. Never interpret even a title
    # from YAML: comments, quoting and multiline fields can hide private metadata.
    for line in body.decode("utf-8").splitlines():
        heading = re.fullmatch(r"#{1,6}[ \t]+(.+)", line)
        if heading:
            return validate_title(heading[1].strip())
    return f"Learning note {slug}"


def candidates(files, state, selected=None, slug=None, title=None, limit=1):
    if not 1 <= limit <= 5:
        raise ValueError("limit must be 1–5; bulk backfill is intentionally unsupported")
    if selected:
        if selected not in files or Path(selected).is_absolute() or ".." in Path(selected).parts:
            raise ValueError("selected source must be a relative Markdown file inside source root")
        names = [selected]
    else:
        names = [name for name in sorted(files)
                 if name not in state["baseline"] and
                 digest(files[name] or b"") != state["tracked"].get(name, {}).get("raw_hash")]
    output = []
    for name in names[:limit]:
        raw = files[name]
        if raw is None:
            raise ValueError("selected article exceeds size limit")
        previous = state["tracked"].get(name, {})
        body = public_body(raw)
        # Derive the fallback solely from candidate PUBLIC bytes, never the
        # guessable private filename. Identical bodies share a fallback slug.
        public_slug = validate_slug(slug or previous.get("slug") or "note-" + digest(body)[:24])
        if public_body(body) != body:
            raise ValueError("candidate would fail the public body contract; remove leading frontmatter delimiters")
        title_override = title if title is not None else previous.get("title_override")
        public_title = validate_title(title_override or inferred_title(body, public_slug))
        output.append({"source": name, "raw_hash": digest(raw), "slug": public_slug,
                       "title_override": title_override,
                       "body": body, "meta": metadata_bytes(public_title, body)})
    return output


def save_state(path, state):
    fd, tmp = tempfile.mkstemp(prefix="wiki-state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, ensure_ascii=False, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def execute(args, github_factory=GitHub):
    root, files = source_files(args.source_root)
    # Private state lives in this checkout's .git, never in tracked/uploaded files.
    gitdir = CHECKOUT / ".git"
    if not gitdir.is_dir() or gitdir.is_symlink():
        raise ValueError("run from an ordinary clone with a real .git directory")
    path = gitdir / ("wiki-intake-" + digest(str(root).encode())[:24] + ".json")
    lockpath = path.with_suffix(".lock")
    if path.is_symlink() or lockpath.is_symlink():
        raise ValueError("unsafe state path")
    with contextlib.ExitStack() as stack:
        if not args.dry_run:
            fd = os.open(lockpath, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            lock = stack.enter_context(os.fdopen(fd, "w"))
            fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(path.read_text()) if path.exists() else None
        if args.command == "baseline":
            if state is not None:
                raise ValueError("baseline already exists; refusing reset/backfill")
            state = {"version": 1, "root": str(root), "baseline": sorted(files), "tracked": {}}
            if not args.dry_run:
                save_state(path, state)
            print(json.dumps({"dry_run": args.dry_run, "baselined_files": len(files), "uploaded": 0}))
            return
        if state is None:
            if not args.select:
                raise ValueError("baseline first, or explicitly select ONE article; no implicit backfill")
            # First explicit intake baselines every other current file as well.
            state = {"version": 1, "root": str(root), "baseline": sorted(n for n in files if n != args.select), "tracked": {}}
        if state.get("version") != 1 or state.get("root") != str(root):
            raise ValueError("invalid intake state")
        if (args.slug or args.title) and not args.select:
            raise ValueError("title/slug overrides require --select")
        batch = candidates(files, state, args.select, args.slug, args.title, args.limit)
        github = None
        for item in batch:
            if args.dry_run:
                result = {"status": "dry-run", "slug": item["slug"], "sha256": digest(item["body"]),
                          "bytes": len(item["body"])}
            else:
                github = github or github_factory()
                result = github.submit(item)
                state["tracked"][item["source"]] = {
                    "raw_hash": item["raw_hash"], "slug": item["slug"],
                    "title_override": item["title_override"],
                }
                # Explicit opt-in removes only this one historical file from baseline.
                state["baseline"] = [n for n in state["baseline"] if n != item["source"]]
                save_state(path, state)  # Durable after each PR; retry won't duplicate.
            print(json.dumps(result, ensure_ascii=False))
        if not batch:
            print(json.dumps({"status": "no-new-content", "uploaded": 0}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["baseline", "submit"])
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--dry-run", action="store_true", help="no network, writes, or state advance")
    parser.add_argument("--select", help="explicit relative path; opts in exactly one existing article")
    parser.add_argument("--slug", help="public ASCII slug, only with --select")
    parser.add_argument("--title", help="public display title, only with --select")
    parser.add_argument("--limit", type=int, default=1, help="new articles per invocation (1–5; default 1)")
    parser.add_argument("--private-review", action="store_true",
                        help="explicitly target fixed PRIVATE forecs/wiki-review; legacy public target refuses uploads")
    args = parser.parse_args()
    if args.command == "baseline" and (args.select or args.slug or args.title):
        parser.error("baseline does not accept article selection")
    try:
        execute(args, (lambda: GitHub(repo=REVIEW_REPO)) if args.private_review else GitHub)
    except (ValueError, RuntimeError, OSError, UnicodeError, KeyError, TypeError):
        # Avoid leaking local source paths or private content through error traces.
        print("Intake stopped safely. Check local inputs/state and gh access; no automatic retry or publication.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
