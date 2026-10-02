"""Strict data-only public article contract. No YAML, templates, or plugins."""
import hashlib
import json
from pathlib import Path
import re

SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
MAX_BYTES = 262144


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def validate_slug(slug):
    if not isinstance(slug, str) or len(slug) > 80 or not SLUG.fullmatch(slug):
        raise ValueError("invalid public slug")
    return slug


def validate_title(title):
    if (not isinstance(title, str) or not title.strip() or len(title) > 200
            or any(ord(c) < 32 for c in title)):
        raise ValueError("title must be a plain single line of 1–200 characters")
    return title


def public_body(data):
    if len(data) > MAX_BYTES:
        raise ValueError("article exceeds 256 KiB")
    text = data.decode("utf-8-sig").replace("\r\n", "\n")
    lines = text.splitlines(keepends=True)
    # Discard ALL source frontmatter; never interpret YAML or copy private fields.
    if lines and lines[0].strip() == "---":
        end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
        if end is None:
            raise ValueError("unterminated source frontmatter")
        text = "".join(lines[end + 1:])
    text = text.strip() + "\n"
    if not text.strip() or "\x00" in text:
        raise ValueError("empty or invalid article")
    # Defense in depth, not a DLP/PII detector. Human review remains mandatory.
    if re.search(r"(?:file://|/home/|/Users/|[A-Za-z]:\\Users\\)", text):
        raise ValueError("remove local filesystem references before intake")
    return text.encode("utf-8")


def metadata(title, body):
    return {"title": validate_title(title), "sha256": digest(body)}


def metadata_bytes(title, body):
    return (json.dumps(metadata(title, body), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def validate_articles(root: Path):
    root = Path(root)
    if root.is_symlink():
        raise ValueError("article root must not be a symlink")
    if not root.exists():
        return []
    files = {}
    for path in root.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError("only regular article files allowed")
        if path.name == ".gitkeep" and path.stat().st_size == 0:
            continue
        if path.suffix not in (".md", ".json"):
            raise ValueError("unexpected article file")
        validate_slug(path.stem)
        if path.stat().st_size > MAX_BYTES:
            raise ValueError("oversized article file")
        files[path.name] = path
    slugs = sorted({Path(name).stem for name in files})
    result = []
    for slug in slugs:
        if f"{slug}.md" not in files or f"{slug}.json" not in files:
            raise ValueError("article body/metadata pair required")
        body = files[f"{slug}.md"].read_bytes()
        info = json.loads(files[f"{slug}.json"].read_text(encoding="utf-8"), object_pairs_hook=unique_json)
        if not isinstance(info, dict) or set(info) != {"title", "sha256"}:
            raise ValueError("only public title and content digest allowed")
        validate_title(info["title"])
        if info["sha256"] != digest(body):
            raise ValueError("article changed: digest mismatch; obtain fresh human review")
        if public_body(body) != body:
            raise ValueError("article must be normalized and contain no source frontmatter")
        result.append({"slug": slug, "title": info["title"], "body": body.decode("utf-8"), "sha256": info["sha256"]})
    return result


if __name__ == "__main__":
    print(f"Validated {len(validate_articles(Path(__file__).resolve().parents[1] / 'publish_articles'))} article(s)")
