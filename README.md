# forecs — personal wiki & learning blog

This private repository retains the original generated Hexo site and adds a small,
standard-library-only publishing pipeline. Nothing is deployed by merging the setup
PR: deployment requires a separate human opt-in and a compatible GitHub plan.

**Installation blocker:** the existing native `gh` OAuth login can push code/create
PRs, but GitHub rejected `.github/workflows/*` because it lacks `workflow` scope.
The reviewed, linted workflows are therefore **uninstalled templates** under
`workflow-templates/`. This PR runs no GitHub Actions checks or deployment. The
owner must install them with an appropriately authorized identity before the
end-to-end hosted pipeline is active; see the activation checklist.

```
local wiki → local bounded intake → private, version-specific content PR
                                      ↓ human reviews and merges exact head
                            master/publish_articles
                                      ↓ separately enabled Pages workflow
                            isolated static public site
```

- **Content gate = deliberate human merge**, not a bot review, label or comment.
- Pending articles exist only on private PR branches. The CI template uploads no PR previews.
- Only normalized body + public title + SHA-256 enter a content PR. Source
  frontmatter, paths and intake state are not uploaded.
- Existing site files remain untouched. An explicit allowlist preserves old article,
  archive and asset URLs. Original home is linked at `/legacy/`; the new home is a
  learning-blog index with a full-text `/wiki/` listing.

## Local verification

Requires Python 3.12+; no Python packages, Node, Ruby, Hexo plugins or secret setup.

```sh
python3 -m unittest discover -s tests -v
python3 scripts/content.py
python3 scripts/build_site.py --output _site
```

The output must be absent or empty. Do not serve a repository checkout or PR branch
as a public site; deploy only the workflow-generated `_site` artifact from `master`.

Read **[docs/wiki-pipeline.md](docs/wiki-pipeline.md)** for baseline/intake,
SHA-bound human approval, privacy boundaries, supported Markdown, and the exact
activation checklist. GitHub CLI's existing native login is sufficient for intake.
