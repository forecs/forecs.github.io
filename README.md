# forecs — personal wiki & learning blog

This **public** repository preserves the original generated Hexo website and adds
a standard-library-only learning-wiki builder. Unapproved drafts belong exclusively
in **private [`forecs/wiki-review`](https://github.com/forecs/wiki-review)**.

```
private local wiki → explicit private intake → private review PR
                          human reviews exact SHA and squash-merges
                                  ↓ local native-gh approved export
                    public content-only PR in forecs.github.io
                          human reviews and merges public PR
                                  ↓ separately enabled Pages workflow
                            isolated public static site
```

**Setup is not activation.** Both setup PRs remain reviewable; no real article,
historical backfill, approval, merge, timer, or Pages activation is performed.
The current native `gh` credential can create ordinary repos/PRs but lacks
`workflow` scope. Workflows remain **uninstalled templates** in
`workflow-templates/`; no new hosted CI/deployment is claimed.

- Private approval is a **human, exact-head squash merge**, not a label, comment,
  bot review, or self-approval. GitHub cannot distinguish human/agent use of one token.
- Export verifies the merged revision and copies only the approved article pair;
  it creates new public history, never pushes/cherry-picks private Git history.
- The legacy intake default still refuses this now-public repository. The explicit
  `--private-review` flag selects the fixed private review repository; sensitive
  writes recheck visibility. No arbitrary destination is accepted.
- Public branches/PRs expose approved content immediately, even before merge.
  Approving a private content PR therefore authorizes **public disclosure**.
- Existing tracked website files are preserved. The builder allowlists legacy assets,
  links the original homepage at `/legacy/`, and adds a full-text `/wiki/` listing.

## Local verification

Python 3.12+ and the existing native GitHub CLI login; no added secret or connector.

```sh
python3 -m unittest discover -s tests -v
python3 scripts/content.py
python3 scripts/build_site.py --output _site
```

Build output must be absent or empty. Never serve a checkout or private PR branch.
See **[docs/wiki-pipeline.md](docs/wiki-pipeline.md)** for approval/export commands,
privacy boundaries, recovery, current live checks, and the activation checklist.
