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

**Setup is merged; the new pipeline is not active.** Both setup PRs merged on
2026-10-02. Neither setup merge approves an article. The current native `gh`
credential lacks `workflow` scope, and the two new workflows remain **uninstalled
templates** in `workflow-templates/`; their hosted checks have not run.

**Live deployment warning (verified after merge):** GitHub Pages is currently
publishing the repository root from `master` using its legacy Jekyll workflow.
[That deployment succeeded](https://github.com/forecs/forecs.github.io/actions/runs/36961685309),
but it does **not** run `scripts/build_site.py`, enforce its output allowlist, or
honor `WIKI_PAGES_ENABLED`. It serves the old homepage, not the new `/wiki/` site,
and includes public repository scripts/tests and historical EXE/C++ files.
Installing templates or leaving their opt-in unset does not stop that separate
legacy deployment. See [the current findings and owner migration checklist](docs/wiki-pipeline.md#read-only-live-platform-findings-2026-10-02)
before enabling the new publisher. No Pages settings were changed by verification.

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
