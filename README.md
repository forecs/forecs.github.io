# forecs — personal wiki & learning blog

This **public** repository is a modern **VitePress 1.6.4-only** personal blog
and learning wiki. The owner's decision removes all generated historical Hexo
assets and EXE/C++ files from the current Git tree, with no legacy/archive routes
or historical download links. Deletion does not purge Git history or caches.
Standard-library Python helpers enforce the approved-content and isolated-artifact
boundaries; VitePress provides the responsive frontend, dark mode and local search.
Unapproved drafts belong exclusively in
**private [`forecs/wiki-review`](https://github.com/forecs/wiki-review)**.

```
private local wiki → explicit private intake → private review PR
                          human reviews exact SHA and squash-merges
                                  ↓ local native-gh approved export
                    public content-only PR in forecs.github.io
                          human reviews and merges public PR
                                  ↓ separately enabled Pages workflow
                            isolated public static site
```

**Workflow files are included in this branch; deployment activation is not done.**
The setup merges do not approve any article. Actual workflows
`.github/workflows/wiki-checks.yml` and `.github/workflows/wiki-pages.yml` replace
the former templates. The native `gh` credential has `repo`, `read:org`, `gist`,
but no `workflow` scope; pushing workflow changes may be blocked. Local inclusion
is not evidence of a successful push, merge, hosted checks or deployment.

**Owner-controlled transition still required:** the last verified Pages setting
was legacy Jekyll publishing from `master` / root, which bypasses the isolated
builder and does not honor `WIKI_PAGES_ENABLED`. The supported publisher is now
**GitHub Actions Pages only**, gated by default branch `master` and
`WIKI_PAGES_ENABLED=true`. The owner separately coordinates switching Pages to
GitHub Actions and reviewing/merging this branch; neither action is performed by
this documentation update. See [the findings and activation checklist](docs/wiki-pipeline.md#read-only-live-platform-findings-2026-10-02).

- Private approval is a **human, exact-head squash merge**, not a label, comment,
  bot review, or self-approval. GitHub cannot distinguish human/agent use of one token.
- Export verifies the merged revision and copies only the approved article pair;
  it creates new public history, never pushes/cherry-picks private Git history.
- The legacy intake default still refuses this now-public repository. The explicit
  `--private-review` flag selects the fixed private review repository; sensitive
  writes recheck visibility. No arbitrary destination is accepted.
- Public branches/PRs expose approved content immediately, even before merge.
  Approving a private content PR therefore authorizes **public disclosure**.
- Historical URL preservation is deliberately out of scope; the owner selected
  modern-only publication. No compatibility acceptance blocker remains.
- See **[VitePress migration, deployment and rollback](docs/vitepress-migration.md)**
  and **[executed test/artifact evidence](docs/vitepress-verification.md)**.
  Rollback is limited to a previously verified modern artifact or revision,
  never the old Jekyll site or a Python fallback publisher.

## Local verification

Python 3.12+ and Node.js 22 LTS; exact npm pins are VitePress **1.6.4** and
Playwright **1.63.0**. The existing native GitHub CLI login is used only
for intake/export, not static builds; no added secret or connector.

```sh
npm ci
npx playwright install --with-deps chromium
python3 -m unittest discover -s tests -v
python3 scripts/content.py
npm test
npm run build
python3 -B scripts/audit_site.py --output _site
python3 -m http.server 8000 --directory _site --bind 127.0.0.1
```

`scripts/build_site.py` is a helper module only, not a standalone publisher;
there is no Python fallback. Deploy `_site` from the isolated npm build, never
the checkout, temporary staging tree, or VitePress sources.

Initial build output must be absent or empty. Repeat npm builds replace only their
own byte-verified output using the adjacent receipt (never deploy that receipt).
Never serve a checkout or private PR branch.
See **[docs/wiki-pipeline.md](docs/wiki-pipeline.md)** for approval/export commands,
privacy boundaries, recovery, dated live findings, and the activation checklist.
