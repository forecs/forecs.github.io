# VitePress migration and deployment runbook

## Scope and status

This migration starts from public `origin/master` commit
`8b9d85c82f47146a27668a3536a118dfc4a2fc47` (including the merged validation and
idempotence fixes). The owner explicitly selected modern VitePress ONLY, not a
new publication authority.
No article is approved, imported or published by this migration. The initial wiki
is intentionally empty. Actual `.github/workflows/wiki-checks.yml` and
`.github/workflows/wiki-pages.yml` are included in this branch, replacing the
former templates. Local inclusion is not a successful push, remote integration,
hosted CI run or deployment. **Activation is not done here.**

**Do not merge and assume the site has safely migrated.** The last read-only
GitHub API verification on 2026-10-02 reported Pages `build_type: legacy`,
`master` `/`.
That publisher serves the checkout through Jekyll, not our isolated `_site`.
Merging tooling while that publisher is enabled can publish additional repository
files. Plan the owner-controlled source transition before merging/deploying.
The owner separately coordinates the Pages source switch and review/merge; this
documentation update performs neither. The supported deployment path is GitHub
Actions Pages only, on default `master` with `WIKI_PAGES_ENABLED=true`.

## Architecture and trust boundaries

- Private local wiki → explicit intake to private `forecs/wiki-review` → human
  reviews exact private head and deliberately squash-merges → existing local
  exporter verifies the merged revision → **new public content-only PR** → human
  merges public PR. These gates and their same-account limitations are unchanged.
- `scripts/content.py` remains the public article contract. Only canonical
  `publish_articles/<slug>.md` plus its strict title/SHA-256 approval object are
  eligible. A digest is integrity evidence, not proof of human intent. The
  isolated builder is not a replacement for review or a DLP engine.
- Python remains standard-library-only. Its inert Markdown renderer prevents
  articles from becoming Vue, JavaScript, HTML, includes or configuration.
  `scripts/build_site.py` is a helper module only; there is no standalone Python
  publisher or fallback. VitePress receives only isolated generated sources and
  explicitly trusted theme code, never the repository root as its source or
  `public` directory.
- VitePress is exactly pinned to stable **1.6.4**, and Playwright to **1.63.0**,
  with a committed npm lockfile.
  No v2 prerelease is used. New pages provide responsive navigation, dark mode,
  system Chinese/English typography and local search; no remote search service is
  required. Search indexes contain approved public text, not approval JSON.
- The final artifact includes only generated modern public pages/runtime assets.
  Tests, source scripts, docs, package files, approval
  metadata, draft directories, symlinks, C++ sources and executables are not Pages
  inputs. Install/build dependencies only in a trusted checkout; this is not a
  sandbox for concurrently hostile filesystem mutation or a malicious maintainer.
- All generated historical Hexo HTML, articles, archives, styles, scripts, fonts,
  images and historical EXE/C++ files are removed from the current Git tree. They
  are not staged into VitePress or linked as alternate downloads.

See [wiki-pipeline.md](wiki-pipeline.md) for the complete private approval/export
procedure. Never point a preview server at a checkout or a private review branch.

## Modern-only routes and historical deletion

`/` and `/index.html` serve the modern homepage, with approved learning notes under
`/wiki/`. There is no historical archive navigation, `/archives/` or `/legacy/`
route, relocated old homepage, preserved dated Hexo article route, or historical
download link. Old article, archive, EXE/C++ and checkout-tooling URLs are
intentionally absent from the modern artifact, not compatibility promises or
redirect requirements. The owner has explicitly chosen this removal: **no
compatibility acceptance blocker remains**.

Deletion removes historical files from the current Git tree, not from prior Git
commits or already distributed copies. It does not purge Git history, old Pages
artifacts, browser/CDN caches or third-party copies. No history rewrite or cache
purge is performed or claimed by this change.

## Local verification and preview

Use Python 3.12+ and Node.js 22 LTS (the workflows use Node 22):

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

For a first build, the final output directory must be absent or empty. Repeat
`npm run build` verifies every previous output byte against the adjacent
`_site.build-receipt.json` before replacing its own output; it refuses altered or
unowned directories and orphan receipts. The receipt stays outside `_site` and
must never be uploaded. Stage/finalize still require absent/empty output. Do not
weaken these checks or the existing article content validation. Serve only `_site`.
There is no `build_site.py` publishing command or Python fallback; build through
`npm run build` only.

Inspect `/`, `/wiki/` and approved article direct loads. Verify the artifact has
no legacy/archive routes, historical assets, EXE/C++ files or download links;
confirm intentionally removed URLs return 404 after deployment. Test narrow mobile
navigation, keyboard focus, light/dark mode and local search with synthetic
approved content. Empty production wiki search must not invent unpublished notes.
Synthetic fixtures never belong in `publish_articles` on a public branch.

## Owner deployment checklist — separate authorization required

1. Review the exact branch revision, tests and modern-only artifact inventory.
   Keep private review visibility, exact-SHA approval procedure and export
   destination unchanged. Historical removal is the owner's explicit decision,
   not an outstanding URL-preservation acceptance requirement.
2. Coordinate a source transition away from the last verified legacy `master`
   root publisher **before relying on isolation**. The owner separately switches
   Pages source to GitHub Actions and reviews/merges this branch; neither action
   is performed by this documentation update. Preserve HTTPS/domain and the
   existing `github-pages` environment restriction to `master`. Do not treat
   merging the branch as proof that the source setting changed.
3. Review the actual `.github/workflows/wiki-checks.yml` and `wiki-pages.yml`
   included in this branch, which replace the former templates. Native gh has
   `repo`, `read:org`, `gist` but no `workflow` scope; pushing may be blocked.
   If blocked, the owner must use separately authorized workflow-capable tooling;
   do not bypass the restriction or claim the push succeeded. No new token or
   secret is required by the architecture and no scope expansion is performed.
4. Obtain hosted **Wiki checks** evidence, including a passing run on default
   `master` after integration. PR checks run synthetic tests only; they do not
   upload previews/artifacts, access private sources, or deploy. Local tests are
   not evidence of hosted CI execution.
5. Verify GitHub Actions is the Pages source. Keep `WIKI_PAGES_ENABLED` absent or
   false until ready. It gates only the custom workflow, not legacy Jekyll;
   branch inclusion or source migration alone is not a verified deployment.
6. Explicitly set `WIKI_PAGES_ENABLED=true` and dispatch **Publish modern VitePress site**
   on `master`, or trigger by a later approved public merge. Setting the variable
   alone runs nothing. The workflow checks repository `forecs/forecs.github.io`,
   default branch `master` and event ref `refs/heads/master`, checks out the exact
   event SHA without persisted credentials, runs Python + npm tests,
   builds/audits `_site`, and uploads only that isolated directory. Deployment
   alone receives Pages/OIDC permissions.
7. Inspect the actual hosted artifact and live URLs. Confirm no historical
   assets/routes/download links, scripts/tests/source/binaries/approval metadata,
   functional navigation/search/theme at desktop and mobile sizes, and expected
   404s for intentionally excluded paths. Retain deployment commit/artifact
   evidence. Removal does not erase prior Git history, hosted copies or caches.

Action references in the workflow files are full commit pins. The Node setup v4 pin
was verified through the upstream GitHub ref. Direct pins do not make all
transitive action implementations immutable (`upload-pages-artifact` uses
`upload-artifact@v4` internally). npm lockfiles pin package integrity; review
updates and their dependency advisories rather than drifting to a prerelease.

## Dependency advisory review (2026-10-02)

The fresh audit for this update reports **3 affected packages: 1 high, 2 moderate** in the
stable VitePress 1.6.4 development dependency chain (`vite`, `esbuild`, and the
transitive VitePress entry). The reported issues concern development-server file
access/path handling and esbuild development-server cross-origin access, not
executables shipped in the static Pages artifact. npm reports no available fix
within this stable dependency selection. This is **not a clean dependency audit**.

The supported commands use VitePress's one-shot build only; no Vite/esbuild dev
server is started or exposed. Preview is a loopback-only Python static server
rooted at the audited `_site`, not the checkout. Do not add an exposed Vite dev
server or use these advisories as justification to bypass approval boundaries.
Review upstream stable releases and retest before changing toolchain pins; this
migration does not silently force incompatible major dependencies or a prerelease.
Owner review should explicitly consider this bounded build-tool residual risk.

Advisories: [esbuild cross-origin dev-server access](https://github.com/advisories/GHSA-67mh-4wv8-2f99),
[Vite optimized-deps traversal](https://github.com/advisories/GHSA-4w7w-66w2-5vf9),
[Windows editor UNC handling](https://github.com/advisories/GHSA-v6wh-96g9-6wx3),
[Vite Windows deny bypass](https://github.com/advisories/GHSA-fx2h-pf6j-xcff).

## Rollback — verified modern versions only

- **Before activation:** leave deployment disabled while the owner resolves build,
  CI or source-transition issues. The modern-only decision does not authorize
  preserving or restoring the old site. No private content/export state needs
  rollback merely because frontend activation is deferred.
- **After activation:** setting `WIKI_PAGES_ENABLED` false stops future custom
  deployments, not the currently served site or caches. Investigate failures
  without weakening approval, exact-SHA, receipt or artifact validation checks.
- Recover only by redeploying a **previously verified modern VitePress artifact**
  or rebuilding a **previously verified modern revision**, through owner-reviewed
  deployment tooling. Re-audit artifact scope/integrity and retain exact revision,
  dependency and deployment evidence. Keep Actions Pages, default `master`, its
  opt-in and environment policies. Rebuilds must use isolated output and respect
  the receipt contract; do not overwrite an altered/unowned directory.
- If no previously verified modern artifact/revision exists, pause activation or
  deployment and fix forward under review; there is no legacy recovery target.
  Never switch to root-branch Jekyll, restore historical Hexo routes/assets, or use
  a Python fallback publisher. Do not force-push `master` or fetch private Git
  history into public branches. Content changes still require the separate
  private approval/public review procedure in [wiki-pipeline.md](wiki-pipeline.md).
