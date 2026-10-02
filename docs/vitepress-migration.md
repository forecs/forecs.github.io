# VitePress migration and deployment runbook

## Scope and status

This migration starts from public `origin/master` commit
`8b9d85c82f47146a27668a3536a118dfc4a2fc47` (including the merged validation and
idempotence fixes). It adds a VitePress frontend, not a new publication authority.
No article is approved, imported or published by this migration. The initial wiki
is intentionally empty. Workflow files remain **uninstalled templates**.

**Do not merge and assume the site has safely migrated.** On 2026-10-02, read-only
GitHub API verification still reports Pages `build_type: legacy`, `master` `/`.
That publisher serves the checkout through Jekyll, not our isolated `_site`.
Merging tooling while that publisher is enabled can publish additional repository
files. Plan the owner-controlled source transition before merging/deploying.
This PR neither changes Pages settings nor installs workflows.

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
  VitePress receives only isolated generated sources and explicitly trusted theme
  code, never the repository root as its source or `public` directory.
- VitePress is exactly pinned to stable **1.6.4**, with a committed npm lockfile.
  No v2 prerelease is used. New pages provide responsive navigation, dark mode,
  system Chinese/English typography and local search; no remote search service is
  required. Search indexes contain approved public text, not approval JSON.
- The final artifact includes only generated public pages/runtime assets and the
  historical asset manifest. Tests, source scripts, docs, package files, approval
  metadata, draft directories, symlinks, C++ sources and executables are not Pages
  inputs. Install/build dependencies only in a trusted checkout; this is not a
  sandbox for concurrently hostile filesystem mutation or a malicious maintainer.
- Historical HTML/JS remains trusted, unsanitized legacy content; its pre-existing
  external requests are not covered by modern-page privacy guarantees.

See [wiki-pipeline.md](wiki-pipeline.md) for the complete private approval/export
procedure. Never point a preview server at a checkout or a private review branch.

## URL and historical-content compatibility

The existing `site/legacy-files.txt` explicitly inventories the legacy website.
All non-root listed files retain their original paths and exact bytes, including
article URLs, `/archives/`, dated archives, CSS, JS, fonts and images. Both
`/` and `/index.html` resolve to the modern homepage. The historical root remains
unchanged **in Git** and is also available at `/legacy/` and `/legacy/index.html`;
its generated relocation preserves root-relative resources and document anchors.
No historical binary, source artifact, article, stylesheet, image or script is
deleted or rewritten in Git. Missing historical resources are not invented.

### Explicit download-URL exception / deployment acceptance decision

The old root publisher exposes five repository artifacts:

- `/Demo-Enable-SoftAP-WinRT.exe`
- `/Demo-IOCP-WinRT.exe`
- `/Demo-QOSAddSocketToFlow.exe`
- `/Demo-QOSAddSocketToFlow.cpp`
- `/main.cpp`

Serving those same bytes at those same Pages URLs conflicts with the requirement
that Pages contain no executables or source artifacts. This migration prioritizes
the isolated Pages boundary: the artifacts remain unchanged in Git and are linked
through revision-pinned GitHub URLs instead, not copied into `_site`. **Their old
Pages download URLs are not preserved.** Already-exposed tooling URLs such as
`/scripts/wiki_export.py` are intentionally removed from the new artifact too.
GitHub Pages has no configurable server-side redirects for arbitrary file URLs.
A generic JavaScript 404 redirect is not equivalent to retaining download URLs
(for command-line clients or HTTP status), so no such compatibility claim is made.

Before deployment, the owner must explicitly accept this download-URL exception,
or arrange and validate a separately managed redirect/download hosting solution.
If literal preservation of every existing public URL is mandatory, deployment
remains blocked on that external decision; this PR alone cannot meet both
requirements. Historical homepage fragment URLs on `/` also now belong to the
modern page; use `/legacy/index.html#…` for the unchanged historical document.

## Local verification and preview

Use Python 3.12+ and Node.js 22 LTS (the workflows use Node 22):

```sh
npm ci
npx playwright install --with-deps chromium
python3 -m unittest discover -s tests -v
python3 scripts/content.py
npm test
npm run build
python3 -m http.server 8000 --directory _site --bind 127.0.0.1
```

For a first build, the final output directory must be absent or empty. Repeat
`npm run build` verifies every previous output byte against the adjacent
`_site.build-receipt.json` before replacing its own output; it refuses altered or
unowned directories and orphan receipts. The receipt stays outside `_site` and
must never be uploaded. Stage/finalize and the Python-only fallback still require
absent/empty output. Do not weaken these checks. Serve only `_site`.
The Python-only fallback remains available with
`python3 scripts/build_site.py --output _site-python` (also absent/empty output),
without npm dependencies; it is a basic renderer, not the VitePress deployment.

Inspect `/`, `/wiki/`, the modern archive navigation, `/legacy/`, both dated
articles and old archive URLs. Test narrow mobile navigation, keyboard focus,
light/dark mode, local search with synthetic approved content, and direct page
loads. Empty production wiki search must not invent unpublished notes. Synthetic
fixtures never belong in `publish_articles` on a public branch.

## Owner deployment checklist — separate authorization required

1. Review the PR and exact commit, tests, artifact inventory and URL exception.
   Keep private review visibility, approval procedure and export destination
   unchanged. Resolve the download-URL acceptance decision above.
2. Coordinate a source transition away from the current legacy `master` root
   publisher **before relying on isolation**. Moving Pages source is an owner
   action, not authorized/performed by this PR. Preserve HTTPS/domain and the
   existing `github-pages` environment restriction to `master`.
3. Install reviewed `workflow-templates/wiki-checks.yml` and `wiki-pages.yml` in
   `.github/workflows/` through separately authorized workflow-capable tooling.
   The current native credential lacks `workflow` scope; templates are not active
   workflows. Do not bypass that restriction. No new token or secret is needed
   for the design; workflow installation is a separate owner-controlled action.
4. Obtain hosted **Wiki checks** evidence. PR checks run synthetic tests only;
   they do not upload previews/artifacts, access private sources, or deploy.
   Local tests in this PR are not evidence of hosted CI execution.
5. After owner review/merge, choose GitHub Actions as Pages source; keep
   `WIKI_PAGES_ENABLED` absent/false until ready. The opt-in gates only the custom
   workflow, not legacy Jekyll. Install/source migration alone does not deploy.
6. Explicitly set `WIKI_PAGES_ENABLED=true` and dispatch **Publish approved wiki**
   on `master`, or trigger by a later approved public merge. It checks repository,
   default branch and event ref, checks out the event SHA without persisted
   credentials, runs Python + npm tests, builds/audits `_site`, and uploads only
   that isolated directory. Deployment alone receives Pages/OIDC permissions.
7. Inspect the actual hosted artifact and live URLs. Confirm legacy manifest
   checksums, no scripts/tests/source/binaries/approval metadata, functional
   navigation/search/theme at desktop and mobile sizes, and expected 404s for
   intentionally excluded paths. Retain the deployment commit/artifact evidence.
   Removal from a new artifact does not erase prior Git history or caches.

Action references in the templates are full commit pins. The Node setup v4 pin
was verified through the upstream GitHub ref. Direct pins do not make all
transitive action implementations immutable (`upload-pages-artifact` uses
`upload-artifact@v4` internally). npm lockfiles pin package integrity; review
updates and their dependency advisories rather than drifting to a prerelease.

## Dependency advisory review (2026-10-02)

`npm audit` currently reports **3 affected packages: 1 high, 2 moderate** in the
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

## Rollback

- **Before activation:** close/revert the migration PR without merging, or leave
  it unactivated. Existing historical tracked files were never rewritten. No
  private content/export state needs rollback.
- **After activation:** set the custom opt-in false to stop future custom
  deployments, noting this does not retract the current site. Revert the
  modernization code through a reviewed PR; use the existing Python isolated
  builder/template path from the pre-migration commit and deploy only its
  allowlisted output through an owner-reviewed workflow. This retains the
  original artifact privacy boundary but loses the modern frontend/local search.
- To recover a previously verified VitePress version, rebuild/redeploy its exact
  reviewed commit via owner-controlled deployment tooling, retaining the same
  artifact audit and branch/environment policies. Do not force-push master or
  fetch private Git history into public branches.
- **Do not switch back to root-branch Jekyll as a routine rollback**: that
  republishes checkout scripts/tests and EXE/C++ files and bypasses the allowlist.
  If the owner deliberately chooses that behavior, it is a separate security
  decision, not a safe rollback offered by this migration.
