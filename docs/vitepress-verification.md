# Modern-only VitePress verification — 2026-10-02

This replaces the earlier legacy-preserving verification. The owner's explicit
new decision is **delete all historical site files and publish only modern
VitePress through GitHub Actions Pages**. No URL-compatibility acceptance gate
remains. This document records local evidence, not a hosted deployment claim.

## Scope and deletion evidence

- Existing worktree/branch: `openclaw/vitepress-blog-modernization`, PR #3.
- Follow-up starts at `bd533601b96d1997110a376cb59feb632addba16`; original migration
  base remains `8b9d85c82f47146a27668a3536a118dfc4a2fc47`.
- **34 historical files deleted** from the current tree: 29 generated Hexo web
  files/assets plus three EXE binaries and two C++ sources. The exact inventory
  is [`legacy-deleted-files.txt`](legacy-deleted-files.txt), enforced by tests.
- Also removed: `site/legacy-files.txt`,
  `tests/fixtures/legacy-source-sha256.json`, `tests/test_legacy_snapshot.py`,
  `site/frontend/archive/index.md`, and
  `site/frontend/.vitepress/theme/components/ArchiveIndex.vue`.
- The two `workflow-templates/wiki-{checks,pages}.yml` paths are replaced by actual
  `.github/workflows/wiki-{checks,pages}.yml` files, not retained as templates.
  There are **41 removed old paths** when viewing the follow-up with rename
  detection disabled (34 historical + 5 obsolete support + 2 relocated workflows).
- `/legacy/`, `/archive/`, `/archives/`, old dated articles/assets and download
  compatibility links are absent. The root homepage is modern, not a relocated
  historical page. No Python fallback publisher remains; `build_site.py` only
  supplies shared validation, safe filesystem operations and inert rendering.
- Public validator and intake/export behavior are preserved. Exporter changes
  only its documentation wording; exact-SHA private approval and separate public
  review/merge remain mandatory. No article intake/export/approval occurred;
  production has **zero approved article pairs**.
- Deletion is not a Git history rewrite, cache purge or retraction of prior public
  copies. No PR merge or repository Pages setting change was performed.

## Executed local checks

Runtime: Linux ARM64, Python **3.12.3**, Node **24.21.0**, npm **11.19.0**.
Installed workflows select Node **22** LTS; no hosted-runtime result is implied.

| Check | Result |
|---|---|
| `npm ci` with committed lockfile | Pass; 128 packages installed, exact VitePress 1.6.4 and Playwright 1.63.0 |
| `python3 -B -m unittest discover -s tests -v` | **348 passed** |
| `python3 -B scripts/content.py` | **0 articles validated** |
| `npm test` | **348 Python + 9 Chromium tests passed**, none skipped |
| `npm run build` | Pass; **30 allowlisted files** |
| Repeat `npm run build` | Pass; previous output byte-verified before replacement |
| `python3 -B scripts/audit_site.py --output _site` | Pass; exact inventory, digests, modern routes and SSR links |
| Per-file SHA-256 snapshot check | **30/30 passed** |
| Production legacy/source/private-marker scan | Pass |
| `python3 -m compileall -q scripts tests` | Pass |
| actionlint **1.7.7**, actual `.github/workflows/*.yml` | Pass |
| Five direct GitHub Actions commit pins | All resolved through upstream GitHub commit API |
| `git diff --check` and staged diff check | Pass |

Test counts differ from the superseded 364-test suite because obsolete historical
preservation/Python publisher tests were retired and replaced with modern helper,
artifact audit, deletion and route-rejection tests. Intake/export contract tests
remain. Local logs are in the ignored `_build-temp-verification/` directory; they
are not uploaded into the Pages artifact.

## Browser evidence — synthetic fixtures only

Real Chromium builds an empty fixture and two synthetic approved notes, then
verifies:

1. Hostile HTML, Vue expressions, include syntax and titles remain inert text.
2. Actual VitePress local search finds English and Chinese body-only queries,
   handles no results, and navigates without executing hostile titles.
3. Wiki sidebar and body filtering escape public data.
4. Dark mode toggles and persists across navigation.
5. Home, wiki and article have no horizontal overflow at **390×844**; mobile
   navigation works.
6. Every removed historical file URL except the intentionally replaced root
   `index.html` returns **404** on the isolated static fixture. `/archive/`,
   `/archives/` and `/legacy/` also return 404. Modern navigation has no old routes,
   revision-pinned downloads or historical-preservation claims.
7. Frontend data contracts reject obsolete legacy/download fields and extra
   private metadata.
8. Empty production-shaped fixture is honestly empty with no source/approval
   files or historical content in its receipt.
9. Tested modern pages emit **zero browser errors and zero third-party requests**.

The browser fixture server binds only `127.0.0.1` and serves generated output.
No Vite/esbuild development server or checkout-root server is exposed.

## Artifact inventory

Canonical checksum file: [`vitepress-artifact-sha256.txt`](vitepress-artifact-sha256.txt).
Its SHA-256 is:

```
ba16b7207589c8a006db2cce312e9137e71bd46034e096047a106395542813ea
```

**30 files total:**

- **3 HTML:** `index.html`, `wiki/index.html`, `404.html`.
- **9 generated JavaScript** runtime/page/search chunks.
- **2 CSS** files.
- **14 bundled WOFF2** font files.
- **1 JSON:** VitePress's public `hashmap.json` route/chunk map, not approval data.
- **1 empty `.nojekyll`** marker.

No legacy HTML/assets, EXE, C++, Python, raw Markdown/Vue, source maps, tests,
workflow YAML, docs, package files, approval JSON, source directory, Git data,
private metadata or source/build paths occur in this artifact. Runtime chunks
are generated modern frontend code, not checkout scripts. The adjacent build
receipt is deliberately outside `_site` and is not an upload input.

Python staging admits only explicitly enumerated trusted frontend files plus
validated public data. Finalization verifies Rollup's exact file/digest receipt,
closed output path policy and the approved-content digest. The independent
post-build audit checks the final receipt, routes and real SSR `href/src`
attributes; escaped article examples are not treated as active links. Browser
checks additionally exercise runtime navigation. Neither receipts nor these
checks defend against a malicious maintainer changing the trusted code/toolchain.

A read-only independent review found no current publication/privacy blocker under
the trusted, quiescent-checkout assumption. Its stale-evidence finding is resolved
by this replacement report; its link-audit concern led to HTML-aware checks and
regressions for historical download URLs and harmless escaped examples.

## Remaining remote gates and bounded risks

- **Workflow-capable push:** native gh exposes `repo`, `read:org`, `gist`, not
  `workflow`. Workflow changes may be rejected on push; local inclusion cannot be
  represented as remote installation. The PR handoff records the exact attempted
  push result and commit. No credential/scope change or bypass is performed.
- **Pages source:** fresh read-only API inspection still reports `legacy`, source
  `master` `/`, status `built`. Owner must separately migrate to **GitHub Actions**;
  the custom opt-in does not disable root Jekyll publishing. Do not merge and
  assume this settings transition occurred.
- **Deployment gates:** repository `forecs/forecs.github.io`, default `master`,
  event ref `refs/heads/master`, and `WIKI_PAGES_ENABLED=true` are required for
  build/deploy. Exact event SHA is checked out, only audited `_site` is uploaded,
  and only deploy receives Pages/OIDC writes. PR checks publish nothing.
- **Dependency audit:** fresh `npm audit` reports **3 affected build-tool packages
  (1 high, 2 moderate)**: Vite, esbuild and the dependent VitePress entry; npm
  reports no available fix in this stable selection. This is not a clean audit.
  Stable direct pins/lockfile remain; no incompatible overrides or prerelease
  upgrades are hidden. Only one-shot builds and loopback static preview are
  supported. See [the advisory review](vitepress-migration.md#dependency-advisory-review-2026-10-02).
- No hosted CI success, Pages deployment, settings activation, public article
  publication or PR merge is claimed by this local report.
