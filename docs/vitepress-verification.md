# VitePress verification evidence — 2026-10-02

## Base and scope

- Managed Git worktree on new branch `openclaw/vitepress-blog-modernization`.
- Base: public `origin/master` at `8b9d85c82f47146a27668a3536a118dfc4a2fc47`.
- No private content, approval, export, merge, workflow installation or Pages
  setting change performed. `publish_articles` still contains zero articles.
- Existing content validator, intake/export scripts, Python-only builder, legacy
  manifest and historical files have **no diff** against the base.

## Executed checks

Local runtime: Linux ARM64, Python **3.12.3**, Node **24.21.0**, npm **11.19.0**.
Workflow templates select Node **22** LTS; hosted execution is not claimed.

| Check | Result |
|---|---|
| Clean `npm ci` with committed lockfile | Pass; exact stable VitePress 1.6.4 |
| `python3 -m unittest discover -s tests -v` | **364 tests passed**, including all original 330 |
| `python3 scripts/content.py` | **0 article(s)** validated |
| `npm test` | **364 Python tests + 8 real Chromium tests passed**, none skipped |
| `npm run build` | Pass; **62 allowlisted final files** |
| Repeat production build | Pass; previous output byte-verified before replacement |
| Python-only fallback build | Pass; remains usable without VitePress |
| `python3 -m compileall -q scripts tests` | Pass |
| `actionlint` 1.7.7, both workflow templates | Pass |
| `git diff --check` | Pass |
| Historical Git files versus base | **34/34 byte-identical** (29 web files + 5 downloads) |
| Non-root historical files in final artifact | **28/28 byte-identical**, original paths |
| Final artifact inventory and every SHA-256 versus external build receipt | Exact match |

### Browser verification (synthetic fixtures only)

The committed `tests/modern-browser.test.mjs` builds an empty fixture and a fixture
with two synthetic approved notes in an isolated temporary tree. It never adds
fixtures to the real public article directory. Real Chromium verifies:

1. SSR title/article output renders malicious script, Vue interpolation, include,
   image and iframe payloads as inert text; no article code executes.
2. VitePress local search finds **body-only English and Chinese** text, handles
   no-results state, and navigates to the correct article without title injection.
3. Wiki sidebar and client-side full-text filtering work with escaped titles.
4. Dark mode toggles and persists across navigation.
5. Home, wiki, article and archive have no horizontal overflow at **390×844**;
   mobile navigation opens.
6. Modern archive links the pinned GitHub downloads; excluded original downloads
   are absent, while historical articles and legacy home return successfully.
7. Empty fixture has an honest empty state; no approval/checkout files leak.
8. Modern tested pages emit **zero browser JS errors and zero third-party requests**.
   This does not apply to unsanitized historical pages and their old dependencies.

Production (zero-note) screenshots were also captured and visually inspected for
home, wiki, archive, desktop light/dark mode, and mobile home. The rendered design
uses a restrained green palette, readable bilingual text, responsive cards and
navigation; screenshots are local verification artifacts, not Pages inputs.

## Artifact inspection

The canonical per-file checksum inventory is committed at
[`vitepress-artifact-sha256.txt`](vitepress-artifact-sha256.txt). Its SHA-256 is:

```
51a60fe7cdde279c69622da24f35fa8373d75691fbb5e3e3d2ba124eb079e1ad
```

Inventory: **28 exact historical copies + 1 relocated historical home + 32
VitePress files + `.nojekyll` = 62**. The 32 VitePress files comprise three main
pages, 404, `hashmap.json`, `vp-icons.css`, and 26 emitted runtime/font/style files.
`hashmap.json` is VitePress's public route/chunk map—not approval metadata.

Inspection found no `.exe`, `.cpp`, `.py`, raw `.md`, `.vue`, source maps,
workflow YAML, approval JSON, checkout scripts/tests/docs, node_modules, Git data
or private source directories. Text scans found no checkout absolute path,
temporary build path, private sentinel, staged JSON filename or approval SHA field.
Article bodies may appear in public runtime/search chunks by design; only already
validated public article content is supplied.

The three added historical snapshot tests lock the 34 original input checksums
and exact legacy web manifest. New modern-builder regressions cover stale content,
changed digests, hostile content, symlinks/FIFOs, unexpected assets/routes,
nonempty or unowned output, orphan receipts and output-path protection.

An independent read-only code/artifact review found no additional blocking defect
under the documented trusted/quiescent-checkout and trusted-toolchain assumption.
The output receipt is integrity evidence, not a signature or protection against a
malicious maintainer modifying build code and its receipt generator together.

## Explicit limitations and owner gates

- **Not every prior Pages URL is preserved.** Five historical `.exe`/`.cpp`
  download URLs are excluded to meet the no-binaries/source artifact rule;
  unchanged Git files and revision-pinned GitHub links retain access to content.
  Owner must accept the exception or arrange a separately managed redirect host.
  Old root-page fragments now refer to the modern root; historical fragments are
  available under `/legacy/index.html#…`.
- Read-only Pages API still reported **legacy / master / root**. The active root
  publisher bypasses this builder; template-only changes do not secure it.
- Workflows remain **uninstalled** because the native credential lacks `workflow`
  scope. Local results are not hosted CI/deployment evidence.
- `npm audit`: **3 affected packages (1 high, 2 moderate)** in the stable build-tool
  chain; no fix reported within that selection. The documented advisory review
  requires avoiding Vite/esbuild dev servers and serving only the audited static
  output. No clean audit claim is made.

See [migration, deployment and rollback instructions](vitepress-migration.md).
Review/merge, URL-exception acceptance, workflow installation, source transition,
opt-in and hosted verification are separate owner actions. No live deployment is
claimed.
