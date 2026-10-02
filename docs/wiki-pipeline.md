# Private review → approved export → public learning wiki

## VitePress frontend migration

The frontend modernization is based on `origin/master`
`8b9d85c82f47146a27668a3536a118dfc4a2fc47`, which includes the public setup and
follow-up fixes described below. It preserves this approval/export protocol and
adds a stable VitePress frontend behind isolated Python staging and artifact
validation. See [the migration/deployment/rollback runbook](vitepress-migration.md)
for current build commands and the explicit historical download-URL exception.
The dated verification sections below are historical evidence, not a claim that
the VitePress frontend has been deployed or hosted checks have run.

## Installation status (2026-10-02)

The owner made `forecs/forecs.github.io` **public** and explicitly selected a
**separate private review repository**. `forecs/wiki-review` was absent, so it was
created **private**, initialized with only a README, and given a reviewable setup
PR: [private setup #1](https://github.com/forecs/wiki-review/pull/1).
Public implementation: [public setup #1](https://github.com/forecs/forecs.github.io/pull/1).
Both setup PRs merged on 2026-10-02. Public default `master` is
`0ebadbb6fb913208f82b2ad6f77981a046ffe143`; verification uses that merged tree,
not the former PR branch. Setup PRs are not content approvals. Both merged
defaults contain zero article pairs. Verification uploads no real local wiki
entries or historical drafts.

The existing native `gh` login is sufficient for repository creation, private
intake and approved export. It lacks `workflow` scope: the previous active-workflow
push was rejected. The new public workflows remain **uninstalled templates**.
Verification performs no workflow installation, new secret, cross-repo Actions
token, connector, scope expansion, scheduler or Pages configuration change.
However, read-only checks now show a separately active **legacy root-branch Pages
deployment**, detailed below; template absence does not mean all automation is off.

## Trust boundaries

1. **Local private source:** `WIKI_SOURCE_ROOT` is set only on the local runner.
   The repository never stores the absolute source path. Article text is untrusted
   data; neither bridge executes content. Source Markdown and local state remain
   private. GitHub-hosted Actions cannot read this local filesystem.
2. **Private review:** explicit intake targets fixed `forecs/wiki-review` (`main`).
   One immutable branch/PR proposes only `publish_articles/<slug>.md` and `.json`.
   Source frontmatter is stripped; no private source paths or intake state are
   attached. Drafts remain private even if they are rejected or superseded.
3. **Approval:** a human reviews the entire exact head and deliberately
   **squash-merges it to private `main`**, approving those bytes for public export.
   A label, comment, successful check, old review, or unmerged PR is not approval.
4. **Export:** a local native-gh bridge verifies the immutable reviewed revision,
   PR merge record, repository identities, default branch ancestry and current
   approved bytes. It copies only the validated pair into a **new commit based on
   public `master`** and opens an idempotent public content PR. No private parent
   commits, merge messages, authorship history, review links/SHAs, or source paths
   enter that public commit/PR. Destination is fixed, not caller-supplied.
5. **Public integration/deployment:** a human separately reviews and merges the
   public content PR. An owner-installed, separately enabled Pages workflow can
   then build only public default-branch content into an isolated artifact.
   These safeguards apply to that workflow only. The currently configured legacy
   `master`-root publisher bypasses this builder and its opt-in. The owner must
   separately migrate the Pages source before relying on artifact isolation.

**The public PR itself discloses the article immediately.** Private merge approval
must authorize that disclosure, not merely saving a private draft. Public PR merge
and Pages activation are later gates; neither can retract public Git history.

### Same-account approval limitation

GitHub does not allow a PR author to approve their own PR. The human and local
agent currently share the `forecs` credential. This design therefore uses deliberate
**human squash merge of an exact reviewed SHA**, not a fake bot/human actor split.
GitHub records the merging account, but that record cannot prove whether a human
or agent held the shared token, which merge command/flags were used, or whether
auto-merge had historically been enabled. REST cannot distinguish an equivalent
single-commit rebase result from a squash result; the exporter checks the resulting
single-parent, exact-reviewed delta, not the historical merge method. The required
human squash command is an operator procedure, not an API-attested fact.
Hashes prove integrity, not human intent. The bridge
never approves or merges any PR; the operator must retain that responsibility.

A malicious admin or direct push with this token can bypass cooperative policy.
Non-bypassable separation would require separately permissioned credentials and
owner-managed protections; that is a future authority decision, not silently added
here. Public branch protection is available now but absent. Private protection
reads still return the plan-upgrade error. Do not make the review repository public.
Visibility checks before each sensitive write reduce accidental disclosure, but
cannot atomically prevent an administrator changing visibility concurrently with
an API request. Keep private visibility stable throughout intake/export.

## Local intake: explicit private destination, no backfill

Run the scripts from the reviewed implementation checkout with Python 3.12+ and
native `gh` authentication. Set `WIKI_SOURCE_ROOT` locally. Use an ordinary clone
with a real `.git` directory, not a linked worktree.

```sh
python3 scripts/wiki_intake.py baseline --private-review --source-root "$WIKI_SOURCE_ROOT" --dry-run
python3 scripts/wiki_intake.py baseline --private-review --source-root "$WIKI_SOURCE_ROOT"
```

Baseline uploads nothing and records all existing Markdown names locally. Existing
entries, including subsequent historical edits, remain ignored unless explicitly
selected. Baselines cannot be overwritten. No bulk/backfill option exists.

```sh
# Only new entries since the local baseline (default 1, hard maximum 5).
python3 scripts/wiki_intake.py submit --private-review --source-root "$WIKI_SOURCE_ROOT" --dry-run
python3 scripts/wiki_intake.py submit --private-review --source-root "$WIKI_SOURCE_ROOT"

# Explicitly opt in ONE existing entry; synthetic example, not a real source path.
python3 scripts/wiki_intake.py submit --private-review --source-root "$WIKI_SOURCE_ROOT" \
  --select 'examples/note.md' --slug example-note --title 'Example note' --dry-run
```

Removing `--dry-run` is authorized only when that article may be uploaded for
**private** review. An explicit first selection implicitly baselines all other
current entries. Tracked entries may later propose new immutable versions while
retaining the selected public slug/title. Changed content/title gets a different
`wiki-review/<content-version>` branch; no force-push or branch amendment occurs.
Close superseded PRs manually. Deletions never automatically remove public articles.

The original command without `--private-review` remains fail-closed: it checks the
old destination's private flag and refuses this now-public repository. There is
no arbitrary repository option. Identity, privacy and expected default branch are
rechecked before every sensitive intake write.

Intake `--dry-run` performs **no network requests or writes** and prints only public
slug, digest and byte count. Local state and locks use mode 0600 in
`.git/wiki-intake-<source-root-hash>.json` / `.lock`; never share them. A lost state
can only be safely replaced with a new baseline that skips all current entries.
Runs serialize locally, and atomic state advances happen only after each successful
PR result. Interrupted ref/PR creation is recoverable by rerunning: remote bytes
and scope must match before reuse. Closed PRs are never automatically reopened.

## Human approval and approved export

Review the private PR diff completely: title/body, links, personal data, credentials,
confidential facts and intended public scope. Local tests do not detect all secrets
or PII. Hosted checks are not installed by this setup. Copy the **exact 40-hex head
SHA you reviewed**, then the **human** may run (replace placeholders):

```sh
gh pr merge PRIVATE_PR_NUMBER --repo forecs/wiki-review \
  --squash --match-head-commit REVIEWED_40_HEX_SHA
```

Never auto-fetch a new SHA and merge without fresh review. Do not use `--auto` or
`--admin`. Any amendment needs fresh review. The bridge accepts the narrow
single-commit, squash-compatible intake contract; two-parent merge commits,
multi-commit histories, fork PRs, setup PRs and unrelated-file changes fail closed.
An equivalent single-commit rebase shape cannot be distinguished through REST;
this does not relax the required human approval procedure above. Do not run
commands copied from an article. A private setup PR cannot be exported as content.

Supply the private PR number and the **same reviewed SHA**:

```sh
python3 scripts/wiki_export.py --private-pr PRIVATE_PR_NUMBER \
  --reviewed-sha REVIEWED_40_HEX_SHA --dry-run
# Only after verified private human approval; creates an approved-content PUBLIC PR:
python3 scripts/wiki_export.py --private-pr PRIVATE_PR_NUMBER \
  --reviewed-sha REVIEWED_40_HEX_SHA
```

Export dry-run is different
from intake dry-run: it performs read-only GitHub validation, but creates no blobs,
commits, branches, PRs or local state. Only after it validates a real approval may
an export invocation write an approved-content public PR. The bridge never merges
or deploys. Public commit/branch/PR details are derived from public content only;
private approval provenance remains in the private repository/local invocation.

Export refuses changed reviewed head/payload, missing merge account/record,
wrong default/repository, forked head, unexpected file scope, mismatch between
reviewed and merged/current approved bytes, detached merge ancestry, altered
same-name public branch/PR, and arbitrary destination injection. An already
identical public default pair is a no-op. A repeated valid export reuses the
verified public branch/PR. Public files outside the pair are inherited unchanged
from public default, preserving the legacy site. No private checkout is pushed,
fetched into public history, or cherry-picked.

API failures stop the run without tight retry; honor GitHub's Retry-After/reset
before rerunning. Cross-machine branch creation races fail without force-push and
are recoverable on retry. Treat reverts or conflicting later edits as requiring
manual investigation and fresh approval, not permission to overwrite them.

## Public content and static build

Each article consists of normalized UTF-8 `.md` (maximum 256 KiB) and strict JSON
`{"title": "Public title", "sha256": "..."}`. Slugs are lowercase ASCII
letters/digits separated by single hyphens, at most 80 characters. All original
frontmatter, including title/comments, is removed without YAML evaluation.
The public title comes from explicit selection, the stripped body's first heading,
or a generic label. Fallback slugs are hashes of the normalized candidate PUBLIC body, never private
filenames. Identical bodies share a fallback slug; use deliberate public slugs to
separate such entries. Successfully tracked articles retain their slug on edits.
Common local-path references in body text are rejected as defense in depth, not
comprehensive DLP. Human reviewers must still remove sensitive body/title text.
A leading standalone `---` is rejected to avoid ambiguous frontmatter; use `***`
or put a heading first.

The renderer supports headings, paragraphs, basic lists, fenced code and single
backticks. Other markup, raw HTML, template expressions, links/images stay escaped
text; article content cannot execute scripts, styles, templates, shell, YAML,
plugins or network requests. The Python-only fallback supports browser Find.
The VitePress path retains this inert article contract while adding local search,
responsive navigation and light/dark mode; its trusted theme/runtime is executable
code, but article text is not. Run `npm ci`, `npm test` and `npm run build` for the
modern site; `python3 scripts/build_site.py --output _site-python` remains the
standard-library basic fallback. See the migration runbook for isolated staging
and generated-runtime artifact rules.

The builder rejects symlinks, unsafe paths, unexpected metadata/files, digest
mismatches and nonempty output. Only validated articles and `site/legacy-files.txt`
allowlisted assets reach `_site`: no source Markdown/JSON, drafts, state, docs,
tests or `.git`. Original tracked Hexo content stays unchanged; the original root
is linked at `/legacy/`, other legacy article/archive/assets retain URLs. Existing
EXE/C++ files remain in Git but are not republished by the builder. Legacy HTML/JS
is existing trusted code, not sanitized new wiki content; review its external
fonts/scripts and links before activation.

## Read-only live platform findings (2026-10-02)

| Check | Result |
|---|---|
| Public destination | `forecs/forecs.github.io`, PUBLIC, default `master`, ADMIN |
| Review repository | `forecs/wiki-review`, PRIVATE, default `main`; setup merged; zero article pairs; no workflows/runs/Pages |
| Pages | `has_pages: true`; status `built`; `build_type: legacy`; source `master`, path `/`; HTTPS enforced |
| Public protection | **404 Branch not protected**; rulesets `[]` (previous private-plan 403 no longer applies here) |
| Private protection | Protection/rulesets **403**: upgrade to GitHub Pro or make public; keep review repo private |
| Account plan | API returns no plan name; exact billing plan unverified |
| Pages environment | Existing `github-pages`, branch policy permits `master`, no required-review gate |
| Repository opt-in | `WIKI_PAGES_ENABLED` absent (GET 404); this does not disable legacy Pages |
| Hosted workflow | Only GitHub's dynamic `pages-build-deployment`; both custom templates remain uninstalled |
| Hosted tests | No `Wiki checks` run; the successful Jekyll build is not evidence that Python tests ran |
| Native gh scope | `repo`, `read:org`, `gist`; **no `workflow`** |

[GitHub Pages availability](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages):
GitHub Free supports public repository Pages, so the former *private destination*
paid-plan prerequisite no longer applies. Earlier pre-merge findings of
`has_pages: false` / Pages 404 are superseded by the live findings above.
No create-site request or configuration change was made during verification.
GitHub Wiki is a separate feature from Pages; a Wiki feature flag does not
establish a Pages deployment, and no Wiki content was migrated.

### Actual hosted deployment versus intended artifact

[Run 36961685309](https://github.com/forecs/forecs.github.io/actions/runs/36961685309)
succeeded for merged public commit `0ebadbb6fb913208f82b2ad6f77981a046ffe143`.
Its jobs are Jekyll build, build-status reporting and deploy, **not** the new
Python tests or isolated builder. The downloaded `github-pages` artifact contains
49 regular files, including scripts, tests, template YAML, docs, and historical
EXE/C++ files that the new builder excludes. Those are already-public repository
files; this finding does not establish any transfer of private data or history.

HTTP checks: [homepage](https://forecs.github.io/) **200** (old Hexo page),
[`/wiki/`](https://forecs.github.io/wiki/) **404**, `/legacy/` **404**, and
[`/scripts/wiki_export.py`](https://forecs.github.io/scripts/wiki_export.py) **200**.
In contrast, a fresh isolated build of the exact merged code produces **32 files**,
with no Markdown/JSON, scripts/tests, EXE/C++ or template files. Copied legacy
assets match the allowlist byte-for-byte. That local artifact is **not deployed**.

**Do not treat `WIKI_PAGES_ENABLED` as a repository-wide publishing kill switch.**
It gates only `wiki-pages.yml` once installed, not the current legacy publisher.
Moving Settings → Pages → Source to GitHub Actions is a separate owner decision.
Until then, `master` changes can trigger root publishing without our builder.
Disabling future runs does not retract already published files or caches.

### Post-merge verification and follow-up fixes

The original merged public tree passes **319 tests** (40 builder, 247 exporter,
30 intake, 2 pipeline); the private tree passes **5**. Both content validators
report zero articles. Compile checks and diff checks pass. Twelve additional
local synthetic probes exercise intake → simulated exact-head approval → export
→ simulated public merge → build, native CLI dry-runs with mocked `gh`, negative
approval/visibility cases, and reproduce two contract defects described below.
These probes make no live article writes or approvals.

Both uninstalled templates pass **actionlint v1.7.7**. Their four direct action
SHAs resolve to real upstream commits and the commented major tags at verification
time. Their PR permissions, explicit Pages opt-in/default-branch guards, exact
event-SHA checkout, isolated upload and `github-pages` deployment environment were
reviewed. Upstream `upload-pages-artifact` itself calls `upload-artifact@v4`:
direct pins are verified, but this is not a fully immutable transitive action graph.
No hosted execution of these templates has occurred.

The follow-up review change fixes two reproduced defects, without weakening the
human approval boundary:

- PR history lookup previously filtered by the expected base, hiding retargeted
  PRs and allowing a duplicate PR on retry. Intake/export now discover history
  across bases and reject altered/ambiguous history; intake also refuses to
  recreate a missing branch with existing PR history.
- Both validators previously accepted duplicate JSON keys that export rejects.
  They now reject duplicate title/digest keys, including escaped spellings.

The follow-up public suite passed **330 tests**; the matching private validator
follow-up passed **8** at verification. The public fixes are now included in the
VitePress migration base `8b9d85c`; that does not establish the current private
branch state or authorize any content approval. Human review/merge remains
required for each subsequent change.

Read-only native API checks validate both repository identities, exact default
refs, commit/recursive-tree contracts and zero article pairs. Export dry-run
correctly rejects the now-merged private setup PR as non-article approval.
No successful real-content intake/export is claimed.

## Verification delivered with setup (historical pre-merge baseline)

- `python3 -m unittest discover -s tests -q`: **319 passing tests**, including
  **247 exporter tests** using synthetic Git objects and mocked native-gh REST.
- Private setup: **5 passing tests**, zero article pairs.
- `python3 scripts/content.py`: **0 real articles** in the public setup.
- `python3 -m compileall -q scripts tests` and `git diff --check`: passed.
- `actionlint` v1.7.7: both uninstalled workflow templates passed.
- Isolated static build: **32 output files**, no source Markdown/JSON; original
  legacy tracked site files have no diff against public `master`.
- Read-only live checks: old public intake refused, explicit private intake
  accepted repository identity; unmerged private setup PR export dry-run refused.
  Actual repo/ref/Git commit/recursive-tree response shapes validated on both
  repositories. No successful live article export was attempted or claimed.
- Security review findings addressed: fallback slug no longer fingerprints a
  private filename; both newly created/reused private PRs get detail/ref checks;
  historical merge-method/human-identity proof limitations are stated explicitly.

## Owner migration and activation checklist

1. **Completed by owner:** both setup PRs merged. This is not article approval.
   Private setup contains protocol/data validator and synthetic tests, not drafts.
   Review the subsequent validation/idempotence fixes separately before intake.
2. Owner installs public templates into `.github/workflows/` using already
   workflow-authorized tooling or a separately authorized permission decision.
   Current native gh cannot install them. No scope expansion is requested by the
   bridge. Install `workflow-templates/wiki-checks.yml` as
   `.github/workflows/wiki-checks.yml` and `workflow-templates/wiki-pages.yml` as
   `.github/workflows/wiki-pages.yml` through a separately reviewed change.
   Obtain a passing **Wiki checks** run on `master`; template-only merges do not
   activate these checks. Legacy Pages remains a separate active path.
3. Decide suitable public/private protections, reviewer/account separation and
   plan implications. None were changed here. Keep `wiki-review` PRIVATE.
4. Explicitly authorize baseline/intake for intended new/current entries. Review
   and squash-merge each exact private content head; validate/export its approved
   bytes, then review/merge the resulting public content PR.
5. Before relying on the new publication boundary, owner explicitly migrates
   [Settings → Pages](https://github.com/forecs/forecs.github.io/settings/pages)
   from **Deploy from a branch (`master` / root)** to **GitHub Actions**. This is
   migration of an existing live site, not first-time activation. Preserve the
   `github-pages` environment `master` restriction and review the legacy assets.
   Requesting verification alone does not authorize this settings change.
6. Explicitly set `WIKI_PAGES_ENABLED=true`, then manually dispatch **Publish
   approved wiki** on `master` or let a subsequent approved public merge trigger it.
   Setting the variable alone runs nothing. Build/deploy must be verified live.

The scripts are automation-capable, **not an active fully automatic wiki pipeline**.
The currently active legacy Pages automation is not that pipeline.
Future scheduling requires separate owner authorization, a trusted local runner
with access to the source and native gh, an established no-backfill state, bounded
intake and explicit approved PR/SHA inputs. Scheduled intake must never approve or
merge; scheduled export must enforce the same merge/version checks. No timers,
cron, Actions schedules, cross-repo secrets or service changes are installed.
Pausing future deployment does not retract already public content/history/caches.
