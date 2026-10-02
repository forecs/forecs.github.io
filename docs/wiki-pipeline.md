# Private review → approved export → public learning wiki

## VitePress frontend migration

The frontend modernization is based on `origin/master`
`8b9d85c82f47146a27668a3536a118dfc4a2fc47`, which includes the public setup and
follow-up fixes described below. It preserves this approval/export protocol and
uses VitePress **1.6.4** as the only frontend/publisher, with Playwright **1.63.0**
exactly pinned, behind isolated Python staging and artifact validation. The owner
explicitly chose removal of all historical Hexo assets and EXE/C++ files from the
current Git tree, with no legacy/archive routes or historical download links.
This does not purge Git history or caches. No compatibility acceptance blocker
remains. See [the migration/deployment/rollback runbook](vitepress-migration.md)
for build commands and modern-only recovery.
The dated verification sections below are historical evidence, not a claim that
the VitePress frontend has been deployed or hosted checks have run.

## Installation status (2026-10-02)

The owner made `forecs/forecs.github.io` **public** and explicitly selected a
**separate private review repository**. `forecs/wiki-review` was absent, so it was
created **private**, initialized with only a README, and given a reviewable setup
PR: [private setup #1](https://github.com/forecs/wiki-review/pull/1).
Public implementation: [public setup #1](https://github.com/forecs/forecs.github.io/pull/1).
Both setup PRs merged on 2026-10-02. At that verification, public default `master` was
`0ebadbb6fb913208f82b2ad6f77981a046ffe143`; that verification used the merged tree,
not the former PR branch. Setup PRs are not content approvals. Both merged
defaults contain zero article pairs. Verification uploads no real local wiki
entries or historical drafts.

The existing native `gh` login is sufficient for repository creation, private
intake and approved export. Its scopes are `repo`, `read:org`, `gist`, with no
`workflow` scope; a previous active-workflow push was rejected. This branch now
includes actual `.github/workflows/wiki-checks.yml` and
`.github/workflows/wiki-pages.yml`, replacing the former workflow templates.
A push containing them may be blocked; inclusion locally does not establish a
successful push, merge, hosted check or deployment. Activation is not done here.
The owner separately coordinates Pages source migration to GitHub Actions and
review/merge. No new secret, cross-repo Actions token, connector, scope expansion,
scheduler or Pages configuration change is performed by this documentation update.
The last verified remote deployment was still **legacy root-branch Pages**;
branch-local workflow files do not disable that separate publisher.

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
   public content PR. The branch-included, separately enabled Actions Pages workflow can
   then build only public default-branch content into an isolated artifact.
   These safeguards apply to that workflow only. The last verified legacy
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
or PII. Private review hosted checks were not installed by the setup; the public
workflow files do not add private checks or substitute for review. Copy the **exact 40-hex head
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
from public default, preserving unrelated public files. No private checkout is pushed,
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
plugins or network requests. VitePress retains this inert article contract while
adding local search, responsive navigation and light/dark mode; its trusted
theme/runtime is executable code, but article text is not. Run `npm ci`, `npm test`
and `npm run build`. `scripts/build_site.py` is a standard-library helper module
only, not a standalone builder or fallback publisher. See the migration runbook
for isolated staging and generated-runtime artifact rules.

The builder rejects symlinks, unsafe paths, unexpected metadata/files and digest
mismatches. Initial output must be absent/empty; repeat npm builds replace only
their own exact byte-verified output using an adjacent receipt. Altered/unowned
output and orphan receipts fail closed; the receipt must never be uploaded.
Only validated articles and trusted modern theme/runtime inputs reach `_site`:
no source Markdown/JSON, drafts, state, docs, tests, `.git`, historical Hexo assets,
EXE or C++ files. No legacy/archive routes or historical download links are
emitted. Removal from the current Git tree and new artifact does not erase earlier
Git history, hosted copies or caches. Content validation and receipt safeguards
are unchanged by the modern-only decision.

## Read-only live platform findings (2026-10-02)

A fresh Pages API read during this modern-only update still reports `build_type:
legacy`, source `master` / root, and status `built`. No Pages setting was changed.
This is the old publisher, not evidence of the isolated modern build being live.
The installed workflow files in this branch require remote integration and hosted
verification. Native gh currently has `repo`, `read:org`, `gist`, but no `workflow`
scope, so pushing these workflow changes may be blocked.

**Do not treat `WIKI_PAGES_ENABLED` as a repository-wide publishing kill switch.**
It gates only `.github/workflows/wiki-pages.yml`, not root-branch Jekyll. The owner
must separately select GitHub Actions as the Pages source before relying on this
artifact boundary. No private content has been imported or approved by this work;
`publish_articles` remains empty. Deletion from the current tree does not purge
old Git history, earlier deployments, or caches.

The merged validation/idempotence fixes remain in this branch: duplicate JSON
keys fail closed, PR history lookup includes all bases to detect retargeted or
ambiguous history, and intake refuses to recreate a missing branch with existing
PR history. Public content validator and intake/export implementation are unchanged
by modern-only site cleanup. See [current verification evidence](vitepress-verification.md)
and [the deployment runbook](vitepress-migration.md), not obsolete legacy artifact
counts, for acceptance criteria.

## Owner migration and activation checklist

1. **Completed by owner:** both setup PRs merged. This is not article approval.
   Private setup contains protocol/data validator and synthetic tests, not drafts.
   Review the subsequent validation/idempotence fixes separately before intake.
2. Review the actual `.github/workflows/wiki-checks.yml` and
   `.github/workflows/wiki-pages.yml` included in this branch. The former templates
   are replaced, not an additional installation step. Native gh lacks `workflow`
   scope, so pushing may be blocked: owner-authorized workflow-capable tooling
   must handle any blocked push without bypassing credential restrictions. Branch
   inclusion is not remote integration or activation. The owner separately
   reviews/merges; obtain a passing **Wiki checks** run on default `master`.
   No hosted success is claimed here. Coordinate step 5's source transition before
   relying on isolation; the legacy publisher is a separate path until then.
3. Decide suitable public/private protections, reviewer/account separation and
   plan implications. None were changed here. Keep `wiki-review` PRIVATE.
4. Explicitly authorize baseline/intake for intended new/current entries. Review
   and squash-merge each exact private content head; validate/export its approved
   bytes, then review/merge the resulting public content PR.
5. Before relying on the new publication boundary, owner explicitly migrates
   [Settings → Pages](https://github.com/forecs/forecs.github.io/settings/pages)
   from **Deploy from a branch (`master` / root)** to **GitHub Actions**. This is
   migration of an existing live site, not first-time activation. Preserve the
   `github-pages` environment `master` restriction. Modern VitePress is the only
   supported publisher; historical compatibility needs no further acceptance.
   Requesting verification alone does not authorize this settings change.
6. Explicitly set `WIKI_PAGES_ENABLED=true`, then manually dispatch **Publish modern VitePress site** on `master` or let a subsequent approved public merge trigger it.
   Setting the variable alone runs nothing. The workflow additionally requires
   the fixed public repository, default branch `master`, and event ref
   `refs/heads/master`; it checks out the exact event SHA and uploads only `_site`.
   Build/deploy and intentionally absent historical routes must be verified live.
   Recover only to a previously verified modern artifact/revision, never Jekyll
   or a Python fallback; retain review and artifact/security checks.

The scripts are automation-capable, **not an active fully automatic wiki pipeline**.
The last verified legacy Pages automation is not that pipeline.
Future scheduling requires separate owner authorization, a trusted local runner
with access to the source and native gh, an established no-backfill state, bounded
intake and explicit approved PR/SHA inputs. Scheduled intake must never approve or
merge; scheduled export must enforce the same merge/version checks. No timers,
cron, Actions schedules, cross-repo secrets or service changes are installed.
Pausing future deployment does not retract already public content/history/caches.
