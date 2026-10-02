# Private review → approved export → public learning wiki

## Installation status (2026-10-02)

The owner made `forecs/forecs.github.io` **public** and explicitly selected a
**separate private review repository**. `forecs/wiki-review` was absent, so it was
created **private**, initialized with only a README, and given a reviewable setup
PR: [private setup #1](https://github.com/forecs/wiki-review/pull/1).
Public implementation: [public setup #1](https://github.com/forecs/forecs.github.io/pull/1).
Setup PRs are not content approvals and have not been merged. No real local
wiki entries or historical drafts were uploaded to either repository.

The existing native `gh` login is sufficient for repository creation, private
intake and approved export. It lacks `workflow` scope: the previous active-workflow
push was rejected. Public workflows remain **uninstalled templates**. No new
workflow push, alternate API installation, new secret, cross-repo Actions token,
Control UI connector, scope expansion, scheduler, or Pages activation was attempted.

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
plugins or network requests. Full-text `/wiki/` supports browser Find. Trusted
local CSS provides responsive light/dark styling.

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
| Review repository | `forecs/wiki-review`, PRIVATE, default `main`, ADMIN; created with README only |
| Pages | Destination `has_pages: false`, Pages GET **404**; not activated |
| Public protection | **404 Branch not protected**; rulesets `[]` (previous private-plan 403 no longer applies here) |
| Private protection | Protection/rulesets **403**: upgrade to GitHub Pro or make public; keep review repo private |
| Account plan | API returns no plan name; exact billing plan unverified |
| Pages environment | Existing `github-pages`, branch policy permits `master`, no required-review gate |
| Repository variables | Empty; `WIKI_PAGES_ENABLED` absent |
| Native gh scope | `repo`, `read:org`, `gist`; **no `workflow`** |

[GitHub Pages availability](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages):
GitHub Free supports public repository Pages, so the former *private destination*
paid-plan prerequisite no longer applies. The read-only 404/has_pages check means
there is no configured Pages site, not evidence of a remaining public-plan block.
No create-site request was made to test activation. GitHub Wiki (`hasWikiEnabled`)
is a separate feature from Pages; existing Wiki pages were not migrated or altered.

## Verification delivered with setup

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

## Owner activation checklist — NOT performed

1. Review the public setup PR and private setup PR; merge each only when satisfied.
   Private setup contains protocol/data validator and synthetic tests, not drafts.
2. Owner installs public templates into `.github/workflows/` using already
   workflow-authorized tooling or a separately authorized permission decision.
   Current native gh cannot install them. No scope expansion is requested by the
   bridge. Obtain passing hosted checks; template-only merges leave automation off.
3. Decide suitable public/private protections, reviewer/account separation and
   plan implications. None were changed here. Keep `wiki-review` PRIVATE.
4. Explicitly authorize baseline/intake for intended new/current entries. Review
   and squash-merge each exact private content head; validate/export its approved
   bytes, then review/merge the resulting public content PR.
5. When ready for public hosting, Settings → Pages → GitHub Actions. Preserve the
   existing `master` environment restriction. Review the legacy-site exposure.
6. Explicitly set `WIKI_PAGES_ENABLED=true`, then manually dispatch **Publish
   approved wiki** on `master` or let a subsequent approved public merge trigger it.
   Setting the variable alone runs nothing. Build/deploy must be verified live.

The scripts are automation-capable, **not an active fully automatic pipeline**.
Future scheduling requires separate owner authorization, a trusted local runner
with access to the source and native gh, an established no-backfill state, bounded
intake and explicit approved PR/SHA inputs. Scheduled intake must never approve or
merge; scheduled export must enforce the same merge/version checks. No timers,
cron, Actions schedules, cross-repo secrets or service changes are installed.
Pausing future deployment does not retract already public content/history/caches.
