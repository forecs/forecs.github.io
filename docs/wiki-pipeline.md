# Private review → human merge → public learning wiki

## Current installation status — owner action required

The core bridge/builder/tests are implemented. GitHub refused the initial push of
`.github/workflows/wiki-checks.yml` because the existing native `gh` OAuth login
lacks **`workflow` scope**. No credential refresh or extra authority was granted.
To deliver a reviewable private setup PR without installing privileged automation,
the two workflows are stored only in **`workflow-templates/`**. Templates do not
execute. All CI/Pages behavior below describes the design **after owner installation**;
this setup PR has local test/lint/build evidence, not a hosted Actions run.

The full active-workflow version is also retained on a local-only implementation
branch, but is not a remote PR. No alternate API was used to bypass the scope check.

## State and trust model

1. **Local source** is private and untrusted data. GitHub-hosted Actions cannot read
   the local Gateway filesystem; `scripts/wiki_intake.py` is the explicit bridge.
2. **Review candidate** is a private PR adding/updating exactly two files:
   `publish_articles/<slug>.md` and `<slug>.json`. Those files do **not** exist on
   `master` until a human merges the PR. No separate drafts folder is copied into
   the publishing branch, avoiding a promotion bot with write privileges.
3. **Approved content** is the exact tree produced by a deliberate human merge to
   `master`. The merge commit/PR history is the approval record. Body SHA-256 is
   checked at build time; title + body + slug bind the immutable review version.
4. **Public site** is an isolated build of `master`, only after a separate owner
   deployment opt-in. PR checks run tests with synthetic data and validate article
   structure; they never build/upload a real candidate preview or request Pages
   privileges. No `pull_request_target`, `workflow_run`, issue-comment execution,
   scheduled event, auto-merge, approval bot, or content-driven shell command exists.

### Same-account approval, precisely

The native `forecs` login can create a private PR, but GitHub does not let a PR author
approve their own PR review. Requiring a self-review or pretending an unavailable
private environment reviewer gate exists would deadlock the pipeline.

Instead, **the human's deliberate, SHA-bound merge is the approval action**. There
is no earlier reusable `approved` state. Review the current diff and checks, copy
its exact head SHA, then the human (not the intake agent) may run:

```sh
# Replace both literals with the PR number and the EXACT SHA whose full diff you reviewed.
gh pr merge PR_NUMBER --repo forecs/forecs.github.io --squash --match-head-commit REVIEWED_40_HEX_SHA
```

Do not add `--auto` or `--admin`. The command fails if the current head no longer
matches. A merge from the GitHub UI is also an explicit human decision, but the
SHA-matching command above makes stale-review protection explicit. Never fetch a
fresh SHA automatically and merge without reviewing it. Never execute commands
from article text. A label, approving comment, old CI success or previous PR review
is not sufficient. An amendment changes the review version/head, requires fresh
human review, and invalidates a previous SHA-bound merge command. Intake never
force-pushes or updates review branches; changed content gets a different PR.
Close superseded PRs manually so an older version is not accidentally selected.

**Important security boundary:** GitHub cannot distinguish a human from an agent
using the same account token. This is a safe cooperative workflow, not a technical
barrier against a malicious admin or a direct push using that credential. Current
private-repo branch protection/rules APIs return a plan-upgrade error. No protection
was changed. Strong non-bypassable separation requires a separately permissioned
intake identity plus owner-managed protections/required reviews on a supported
plan. That is an optional future authority decision, not something this setup
silently enables. Hashes prove byte integrity, not the identity of a human.

## Local intake (manual; no scheduling enabled)

Use an ordinary clone with a real `.git` directory and Python 3.12+ on Linux/macOS.
The bridge uses the already authenticated `gh` executable; ordinary content PRs
need no Control UI connector, new secret, or Git configuration change. Installing
GitHub Actions workflows is a separate permission requirement noted above. Run from the implementation
checkout after setup is reviewed. Set `WIKI_SOURCE_ROOT` locally to the structured
wiki directory. It is deliberately not hardcoded into this private/public repository.

### Start safely: baseline, never backfill

```sh
python3 scripts/wiki_intake.py baseline --source-root "$WIKI_SOURCE_ROOT" --dry-run
python3 scripts/wiki_intake.py baseline --source-root "$WIKI_SOURCE_ROOT"
```

Baseline records the names of **all existing Markdown files locally** and uploads
nothing. Existing files, including later edits to historical entries, are ignored
unless explicitly selected. A baseline cannot be overwritten. State and its lock
live at `.git/wiki-intake-<source-root-hash>.json` / `.lock`, with mode 0600. They
contain private source names and must not be shared or added to Git. No state is
stored alongside the source wiki. Back up this state locally if needed. If it is
lost, a new baseline skips all then-existing files; it never backfills them.

### New items after baseline

```sh
python3 scripts/wiki_intake.py submit --source-root "$WIKI_SOURCE_ROOT" --dry-run
python3 scripts/wiki_intake.py submit --source-root "$WIKI_SOURCE_ROOT"
```

Default is **one article per invocation**, sorted by relative filename. `--limit 2`
through `--limit 5` permit a small bounded batch. No bulk/backfill flag exists.
Successful intake tracks that file; subsequent edits to tracked files are eligible
for a new immutable version PR, retaining any explicitly selected public slug/title.
Historical entries remain excluded.

`--dry-run` performs no network calls, writes, branch creation, state advance, or
article-body logging. Output is limited to public slug, body digest, byte count,
status and (on submission) private PR URL/head/version. Inspect candidate text in
the private PR before merging; dry-run is not a content approval or DLP scan.

### Explicit one-article opt-in / today's memo

For any existing entry, select exactly one relative Markdown path and preferably
choose a deliberate public slug and title. The sample below is schematic; do not
put an absolute source path in repository docs or PR descriptions.

```sh
python3 scripts/wiki_intake.py submit --source-root "$WIKI_SOURCE_ROOT" \
  --select 'tech/ai/example.md' --slug agentic-ai-design \
  --title '智能体 AI 应用设计备忘' --dry-run
# Remove --dry-run only when that one file is authorized for private review.
```

An initial explicit selection without an existing baseline implicitly baselines
all other current files. It never uploads its neighbors. Today's real memo can be
such a candidate; this setup contains **no real article** and uploads no historical
wiki. The actual source path is supplied only on the local CLI.

### Idempotency and failures

- Branch name is `wiki-review/<SHA256(slug + metadata + normalized-body)>`.
- The API creates a single commit against the current default-branch SHA, changing
  only the article pair. It does not use local Git hooks, switch the checkout,
  amend an existing branch or write `master`.
- Repeating an explicit selection reuses the same PR only after validating its
  exact payload and changed-file scope. An amended/unexpected branch is refused.
- The bridge checks `private == true` before remote writes. A repository made
  public causes intake to stop rather than disclose a candidate.
- A crash after branch creation is recoverable: retry locates and verifies that
  branch before creating/reusing the PR. State advances only after a successful
  result and is atomically saved after each item. A closed PR stays closed; edit
  content for a new review or decide manually whether to reopen it. A byte-identical
  pair already on default is reported without creating another branch.
- Concurrent local runs serialize with a file lock; cross-machine ref collisions
  fail without force-push and may be retried. No tight retries occur. On HTTP
  errors, including 429, stop; honor the service's Retry-After/reset time before
  manually retrying. The bridge does not log request payloads or tokens.
- Renames get a new automatic slug and may propose another note. For intentional
  updates/renames use the original public `--slug` with explicit selection. Deletion
  never deletes a public article automatically; use a separate human-reviewed PR.

## Public data contract and rendering

Each article has a normalized UTF-8 `.md` body (max 256 KiB, LF, one trailing
newline) and strict JSON `{ "title": "Public title", "sha256": "..." }`. Slugs
are lowercase ASCII letters/digits separated by single hyphens, at most 80 chars.
The default slug is a path hash, not a local filename. All original frontmatter is
removed without YAML evaluation, including its title and comments. The public title
comes from an explicit `--title`, the first heading in the stripped public body,
or a generic note label. No tags, category, source, timestamps, raw source path, or other
private metadata is attached. Source references to common local filesystem paths
are rejected as defense in depth. This is **not** comprehensive secret/PII detection:
private facts in the body/title still require careful human review. A body beginning
with a standalone `---` is deliberately rejected before remote submission to avoid
ambiguity with frontmatter; use `***` or put a heading before a leading horizontal
rule. Intake validates this normalization contract before creating a PR.

The renderer supports headings, paragraphs, basic ordered/unordered lists,
fenced code and single-backtick inline code. Other inline Markdown, link/image
syntax, raw HTML and template expressions remain escaped text; links/images supplied by content never become active network
requests. No YAML, Liquid, Jekyll, shell substitution, plugins or embedded code is
executed. The `/wiki/` page includes full text for browser Find (Ctrl/Cmd-F), with no
JavaScript/search service. A small trusted local stylesheet provides responsive
light/dark reading layout; article content cannot supply styles. The homepage is
a title index, not a dated feed; add
public dates/tags later only through an explicit schema/review change.

The builder preflights paths and validates all article digests. Symlink input and
output, path traversal, unexpected metadata/files, and nonempty outputs fail closed.
Only validated articles and files explicitly named in `site/legacy-files.txt`
reach `_site`. It never recursively publishes the checkout, tests, docs, `.git`,
intake state, source wiki, drafts, raw Markdown or article JSON.

### Existing generated Hexo site

There was no Hexo source/config/package file to build. Existing tracked files are
preserved unchanged. The allowlist preserves the original `/2016/...`, `/archives/`,
CSS, JS, fonts and image paths. The old root is copied to `/legacy/index.html` with
a root base URL; new homepage navigation links it and the old archive. Existing
EXE/C++ downloads remain in Git but are deliberately **not** emitted by the new
builder; restoring downloads requires a separate explicit public-asset decision.
Legacy HTML/JS is existing trusted code, not sanitized wiki content; its external
fonts/scripts and legacy links are unchanged. Review that legacy exposure before
activation. The strict no-content-execution policy applies to new wiki articles.

## Pages / plan inspection (2026-10-02; read-only)

- Repository API: private, default `master`, current login `forecs`, ADMIN access.
- Existing site is static generated Hexo HTML; no existing workflows or build config.
- `has_pages: false`; GET `/repos/forecs/forecs.github.io/pages` returned **404**.
  A 404 alone does not prove plan eligibility or ineligibility.
- Branch protection and ruleset reads returned **403** with
  `Upgrade to GitHub Pro or make this repository public to enable this feature.`
- Account API did not expose a plan name (`null`). Exact billing status cannot be
  verified with this token. Do not infer a successful Pages activation from that.
- Existing `github-pages` environment has a branch policy permitting `master`,
  not a required-human-review protection. It was not modified. Existing global
  workflow permission defaults were not changed; these new workflows explicitly
  reduce permissions, and checkout does not persist credentials.
- `WIKI_PAGES_ENABLED` was absent. No variable, Pages source, environment, rule,
  visibility, branch protection, scheduler, or deployment was changed.
- Actual workflow push was rejected: `refusing to allow an OAuth App to create or
  update workflow ... without workflow scope`. Existing native login remains
  sufficient for code/content PRs, but not installing the workflow files. Templates
  were committed instead; no hosted CI/deploy workflow is installed by this PR.

[GitHub Pages availability](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages):
private-repository Pages requires GitHub Pro, Team, or Enterprise; GitHub Free
supports public-repository Pages. A private source repository does **not** make an
ordinary Pages site private. The intended site is public, so review every emitted
legacy asset and article. Given the upgrade responses, resolve/verify eligible
billing with the owner before enabling Pages. This implementation does not attempt
a create-site API call merely to probe capability, because that would change config.

## Owner activation checklist — deliberately NOT performed

1. Review the **implementation setup PR** and local verification. Install the two
   files in `workflow-templates/` into `.github/workflows/` using an identity allowed
   to write workflows (for example, the owner can explicitly grant the existing
   native `gh` login the `workflow` scope through GitHub's authorization flow).
   Do not expand credentials implicitly. After installation, obtain a passing
   **Wiki checks** hosted run and human-merge the setup. Installing/merging alone
   publishes nothing: Pages still requires `WIKI_PAGES_ENABLED == 'true'`, exact
   `master`, and the expected repository/default branch. A template-only setup
   merge is possible, but hosted automation remains uninstalled until this step.
2. Resolve private Pages eligibility (likely GitHub Pro for this personal account;
   confirm with billing/settings). **Do not make this review repository public.**
   A separate public-output repo is an alternative architecture requiring a new
   owner decision/implementation, not an automatic workaround.
3. In repository Settings → Pages select **GitHub Actions** as the source after
   confirming eligibility. Keep the existing `github-pages` environment restricted
   to `master`. Confirm public exposure of the allowlisted legacy site is intended.
4. Establish the local baseline; optionally submit only the selected current memo.
   Human-review and merge each exact content PR head separately. No bot merge.
5. Only when ready, create repository Actions variable `WIKI_PAGES_ENABLED=true`.
   Then manually dispatch **Publish approved wiki** on `master` (or let the next
   approved content merge trigger it). Future default-branch pushes rebuild the
   approved set. Enabling the variable itself does not run a workflow.
6. Verify build/deploy success, inspect the actual public URLs and artifact for
   unintended content. No live public deployment was tested during setup.

No timer is necessary for manual intake. Any future Gateway scheduling, protection
changes, alternate identity, or environment reviewers require a separate owner
request. To pause future deployments, unset/set the variable to `false`; this does
not remove an already published site. Removing/retracting a public site or article
requires a deliberate follow-up and cannot erase third-party caches/history.
