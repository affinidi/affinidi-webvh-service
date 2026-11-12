# Releases

What operators deploy is a **release**, named by its `major.minor` version
(`0.9`, `0.10`, …). It is cut from `nightly`, stabilised and patched on its own
branch for as long as it is supported, and published as crates and a tag from
there. Patches (`0.9.1`, `0.9.2`, …) only ever happen on the release branch.

This follows the branching model of verifiable-trust-infrastructure, with one
difference: a release here is named by its version, not a tree name, and every
crate in the workspace carries that version. Tagging, `nightly` and the
`branch rules` check run the `release-*` actions of
[affinidi/pipeline-rust](https://github.com/affinidi/pipeline-rust) (README,
"Release branches"). The cut, prep, backport and `release guards` stay local
while only they handle `changelog.d/`.

## Branches

```
feature/*  ──PR──▶  main  ──(nightly.yml: last fully green commit)──▶  nightly
                                                                          │
                          release/0.9  ◀── cut ───────────────────────────┤
                          release/0.10 ◀── cut ───────────────────────────┘
```

| Branch | What it is | Written by |
|---|---|---|
| `main` | Active development. Every PR lands here first. Carries the *next* release's version (`0.10.0` once `release/0.9` is cut) and publishes nothing. | PRs |
| `nightly` | The newest `main` commit on which **every** CI job passed. Fast-forward only. Releases are cut from here, never from `main`'s tip. | `nightly.yml`, daily at 02:00 UTC |
| `release/<major.minor>` | One release, from its cut to its end of life. Takes backported fixes only. | Backport and prep PRs |
| `feature/*`, `fix/*` | Short-lived work. A large effort lands on `main` behind a feature flag, not on a long-lived branch. | Anyone |

## Versions and tags

Every workspace crate has the same version on a release branch, and it is the
release's: `release/0.9` publishes `0.9.0`, then `0.9.1`, … for all six crates
at once. The branch's current version is its `RELEASE` file; the tag is `v` +
that.

| Step | `RELEASE` | Tag | Crates |
|---|---|---|---|
| **Cut** `release/0.9` from `nightly` | `0.9.0-rc.0` | `v0.9.0-rc.0` (prerelease) | set to `0.9.0`, not published |
| **Stabilise** — backport fixes; each prep is another candidate | `0.9.0-rc.1`, … | `v0.9.0-rc.1`, … (prerelease) | — |
| **GA** | `0.9.0` | `v0.9.0` | publish `0.9.0` |
| **Patch** as fixes are backported | `0.9.1`, `0.9.2`, … | `v0.9.1`, … | publish `0.9.N` |
| **EOL** — marked in the table below; the branch stays, read-only | — | — | — |

`main` never publishes and never edits a `version =`: the cut moves it to the
next minor. A patch never changes a public API in a breaking way; a fix that
needs one stays on `main` for the next release.

`did-hosting-ui/package.json` keeps its own version; the tooling does not
touch it.

## Schedule

| Release | Branch | First RC | GA | Latest | Status |
|---|---|---|---|---|---|
| ≤ 0.8 | — | — | — | `0.8.x` | tagged from `main` before release branches existed |
| 0.9 | `release/0.9` | 2026-10-12 (`v0.9.0-rc.0`, from `5d8cfab`) | 2026-10-13 | `0.9.0` | end of life (2026-11-03) |
| 0.10 | `release/0.10` | 2026-10-20 (`v0.10.0-rc.0`, from `95a5dda`) | 2026-10-20 | `0.10.1` | supported (N-1) |
| 0.11 | `release/0.11` | 2026-11-03 (`v0.11.0-rc.0`, from `60cb79c`) | 2026-11-03 | `0.11.0` | supported (N) |
| 0.12 | — | TBD | TBD | — | in development on `main` |

Earlier deployments were also tagged with the VTI stack's release names
(`VTI-Cypress`, `VTI-Dogwood`, `VTI-Eucalyptus`). Those tags stay; new releases
are tagged `v<version>` only.

## Support

The newest two GA releases (N and N-1) are supported. When a release goes GA,
the release before N-1 reaches end of life. "Supported" means fixes for
security problems and for defects that break a deployment are backported and
released. Features never are.

## What goes on a release branch

**Fix on `main` first, then backport.** Label the merged PR
`backport release/<major.minor>` (one label per target branch); `backport.yml`
opens the cherry-pick as a PR on that branch. A backport carries no changelog
notes: a patch's changelog is generated from the commit subjects it ships. So
`CHANGELOG.md` never conflicts (the workflow keeps the release branch's copy),
and `backport.yml` removes the `changelog.d/` fragments the cherry-pick adds in
a follow-up signed-off commit on the backport PR. Any other conflict currently fails the backport — the action's conflict commit
(`BACKPORT-CONFLICT`) is rejected by the commit-message rule — so cherry-pick it
by hand onto a branch named `backport-<pr>-to-release/<major.minor>` and open
that PR against the release branch.

Only fix on the release branch directly when the code there no longer exists on
`main`: a maintainer adds the `release-direct` label to that PR, and its
description says why.

The `branch rules` check holds all of this: a PR into `release/**` is a
backport or prep PR, or labelled `release-direct`; only the release tooling
changes versions, `RELEASE` or `CHANGELOG.md`, on any branch. A cut, prep or
backport PR counts as one only when the release-bot app
(`affinidi-semantic-release[bot]`) opened it from a branch of this repository:
a branch name alone proves nothing. A cut or prep PR also counts when a person
with the admin or maintain role opened it, since cuts are run by hand. The
check runs pipeline-rust's rules, then `scripts/check-branch-rules.py` for the
`CHANGELOG.md` rule.

## Changelog

A PR records a user-facing change as a new file,
`changelog.d/<short-kebab-name>.md`, holding one or more entries in the
changelog's own format (`### <Kind> — <title>`, then paragraphs or bullets);
[changelog.d/README.md](changelog.d/README.md) has the details. It never edits
`CHANGELOG.md`: on `main` that file's `## Unreleased` holds only a line
pointing at `changelog.d/`, which the `release guards` check enforces, and the
`branch rules` check fails a PR that changes `CHANGELOG.md` unless it comes from
a release-tooling branch in this repository. Every PR adds its own file, so
open PRs never conflict over the changelog.

`scripts/changelog_fragments.py` turns the fragments into a release's section
and deletes them. Entries are ordered by kind (Breaking, Changed, Fixed, Added,
Removed, Deprecated, Security, then any other), and within a kind by when the
fragment was added on the branch, oldest first, then by file name. The section
is laid out as `## Unreleased` always was, so `release-tag.yml` reads it
unchanged.

| Step | What happens to the fragments |
|---|---|
| **Cut** | main's `release-cut/<name>` PR assembles the fragments the cut's source commit has into `## <name>.0 (release/<name>)`; ones added after it stay for the next release. The release branch keeps its copies. |
| **rc** | Untouched. |
| **GA** | The prep assembles the release branch's fragments into `## <name>.0 (date)`. |
| **Patch** | Notes are the commit subjects since the last tag. A fragment that reached the branch (a `release-direct` PR) is assembled above them. |
| **Backport** | `backport.yml` drops the fragments the cherry-pick adds. |

```sh
python3 scripts/changelog_fragments.py --dry-run   # the next section, as it would be written
python3 scripts/changelog_fragments.py --check     # validate the fragments
```

## Procedures

### Cut

```sh
python3 scripts/cut-release.py 0.9 --dry-run   # builds both commits, pushes nothing
python3 scripts/cut-release.py 0.9
```

From a clean checkout with push access and `gh` authenticated. It pushes
`release/0.9` (every crate at `0.9.0`, `RELEASE` = `0.9.0-rc.0`, which
`release-tag.yml` tags), creates the `backport release/0.9` label, and opens
the `release-cut/0.9` PR that moves `main` to `0.10.0` and assembles the
`changelog.d/` fragments that shipped into `## 0.9.0 (release/0.9)` (the
release branch's copy is assembled, with its date, at GA). Merge it, then
update the schedule table above.

`--from <rev>` cuts from something other than `origin/nightly` — the first cut,
before `nightly` exists, is `--from origin/main`.

### Release candidate, GA, patch

Actions → **Prepare a release** → choose the release branch as the ref and
`rc`, `ga` or `patch`. It moves `RELEASE`, writes the changelog (GA: the
`changelog.d/` fragments become `## 0.9.0 (date)`, replacing `## Unreleased`;
patch: a new section listing
the commits since the last tag), bumps every crate for a patch, and opens a
`chore(release): v…` PR. **Merging it tags the release** (`release-tag.yml`:
the tag and a GitHub Release whose notes are that version's changelog section).

### Publish

After a GA or patch is tagged, publish its crates from the tag, in dependency
order. The control plane embeds the UI, so build it first and see CLAUDE.md on
`--allow-dirty`:

```sh
git switch --detach v0.9.1
(cd did-hosting-ui && npm ci && npm run build:web)
git status   # nothing but the untracked ui-dist
for c in did-hosting-common did-hosting-server webvh-witness webvh-watcher did-hosting-control did-hosting-daemon; do
  cargo publish -p "$c" --allow-dirty
done
```

### End of life

Set the status in the table. Nothing is deleted: the branch, its tags and its
crates stay.

## Repository settings this relies on

Settings, not files:

- **Ruleset on `release/**`:** require a PR, require the CI jobs and
  `branch rules`, block force pushes and deletion.
- **Ruleset on `main`:** require a PR, and require `branch rules`.
- **Ruleset on `nightly`:** block force pushes and deletion; only the release
  bot (which `nightly.yml` runs as), maintainers and admins may create or
  update it.
- **Environment `release`**, with secrets **`RELEASE_BOT_APP_ID`** and
  **`RELEASE_BOT_PRIVATE_KEY`** — the `affinidi-semantic-release` app.
  `backport.yml`, `release-prep.yml`, `release-tag.yml` and `nightly.yml` run
  in it and mint a token scoped to what each needs. It opens the backport and
  prep PRs: the enterprise does not allow `GITHUB_TOKEN` to open pull
  requests, and a PR it opened would trigger no CI anyway.
