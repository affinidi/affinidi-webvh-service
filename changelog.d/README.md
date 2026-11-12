# Changelog fragments

A PR with a user-facing change adds **one new file here** instead of editing
`CHANGELOG.md`. Every PR writes its own file, so open PRs never conflict over
the top of `## Unreleased`. The `branch rules` check fails a PR into `main` or
a release branch that changes `CHANGELOG.md`; only the release tooling writes
it.

## Naming

`changelog.d/<short-kebab-name>.md`: lower-case letters, digits and hyphens,
named after the change (`admin-suspension-sticky.md`,
`witness-listener-limits.md`). The name only has to be unique; it never
appears in the changelog.

## Format

Exactly what a `CHANGELOG.md` entry looks like: a `### <Kind> — <title>`
heading, then paragraphs or bullets. One file may hold several entries.

```markdown
### Fixed — a DID an administrator suspended stays suspended until an administrator resumes it

`did/set-state` stored only whether a slot was suspended, not who
suspended it, and a re-register wrote every slot back as active. …
```

Kind is one of **Breaking**, **Changed**, **Fixed**, **Added**, **Removed**,
**Deprecated** or **Security**; the free text after the dash says what changed.
A change that breaks an operator, a client or a peer (a Trust Task version, a
config key, a stored format) is **Breaking**, or says `BREAKING` in its entry.

`python3 scripts/changelog_fragments.py --check` validates the fragments (the
`release guards` CI job runs it).

## At release

`scripts/changelog_fragments.py` gathers the fragments into the release's
`CHANGELOG.md` section and deletes them: on `main` when the release is cut
(`cut-release.py`), on the release branch at GA (`prepare-release.py`).
Entries are ordered by kind (Breaking, Changed, Fixed, Added, Removed,
Deprecated, Security, then any other), and within a kind by when the fragment
was added, oldest first, then by file name. See what the next section would
be with:

```sh
python3 scripts/changelog_fragments.py --dry-run
```

A backport to a release branch carries no fragment: `backport.yml` drops it,
and a patch's notes come from the commit subjects it ships (RELEASES.md).

This README is never assembled.
