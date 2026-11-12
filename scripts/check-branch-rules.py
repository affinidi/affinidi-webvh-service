#!/usr/bin/env python3
"""Enforce where a PR may go and what it may change (RELEASES.md).

Run by `.github/workflows/branch-rules.yml` on every PR into `main` or
`release/**`, against the PR's merge commit (HEAD^1 = base, HEAD = merged).

Into `release/<major.minor>`:
  1. Only a bot backport (`backport-<pr>-to-release/<name>`, opened by
     backport.yml), a prep PR (`release-prep/<name>/<version>`), or a PR
     labelled `release-direct` by a maintainer. A fix lands on main first.
  2. Only a prep PR changes a crate's `version` or `RELEASE`.

Into `main`:
  3. Only a cut PR (`release-cut/<name>`, from cut-release.py) changes a
     crate's `version`: main carries the next release's version, set at the cut.
  4. No PR adds a `RELEASE` file: it marks a release branch.

Either way:
  5. A head branch whose name the rules above treat specially (`backport-…`,
     `release-prep/…`, `release-cut/…`) must live in this repository. A fork
     can name a branch anything, so only a branch pushed here carries the
     meaning of its name.
  6. Only the release tooling's branches (those same names, in this
     repository) change CHANGELOG.md. Everyone else adds a `changelog.d/`
     fragment (changelog.d/README.md), so open PRs never conflict over
     `## Unreleased`. The one change anyone may make is moving entries out:
     a CHANGELOG.md that differs from the base only in `## Unreleased`, which
     is left holding nothing but the pointer line.

Environment: BASE_REF, HEAD_REF, LABELS (JSON list of label names), REPO
(this repository, `owner/name`) and HEAD_REPO (the repository the head branch
lives in). Without REPO (a local run), rule 5 is not checked; with REPO set,
an empty HEAD_REPO (a head repository that has since been deleted) counts as
another repository.
"""

import json
import os
import re
import subprocess
import sys
import tomllib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from changelog_fragments import unreleased_is_pointer_only  # noqa: E402
from release_lib import unreleased_split  # noqa: E402


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def show(rev, path):
    out = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True)
    return out.stdout if out.returncode == 0 else None


def package_version(rev, path):
    text = show(rev, path)
    if text is None:
        return None
    try:
        return tomllib.loads(text).get("package", {}).get("version")
    except tomllib.TOMLDecodeError:
        return None


def only_empties_unreleased():
    """Whether the PR's CHANGELOG.md change only moves `## Unreleased` entries out."""
    before, after = show("HEAD^1", "CHANGELOG.md"), show("HEAD", "CHANGELOG.md")
    b = unreleased_split(before) if before is not None else None
    a = unreleased_split(after) if after is not None else None
    return bool(a and b and unreleased_is_pointer_only(a[1]) and (a[0], a[2]) == (b[0], b[2]))


def main():
    base = os.environ["BASE_REF"]
    head = os.environ["HEAD_REF"]
    labels = set(json.loads(os.environ.get("LABELS") or "[]"))
    repo = os.environ.get("REPO") or ""
    head_repo = os.environ.get("HEAD_REPO") or ""
    changed = git("diff", "--name-only", "HEAD^1", "HEAD").split()

    versions = []
    for path in changed:
        if path.endswith("Cargo.toml") and not path.startswith("fuzz/"):
            before, after = package_version("HEAD^1", path), package_version("HEAD", path)
            if before and after and before != after:
                versions.append(f"{path}: {before} -> {after}")
    release_file = "RELEASE" in changed

    problems = []
    tooling_name = re.match(r"(backport-\d+-to-release/|release-prep/|release-cut/)", head)
    if tooling_name and repo and head_repo != repo:
        where = head_repo or "a repository that no longer exists"
        problems.append(
            f"`{head}` is a release-tooling branch name, but this branch is in {where}, "
            f"not {repo}. Those names are only honoured on branches in {repo}; rename the "
            "branch."
        )
        # Judge the rest as an ordinary branch.
        head = f"{head_repo or 'unknown'}:{head}"

    if base.startswith("release/"):
        name = base.removeprefix("release/")
        backport = re.fullmatch(rf"backport-\d+-to-release/{re.escape(name)}", head)
        prep = head.startswith(f"release-prep/{name}/")
        if not (backport or prep or "release-direct" in labels):
            problems.append(
                f"A change reaches {base} by backport, not directly. Open this PR against main "
                f"instead; once it merges, label it `backport {base}` and backport.yml opens the "
                f"cherry-pick here. If the code no longer exists on main, a maintainer adds the "
                f"`release-direct` label, and the description says why."
            )
        if not prep and (versions or release_file):
            what = versions + (["RELEASE"] if release_file else [])
            problems.append(
                f"Only the *Prepare a release* workflow changes versions or RELEASE on {base}. "
                "Revert: " + "; ".join(what)
            )
    elif base == "main":
        if versions and not head.startswith("release-cut/"):
            problems.append(
                "A PR never edits a crate's `version =`: main carries the next release's "
                "version, set when a release is cut (RELEASES.md). Revert: " + "; ".join(versions)
            )
        if release_file:
            problems.append("RELEASE marks a release branch; it never belongs on main. Remove it.")

    # `head` is already demoted to `<fork>:<name>` above when a fork borrows a
    # tooling name, so this match means a release-tooling branch in this repo.
    tooling = re.match(r"(backport-\d+-to-release/|release-prep/|release-cut/)", head)
    if "CHANGELOG.md" in changed and not tooling and not only_empties_unreleased():
        problems.append(
            "Only the release tooling edits CHANGELOG.md. Revert it, and record the change as a "
            "new file changelog.d/<short-kebab-name>.md holding the `### <Kind> — <title>` entry "
            "(changelog.d/README.md); it is assembled into CHANGELOG.md at release."
        )

    if problems:
        print(f"Branch rules ({head} -> {base}), RELEASES.md:\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}\n", file=sys.stderr)
        return 1
    print(f"{head} -> {base}: branch rules hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
