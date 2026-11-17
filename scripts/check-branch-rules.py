#!/usr/bin/env python3
"""The branch rules pipeline-rust's shared check cannot hold here (RELEASES.md).

Run by `.github/workflows/branch-rules.yml` after pipeline-rust's
`release-branch-rules` action, on every PR into `main` or `release/**`,
against the PR's merge commit (HEAD^1 = base, HEAD = merged). The shared
action already decides where a PR may go (backport, prep or `release-direct`
into `release/**`) and that no PR adds `RELEASE` to main. This script adds:

  1. Versions. The shared check reads the workspace version from the root
     `[workspace.package] version`, which this repository does not set: every
     crate carries its own literal `version`. It then treats every PR as the
     workspace's bootstrap and skips its version rules. So here: into
     `release/<name>`, only a prep PR changes a crate's `version`; into `main`,
     only a cut PR does.
  2. CHANGELOG.md. Only the release tooling (cut and prep PRs) changes it.
     Everyone else adds a `changelog.d/` fragment (changelog.d/README.md), so
     open PRs never conflict over `## Unreleased`. The one change anyone may
     make is moving entries out: a CHANGELOG.md that differs from the base only
     in `## Unreleased`, which is left holding nothing but the pointer line.

A cut or prep PR is recognised as the shared check recognises it, never by its
branch name alone: a `release-cut/…` or `release-prep/<name>/…` branch of this
repository, opened by the release bot (known by its account ID, which unlike a
login is never reused) or, with MAINTAINER_RELEASES=true (set while cuts and
preps still run by hand, as the shared action's `maintainer-releases` input),
by a person with the admin or maintain role. A backport carries neither a version change nor
a CHANGELOG.md change (backport.yml keeps the release branch's copy), so it has
no exemption here.

Environment: BASE_REF, HEAD_REF, REPO (this repository, `owner/name`),
HEAD_REPO (the repository the head branch lives in), AUTHOR and AUTHOR_ID (the
PR author's login and account ID), MAINTAINER_RELEASES, and GITHUB_TOKEN to read the author's role
(GITHUB_API_URL, default `https://api.github.com`). The role is read only for a
cut or prep branch whose author is not the release bot.
"""

import json
import os
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from changelog_fragments import unreleased_is_pointer_only  # noqa: E402
from release_lib import unreleased_split  # noqa: E402

# affinidi-semantic-release[bot], the account the release bot app acts as; the
# same ID pipeline-rust's check-branch-rules.py trusts.
RELEASE_BOT_ID = 169678785


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


def is_maintainer(repo, login):
    """Whether `login` holds the admin or maintain role on `repo`."""
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    req = urllib.request.Request(
        f"{api}/repos/{repo}/collaborators/{urllib.parse.quote(login, safe='')}/permission",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            role = json.load(resp).get("role_name")
    except urllib.error.HTTPError as e:
        if e.code == 404:  # not a collaborator
            return False
        raise SystemExit(f"could not read {login}'s role on {repo}: HTTP {e.code}")
    return role in ("admin", "maintain")


def main():
    base = os.environ["BASE_REF"]
    head = os.environ["HEAD_REF"]
    repo = os.environ["REPO"]
    same_repo = os.environ.get("HEAD_REPO") == repo
    author = os.environ.get("AUTHOR") or ""
    by_bot = os.environ.get("AUTHOR_ID") == str(RELEASE_BOT_ID)
    manual = os.environ.get("MAINTAINER_RELEASES") == "true"

    def released_by(branch_matches):
        # The role is read only for a cut or prep branch, so other PRs make no API call.
        return (
            branch_matches
            and same_repo
            and (by_bot or (manual and bool(author) and is_maintainer(repo, author)))
        )

    if base.startswith("release/"):
        name = base.removeprefix("release/")
        tooling = released_by(head.startswith(f"release-prep/{name}/"))
    elif base == "main":
        tooling = released_by(head.startswith("release-cut/"))
    else:
        tooling = False

    changed = git("diff", "--name-only", "HEAD^1", "HEAD").split()

    versions = []
    for path in changed:
        if path.endswith("Cargo.toml") and not path.startswith("fuzz/"):
            before, after = package_version("HEAD^1", path), package_version("HEAD", path)
            if before and after and before != after:
                versions.append(f"{path}: {before} -> {after}")

    problems = []
    if versions and not tooling:
        if base.startswith("release/"):
            problems.append(
                f"Only the *Prepare a release* workflow changes versions on {base}. "
                "Revert: " + "; ".join(versions)
            )
        else:
            problems.append(
                "A PR never edits a crate's `version =`: main carries the next release's "
                "version, set when a release is cut (RELEASES.md). Revert: " + "; ".join(versions)
            )

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
    print(f"{head} -> {base}: local branch rules hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
