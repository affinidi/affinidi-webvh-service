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

Environment: BASE_REF, HEAD_REF, LABELS (JSON list of label names).
"""

import json
import os
import re
import subprocess
import sys
import tomllib


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def package_version(rev, path):
    out = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True)
    if out.returncode:
        return None
    try:
        return tomllib.loads(out.stdout).get("package", {}).get("version")
    except tomllib.TOMLDecodeError:
        return None


def main():
    base = os.environ["BASE_REF"]
    head = os.environ["HEAD_REF"]
    labels = set(json.loads(os.environ.get("LABELS") or "[]"))
    changed = git("diff", "--name-only", "HEAD^1", "HEAD").split()

    versions = []
    for path in changed:
        if path.endswith("Cargo.toml") and not path.startswith("fuzz/"):
            before, after = package_version("HEAD^1", path), package_version("HEAD", path)
            if before and after and before != after:
                versions.append(f"{path}: {before} -> {after}")
    release_file = "RELEASE" in changed

    problems = []
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

    if problems:
        print(f"Branch rules ({head} -> {base}), RELEASES.md:\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}\n", file=sys.stderr)
        return 1
    print(f"{head} -> {base}: branch rules hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
