#!/usr/bin/env python3
"""Prepare the next rc, GA or patch on a release branch (RELEASES.md).

    python3 scripts/prepare-release.py --kind rc|ga|patch [--pr-body FILE]

Run by `release-prep.yml` from a checkout of `release/<major.minor>`; it
edits the tree and the workflow commits it as a `chore(release): v…` PR.
Merging that PR is the release: `release-tag.yml` tags `v<RELEASE>`.

  rc     0.9.0-rc.N -> 0.9.0-rc.N+1   RELEASE only.
  ga     0.9.0-rc.N -> 0.9.0          RELEASE; CHANGELOG `## Unreleased`
                                      and the `changelog.d/` fragments
                                      become `## 0.9.0 (date)`.
  patch  0.9.N      -> 0.9.N+1        every crate's version; RELEASE; a
                                      CHANGELOG section listing the commits
                                      since the last tag.

The changelog entries are `changelog.d/` fragments until GA, when
changelog_fragments.assemble() writes them into the version's section (in the
same layout `## Unreleased` had, so release-tag.yml's extraction is unchanged)
and deletes them. An rc touches neither.

A patch's entries come from the commit subjects since the previous tag, not
from cherry-picked notes: backport.yml keeps the release branch's CHANGELOG.md
and drops a backport's `changelog.d/` fragments. Commit subjects are
conventional, so they read as entries. A fragment that reached the branch
anyway (a `release-direct` PR) is assembled above the commits.
"""

import argparse
import datetime
import sys

from changelog_fragments import assemble, fragment_paths
from release_lib import ROOT, git, parse_release, set_version, unreleased_split


def commits_since(tag):
    if git("rev-parse", "-q", "--verify", f"refs/tags/{tag}", check=False).returncode:
        return None
    out = git("log", "--no-merges", "--format=%s", f"{tag}..HEAD").stdout.splitlines()
    return [s for s in out if not s.startswith("chore(release)")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", required=True, choices=["rc", "ga", "patch"])
    ap.add_argument("--pr-body")
    args = ap.parse_args()

    branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    release_file = ROOT / "RELEASE"
    if not release_file.exists():
        sys.exit("no RELEASE file: run this on a release/<major.minor> branch")
    current = release_file.read_text().strip()
    major, minor, patch, rc = parse_release(current)
    if branch not in ("HEAD", f"release/{major}.{minor}"):
        sys.exit(f"RELEASE says {current}, but this is {branch}")

    today = datetime.date.today().isoformat()
    changelog = ROOT / "CHANGELOG.md"
    text = changelog.read_text()
    since = commits_since(f"v{current}")

    if args.kind == "rc":
        if rc is None:
            sys.exit(f"{current} is GA; an rc comes before GA. Use `patch`.")
        target = f"{major}.{minor}.{patch}-rc.{rc + 1}"
    elif args.kind == "ga":
        if rc is None:
            sys.exit(f"{current} is already GA. Use `patch`.")
        target = f"{major}.{minor}.{patch}"
        if not unreleased_split(text):
            sys.exit("CHANGELOG.md has no `## Unreleased` section to release")
        assemble(f"{target} ({today})", ROOT)
    else:
        if rc is not None:
            sys.exit(f"{current} is a release candidate; use `rc` or `ga` first.")
        if since is None:
            sys.exit(f"tag v{current} is missing: did release-tag.yml run for it?")
        if not since:
            sys.exit(f"nothing has changed since v{current}")
        target = f"{major}.{minor}.{patch + 1}"
        set_version(ROOT, target)
        entries = "".join(f"- {s}\n" for s in since)
        if unreleased_split(text) or fragment_paths(ROOT):
            # Notes that reached the branch (a `## Unreleased` section, or a
            # fragment from a `release-direct` PR) are this patch's.
            assemble(f"{target} ({today})", ROOT, extra=f"### Commits\n\n{entries}")
        else:
            head, sep, rest = text.partition("\n## ")
            text = f"{head}\n## {target} ({today})\n\n{entries}{sep}{rest}" if sep else f"{text}\n## {target} ({today})\n\n{entries}"
            changelog.write_text(text)

    release_file.write_text(f"{target}\n")
    print(f"{current} -> {target}")

    if args.pr_body:
        lines = [f"Prepares **v{target}** on `release/{major}.{minor}` (was `v{current}`).", ""]
        lines.append("Merging this PR is the release: `release-tag.yml` tags it.")
        if since:
            lines += ["", f"Changes since `v{current}`:", ""] + [f"- {s}" for s in since]
        with open(args.pr_body, "w") as f:
            f.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
