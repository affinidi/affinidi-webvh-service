#!/usr/bin/env python3
"""Cut a release: create `release/<major.minor>` and move main to the next one.

    python3 scripts/cut-release.py 0.9 [--from origin/nightly] [--dry-run]

Run by the release manager from a clean checkout with push access and `gh`
authenticated. It:

  1. resolves the source commit — `origin/nightly` by default, the newest main
     commit the full CI suite passed (RELEASES.md) — and refuses one main
     doesn't have, since only main is reviewed;
  2. pushes `release/<name>` = source commit + one commit that sets every
     workspace crate to `<name>.0`, its internal pins to `<name>`, and writes
     `RELEASE` = `<name>.0-rc.0`. `release-tag.yml` then tags `v<name>.0-rc.0`;
  3. opens a PR to main (`release-cut/<name>`) that moves every crate to the
     next minor (`0.10.0` after `0.9`) and writes the release's CHANGELOG.md
     section, `## <name>.0 (release/<name>)`, from the `changelog.d/`
     fragments the source commit has (changelog_fragments.assemble()),
     deleting them. `## Unreleased` stays, holding only the pointer line;
  4. creates the `backport release/<name>` label backport.yml reads.

Fragments added on main after the source commit stay in `changelog.d/`: they
belong to the next release. The release branch keeps its fragments until its
GA prep assembles them into `## <name>.0 (date)`.

The split is only automatic when every shipped fragment is unchanged on main
and main's `## Unreleased` holds what the source commit's did. If not, main's
CHANGELOG is left alone and the script says so: move the entries that shipped
in the release under its heading by hand, in the PR.
"""

import argparse
import pathlib
import sys
import tempfile

from changelog_fragments import FRAGMENT_DIR, README, assemble, strip_pointer
from release_lib import RELEASE_NAME, git, run, set_version, unreleased_split


def worktree(rev, tmp, name):
    path = pathlib.Path(tmp) / name
    git("worktree", "add", "--detach", str(path), rev)
    return path


def shipped_fragments(source, mn):
    """(names, problems): the source commit's fragments, as main still has them."""
    listing = git("ls-tree", "--name-only", f"{source}:{FRAGMENT_DIR}", check=False).stdout.split()
    names, problems = set(), []
    for name in listing:
        if name == README or not name.endswith(".md"):
            continue
        on_main = mn / FRAGMENT_DIR / name
        if not on_main.exists():
            continue  # removed on main since: nothing to move
        if on_main.read_text() != git("show", f"{source}:{FRAGMENT_DIR}/{name}").stdout:
            problems.append(f"{FRAGMENT_DIR}/{name} changed on main since the cut's source")
        names.add(name)
    return names, problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name", help="major.minor, e.g. 0.9")
    ap.add_argument("--from", dest="source", default="origin/nightly")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    m = RELEASE_NAME.fullmatch(args.name)
    if not m:
        sys.exit(f"release name {args.name!r} is not major.minor")
    major, minor = map(int, m.groups())
    branch = f"release/{args.name}"
    version = f"{args.name}.0"
    next_version = f"{major}.{minor + 1}.0"

    git("fetch", "origin", "--tags", "--prune")
    if git("ls-remote", "--exit-code", "--heads", "origin", branch, check=False).returncode == 0:
        sys.exit(f"{branch} already exists")
    source = git("rev-parse", "--verify", f"{args.source}^{{commit}}").stdout.strip()
    main_sha = git("rev-parse", "--verify", "origin/main^{commit}").stdout.strip()
    if git("merge-base", "--is-ancestor", source, main_sha, check=False).returncode:
        sys.exit(f"{args.source} ({source[:12]}) is not on main: a release is cut from a reviewed main commit")
    print(f"cutting {branch} from {args.source} ({source[:12]}); main is {main_sha[:12]}")

    # Prune after the temporary directory is gone: pruned inside it, the
    # worktrees still exist and their records are left behind.
    try:
        with tempfile.TemporaryDirectory() as tmp:
            # The release branch.
            rel = worktree(source, tmp, "release")
            set_version(rel, version)
            (rel / "RELEASE").write_text(f"{version}-rc.0\n")
            git("add", "-A", cwd=rel)
            git("commit", "-s", "-m", f"chore(release): cut {branch} at {version}-rc.0", cwd=rel)

            # main's half.
            mn = worktree(main_sha, tmp, "main")
            set_version(mn, next_version)
            source_log = git("show", f"{source}:CHANGELOG.md").stdout
            main_log = (mn / "CHANGELOG.md").read_text()
            src, cur = unreleased_split(source_log), unreleased_split(main_log)
            shipped, drift = shipped_fragments(source, mn)
            for d in drift:
                print(f"WARNING: {d}", file=sys.stderr)
            split = bool(
                src and cur and strip_pointer(src[1]).strip() == strip_pointer(cur[1]).strip() and not drift
            )
            if split:
                assemble(f"{version} ({branch})", mn, keep_unreleased=True, only=shipped)
            git("add", "-A", cwd=mn)
            git(
                "commit", "-s", "-m",
                f"chore(release): cut {branch}; main moves to {next_version}",
                cwd=mn,
            )

            print(git("show", "--stat", "HEAD", cwd=rel).stdout)
            print(git("show", "--stat", "HEAD", cwd=mn).stdout)
            if not split:
                print(
                    "WARNING: main's `## Unreleased` differs from the cut's; CHANGELOG.md on "
                    "main was not split. Move the shipped entries under "
                    f"`## {version}` by hand in the release-cut PR.",
                    file=sys.stderr,
                )
            if args.dry_run:
                print("dry run: nothing pushed")
                return 0

            git("push", "origin", f"HEAD:refs/heads/{branch}", cwd=rel)
            cut_head = f"release-cut/{args.name}"
            git("push", "origin", f"HEAD:refs/heads/{cut_head}", cwd=mn)
            run(
                "gh", "label", "create", f"backport {branch}", "--force",
                "--color", "5319e7", "--description", f"Cherry-pick onto {branch} once merged",
            )
            run(
                "gh", "pr", "create", "--base", "main", "--head", cut_head,
                "--title", f"chore(release): cut {branch}; main moves to {next_version}",
                "--body",
                f"Cuts `{branch}` from `{source[:12]}` ({args.source}). "
                f"`main` moves to `{next_version}`."
                + ("" if split else "\n\n**CHANGELOG.md needs splitting by hand** — see the cut output."),
            )
            print(f"pushed {branch}; opened the {cut_head} PR. Update the table in RELEASES.md.")
    finally:
        git("worktree", "prune")
    return 0


if __name__ == "__main__":
    sys.exit(main())
