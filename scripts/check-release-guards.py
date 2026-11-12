#!/usr/bin/env python3
"""Build-free checks that keep the changelog the release tooling expects.

    python3 scripts/check-release-guards.py

Run by the `release guards` job in ci.yml on every PR and push. The release
scripts (RELEASES.md) assume these hold and would otherwise find out mid-cut
or mid-prep:

  1. CHANGELOG.md exists at the root.
  2. On main (no `RELEASE` file), its `## Unreleased` section holds nothing
     but the pointer line: entries are `changelog.d/` fragments until a
     release assembles them (changelog_fragments.py, called by cut-release.py
     and the GA / patch prep).
  3. On every branch, each fragment is well-formed: a kebab-case `<name>.md`
     file holding `### <Kind> — <title>` entries, with no text before the
     first heading and no heading with nothing under it.

Exit 1 with every problem listed; 0 when all hold.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from changelog_fragments import POINTER, fragment_paths, fragment_problems, unreleased_is_pointer_only  # noqa: E402
from release_lib import ROOT, unreleased_split  # noqa: E402


def changelog_problems():
    changelog = ROOT / "CHANGELOG.md"
    if not changelog.exists():
        return ["CHANGELOG.md is missing at the repository root (the release tooling writes to it)"]
    problems = []
    if not (ROOT / "RELEASE").exists():
        # main, or a branch off it.
        parts = unreleased_split(changelog.read_text())
        if not parts:
            problems.append("CHANGELOG.md has no `## Unreleased` section (main always carries one)")
        elif not unreleased_is_pointer_only(parts[1]):
            problems.append(
                "CHANGELOG.md's `## Unreleased` holds entries: on main it holds only the line "
                f"{POINTER!r}. Move each entry into its own changelog.d/<name>.md fragment "
                "(changelog.d/README.md)"
            )
    return problems


def main():
    sections = [
        ("CHANGELOG.md", changelog_problems()),
        (f"changelog.d ({len(fragment_paths(ROOT))} fragments)", fragment_problems(ROOT)),
    ]
    failed = False
    for name, problems in sections:
        if problems:
            failed = True
            print(f"FAIL  {name}:")
            for p in problems:
                print(f"        - {p}")
        else:
            print(f"ok    {name}")
    if failed:
        print("\nSee RELEASES.md and changelog.d/README.md.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
