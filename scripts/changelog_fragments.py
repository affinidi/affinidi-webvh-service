#!/usr/bin/env python3
"""Assemble `changelog.d/` fragments into a CHANGELOG.md section (RELEASES.md).

    python3 scripts/changelog_fragments.py --dry-run [--into HEADING]
    python3 scripts/changelog_fragments.py --into "0.12.0 (2026-11-20)" [--keep-unreleased]
    python3 scripts/changelog_fragments.py --check
    python3 scripts/changelog_fragments.py --self-test

A PR records its user-facing change as a new file `changelog.d/<name>.md`
instead of editing CHANGELOG.md, so open PRs never conflict over the top of
`## Unreleased`. A fragment holds one or more entries in CHANGELOG.md's own
format: a `### <Kind> — <title>` heading, then bullets or paragraphs.
`changelog.d/README.md` explains this and is never assembled.

At release time (cut-release.py for main's copy, prepare-release.py for GA and
patch on the release branch) `assemble()` replaces `## Unreleased` with
`## <into_heading>`, holding whatever `## Unreleased` already held (apart from
the pointer line) followed by every fragment's entries, and deletes the
fragments it used; the caller's `git add -A` records the deletions.

Entries are ordered by kind — Breaking, Changed, Fixed, Added, Removed,
Deprecated, Security, then any other kind (alphabetically) — and within a kind
by when the fragment was added on the current branch
(`git log --diff-filter=A --format=%ct`, oldest first; a fragment not yet
committed counts as newest), then by file name, then by position in the file.

--dry-run prints the section that would be written and changes nothing.
--check validates every fragment (also run by check-release-guards.py).
--self-test exercises the assembler in a throwaway git repository (CI).
"""

import argparse
import math
import os
import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from release_lib import ROOT, unreleased_split  # noqa: E402

CHANGELOG = "CHANGELOG.md"
FRAGMENT_DIR = "changelog.d"
README = "README.md"
KINDS = ("Breaking", "Changed", "Fixed", "Added", "Removed", "Deprecated", "Security")

# The only line `## Unreleased` holds on main: entries live in fragments until
# a release assembles them.
POINTER = (
    "Entries for the next release are kept in [`changelog.d/`](changelog.d/README.md) "
    "until it is released."
)

HEADING = re.compile(r"^### ([A-Z][A-Za-z]*)(?: — \S.*)?$")
FRAGMENT_NAME = re.compile(r"[a-z0-9][a-z0-9-]*\.md")


def strip_pointer(body):
    """`## Unreleased`'s body without the pointer line."""
    return "".join(line for line in body.splitlines(keepends=True) if line.strip() != POINTER)


def unreleased_is_pointer_only(body):
    return not strip_pointer(body).strip()


def _trim(lines):
    while lines and not lines[-1].strip():
        lines.pop()
    while lines and not lines[0].strip():
        lines.pop(0)
    return "".join(lines).rstrip("\n")


def split_entries(text):
    """(preamble, [entry, …]): each entry is a `### ` heading and what follows it.

    A heading followed directly by another heading (no text between) belongs
    to the same entry, so a stray heading never becomes an entry of its own
    and the text keeps its bytes. Entries carry no leading or trailing blank
    lines.
    """
    preamble, entries, cur = [], [], None
    for line in text.splitlines(keepends=True):
        if line.startswith("### "):
            if cur is None or any(x.strip() and not x.startswith("### ") for x in cur):
                if cur is not None:
                    entries.append(cur)
                cur = [line]
            else:
                cur.append(line)
        elif cur is None:
            preamble.append(line)
        else:
            cur.append(line)
    if cur is not None:
        entries.append(cur)
    return _trim(preamble), [_trim(e) for e in entries]


def kind_of(entry):
    m = re.match(r"### (\S+)", entry)
    return m.group(1) if m else ""


def fragment_paths(root=ROOT):
    d = pathlib.Path(root) / FRAGMENT_DIR
    if not d.is_dir():
        return []
    return sorted(p for p in d.glob("*.md") if p.name != README)


def added_time(root, path):
    """When `path` was (last) added on the current branch; +inf if never committed."""
    out = subprocess.run(
        ["git", "log", "--diff-filter=A", "--format=%ct", "--", str(path.relative_to(root))],
        capture_output=True, text=True, cwd=root,
    )
    # Newest add first: a name reused after an earlier release removed it
    # counts from its current add.
    lines = out.stdout.split() if out.returncode == 0 else []
    return float(lines[0]) if lines else math.inf


def fragment_problems(root=ROOT):
    """Every way a fragment breaks the format (empty list = all good)."""
    root = pathlib.Path(root)
    d = root / FRAGMENT_DIR
    if not d.is_dir():
        return []
    problems = []
    for p in sorted(d.iterdir()):
        rel = p.relative_to(root)
        if p.name == README:
            continue
        if p.is_dir() or p.suffix != ".md":
            problems.append(f"{rel}: only `<name>.md` fragments (and README.md) belong in {FRAGMENT_DIR}/")
            continue
        if not FRAGMENT_NAME.fullmatch(p.name):
            problems.append(f"{rel}: name a fragment in lower-case kebab-case, e.g. `ws-relay-timeouts.md`")
        preamble, entries = split_entries(p.read_text())
        if preamble:
            problems.append(f"{rel}: text before the first `### <Kind> — <title>` heading")
        if not entries:
            problems.append(f"{rel}: no `### <Kind> — <title>` entry")
        for e in entries:
            for line in e.splitlines():
                if line.startswith("### ") and not HEADING.match(line):
                    problems.append(f"{rel}: heading {line!r} is not `### <Kind> — <title>`")
            if e.startswith("### ") and all(x.startswith("### ") for x in e.splitlines()):
                problems.append(f"{rel}: entry {e.splitlines()[0]!r} has no text under it")
        for line in p.read_text().splitlines():
            if re.match(r"#{1,2} ", line):
                problems.append(f"{rel}: {line!r}: a fragment holds `###` entries only")
    return problems


def collect(root=ROOT, only=None, body=""):
    """(blocks, used fragment paths): the ordered entries of a release section.

    `body` is what `## Unreleased` already holds; its entries count as older
    than any fragment. `only`, when given, is the set of fragment file names to
    use; the rest are left in place.
    """
    root = pathlib.Path(root)
    problems = fragment_problems(root)
    if problems:
        raise SystemExit("changelog.d has malformed fragments:\n  " + "\n  ".join(problems))

    def rank(kind):
        return (KINDS.index(kind), "") if kind in KINDS else (len(KINDS), kind)

    items = []
    preamble, body_entries = split_entries(strip_pointer(body))
    for i, e in enumerate(body_entries):
        items.append(((*rank(kind_of(e)), -math.inf, "", i), e))
    used = []
    for p in fragment_paths(root):
        if only is not None and p.name not in only:
            continue
        used.append(p)
        when = added_time(root, p)
        for i, e in enumerate(split_entries(p.read_text())[1]):
            items.append(((*rank(kind_of(e)), when, p.name, i), e))
    items.sort(key=lambda kv: kv[0])
    return ([preamble] if preamble else []) + [e for _, e in items], used


def assemble(into_heading, root=ROOT, *, keep_unreleased=False, only=None, extra=None, dry_run=False):
    """Turn `## Unreleased` (plus the fragments) into `## <into_heading>`.

    Returns the new section's text. Unless `dry_run`, writes CHANGELOG.md and
    deletes the fragments it used. With `keep_unreleased`, a fresh
    `## Unreleased` holding only the pointer line stays above the new section
    (main at a cut). Without a `## Unreleased` section, the new section goes
    above the newest release's. `extra` is appended after the entries (a
    patch's `### Commits`).
    """
    root = pathlib.Path(root)
    path = root / CHANGELOG
    text = path.read_text()
    parts = unreleased_split(text)
    if parts:
        before, body, after = parts
    else:
        m = re.search(r"^## ", text, re.M)
        before, body, after = (text[: m.start()], "", text[m.start():]) if m else (text.rstrip("\n") + "\n\n", "", "")
    blocks, used = collect(root, only, body)
    if extra:
        blocks.append(extra.strip("\n"))
    section = f"## {into_heading}\n\n" + ("\n\n".join(blocks) + "\n\n" if blocks else "")
    head = f"## Unreleased\n\n{POINTER}\n\n" if keep_unreleased else ""
    new = before + head + section + after
    if not after:
        new = new.rstrip("\n") + "\n"
    if not dry_run:
        path.write_text(new)
        for p in used:
            p.unlink()
    return section


# --- self-test ---------------------------------------------------------------


def _self_test():
    def git(*args, cwd, date=None):
        env = dict(os.environ)
        if date is not None:
            env.update(GIT_AUTHOR_DATE=f"@{date} +0000", GIT_COMMITTER_DATE=f"@{date} +0000")
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
             *args],
            cwd=cwd, env=env, check=True, capture_output=True,
        )

    def check(cond, what):
        if not cond:
            raise AssertionError(what)
        print(f"ok    {what}")

    old = "## 0.1.0 (2026-01-01)\n\n### Fixed — old\n\n- old fix\n"
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        git("init", "-q", cwd=root)
        (root / CHANGELOG).write_text(f"# Changelog\n\nIntro.\n\n## Unreleased\n\n{POINTER}\n\n{old}")
        frag = root / FRAGMENT_DIR
        frag.mkdir()
        (frag / README).write_text("# not an entry\n")
        git("add", "-A", cwd=root)
        git("commit", "-q", "-m", "init", cwd=root, date=1000)

        def add(name, text, date):
            (frag / name).write_text(text)
            git("add", "-A", cwd=root)
            git("commit", "-q", "-m", name, cwd=root, date=date)

        add("zeta.md", "### Fixed — z\n\n- z fix\n", 2000)
        add("alpha.md", "### Fixed — a\n\n- a fix\n", 3000)
        add("beta.md", "### Fixed — b\n\n- b fix\n", 3000)  # same second as alpha: name breaks the tie
        add("multi.md", "### Added — m1\n\nm1 text\n\n### Breaking — m2\n\n- m2\n", 4000)
        add("other.md", "### Moved — o\n\n- o\n", 1500)
        add("stray.md", "### Changed — s0\n### Changed — s1\n\n- s\n", 5000)
        (frag / "new.md").write_text("### Fixed — uncommitted\n\n- n\n")  # newest

        check(fragment_problems(root) == [], "well-formed fragments pass --check")
        section = assemble("Unreleased", root, dry_run=True)
        expected = (
            "## Unreleased\n\n"
            "### Breaking — m2\n\n- m2\n\n"
            "### Changed — s0\n### Changed — s1\n\n- s\n\n"
            "### Fixed — z\n\n- z fix\n\n"
            "### Fixed — a\n\n- a fix\n\n"
            "### Fixed — b\n\n- b fix\n\n"
            "### Fixed — uncommitted\n\n- n\n\n"
            "### Added — m1\n\nm1 text\n\n"
            "### Moved — o\n\n- o\n\n"
        )
        check(section == expected, "kind order, then time added, then name; README ignored")
        check(len(fragment_paths(root)) == 7, "--dry-run deletes nothing")
        before = (root / CHANGELOG).read_text()
        check("m2" not in before, "--dry-run leaves CHANGELOG.md alone")

        # A cut on main: only the shipped fragments, a fresh `## Unreleased` kept.
        assemble("0.2.0 (release/0.2)", root, keep_unreleased=True, only={"zeta.md", "multi.md"})
        text = (root / CHANGELOG).read_text()
        check(
            text == "# Changelog\n\nIntro.\n\n## Unreleased\n\n" + POINTER + "\n\n"
            "## 0.2.0 (release/0.2)\n\n### Breaking — m2\n\n- m2\n\n### Fixed — z\n\n- z fix\n\n"
            "### Added — m1\n\nm1 text\n\n" + old,
            "cut: shipped fragments become the release's section; `## Unreleased` keeps the pointer",
        )
        check(
            sorted(p.name for p in fragment_paths(root)) == ["alpha.md", "beta.md", "new.md", "other.md", "stray.md"],
            "cut: shipped fragments deleted, later ones kept",
        )

        # The release-tag.yml extraction (heading excluded, up to the next `## `).
        notes = re.search(r"^## 0\.2\.0 [^\n]*\n(.*?)(?=^## )", text, re.M | re.S).group(1)
        check(notes.strip().startswith("### Breaking — m2"), "release-tag.yml finds the section")

        # GA: `## Unreleased` becomes the version, no `## Unreleased` left.
        (frag / "alpha.md").unlink()
        (frag / "beta.md").unlink()
        (frag / "other.md").unlink()
        (frag / "new.md").unlink()
        assemble("0.3.0 (2026-02-02)", root)
        text = (root / CHANGELOG).read_text()
        check("## Unreleased" not in text and fragment_paths(root) == [], "GA: no `## Unreleased`, no fragments left")
        check(
            "## 0.3.0 (2026-02-02)\n\n### Changed — s0\n### Changed — s1\n\n- s\n\n## 0.2.0" in text,
            "GA: a heading with no text stays with the next one, byte for byte",
        )

        # Patch on a GA'd branch: no `## Unreleased`; a fragment plus commits.
        (frag / "direct.md").write_text("### Security — d\n\n- d\n")
        assemble("0.3.1 (2026-02-03)", root, extra="### Commits\n\n- fix: x\n")
        text = (root / CHANGELOG).read_text()
        check(
            "Intro.\n\n## 0.3.1 (2026-02-03)\n\n### Security — d\n\n- d\n\n### Commits\n\n- fix: x\n\n## 0.3.0" in text,
            "patch: inserted above the newest release, entries then commits",
        )

        # An older `## Unreleased` that still holds entries keeps them, ahead of fragments.
        (root / CHANGELOG).write_text("# C\n\n## Unreleased\n\n### Fixed — kept\n\n- k\n\n## 0.1.0\n")
        (frag / "f.md").write_text("### Fixed — frag\n\n- f\n")
        section = assemble("Unreleased", root, dry_run=True)
        check(section.index("kept") < section.index("frag"), "existing `## Unreleased` entries come first in their kind")
        (frag / "f.md").unlink()

        # --check rejects malformed fragments.
        (frag / "Bad_Name.md").write_text("intro\n### fixed: lower\n")
        (frag / "empty.md").write_text("### Fixed — nothing\n")
        probs = fragment_problems(root)
        check(any("kebab-case" in p for p in probs), "--check: file name must be kebab-case")
        check(any("text before" in p for p in probs), "--check: text before the first heading")
        check(any("is not `### <Kind>" in p for p in probs), "--check: malformed heading")
        check(any("no text under it" in p for p in probs), "--check: heading with no text")
        try:
            collect(root)
        except SystemExit:
            check(True, "assembling refuses malformed fragments")
        else:
            check(False, "assembling refuses malformed fragments")
    print("self-test passed")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--into", help="the new section's heading, without `## ` (e.g. `0.12.0 (2026-11-20)`)")
    ap.add_argument("--keep-unreleased", action="store_true", help="keep an empty `## Unreleased` above it")
    ap.add_argument("--dry-run", action="store_true", help="print the section; change nothing")
    ap.add_argument("--check", action="store_true", help="validate the fragments and exit")
    ap.add_argument("--self-test", action="store_true", help="run the built-in tests and exit")
    args = ap.parse_args()

    if args.self_test:
        return _self_test()
    if args.check:
        problems = fragment_problems(ROOT)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(f"{len(fragment_paths(ROOT))} fragment(s); {'ok' if not problems else 'FAIL'}")
        return 1 if problems else 0
    if args.dry_run:
        sys.stdout.write(assemble(args.into or "Unreleased", ROOT, keep_unreleased=args.keep_unreleased, dry_run=True))
        return 0
    if not args.into:
        ap.error("--into is required unless --dry-run, --check or --self-test")
    assemble(args.into, ROOT, keep_unreleased=args.keep_unreleased)
    print(f"CHANGELOG.md: `## {args.into}` written; fragments removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
