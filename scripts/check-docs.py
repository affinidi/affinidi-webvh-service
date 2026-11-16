#!/usr/bin/env python3
"""Documentation guards (the `docs` CI job).

1. **Status lines.** Every page under `docs/` says what it is: the first
   non-blank line after its `# ` title is

       > **Status:** current[ — note]
       > **Status:** historical — superseded by … / — reason
       > **Status:** proposal[ — note]

   and every page under `docs/archive/` is `historical`.

2. **Retired names.** Current documentation (the READMEs, CONTRIBUTING,
   RELEASES, CLAUDE.md and `docs/` outside `docs/archive/`) must not send a
   reader to a route, binary, function or repository that no longer exists.
   A line that mentions one on purpose — to say it was removed — carries the
   marker `<!-- retired-name-ok -->`.

3. **Retired names in code.** Every `.rs`, `.ts` and `.tsx` file (outside
   build output, dependencies and `docs/archive/`) is held to the same list
   plus code-only names (deleted functions, old thread names, stale version
   claims), so a comment cannot describe something that is gone. A line that
   names one on purpose carries `retired-name-ok` in a comment. A match
   right after `.` is a relative module path (`./api/dids`) and is ignored.

Relative links are checked separately, by lychee (see ci.yml).

    python3 scripts/check-docs.py              # check the repository
    python3 scripts/check-docs.py --self-test  # test this script
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

STATUS_RE = re.compile(r"^> \*\*Status:\*\* (current|historical|proposal)\b")

# Removed routes, binaries, functions and the repository's old URL. Each is a
# plain substring.
RETIRED = [
    "/api/control",
    "/api/dids",
    "/api/didcomm",
    "/api/auth/refresh",
    "/api/identity/",
    "dispatch_did_op",
    "webvh-server",
    "webvh-control",
    "webvh-daemon",
    "webvh-common",
    "routes/didcomm.rs",
    "ADMIN_JWT",
    "github.com/affinidi/did-hosting-service",
]
ALLOW_MARKER = "<!-- retired-name-ok -->"

# Code (Rust and the UI's TypeScript) is held to the same list plus names
# that only ever appeared in code: deleted functions, old thread names and
# version claims. A line that names one on purpose (a test proving a removed
# route stays removed) carries `retired-name-ok` in a comment.
CODE_RETIRED = RETIRED + [
    "bridge_did_management",
    "run_webvh_dispatch",
    "webvh-rest",
    "webvh-storage",
    "0.6 series",
    "= \"0.6\"",
    "v0.7 redesign",
]
CODE_ALLOW_MARKER = "retired-name-ok"
CODE_SUFFIXES = {".rs", ".ts", ".tsx"}

SKIP_DIRS = {"target", "node_modules", ".git", ".claude"}


def docs_pages(root: Path) -> list[Path]:
    return sorted(p for p in (root / "docs").rglob("*.md") if p.is_file())


def current_docs(root: Path) -> list[Path]:
    pages = [root / name for name in ("README.md", "CONTRIBUTING.md", "RELEASES.md", "CLAUDE.md")]
    for child in sorted(root.iterdir()):
        if child.is_dir() and child.name not in SKIP_DIRS:
            readme = child / "README.md"
            if readme.is_file():
                pages.append(readme)
    archive = root / "docs" / "archive"
    pages += [p for p in docs_pages(root) if archive not in p.parents]
    return [p for p in pages if p.is_file()]


def status_of(text: str) -> str | None:
    """The status keyword after the title, or None when the line is missing."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("# "):
            for after in lines[i + 1 :]:
                if after.strip():
                    m = STATUS_RE.match(after)
                    return m.group(1) if m else None
            return None
    return None


def check_status(root: Path) -> list[str]:
    errors = []
    archive = root / "docs" / "archive"
    for page in docs_pages(root):
        rel = page.relative_to(root)
        status = status_of(page.read_text(encoding="utf-8"))
        if status is None:
            errors.append(
                f"{rel}: the first line after the title must be "
                "'> **Status:** current|historical|proposal …'"
            )
        elif archive in page.parents and status != "historical":
            errors.append(f"{rel}: a page in docs/archive/ must be historical, not {status}")
    return errors


def check_retired(root: Path) -> list[str]:
    errors = []
    for page in current_docs(root):
        rel = page.relative_to(root)
        for n, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1):
            if ALLOW_MARKER in line:
                continue
            for name in RETIRED:
                if name in line:
                    errors.append(f"{rel}:{n}: retired name `{name}`: {line.strip()[:120]}")
    return errors


def code_files(root: Path) -> list[Path]:
    """Every Rust and TypeScript source in the repository, outside build
    output, dependencies and the historical archive."""
    found = []
    for path in sorted(root.rglob("*")):
        if path.suffix not in CODE_SUFFIXES or not path.is_file():
            continue
        parts = path.relative_to(root).parts
        if any(p in SKIP_DIRS for p in parts) or parts[:2] == ("docs", "archive"):
            continue
        found.append(path)
    return found


def retired_in_code(line: str) -> list[str]:
    """The retired names `line` mentions. A match right after `.` is a
    relative module path (`./api/dids`), not the route."""
    hits = []
    for name in CODE_RETIRED:
        start = 0
        while (i := line.find(name, start)) != -1:
            if i == 0 or line[i - 1] != ".":
                hits.append(name)
                break
            start = i + 1
    return hits


def check_retired_code(root: Path) -> list[str]:
    errors = []
    for path in code_files(root):
        rel = path.relative_to(root)
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if CODE_ALLOW_MARKER in line:
                continue
            for name in retired_in_code(line):
                errors.append(f"{rel}:{n}: retired name `{name}`: {line.strip()[:120]}")
    return errors


def run(root: Path) -> list[str]:
    return check_status(root) + check_retired(root) + check_retired_code(root)


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "docs" / "archive").mkdir(parents=True)
        (root / "crate").mkdir()
        (root / "README.md").write_text("# Top\n\nSee `/api/trust-tasks`.\n")
        (root / "crate" / "README.md").write_text("# Crate\n\nok\n")
        (root / "docs" / "good.md").write_text("# Good\n\n> **Status:** current\n\nbody\n")
        (root / "docs" / "archive" / "old.md").write_text(
            "# Old\n\n> **Status:** historical — superseded\n\nuses /api/dids freely\n"
        )
        assert run(root) == [], run(root)

        (root / "docs" / "missing.md").write_text("# Missing\n\nno status\n")
        (root / "docs" / "archive" / "wrong.md").write_text("# Wrong\n\n> **Status:** current\n")
        (root / "crate" / "README.md").write_text(
            "# Crate\n\ncall POST /api/dids\n"
            f"the removed `/api/control` proxy {ALLOW_MARKER}\n"
        )
        errors = run(root)
        assert any("missing.md" in e for e in errors), errors
        assert any("wrong.md" in e and "historical" in e for e in errors), errors
        assert any("crate/README.md:3" in e and "/api/dids" in e for e in errors), errors
        assert not any("/api/control" in e for e in errors), errors
        assert len(errors) == 3, errors

        # Code: a retired name in a comment fails; the marker, a relative
        # module path and the archive are exempt.
        (root / "crate" / "src").mkdir()
        (root / "crate" / "src" / "lib.rs").write_text(
            "// calls dispatch_did_op\n"
            "// GET /api/dids is gone  retired-name-ok\n"
            "fn ok() {}\n"
        )
        (root / "crate" / "api.ts").write_text('import * as dids from "./api/dids";\n')
        (root / "docs" / "archive" / "old.rs").write_text("// webvh-rest\n")
        (root / "crate" / "target").mkdir()
        (root / "crate" / "target" / "gen.rs").write_text("// webvh-storage\n")
        errors = run(root)
        code = [e for e in errors if e.startswith("crate/src") or e.endswith(".ts")]
        assert len(code) == 1 and "lib.rs:1" in code[0] and "dispatch_did_op" in code[0], errors
        assert len(errors) == 4, errors
    print("self-test ok")


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        self_test()
        return 0
    errors = run(ROOT)
    for e in errors:
        print(e, file=sys.stderr)
    if errors:
        print(f"{len(errors)} documentation problem(s)", file=sys.stderr)
        return 1
    print("docs ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
