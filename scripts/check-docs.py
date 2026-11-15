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


def run(root: Path) -> list[str]:
    return check_status(root) + check_retired(root)


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
