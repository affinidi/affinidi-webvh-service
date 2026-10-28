#!/usr/bin/env python3
"""Carry the workspace version into the files the shared release actions skip.

    python3 scripts/sync-version-files.py

Run after the release-cut or release-prep action moves the workspace version
(RELEASES.md). It updates:

  - `docs/openapi.json`'s `info.version`: the snapshot embeds
    did-hosting-server's version, and `openapi_snapshot_in_sync` fails CI on
    any drift;
  - `fuzz/Cargo.lock`: the detached fuzz crate records did-hosting-common's
    version, and the nightly Fuzz job gates on `cargo fetch --locked`.
"""

import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main():
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    # Inserted verbatim below, so only a plain crate version is accepted.
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        sys.exit(f"workspace version {version!r} is not major.minor.patch")

    openapi = ROOT / "docs" / "openapi.json"
    text, n = re.subn(
        r'^(    "version": ")[^"]*(")',
        lambda m: f"{m.group(1)}{version}{m.group(2)}",
        openapi.read_text(),
        count=1,
        flags=re.M,
    )
    if n != 1:
        sys.exit(f"{openapi}: no info.version line")
    openapi.write_text(text)

    subprocess.run(
        ["cargo", "update", "--manifest-path", "fuzz/Cargo.toml", "-p", "did-hosting-common"],
        cwd=ROOT,
        check=True,
    )
    print(f"docs/openapi.json and fuzz/Cargo.lock at {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
