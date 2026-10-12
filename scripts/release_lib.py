"""Shared helpers for the release tooling (RELEASES.md).

A release is named `major.minor` (`0.9`) and lives on `release/<major.minor>`.
Every workspace crate carries the same version on a release branch: the
release's (`0.9.0`, then `0.9.1`, …). `main` carries the next release's
`major.minor.0` and publishes nothing.

The release branch's current version is the `RELEASE` file at its root:
`0.9.0-rc.0`, `0.9.0-rc.1`, `0.9.0`, `0.9.1`, … The tag is `v` + that.
"""

import pathlib
import re
import subprocess
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent

RELEASE_NAME = re.compile(r"(\d+)\.(\d+)")
RELEASE_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?")

def run(*args, cwd=ROOT, check=True):
    out = subprocess.run(args, capture_output=True, text=True, cwd=cwd)
    if check and out.returncode:
        raise SystemExit(f"`{' '.join(args)}` failed in {cwd}:\n{out.stderr.strip()}")
    return out


def git(*args, cwd=ROOT, check=True):
    return run("git", *args, cwd=cwd, check=check)


def members(root):
    data = tomllib.loads((root / "Cargo.toml").read_text())
    return [root / m / "Cargo.toml" for m in data["workspace"]["members"]]


def crate_versions(root):
    out = {}
    for manifest in members(root):
        pkg = tomllib.loads(manifest.read_text())["package"]
        out[pkg["name"]] = pkg["version"]
    return out


def set_version(root, version):
    """Set every workspace crate to `version` and its internal pins to `major.minor`.

    The pins rewritten are those naming a workspace member only: an external
    crate that happens to share the number (`tower-http`, `tokio-util`) is
    never touched.

    Then refresh both lockfiles: the root one (`cargo update -w`, members
    only) and the detached fuzz crate's, which records did-hosting-common's
    version and would otherwise turn the nightly Fuzz job red (CLAUDE.md).
    """
    # Validated before it reaches any file: the replacements below insert it
    # verbatim, but nothing that is not a release version belongs there.
    m = RELEASE_VERSION.fullmatch(version)
    if not m:
        raise SystemExit(f"{version!r} is not major.minor.patch[-rc.N]")
    pin = f"{m.group(1)}.{m.group(2)}"
    names = [tomllib.loads(m.read_text())["package"]["name"] for m in members(root)]
    pin_re = re.compile(
        r'^(\s*(?:' + "|".join(map(re.escape, names)) + r')\s*=\s*\{\s*version\s*=\s*")[^"]*(")',
        re.M,
    )
    for manifest in members(root):
        text = manifest.read_text()
        # The first `version =` at the start of a line inside [package].
        head, sep, rest = text.partition("[package]")
        if not sep:
            raise SystemExit(f"{manifest}: no [package] section")
        rest, n = re.subn(r'^version\s*=\s*"[^"]*"', lambda _: f'version = "{version}"', rest, count=1, flags=re.M)
        if n != 1:
            raise SystemExit(f"{manifest}: no [package] version line")
        text = head + sep + rest
        text = pin_re.sub(lambda m: f"{m.group(1)}{pin}{m.group(2)}", text)
        manifest.write_text(text)
    # The committed OpenAPI snapshot embeds did-hosting-server's version, and
    # `openapi_snapshot_in_sync` fails CI on any drift.
    openapi = root / "docs" / "openapi.json"
    if openapi.exists():
        text, n = re.subn(
            r'^(    "version": ")[^"]*(")',
            lambda m: f"{m.group(1)}{version}{m.group(2)}",
            openapi.read_text(),
            count=1,
            flags=re.M,
        )
        if n != 1:
            raise SystemExit(f"{openapi}: no info.version line")
        openapi.write_text(text)
    run("cargo", "update", "-w", cwd=root)
    run("cargo", "update", "--manifest-path", "fuzz/Cargo.toml", "-p", "did-hosting-common", cwd=root)


def parse_release(text):
    m = RELEASE_VERSION.fullmatch(text.strip())
    if not m:
        raise SystemExit(f"RELEASE holds {text.strip()!r}, not major.minor.patch[-rc.N]")
    major, minor, patch, rc = m.groups()
    return int(major), int(minor), int(patch), (None if rc is None else int(rc))


def unreleased_split(changelog):
    """(before, body, after) around the `## Unreleased` section, or None."""
    m = re.search(r"^## Unreleased[^\n]*\n", changelog, re.M)
    if not m:
        return None
    nxt = re.search(r"^## ", changelog[m.end():], re.M)
    end = m.end() + nxt.start() if nxt else len(changelog)
    return changelog[: m.start()], changelog[m.end(): end], changelog[end:]
