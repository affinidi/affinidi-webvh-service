#!/usr/bin/env python3
"""Abort a build when a freshly-drifted dependency is too new to trust (SEC-3897).

The upstream-drift job resolves dependencies unlocked (`cargo update`) and builds
immediately, so a malicious version published minutes ago would be pulled and its
build scripts run before anyone could react. Compromised crates are almost always
yanked within a day or two of discovery, so this gate quarantines any registry
dependency whose resolved version is younger than a threshold (default 48h).

Scope is limited to what actually moved: the resolved versions in the current
Cargo.lock that are not in the committed baseline (`git show <ref>:Cargo.lock`).
Path and git dependencies are skipped (no crates.io release to date). If a
version's age cannot be established, the gate fails closed on purpose: an
unverifiable dependency at exactly this moment is the case to be paranoid about.

Exit codes: 0 = all clear, 1 = gate tripped (too-new or unverifiable), 2 = usage
error.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
USER_AGENT = "affinidi-webvh-service dep-age-gate (security@affinidi.com)"
API = "https://crates.io/api/v1/crates/{name}/{version}"


def parse_registry_pairs(text: str) -> set[tuple[str, str]]:
    """Extract {(name, version)} for crates.io registry packages from a Cargo.lock.

    Cargo.lock is TOML with one [[package]] table per entry holding name, version,
    and (for anything not a local path member) a source. Only registry packages
    carry the crates.io source; path/git deps are dropped.
    """
    pairs: set[tuple[str, str]] = set()
    name = version = source = None
    for line in text.splitlines():
        if line.strip() == "[[package]]":
            name = version = source = None
            continue
        m = re.match(r'name = "(.+)"', line)
        if m:
            name = m.group(1)
            continue
        m = re.match(r'version = "(.+)"', line)
        if m:
            version = m.group(1)
            continue
        m = re.match(r'source = "(.+)"', line)
        if m:
            source = m.group(1)
        # A package block ends at a blank line; commit it if it was a registry dep.
        if line.strip() == "" and name and version:
            if source == REGISTRY:
                pairs.add((name, version))
            name = version = source = None
    # Flush a trailing block with no closing blank line.
    if name and version and source == REGISTRY:
        pairs.add((name, version))
    return pairs


def released_at(name: str, version: str, retries: int = 3) -> datetime:
    """Return the crates.io publish time for name@version, or raise on failure."""
    url = API.format(name=name, version=version)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.load(resp)
            created = data["version"]["created_at"]
            return datetime.fromisoformat(created.replace("Z", "+00:00"))
        except (urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as exc:
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"could not verify release date for {name} {version}: {last}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lock", default="Cargo.lock", help="current (post-update) lockfile")
    ap.add_argument("--baseline-ref", default="HEAD", help="git ref holding the committed baseline lock")
    ap.add_argument("--max-age-hours", type=float, default=48.0)
    args = ap.parse_args()

    try:
        with open(args.lock, encoding="utf-8") as fh:
            current = parse_registry_pairs(fh.read())
    except OSError as exc:
        print(f"::error::cannot read {args.lock}: {exc}")
        return 2

    baseline_text = subprocess.run(
        ["git", "show", f"{args.baseline_ref}:Cargo.lock"],
        capture_output=True, text=True,
    ).stdout
    baseline = parse_registry_pairs(baseline_text)

    moved = sorted(current - baseline)
    if not moved:
        print("dep-age-gate: no registry dependency versions moved; nothing to check.")
        return 0

    print(f"dep-age-gate: {len(moved)} drifted registry version(s) to age-check "
          f"(threshold {args.max_age_hours}h).")
    now = datetime.now(timezone.utc)
    too_new: list[str] = []
    unverifiable: list[str] = []
    for name, version in moved:
        try:
            published = released_at(name, version)
        except RuntimeError as exc:
            print(f"::warning::{exc}")
            unverifiable.append(f"{name} {version}")
            time.sleep(0.3)
            continue
        age_h = (now - published).total_seconds() / 3600.0
        flag = "  <-- TOO NEW" if age_h < args.max_age_hours else ""
        print(f"  {name} {version}: {age_h:.1f}h old{flag}")
        if age_h < args.max_age_hours:
            too_new.append(f"{name} {version} ({age_h:.1f}h)")
        time.sleep(0.3)  # be polite to crates.io

    if too_new or unverifiable:
        print("::error::dep-age-gate tripped; aborting before build.")
        for item in too_new:
            print(f"::error::dependency younger than {args.max_age_hours}h: {item}")
        for item in unverifiable:
            print(f"::error::could not verify age (failing closed): {item}")
        return 1

    print("dep-age-gate: all drifted dependencies are older than the threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
