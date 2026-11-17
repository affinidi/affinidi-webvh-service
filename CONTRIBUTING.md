# Contributing

When contributing to this repository, please first discuss the change you wish to
make by opening a [GitHub issue](https://github.com/affinidi/affinidi-webvh-service/issues/new).

## Development requirements

- **Rust:** the workspace MSRV is `rust-version` in the root
  [`Cargo.toml`](Cargo.toml); CI builds at exactly that version and fails if
  its pinned `MSRV` and `Cargo.toml` disagree. Your local toolchain is
  typically a more recent stable. Edition 2024.
- **Node.js:** `engines.node` in
  [`did-hosting-ui/package.json`](did-hosting-ui/package.json) — the one
  place the floor is stated. The default build of `did-hosting-control` and
  `did-hosting-daemon` includes the `ui` feature and runs npm when the UI
  bundle is missing or stale; their `build.rs` reads the same floor. Build
  with `--no-default-features` (see the crate READMEs) to skip the UI.
- **`cargo-deny`** — CI gates on `cargo deny check` (config in `deny.toml`),
  so run it before pushing a dependency change.

Optional but useful: `cargo-outdated` for dependency hygiene.

## Pre-push workflow

The CI pipeline runs the equivalent of these commands; running them
locally before pushing avoids round-trips:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check-docs.py        # docs status lines + retired names
```

CI (`.github/workflows/ci.yml`) also runs, among others: `cargo doc
--no-deps --workspace` with `RUSTDOCFLAGS=-D warnings` (a broken intra-doc
link fails the build), `cargo package --workspace` (the published tarballs
build), the MSRV build, per-store and per-method builds, `cargo deny`, the
fuzz lockfile check (`fuzz/Cargo.lock` must match; refresh it after a
dependency-requirement bump), and the `docs` job below. The workspace denies
`unsafe_code`.

Server-side modules of `did-hosting-common` compile only with a store
backend: `cargo test -p did-hosting-common --features store-fjall`.

For the UI:

```bash
cd did-hosting-ui
npm ci
npm run typecheck
npm run lint
npm test
npm run build:web   # writes the bundle the control crate embeds (did-hosting-control/ui-dist)
```

### Generated documents

Some files under `docs/` are generated and checked by a drift test; edit the
source, then regenerate:

| File | Source | Regenerate |
| ---- | ------ | ---------- |
| `docs/cli-reference.md` | each binary's clap definition | `UPDATE_CLI_REFERENCE=1 cargo test -p <crate> --bin <binary> cli_reference` |
| `docs/openapi.json` | `#[utoipa::path]` annotations | `UPDATE_OPENAPI=1 cargo test -p did-hosting-server --features openapi openapi_snapshot` |
| `docs/trust-tasks.md` | the control plane's Trust Task table | see the header of the file |

### Documentation

Every page under `docs/` starts with a status line (`current`, `historical`
or `proposal`); superseded designs live in `docs/archive/`. CI checks the
status lines, relative links (lychee, offline) and that current docs do not
use retired names (`scripts/check-docs.py`). The index is
[docs/README.md](docs/README.md).

### Design documents outside this repository

CLAUDE.md cites rules by number (R3.2, R3.6, …) from
`vti-stack-development-guide.md` and its companions in `../design-docs/`. That
is an internal Affinidi document set for the wider trust-infrastructure stack,
checked out beside this repository by maintainers; it is not published.
Outside contributors do not need it: the rules that bind this repository are
stated in CLAUDE.md and [docs/architecture.md](docs/architecture.md), and a
reviewer will point at anything else.

## Branches and releases

All work lands on `main` by PR. Releases are `major.minor` (`0.9`) branches
cut from `nightly` — the last fully green `main` — and patched only there.
Three rules follow (details in [RELEASES.md](RELEASES.md)):

- **Never edit a `version =`.** The release tooling sets versions; the
  `branch rules` check fails a PR that changes one.
- **Record user-facing changes as a `changelog.d/` fragment**, never in
  `CHANGELOG.md`: add a new file `changelog.d/<short-kebab-name>.md` holding a
  `### <Kind> — <title>` entry (format in
  [changelog.d/README.md](changelog.d/README.md)). The release tooling
  assembles the fragments into `CHANGELOG.md`, and the `branch rules` check
  fails any other PR that edits it.
- **Need a fix in a supported release?** Merge it to `main`, then label the PR
  `backport release/<major.minor>`; a bot opens the cherry-pick on that branch.

## Commit hygiene

Both rules below are enforced **server-side** — pushes that violate
either are rejected, so it's worth getting them right before pushing.

### Conventional-commit subjects

The remote rejects commit messages whose subject doesn't match:

```text
(build|ci|docs|feat|fix|perf|refactor|style|test|chore|revert)(\(.*\))?!?:\s.{5,}
```

Any parenthetical scope is accepted (`fix(store): …`, `feat(ui): …`), and a
`!` after the type or scope marks a breaking change (`feat!: …`,
`refactor(control)!: …`). Merge commits must match too — merge `main` into a
PR branch with a message such as `chore: merge main into <branch>`.

### DCO sign-off

Every commit must carry a `Signed-off-by: <name> <email>` trailer.
Run with `-s` to add it automatically:

```bash
git commit -s -m "fix: short subject"
```

Configure your git identity if you haven't:

```bash
git config user.name "Your Name"
git config user.email "you@example.com"
```

## Code-quality expectations

1. **Pipeline checks must pass green.** Don't open a PR with red CI
   unless the failure is explicit context for the discussion.
2. **No mocks/stubs in integration tests.** Integration tests use the
   real fjall store via `tempfile::tempdir`, the real
   `affinidi-messaging-test-mediator`, etc. Unit tests may stub for
   isolation; integration tests prove the whole thing fits.
3. **Tests for new code paths.** Every public function should have at
   least one happy-path test; every Trust Task row in
   `did-hosting-control/src/control_tasks/mod.rs` (and the gate in
   `did-hosting-control/src/messaging/gate.rs` that admits it) should exercise
   both success and at least one failure mode.
4. **Comments explain WHY, not WHAT.** Identifier names + types should
   carry the WHAT. Reserve `///` and `//` for the non-obvious — a
   subtle invariant, a reason for an unusual ordering, a reference to
   an incident or upstream issue.
5. **Prefer descriptive names.** No single-letter loop counters in
   non-trivial loops; no abbreviations that aren't already canonical
   (`did`, `acl`, `kv` are fine; `mnem`, `dscv` are not).
6. **No `unsafe`** in production code without a sign-off in the PR
   description. The workspace lint `unsafe_code = "deny"` enforces it; an
   approved exception (or a test module that mutates the environment)
   carries a scoped `#[allow(unsafe_code)]`.
7. **No `unwrap`/`expect` on user-supplied input.** Use `?` and route
   the error through `AppError`. `unwrap` on `Mutex`-poisoned state or
   on internal-invariant assertions is fine.

## Daemon parity

`did-hosting-daemon` embeds the main features of `did-hosting-server`,
`webvh-witness`, `webvh-watcher`, and `did-hosting-control` in a single
binary. [CLAUDE.md](CLAUDE.md) (workspace root) lists what is mirrored,
what is intentionally omitted, and a heuristic for deciding which side a
new capability belongs on. Read that before adding routes, background
tasks, or CLI subcommands so daemon mode doesn't drift. The same
architecture, written for operators, is in
[docs/architecture.md](docs/architecture.md).

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to make participation in our project
and our community a harassment-free experience for everyone, regardless of
age, body size, disability, ethnicity, gender identity and expression,
level of experience, nationality, personal appearance, race, religion, or
sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

- Using welcoming and inclusive language.
- Being respectful of differing viewpoints and experiences.
- Gracefully accepting constructive criticism.
- Focusing on what is best for the community.
- Showing empathy towards other community members.
- Avoiding obvious comments about things like code styling and indentation.
  If you see yourself wanting to do that more than once, open an issue to
  update the lint/formatter config to address the concern once and for all.
  **Code reviews should be about logic, not indenting or adding more
  newlines.**

Examples of unacceptable behavior by participants include:

- The use of sexualised language or imagery and unwelcome sexual attention or
  advances.
- Trolling, insulting/derogatory comments, and personal or political attacks.
- Public or private harassment.
- Publishing others' private information, such as a physical or electronic
  address, without explicit permission.
- Other conduct which could reasonably be considered inappropriate in a
  professional setting.
