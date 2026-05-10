# Contributing

When contributing to this repository, please first discuss the change you wish to
make by opening a [GitHub issue](https://github.com/affinidi/affinidi-webvh-service/issues/new).

## Development requirements

- **Rust toolchain ≥ 1.94.0** (workspace MSRV declared in `Cargo.toml`).
  The local toolchain is typically a more recent stable; the MSRV is the
  floor we publish against.
- **Edition 2024.**
- **Node ≥ 20** for the `webvh-ui` Expo workspace.

Optional but useful:

- `cargo-outdated` for dependency hygiene.
- `cargo-deny` for license/advisory checks (config lives in `deny.toml`).

## Pre-push workflow

The CI pipeline runs the equivalent of these commands; running them
locally before pushing avoids round-trips:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For the UI:

```bash
cd webvh-ui
node_modules/.bin/tsc --noEmit
npx --no-install expo export --platform web   # only if you touched the UI build path
```

## Commit hygiene

Both rules below are enforced **server-side** — pushes that violate
either are rejected, so it's worth getting them right before pushing.

### Conventional-commit subjects

The remote rejects commit messages whose subject doesn't match:

```text
(build|ci|docs|feat|feat!|fix|perf|refactor|style|test|chore|revert)(\(release\))?:\s.{5,}
```

Notable: the only allowed parenthetical scope is `(release)`. A subject
like `fix(ui): something` will be rejected — use `fix: something` instead.

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
   least one happy-path test; every dispatch arm in
   `webvh-control/src/messaging.rs` and `webvh-control/src/routes/didcomm.rs`
   should exercise both success and at least one failure mode.
4. **Comments explain WHY, not WHAT.** Identifier names + types should
   carry the WHAT. Reserve `///` and `//` for the non-obvious — a
   subtle invariant, a reason for an unusual ordering, a reference to
   an incident or upstream issue.
5. **Prefer descriptive names.** No single-letter loop counters in
   non-trivial loops; no abbreviations that aren't already canonical
   (`did`, `acl`, `kv` are fine; `mnem`, `dscv` are not).
6. **No `unsafe`** in production code without a sign-off in the PR
   description.
7. **No `unwrap`/`expect` on user-supplied input.** Use `?` and route
   the error through `AppError`. `unwrap` on `Mutex`-poisoned state or
   on internal-invariant assertions is fine.

## Daemon parity

`webvh-daemon` embeds the main features of `webvh-server`,
`webvh-witness`, `webvh-watcher`, and `webvh-control` in a single
binary. CLAUDE.md (workspace root) lists what is mirrored, what is
intentionally omitted, and a heuristic for deciding which side a new
capability belongs on. Read that before adding routes, background
tasks, or CLI subcommands so daemon mode doesn't drift.

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
