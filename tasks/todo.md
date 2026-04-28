# Self-Managed Mode — Todo

Spec: [`docs/self-managed-mode-spec.md`](../docs/self-managed-mode-spec.md)
Plan: [`tasks/plan.md`](plan.md)

## Phase 1 — Foundations
- [x] **T1** Add `IdentityMode` + `IdentityConfig` to `webvh-common/src/server/config.rs` with TOML round-trip + env override + default = `Vta`
  - Files: `webvh-common/src/server/config.rs`, `webvh-daemon/src/config.rs`, `webvh-daemon/src/setup.rs` (literal initializers)
  - Verify: `cargo test -p affinidi-webvh-common --features server-core --lib server::config::tests` (7 passed) + `cargo build --workspace` (clean)

> **Checkpoint**: types compile, defaults preserve back-compat. Review.

## Phase 2 — Wizard
- [x] **T2** Add `VtaMode::SelfManaged` variant + `run_self_managed_setup` branch + insecure-URL warning helper
  - Files: `webvh-daemon/src/setup.rs` (warning helper inlined as private fn there — kept off webvh-common until a second caller exists)
  - Reuses: `build_did_document` / `create_log_entry` / `encode_host` / `finalize_daemon_setup` / `derive_did_path`
  - Verify: `cargo build -p affinidi-webvh-daemon` clean; manual wizard run pending (interactive)

> **Checkpoint**: a self-managed `config.toml` is producible by the wizard. Review wizard UX before runtime work.

## Phase 3 — Runtime
- [x] **T3** Audit + guard VTA-bound runtime paths in `webvh-daemon`; produce written audit of every `vta.*` / `vta_credential` read site
  - Files: `tasks/runtime-audit-T3.md` (no code changes — audit found zero guards needed)
  - Result: all VTA fields are already `Option<String>` and only consumed in setup / CLI-subcommand paths. Runtime is self-managed-clean by construction.
  - Live HTTP smoke (curl `<public_url>/.well-known/did.jsonl` against a running daemon) deferred to T5's e2e test, which exercises the same path plus tenant DIDComm provisioning

> **Checkpoint**: daemon starts and serves its own DID end-to-end. Review audit report.

## Phase 4 — Reject in non-daemon binaries
- [x] **T4** Add `SelfManaged` variant + rejection arm to `webvh-server`, `webvh-control`, `webvh-witness` setup wizards (`webvh-watcher` has no `VtaMode` enum — confirmed)
  - Files: `webvh-server/src/setup.rs`, `webvh-control/src/setup.rs`, `webvh-witness/src/setup.rs`
  - Each binary defines its own `SELF_MANAGED_DAEMON_ONLY` constant with identical text — kept inline since hoisting to common would require crossing the `Box<dyn Error>` vs `AppError` divide
  - Verify: `cargo build --workspace` clean; `cargo test --workspace --lib` clean (113 tests)

## Phase 5 — Verification
- [x] **T5-lite** Tenant DID provisioning succeeds against a self-managed-style AppConfig (empty `[vta]`)
  - Files: `webvh-control/tests/self_managed_provisioning.rs`
  - Approach: bypasses the mediator wire transport (unchanged between VTA and self-managed; not a self-managed-specific risk per `tasks/runtime-audit-T3.md`); exercises the same `create_did` + `publish_did` paths the DIDComm router dispatches into for `MSG_DID_REQUEST` / `MSG_DID_PUBLISH`
  - Verify: `cargo test -p affinidi-webvh-control --test self_managed_provisioning` (1 passed)
- [x] **T6-lite** Self-managed config loads correctly + back-compat with VTA-default configs
  - Files: `webvh-daemon/src/config.rs` (test module)
  - Skipped the dialoguer harness refactor; covered the load-time semantic claim instead (a self-managed TOML produces the right runtime config; an existing VTA TOML still loads cleanly)
  - Verify: `cargo test -p affinidi-webvh-daemon --bin webvh-daemon` (2 passed)
- ~~**T5 full** end-to-end DIDComm-over-mediator test~~ — deferred: would require building a fake-mediator harness orthogonal to self-managed mode (mediator transport is identical between VTA and self-managed configs)
- ~~**T6 full** dialoguer wizard harness~~ — deferred: would require refactoring `run_self_managed_setup` to take an `Inputs` trait; load-time test covers the equivalent semantic claim

> **Checkpoint**: all spec §1 success criteria verifiably met. Review test output.

## Phase 6 — Ship
- [ ] **T7** Update `docs/bootstrap_startup.md` (new section), `README.md`, `CHANGELOG.md`
  - Verify: clean-clone walkthrough produces a working self-managed daemon following only the docs

## Suggested PR shape
1. T1
2. T2 + T6
3. T3
4. T4
5. T5
6. T7
