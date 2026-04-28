# Self-Managed Mode — Todo

Spec: [`docs/self-managed-mode-spec.md`](../docs/self-managed-mode-spec.md)
Plan: [`tasks/plan.md`](plan.md)

## Phase 1 — Foundations
- [x] **T1** Add `IdentityMode` + `IdentityConfig` to `webvh-common/src/server/config.rs` with TOML round-trip + env override + default = `Vta`
  - Files: `webvh-common/src/server/config.rs`, `webvh-daemon/src/config.rs`, `webvh-daemon/src/setup.rs` (literal initializers)
  - Verify: `cargo test -p affinidi-webvh-common --features server-core --lib server::config::tests` (7 passed) + `cargo build --workspace` (clean)

> **Checkpoint**: types compile, defaults preserve back-compat. Review.

## Phase 2 — Wizard
- [ ] **T2** Add `VtaMode::SelfManaged` variant + `run_self_managed_setup` branch + insecure-URL warning helper
  - Files: `webvh-daemon/src/setup.rs`, `webvh-common/src/server/config.rs` (warning helper)
  - Reuses: `bootstrap_did` / `create_log_entry` / `finalize_daemon_setup` / `derive_did_path`
  - Verify: scripted `webvh-daemon setup` produces valid self-managed config; "Next steps" output references `webvh-daemon invite --did`

> **Checkpoint**: a self-managed `config.toml` is producible by the wizard. Review wizard UX before runtime work.

## Phase 3 — Runtime
- [ ] **T3** Audit + guard VTA-bound runtime paths in `webvh-daemon`; produce written audit of every `vta.*` / `vta_credential` read site
  - Files: `webvh-daemon/src/main.rs`, `webvh-control/src/server.rs`, `webvh-control/src/messaging.rs` (likely), audit doc in `tasks/runtime-audit-T3.md`
  - Verify: self-managed daemon starts cleanly and `curl <public_url>/.well-known/did.jsonl` returns valid did.jsonl

> **Checkpoint**: daemon starts and serves its own DID end-to-end. Review audit report.

## Phase 4 — Reject in non-daemon binaries
- [ ] **T4** Add `SelfManaged` variant + rejection arm to `webvh-server`, `webvh-control`, `webvh-witness` setup wizards (and `webvh-watcher` if applicable)
  - Files: `webvh-server/src/setup.rs`, `webvh-control/src/setup.rs`, `webvh-witness/src/setup.rs`
  - Verify: each binary's wizard refuses SelfManaged with a consistent error message

## Phase 5 — Verification
- [ ] **T5** End-to-end test: tenant DIDComm provisioning into a self-managed daemon
  - Files: `webvh-daemon/tests/self_managed_e2e.rs`
  - Verify: `cargo test -p affinidi-webvh-daemon --test self_managed_e2e -- --nocapture`
- [ ] **T6** Wizard harness test for SelfManaged branch
  - Files: `webvh-daemon/tests/wizard_self_managed.rs`
  - Verify: `cargo test -p affinidi-webvh-daemon --test wizard_self_managed`

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
