# Plan: Self-Managed (No-VTA) Operating Mode

Spec: [`docs/self-managed-mode-spec.md`](../docs/self-managed-mode-spec.md)
Scope: `webvh-daemon` only (v1)
Branch base: `release/0.6.0`

## Locked decisions (from spec §2)

- DID method: self-hosted `did:webvh`
- Admin auth: passkey-invite **only** via existing `webvh-daemon invite` CLI; wizard prints the command in "Next steps" — no wizard-side invite minting
- Distributed self-managed: out of scope; daemon-only in v1
- DIDComm: stays on (inbound tenant DID provisioning from external VTAs)
- Public URL: permissive with loud warning on `http://` / `localhost`
- Wizard mode: 4th `VtaMode::SelfManaged` variant
- Migration path (self-managed → VTA): not provided
- Stats / registry: confirmed VTA-independent — no guards needed there

## Code-shape facts verified during planning

These were confirmed during this planning pass to prevent rework:

| Fact | Location | Why it matters |
|---|---|---|
| `bootstrap_did` (and `create_log_entry`) builds a DID-doc + signed JSONL log entry from a signing secret + optional KA secret | `webvh-server/src/bootstrap.rs:62`, `webvh-common/src/did/...` | The wizard can build the daemon's DID doc locally without any VTA round-trip. |
| `finalize_daemon_setup(...)` already writes config + secrets, imports the daemon DID into the local store, and seeds admin ACL | `webvh-daemon/src/setup.rs:823` | Self-managed branch reuses this verbatim — passes `AdminChoice::Skip` and a locally-generated `log_entry`. No new finalisation logic. |
| `derive_did_path(public_url)` derives the mnemonic (`.well-known` if URL has no path) | `webvh-daemon/src/setup.rs` (existing helper) | Self-managed reuses this — no new path derivation. |
| `ServerSecrets.vta_credential: Option<String>` already has `None` paths (offline mode, plaintext store) | `webvh-common/src/server/secret_store/mod.rs:51`, plus offline & plaintext call-sites | Runtime already tolerates `None` — no runtime guard needed for credential-absence per se. |
| `webvh-daemon invite --did <DID> [--role admin|owner] [--ttl-hours N]` exists and uses `create_enrollment_invite` | `webvh-daemon/src/main.rs:117`, `webvh-daemon/src/main.rs:1099` | Wizard "Next steps" can reference the CLI directly. No need for a new subcommand. |
| Daemon's outbound ATM is unused: `notify_servers_*` no-ops when `state.atm` is None | `webvh-daemon/src/main.rs:991` | Confirms cross-service push code paths don't need self-managed guards in daemon mode. |
| Existing `VtaMode` enum has 3 variants (`Online`, `OfflineStart`, `OfflineComplete`); each binary owns its own copy | `webvh-daemon/src/setup.rs:269`, `webvh-server/src/setup.rs:340`, `webvh-control/src/setup.rs`, `webvh-witness/src/setup.rs` | Adding `SelfManaged` is a 4-file edit (+ daemon's branch). Each copy is independent — no shared enum to update. |

## Dependency graph

```
T1 (IdentityMode types in webvh-common)
  │
  ├─→ T2 (SelfManaged wizard branch in webvh-daemon)
  │     │
  │     └─→ T6 (wizard harness test) ─────────────────┐
  │                                                    │
  ├─→ T3 (runtime audit + guards in webvh-daemon)      │
  │     │                                              │
  │     └─→ T5 (e2e: tenant DIDComm provisioning) ────┤
  │                                                    │
  └─→ T4 (rejection arms in non-daemon binaries)       │
                                                       │
                                                       ▼
                                                T7 (docs)
```

T1 unlocks everything. T2 and T3 are independent (T2 = setup-time only; T3 = run-time only) and can run in parallel after T1. T4 only needs T1's enum to be importable. T5 needs T2 + T3. T6 needs T2. T7 is last.

## Phases & tasks

Each task is sized for one focused session and one PR. Acceptance criteria are testable. Verification commands are concrete.

---

### Phase 1 — Foundations

#### T1: Add `IdentityMode` + `IdentityConfig` to webvh-common

**Summary**: Introduce a new `[identity]` config section so the runtime can distinguish VTA-managed deployments from self-managed ones. Default to `Vta` for back-compat with every existing config.

**Files**:
- `webvh-common/src/server/config.rs` — add `IdentityMode { Vta, SelfManaged }`, `IdentityConfig { mode: IdentityMode }`, `Default for IdentityMode = Vta`. Add to the `apply_env_overrides` block: `WEBVH_IDENTITY_MODE`.
- `webvh-daemon/src/config.rs` — add `#[serde(default)] pub identity: IdentityConfig` to `DaemonConfig`. Pass through in `server_config()` / `control_config()` / `witness_config()` (or only those that need it — currently *none* read it; this is forward compat for T3).
- `webvh-server/src/config.rs`, `webvh-control/src/config.rs`, `webvh-witness/src/config.rs` — re-export `IdentityConfig` / `IdentityMode` if any of them will be touched in T3 / T4 (likely just re-export from common — same pattern as `VtaConfig` today).
- `webvh-common/src/server/config.rs` (tests module) — TOML round-trip unit test, env-override unit test, default-value unit test.

**Acceptance**:
- `IdentityMode::Vta` is the serde default — an existing config with no `[identity]` section parses successfully and has `identity.mode == Vta`.
- `[identity] mode = "self-managed"` round-trips through TOML.
- `WEBVH_IDENTITY_MODE=self-managed` overrides the file value.
- All existing crates still build with no behavioural changes.

**Verify**:
```
cargo test -p affinidi-webvh-common --lib config
cargo build --workspace
```

**Dependencies**: none. This is the foundation.

**Estimate**: 1 session.

---

### Phase 2 — Wizard (setup-time vertical slice)

#### T2: SelfManaged wizard branch in webvh-daemon

**Summary**: Add the 4th `VtaMode::SelfManaged` variant, the prompt entry, a `run_self_managed_setup` function, and a small helper that generates keys + DID log entry locally. Reuse the existing `finalize_daemon_setup` for everything that follows. Print the "Next steps" block referencing `webvh-daemon invite`.

**Files**:
- `webvh-daemon/src/setup.rs`:
  - Add `SelfManaged` to `enum VtaMode` with rustdoc explaining the slight name oxymoron ("a 'VTA mode' value that means 'no VTA'").
  - Add the prompt item `"Self-managed (no VTA integration — daemon manages its own DID)"` to `prompt_vta_mode`.
  - In `run_wizard`, dispatch `VtaMode::SelfManaged => return run_self_managed_setup(config_path).await`.
  - New `run_self_managed_setup(config_path)`: reuses the `prompt_enable_and_features`, public-URL prompt (with loud warning hook for `http://` / `localhost`), mediator prompt, host/port/log/data-dir/secrets-backend prompts. Then:
    1. `let signing = Secret::generate_ed25519(None, None);`
    2. `let ka = Secret::generate_x25519(None, None)?;`
    3. `let host = encode_host(&public_url)?;`
    4. `let doc = build_did_document(&host, &did_path, &signing.pub_mb, &DidDocumentOptions { key_agreement_multibase: Some(&ka.pub_mb), mediator_endpoint: mediator_did.as_deref() });`
    5. `let (_scid, jsonl) = create_log_entry(&doc, &signing).await?;`
    6. Build `DaemonConfig` with `identity: IdentityConfig { mode: IdentityMode::SelfManaged }`, `vta: VtaConfig::default()` (all `None`).
    7. Call `finalize_daemon_setup(&config, &output_path, ServerSecrets { signing_key: ..., key_agreement_key: ..., jwt_signing_key: generate_ed25519_multibase(), vta_credential: None }, Some(&jsonl), &did_path, AdminChoice::Skip)`.
    8. Print "Setup complete!" + "Next steps" block:
       1. `webvh-daemon --config <path>`
       2. `webvh-daemon invite --did <YOUR_ADMIN_DID> --role admin --config <path>`
       3. Open the printed enrolment URL.
- `webvh-common/src/server/config.rs` — small helper `warn_if_insecure_public_url(url)` that returns a `Vec<&'static str>` of warnings (or just emits via `eprintln!`). Put it next to URL helpers, since other wizards may reuse it later.

**Acceptance**:
- A scripted `webvh-daemon setup` run that selects "Self-managed" produces:
  - `config.toml` with `[identity] mode = "self-managed"`, empty `[vta]`, populated `server_did`, populated `public_url`.
  - Secrets store entry with `vta_credential = None`, both signing + KA + JWT keys present.
  - `dids/<mnemonic>` keyspace entry containing the daemon's `.well-known` (or path-derived) DID log.
  - `acl` keyspace empty.
- The summary block printed at the end contains the literal string `webvh-daemon invite --did` and does not contain any `pnm contexts create` or `vta context create` strings.
- Selecting `http://localhost:8534` triggers the warning hook (visible in stderr); selecting `https://...` does not.

**Verify**:
```
# unit smoke
cargo build -p affinidi-webvh-daemon

# manual end-to-end (interactive)
cd /tmp && rm -rf self-managed-test && mkdir self-managed-test && cd self-managed-test
/path/to/webvh-daemon setup
# answer prompts, choose "Self-managed (no VTA integration)"
# inspect generated config.toml — assert [identity] / empty [vta] / server_did set

# alternatively, drive via wizard harness if T6 lands first
```

**Dependencies**: T1.

**Estimate**: 1–2 sessions.

---

### Phase 2 / 3 checkpoint

> A self-managed config is **producible** by the wizard. We have not yet started the daemon with that config — that is T3. Stop, review the wizard UX (prompt order, warning text, "Next steps" wording) before moving on. Update the spec if the UX shifts.

---

### Phase 3 — Runtime

#### T3: Audit and guard VTA-bound runtime paths in webvh-daemon

**Summary**: Walk every `vta.url` / `vta.did` / `vta_credential` read site in the daemon's runtime path and confirm each one either (a) already gracefully handles absence (e.g., `Option::None`), or (b) needs an `identity.mode == Vta` guard. Document each site. Confirm that with `identity.mode == SelfManaged` and an empty `[vta]` table, the daemon starts cleanly and serves its own DID document.

**Files** (likely; expand during the audit):
- `webvh-daemon/src/main.rs` — startup logic: secret-store load, DID resolver init, DIDComm bring-up, control-state plumbing. Add guards where needed.
- `webvh-control/src/server.rs` — DIDComm bring-up (already gated on `mediator_did`). Confirm no implicit VTA assumption in the start path.
- `webvh-control/src/messaging.rs` — DIDComm router. Confirm `AUTHENTICATE` / `did/request` / `did/publish` / `witness/publish` handlers operate against the local store regardless of VTA mode (per spec §5 — these are tenant-DID protocols, not bootstrap).
- Anywhere a `vta_credential` re-auth refresh is scheduled — gate behind `IdentityMode::Vta`.

**Acceptance**:
- Audit report (could live as a comment block in main.rs or in `tasks/runtime-audit-T3.md`) listing each `vta.*` / `vta_credential` read site, the file:line, and whether it required a guard, a no-op short-circuit, or no change.
- A self-managed daemon (config produced by T2) starts cleanly: no errors, no warnings about missing VTA URL / credential.
- `curl http://<host>:<port>/.well-known/did.jsonl` returns the daemon's DID document, validates as a webvh log entry.
- DIDComm listener starts iff `mediator_did` is set (existing behaviour, confirmed under self-managed).
- No tenant-DID protocol behaviour changes (regression guard).

**Verify**:
```
cargo build -p affinidi-webvh-daemon
cargo test -p affinidi-webvh-daemon --lib

# manual smoke (after T2 lands a config-producing wizard)
webvh-daemon --config /tmp/self-managed-test/config.toml &
DAEMON_PID=$!
sleep 1
curl -fsS http://127.0.0.1:8534/.well-known/did.jsonl | head -1   # must succeed
kill $DAEMON_PID
```

**Dependencies**: T1 (for the `IdentityMode` to gate on). Independent of T2 — can be developed against a hand-written self-managed config.

**Estimate**: 1–2 sessions, mostly audit time.

---

### Phase 3 / 4 checkpoint

> The daemon now starts and serves its own DID end-to-end in self-managed mode. Tenant-DID provisioning is **not** yet verified end-to-end — that is T5. Review the runtime-audit report before moving on.

---

### Phase 4 — Non-daemon binaries reject SelfManaged

#### T4: Reject `SelfManaged` in non-daemon setup wizards

**Summary**: Each non-daemon binary's setup wizard offers `SelfManaged` as a visible choice but errors out when selected, pointing the operator at `webvh-daemon`.

**Files**:
- `webvh-server/src/setup.rs` — add `SelfManaged` to its local `VtaMode` enum + prompt; in `run_wizard`'s dispatch, return an `AppError::Config("self-managed mode is daemon-only in v1; see webvh-daemon")`.
- `webvh-control/src/setup.rs` — same pattern.
- `webvh-witness/src/setup.rs` — same pattern.
- `webvh-watcher` — confirm there is no VtaMode prompt to add to (watcher's setup is much smaller). If there is, same pattern.

**Acceptance**:
- Selecting "Self-managed" in any of `webvh-server setup`, `webvh-control setup`, `webvh-witness setup` exits with a non-zero status and the documented error message.
- The error message is consistent across all three binaries (one shared constant in `webvh-common::server::vta_setup` or similar).

**Verify**:
```
cargo build --workspace
# scripted wizard tests, one per binary — see T6
```

**Dependencies**: T1. Independent of T2 / T3.

**Estimate**: 1 session.

---

### Phase 5 — Verification

#### T5: End-to-end test — tenant DIDComm provisioning into a self-managed daemon

**Summary**: Stand up a self-managed daemon in a test, point an external mock VTA (or another test daemon acting as a tenant VTA) at it, drive the existing tenant-DID provisioning flow over DIDComm, assert the tenant DID lands in the daemon's store and resolves at the daemon's well-known URL.

This is the spec's headline success criterion (§1, item 4) and the riskiest claim in the design — it proves DIDComm continues to function for tenant provisioning even though the daemon itself has no parent VTA.

**Files**:
- `webvh-daemon/tests/self_managed_e2e.rs` (new) — integration test using the existing test harnesses for VTA-side DIDComm provisioning.
- May need a fixture helper to build a self-managed `DaemonConfig` programmatically without invoking the wizard (faster + deterministic).

**Acceptance**:
- Test starts a self-managed daemon on a random local port, with mediator configured to a test mediator.
- A test VTA / mock tenant client sends the AUTHENTICATE → `did/request` → `did/publish` sequence.
- Daemon's `dids` keyspace contains the new tenant DID record.
- `GET /<mnemonic>/did.jsonl` returns the freshly provisioned tenant DID document.
- Test asserts `secrets.vta_credential` is still `None` after the flow (no accidental VTA bootstrap got triggered).

**Verify**:
```
cargo test -p affinidi-webvh-daemon --test self_managed_e2e -- --nocapture
```

**Dependencies**: T2 + T3. Optionally also T6 (wizard harness can produce the test config).

**Estimate**: 1–2 sessions, depending on how reusable the existing DIDComm test harness is.

---

#### T6: Wizard harness test — SelfManaged branch

**Summary**: Drive the daemon wizard's SelfManaged branch with scripted input and assert the produced config + secrets + ACL state.

**Files**:
- `webvh-daemon/tests/wizard_self_managed.rs` (new) — uses the same wizard-harness pattern existing tests use (look for prior examples with `dialoguer::test` or env-driven prompts). If no harness exists, refactor `run_self_managed_setup` to take a small input trait so the test can stub it without touching dialoguer's real terminal.

**Acceptance**:
- Test runs SelfManaged wizard with canned answers and asserts:
  - `[identity] mode = "self-managed"`, `[vta]` empty, `server_did` populated.
  - `vta_credential = None` in the secret store.
  - `acl` keyspace empty.
  - Stderr contains `"webvh-daemon invite --did"` and does not contain `"pnm contexts create"` or `"vta context create"`.
- Negative cases: HTTP / localhost public-URL prompts trigger the warning hook.

**Verify**:
```
cargo test -p affinidi-webvh-daemon --test wizard_self_managed
```

**Dependencies**: T2.

**Estimate**: 1 session.

---

### Phase 5 / 6 checkpoint

> All success criteria from spec §1 are verifiably met. Review the test output, especially the e2e tenant provisioning, before merging the docs PR.

---

### Phase 6 — Ship

#### T7: Documentation

**Summary**: Add a "Self-managed mode" section to operator docs and surface the option at the right discovery points.

**Files**:
- `docs/bootstrap_startup.md` — new section: "Self-managed mode (daemon-only)". Walk through: when to choose it, what the wizard does, the post-setup `webvh-daemon invite` step, the security model (passkey-only admin, no VTA fallback). Reference the spec.
- `README.md` — if it lists deployment modes, add self-managed.
- `CHANGELOG.md` — entry under the next unreleased version.

**Acceptance**:
- An operator following only the docs (no spec, no source) can produce and start a working self-managed daemon, enrol an admin via passkey, and have a tenant VTA provision a DID into it.
- The daemon-only constraint is explicit on first read.
- The docs state the no-migration-path decision.

**Verify**:
- Self-review by following the docs from a clean clone in a scratch directory.
- Doc snippets match real CLI output (re-run commands and copy-paste).

**Dependencies**: T1–T6 all merged.

**Estimate**: 1 session.

---

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Runtime audit (T3) finds an unexpected VTA-bound code path that's expensive to gate | Medium | T3 produces a written audit before any code change — if a deep dependency surfaces, escalate before sinking time into a workaround |
| `dialoguer`-based wizard is hard to test from a harness (no built-in stub) | Medium | T6 may need a small refactor to extract an `Inputs` trait. If that bloats the diff, defer T6 to a follow-up and rely on manual + e2e (T5) coverage |
| The "tenant VTA can DIDComm-provision into a self-managed daemon" claim turns out to require a VTA-issued credential we forgot about | Low | T5 is intentionally first-class evidence. If it fails, scope retreat: self-managed daemon serves its own DID but tenant provisioning requires a VTA — still useful, but the spec headline shifts |
| Adding `[identity]` to existing configs without `mode` set causes deserialisation issues on older binaries reading newer configs | Low | `IdentityMode::Vta` is the serde default. Existing configs without the section continue to load. T1 unit test covers this. |

## Out of scope

- Self-managed mode for `webvh-server`, `webvh-control`, `webvh-witness`, `webvh-watcher` standalone (T4 makes them refuse it).
- Distributed self-managed (multiple processes trusting each other without a VTA).
- Self-managed → VTA migration tooling.
- Changes to tenant-DID protocols themselves.

## Suggested PR shape

- PR 1: T1 only (foundations, low-risk, fast review).
- PR 2: T2 + T6 (wizard + harness test).
- PR 3: T3 (runtime + audit). Smoke evidence in PR description.
- PR 4: T4 (rejection arms — small, can land any time after T1).
- PR 5: T5 (e2e test — proves the headline).
- PR 6: T7 (docs).

PRs 1, 4 can land independently. 2, 3 in either order. 5 last before docs. 6 last.
