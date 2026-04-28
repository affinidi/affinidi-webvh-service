# Spec: Self-Managed (No-VTA) Operating Mode

Status: Draft — awaiting review
Scope: `webvh-daemon` only (v1)
Author: glenn.gore@gmail.com

## 1. Objective

Allow a `webvh-daemon` instance to be deployed without any VTA acting as the daemon's *own* trust anchor. The daemon generates its own Ed25519 signing key, X25519 key-agreement key, and a self-hosted `did:webvh` identifier at setup time, with no online or offline VTA round-trip required.

The daemon still functions as a webvh **hosting target** for tenant DIDs provisioned by *other* (tenant-owned) VTAs over DIDComm — what changes is only how the daemon obtains *its own* service identity, not how it serves tenants.

### Why

Operators who want to run a webvh hosting node — whether for development, internal tenant hosting, or as the trust root in a closed deployment — should not be forced to stand up a VTA just to provision the daemon's own keys. Removing this floor lowers the bar to "single binary, single config, working node" without changing the security model for tenant-DID provisioning, which still flows through DIDComm + a tenant's VTA.

### Success criteria

- A fresh `webvh-daemon setup` run completes end-to-end without any VTA prompts when the operator selects "Self-managed".
- The resulting config has `[identity] mode = "self-managed"` and an empty `[vta]` table.
- On first start, the daemon serves its own `did:webvh` document at `<public_url>/.well-known/did.jsonl` and that document resolves successfully via the DID resolver.
- Inbound DIDComm provisioning from an external VTA (`did/request`, `did/publish`, `witness/publish`, `AUTHENTICATE`) succeeds against the self-managed daemon, end-to-end, in an integration test.
- The setup wizard's "next steps" output tells the operator to start the daemon and then run `webvh-daemon invite --did <ADMIN_DID> --role admin` to mint a passkey enrolment URL. After redeeming, the admin authenticates via passkey thereafter. No admin DID is seeded in `acl` by the wizard — the DID is supplied by the operator at `invite` time.
- `webvh-server`, `webvh-control`, `webvh-witness`, `webvh-watcher` standalone wizards reject `SelfManaged` with a clear error message ("self-managed mode is daemon-only in v1").
- The setup wizard refuses an empty/invalid `public_url`, accepts `http://localhost:<port>` with a loud warning, and accepts `https://...` silently.

## 2. Design decisions (resolved)

| Question | Decision |
|---|---|
| DID method | Self-hosted `did:webvh` |
| Admin auth | Passkey-invite **only**, via the existing `webvh-daemon invite` CLI subcommand (`webvh-daemon/src/main.rs:117`). The wizard does **not** create the invite — it prints the command in the next-steps output. The operator runs it after starting the daemon, supplying the admin DID at that point. |
| Distributed self-managed | Out of scope — daemon-only in v1 |
| DIDComm | Stays on. Inbound VTA provisioning protocols remain operational for tenant DIDs; only the daemon's own outbound VTA bootstrap is skipped |
| Public URL validation | Permissive with loud warning for `http://` and `localhost` |
| Wizard mode | New `VtaMode::SelfManaged` variant; doc comment clarifies "no VTA integration" |
| v1 scope | `webvh-daemon` only; other binaries reject `SelfManaged` |

## 3. Tech stack

- Rust 2024, rust-version 1.94
- Existing crates: `affinidi-webvh-common`, `affinidi-webvh-daemon`, `affinidi-tdk` (Secret factory methods), `dialoguer` (wizard prompts)
- No new dependencies required. Local key generation already supported via `Secret::generate_ed25519` / `Secret::generate_x25519`. DID document construction already supported via `webvh-server::bootstrap::bootstrap_did`.

## 4. Project structure (files touched)

```
webvh-common/src/server/
  config.rs                  → add IdentityConfig { mode: IdentityMode }; IdentityMode::{Vta, SelfManaged}
  vta_setup.rs               → reuse `online_provision_setup` shape; add `self_managed_provision()` that
                               generates keys + builds DID doc locally without VTA round-trip
  operator_messages.rs       → add SelfManaged branch (no PNM/VTA hint required)

webvh-daemon/src/
  setup.rs                   → add 4th VtaMode variant `SelfManaged`; new wizard branch that skips
                               vta.{did, context_id, url} prompts and skips run_online_provision
  main.rs                    → no change (config drives everything at runtime)
  config.rs                  → expose new IdentityConfig
  config_writer.rs           → ensure [vta] table is omitted (or written empty) when SelfManaged

webvh-server/src/setup.rs    → match arm: reject SelfManaged with "daemon-only in v1"
webvh-control/src/setup.rs   → match arm: reject SelfManaged with "daemon-only in v1"
webvh-witness/src/setup.rs   → match arm: reject SelfManaged with "daemon-only in v1"
webvh-watcher/src/setup.rs   → match arm: reject SelfManaged with "daemon-only in v1"
                               (or no change if watcher has no VtaMode prompt today)

docs/
  self-managed-mode-spec.md  → this file
  bootstrap_startup.md       → add a "Self-managed mode" section noting daemon-only constraint
```

No new binaries. No new crates.

## 5. Runtime semantics

| Aspect | VTA mode (today) | Self-managed (new) |
|---|---|---|
| `secrets.signing_key` source | `vta_sdk::provision_client::run_provision` | `Secret::generate_ed25519` at setup |
| `secrets.key_agreement_key` source | Same | `Secret::generate_x25519` at setup |
| `secrets.jwt_signing_key` source | Locally generated (already) | Locally generated (unchanged) |
| `secrets.vta_credential` | `Some(CredentialBundle)` | `None` permanently |
| `server_did` | VTA-minted `did:webvh:<scid>:<host>` | Locally-built `did:webvh:<scid>:<host>` |
| DID document publication | Server hosts at well-known URL | Server hosts at well-known URL (identical) |
| Inbound DIDComm listener | Always on if `mediator_did` set | Always on if `mediator_did` set (identical) |
| `did/request` / `did/publish` handlers | Honour requests from authorised tenant VTAs | Identical behaviour — they are tenant-DID protocols, not daemon-bootstrap protocols |
| `[vta]` config table | Required (`url`, `did`, `context_id`) | Empty / omitted |
| `[identity] mode` | `"vta"` (default) | `"self-managed"` |
| Admin bootstrap | VTA-issued admin credential or wizard ACL | Operator runs `webvh-daemon invite --did <admin-did> --role admin` after first start, then redeems the printed URL via the control-plane UI. ACL is empty until redemption completes. |

Runtime guards: any code path that today reads `vta.url` or `vta.did` to call out to a parent VTA must be gated by `identity.mode == Vta`. In self-managed mode those operations are unreachable. Re-authentication-with-VTA paths return early as no-ops.

## 6. Wizard flow (daemon)

```
1. "How will the daemon obtain its identity?"
   - Online — VTA reachable from this host
   - Offline — start a sealed-bundle bootstrap (phase 1)
   - Offline — complete a pending sealed-bundle bootstrap (phase 2)
   - Self-managed (no VTA integration)            ← new

2. (SelfManaged branch only)
   - Public URL prompt (warns loudly on http:// or localhost)
   - Mediator DID prompt (optional — for DIDComm inbound from external VTAs)
   - Host / port / data dir / log level / log format prompts (existing shared block)
   - Secrets backend prompt (existing shared block)
   - Generate Ed25519 + X25519 + JWT keys locally
   - Compute did:webvh identifier from public URL
   - Build DID document via existing bootstrap_did(...)
   - Persist secrets via configured backend
   - Write config.toml with [identity] mode = "self-managed", empty [vta],
     and an empty [acl] section
   - Print summary: server DID + "Next steps" block:
       1. Start the daemon: `webvh-daemon --config <path>`
       2. Mint your first admin enrolment invite:
          `webvh-daemon invite --did <YOUR_ADMIN_DID> --role admin`
       3. Open the printed enrolment URL in a browser to bind a passkey.
     No PNM/VTA-host commands appear in the SelfManaged summary.

3. (existing Online / OfflineStart / OfflineComplete branches unchanged)
```

## 7. Code style

Match the existing wizard module style. New variants get rustdoc explaining intent; no comments that simply restate code.

```rust
/// Choice of VTA reachability for the unified `setup` wizard.
///
/// `SelfManaged` means the daemon is its own trust root — no parent VTA
/// provisions the daemon's keys. Tenant DIDs may still be provisioned by
/// external VTAs via DIDComm at runtime.
enum VtaMode {
    Online,
    OfflineStart,
    OfflineComplete,
    SelfManaged,
}
```

Runtime branching uses the `IdentityMode` enum on `AppConfig`, not the wizard's `VtaMode` (which only exists during setup).

## 8. Testing strategy

- **Unit**: `IdentityMode` round-trips through TOML serde. `apply_env_overrides` honours `WEBVH_IDENTITY_MODE`. Public-URL validation accepts `https://`, accepts `http://localhost` with the warning hook firing, rejects empty/garbage.
- **Wizard integration** (existing harness pattern in `webvh-daemon/tests/`): drive the SelfManaged branch with scripted input; assert the produced config has empty `[vta]`, populated `[identity]`, and that `secrets.vta_credential` is absent.
- **Runtime end-to-end**: spin up a self-managed daemon in a test, point an external test-VTA at it, run the existing tenant-DID provisioning flow over DIDComm, assert success.
- **Negative**: each non-daemon binary rejects `SelfManaged` with a clear message; assert via the wizard harness.
- Coverage target: existing project bar (no new threshold introduced).

## 9. Boundaries

**Always do**
- Generate keys via `Secret::generate_ed25519` / `Secret::generate_x25519` (factory methods only — `Secret` fields are private).
- Persist generated secrets through the configured `secret_store` backend before the wizard exits.
- Reference the existing `webvh-daemon invite` subcommand for admin enrolment — do not duplicate invite-minting logic into the wizard.
- Run `cargo fmt` before commit; sign commits with `-s`.
- Bump dependent sub-crate versions together when bumping any crate version.
- Mirror any new daemon CLI subcommand into `webvh-daemon` per CLAUDE.md daemon-parity rule.

**Ask first**
- Adding any new dependency.
- Changing the on-disk config schema in a way that breaks existing VTA-mode deployments.
- Extending self-managed mode to non-daemon binaries (out of v1 scope).
- Changing the DID method away from `did:webvh`.

**Never do**
- Hard-code or default to plaintext-secrets backend in self-managed mode just because it's simpler.
- Seed an admin DID into `acl` during self-managed setup. The DID enters the system via `webvh-daemon invite --did <...> --role admin` followed by passkey redemption — not via the wizard's config write.
- Mint or persist a passkey invite from inside the setup wizard. The CLI subcommand is the single source of truth for invite creation and must be the only place that calls `create_enrollment_invite`.
- Provide a self-managed → VTA migration path. Mode is permanent at setup time. (Operator can always start a fresh deployment.)
- Strip the existing VTA modes or change their behaviour.
- Add a "self-managed but distributed" path in v1.
- Suppress the `http://`/localhost warning — the user explicitly chose loud-but-permissive.

## 10. Open questions

_All resolved. Stats and registry verified to have no implicit VTA dependency in daemon mode (`webvh-common/src/server/stats_collector.rs` and `webvh-control/src/registry.rs` contain no VTA / credential / signing-key references; `server_push::notify_servers_*` no-ops when `state.atm` is None per `webvh-daemon/src/main.rs:991`; cross-service registration code paths don't run in single-process daemon mode)._

## 11. Plan / tasks

To be expanded under `agent-skills:plan` after this spec is approved. Rough sketch:

1. Add `IdentityConfig` + `IdentityMode` to `webvh-common/src/server/config.rs` (TOML + env override).
2. Add `VtaMode::SelfManaged` + wizard branch to `webvh-daemon/src/setup.rs` with local key generation and a "next steps" print block that names `webvh-daemon invite --did <...> --role admin`.
3. Add `self_managed_provision()` helper to `webvh-common/src/server/vta_setup.rs` (or a new sibling module).
4. Add `IdentityMode == Vta` guards to the small handful of code paths that today unconditionally call out to a parent VTA at runtime.
5. Add `SelfManaged` rejection arms to non-daemon wizards.
6. Tests: unit + wizard-harness + runtime-e2e per §8 (including: post-`invite` redemption succeeds, ACL is empty until redemption, post-redemption auth succeeds).
7. Docs: `docs/bootstrap_startup.md` section, README mention.
