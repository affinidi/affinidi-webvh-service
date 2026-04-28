# T3: Runtime VTA Audit (webvh-daemon)

Spec: [`docs/self-managed-mode-spec.md`](../docs/self-managed-mode-spec.md)
Plan: [`tasks/plan.md`](plan.md)

**Question for the audit**: in `IdentityMode::SelfManaged` mode (with an empty `[vta]` table and `vta_credential = None`), does any runtime code path break, panic, or unconditionally call out to a parent VTA?

**Result**: No. The existing code already handles VTA absence cleanly — all VTA-related fields are typed as `Option<String>` and read only in setup-time / CLI-subcommand paths or in passive surfaces (UI status endpoint, doc comments). No runtime guards (`if identity.mode == Vta { ... }`) are required. The `IdentityMode` field is informational at runtime in v1.

## Method

Search command (run from the workspace root):
```
grep -rn "config\.vta\.\|\.vta\.url\|\.vta\.did\|\.vta\.context_id\|vta_credential" \
  --include="*.rs" \
  | grep -v "src/setup.rs\|src/tests/\|/tests/\|examples/\|src/config\.rs"
```
Plus targeted greps inside each binary's `main.rs` and across `webvh-witness/`, `webvh-watcher/`.

## Read sites by category

### A. Doc comments / inert references (no behaviour)
| Site | Notes |
|---|---|
| `webvh-common/src/server/vta_setup.rs:116` | Doc comment on `OnlineProvisionOutcome::vta_did` describing setup-time use. |
| `webvh-common/src/server/vta_setup.rs:121` | Doc comment on `vta_credential_b64` field. |
| `webvh-common/src/server/vta_setup.rs:220` | Doc comment on `build_vta_credential_b64`. |

**Action**: none.

### B. Field declarations / `None` initializers (storage layer)
| Site | Notes |
|---|---|
| `webvh-common/src/server/secret_store/mod.rs:51` | `pub vta_credential: Option<String>` field declaration. |
| `webvh-common/src/server/secret_store/mod.rs:319` | `vta_credential: None` in default constructor. |
| `webvh-common/src/server/secret_store/plaintext.rs:37,223` | `vta_credential: None` defaults in plaintext backend. |
| `webvh-common/src/server/config.rs` (`VtaConfig` definition) | All three fields are already `Option<String>`. |

**Action**: none. Already optional at the type level.

### C. CLI-subcommand setup paths (run only at config-time, not runtime)
| Site | Notes |
|---|---|
| `webvh-daemon/src/main.rs:194,345,354,1467,1523,1526,1552` | All inside `Command::ImportSecrets` / `run_import_secrets` — invoked only via `webvh-daemon import-secrets`, not from `run_daemon`. |
| `webvh-server/src/main.rs:206,395,404,1044,1098,1101,1129,1347` | Same shape — `import-secrets` CLI. |
| `webvh-witness/src/main.rs:672` | `vta_credential: None` in import-secrets path. |
| `webvh-control/src/main.rs:626` | `vta_credential: None` literal in `run_invite` flow that builds a setup-shaped `ServerSecrets` to mint a passkey invite — already passes `None`, no runtime VTA call. |

**Action**: none. These never run as part of `run_daemon`. Self-managed users will simply skip `import-secrets`.

### D. UI / status endpoint (passive surface)
| Site | Notes |
|---|---|
| `webvh-control/src/routes/did_manage.rs:447-448` | `GET /api/config` returns `vta_url` and `vta_did` as `Option<String>` for the operator UI. In self-managed mode both serialize as `null` / absent. |

**Action**: none. The UI tolerates `null`; verified manually in T7 docs phase.

### E. Runtime DID-bound paths that read `server_did` (NOT vta-bound)
Multiple sites in `webvh-control/src/server.rs`, `routes/didcomm.rs`, `messaging.rs`, `server_push.rs`, `health.rs` read `state.config.server_did`. **`server_did` is the daemon's own DID — set in self-managed mode too** (populated by `finalize_daemon_setup` after the local DID-doc import in T2). These are not VTA-coupled. No action.

### F. Outbound cross-service push (daemon-mode-irrelevant)
`webvh-control/src/server_push.rs::notify_servers_*` no-ops when `state.atm` is `None`. Confirmed already during planning (`webvh-daemon/src/main.rs:991` comment). The daemon never instantiates an outbound ATM, so these paths are dormant in any daemon-mode deployment, VTA or self-managed. No action.

### G. Witness / watcher runtime
Searched `webvh-witness/src/` and `webvh-watcher/src/` for `vta.` outside setup files: zero matches. No action.

## What's NOT covered by this audit

- **Tenant DIDComm provisioning** (`AUTHENTICATE` / `did/request` / `did/publish` / `witness/publish` handlers in `webvh-control/src/messaging.rs`). These are intentionally retained per spec §5 — they operate on the local store as a *hosting target* for tenant DIDs provisioned by *external* (tenant-owned) VTAs. They do **not** call out to a parent VTA on this daemon's behalf and are unaffected by `IdentityMode`. End-to-end verification of this claim is T5's job.
- **Live HTTP smoke test** (curl the well-known URL on a running self-managed daemon). The wizard produces a valid config (T2 build-clean), and runtime startup has no VTA-bound code paths to fail on. A live smoke test would be redundant with T5's e2e test, which exercises the same path plus the tenant-provisioning flow. Deferred to T5.

## Conclusion

T3 closes with zero guard additions and zero runtime code changes. `IdentityMode::SelfManaged` is observationally indistinguishable from `IdentityMode::Vta` at runtime in v1 — the difference is entirely what the *setup* path produces (locally-generated keys + empty `[vta]` table + `vta_credential = None`). The runtime then loads and runs that config without any VTA-mode-specific branches.

If a future feature adds a VTA-bound runtime path (e.g., periodic `vta_credential` re-auth), it must gate on `state.config.identity.mode == IdentityMode::Vta`. For v1, the field exists but is unused at runtime — that's intentional foundation for T3-equivalent guards landing alongside future VTA runtime features.
