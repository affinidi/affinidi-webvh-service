# did-hosting Rollout — Task Breakdown

Plan: [`tasks/did-hosting-rollout-plan.md`](did-hosting-rollout-plan.md)
Specs: [`docs/multi-domain-spec.md`](../docs/multi-domain-spec.md), [`docs/multi-method-hosting-spec.md`](../docs/multi-method-hosting-spec.md), [`docs/did-hosting-client-crate-spec.md`](../docs/did-hosting-client-crate-spec.md)

Tasks are numbered in dependency order. Each task is one focused session and one PR. Files lists are upper bounds — actual diffs may touch fewer. `Verify` is the exact command/check that gates the task as done.

Workstream IDs (WS-*) reference the plan §workstream-decomposition.

---

## Pre-flight (before any task opens)

- [ ] **P0** Patch the three specs for the two factual corrections surfaced during planning
  - Files: `docs/multi-domain-spec.md` (§5.1, §6.3), `docs/multi-method-hosting-spec.md` (§7.1, §9.3), `docs/did-hosting-client-crate-spec.md` (§5.1)
  - Changes:
    - Webvh resolution path `/log/{*mnemonic}` → `/{*mnemonic}/did.jsonl` (it's a catch-all fallback at `webvh-server/src/routes/did_public.rs:150`, not a prefix-mounted route)
    - did:web partial impl already exists at `webvh-server/src/routes/did_public.rs:182`; Phase M2 narrows from "implement" to "formalise + wrap through `DidMethod` trait"
  - Verify: `rg -n "/log/\{.*mnemonic" docs/` returns no matches; `rg -n "serve_did_web" docs/multi-method-hosting-spec.md` cites the existing handler
  - Deps: none
  - Estimate: 0.25 session

---

## Phase I — Foundation (WS-0)

Mechanical + structural setup. Must complete before Phase II opens.

- [ ] **T1** Atomic repo rename: `affinidi-webvh-service` → `did-hosting-service`
  - Files: `Cargo.toml` (workspace), every crate's `Cargo.toml` (rename `name` + `webvh-* → did-hosting-*` except `webvh-witness`/`webvh-watcher`), folder renames via `git mv`, env-var rename in `webvh-common/src/server/config.rs` (`WEBVH_* → DID_HOSTING_*`), binary names in `webvh-daemon/src/main.rs` and siblings, `README.md`, `CHANGELOG.md`, CI workflow files, docs/* references
  - Acceptance: `cargo build --workspace --all-features` clean; full existing test suite passes; CHANGELOG entry documents env-var rename with one-line migration note; new operator-facing CLI `did-hosting-daemon migrate-from-webvh-config /path/to/old.toml` skeleton exists (impl can be empty `unimplemented!` for now — fills in T2 + later)
  - Verify: `cargo build --workspace --all-features && cargo test --workspace` + `rg -l "affinidi-webvh-service" .` returns only historical/changelog mentions
  - Deps: P0
  - Estimate: 1 session (mechanical, atomic — pause other merges during review)

- [ ] **T2** Migration-runner skeleton + meta-keyspace
  - Files: `did-hosting-common/src/migrations/mod.rs` (new) + `did-hosting-common/src/migrations/runner.rs` (new), `did-hosting-common/src/server/store/keyspaces.rs` (new — see T3, but `meta` lands here first), wire into `did-hosting-daemon/src/main.rs` boot path
  - Acceptance:
    - `Migration` trait with `id() -> &'static str`, `run(&mut Store)` async; idempotent dispatcher walks an in-process registry and skips any whose id is already in the `meta` keyspace under `migration:applied:{id}`
    - Empty migration set runs cleanly on a fresh store, marks nothing
    - Dispatcher fails-fast on a migration's `run()` error and refuses to mark it applied
  - Verify: `cargo test -p did-hosting-common migrations` (new tests) + `cargo build --workspace`
  - Deps: T1
  - Estimate: 1 session

- [ ] **T3** Centralised keyspace registry
  - Files: `did-hosting-common/src/server/store/keyspaces.rs` (extend T2's stub), refactor existing call-sites that hardcode keyspace names: `did-hosting-server/src/main.rs:644`, `did-hosting-daemon/src/main.rs:459–470` and other open-on-demand sites, `did-hosting-control/tests/change_owner_rest.rs:1–7`, `did-hosting-server/tests/smoke.rs:41–43`, `did-hosting-server/src/backup.rs:55–58`
  - Acceptance:
    - `pub const KS_DIDS: &str = "dids"; ...` for every existing keyspace (`acl`, `sessions`, `stats`, `timeseries`, `registry`, `witnesses`, `meta`) + the new ones (`domains`, `assignments`, `pending_purges`)
    - Every existing `keyspace("dids")` etc. call uses the const
    - A `grep KS_` returns all opens, a `grep 'keyspace("'` returns zero matches outside the registry module
  - Verify: `cargo build --workspace && cargo test --workspace` + `rg -n 'keyspace\("' --type rust -g '!target' -g '!keyspaces.rs'` returns empty
  - Deps: T2
  - Estimate: 1 session

- [ ] **T4** Shared wizard prompt helpers (extend existing module)
  - Files: `did-hosting-common/src/server/setup_prompts.rs` (new — split off from existing `secret_store/wizard.rs`), refactor `did-hosting-server/src/setup.rs`, `did-hosting-control/src/setup.rs`, `did-hosting-daemon/src/setup.rs`, `webvh-witness/src/setup.rs` to use new helpers for the existing duplicated prompts (public URL, listen host/port, log format)
  - Acceptance:
    - New helpers: `prompt_public_url`, `prompt_listen_host`, `prompt_listen_port`, `prompt_log_format` — each takes a default + returns the validated value
    - All four wizards build and pass their existing tests against the shared helpers
    - No behaviour change in any wizard flow
  - Verify: `cargo build --workspace` + manual wizard run on `did-hosting-daemon setup` confirms identical UX
  - Deps: T1
  - Estimate: 1 session

> **Checkpoint I (gate to Phase II)**: All foundation PRs merged. Build clean. No existing tests regressed. Migration runner accepts an empty set without error. Reviewers from each crate confirmed wizard refactor didn't change UX.

---

## Phase II — Substrate (WS-1, WS-2, WS-3 — parallel)

Three workstreams in parallel. They don't conflict at the file level (different modules).

### Track 1: Trust-Tasks transport (WS-1)

- [ ] **T5** Decide and execute Trust-Tasks primitive sourcing
  - Files: either (a) `trust-tasks/` new workspace member with `src/{mod.rs, router.rs, extractor.rs}` ported from `verifiable-trust-infrastructure/vti-common/src/trust_task/` — plus add to workspace `Cargo.toml`; OR (b) copy into `did-hosting-common/src/trust_task/`
  - Acceptance:
    - Decision recorded in PR description with rationale (extract = single source of truth across orgs; copy = no cross-repo dep)
    - `TrustTask` newtype, `TrustTaskRouter`, `Trust-Task` header extractor working with the same surface as VTI's
    - Tests ported (exact-match, missing-header 400, mismatch 415, byte-strict version comparison, health exempt) all green
  - Verify: `cargo test -p trust-tasks` or `cargo test -p did-hosting-common trust_task`
  - Deps: T3 (workspace registry)
  - Estimate: 1 session (extract) or 0.5 session (copy)

- [ ] **T6** DIDComm dispatch helper for Trust-Tasks (new — not in VTI)
  - Files: `trust-tasks/src/didcomm.rs` (or `did-hosting-common/src/trust_task/didcomm.rs` per T5 decision), new
  - Acceptance:
    - Helper `fn dispatch_by_type(msg_type: &str, dispatcher: &TaskDispatcher) -> Result<Handler, TaskErr>` — exact-match lookup with the same semantics as the REST router
    - Unit tests cover the equivalent of router's exact-match / mismatch / missing cases
  - Verify: `cargo test -p trust-tasks didcomm` (or equivalent)
  - Deps: T5
  - Estimate: 0.5 session

- [ ] **T7** Trust-Tasks URL constants module
  - Files: `did-hosting-common/src/did_hosting_tasks.rs` (new)
  - Acceptance:
    - One `LazyLock<TrustTask>` const per registered URL, covering everything from `webvh-common/src/didcomm_types.rs:10–71` (auth, DID lifecycle, witness, sync, server-register, stats, health) plus the new domain-management URLs
    - Generic ops under `https://trusttasks.org/did-hosting/{path}/1.0`
    - Method-specific (witness, rollback, raw-log) under `https://trusttasks.org/webvh/{path}/1.0`
    - Unit test asserts every const validates as a `TrustTask::new`
  - Verify: `cargo test -p did-hosting-common did_hosting_tasks`
  - Deps: T5
  - Estimate: 0.5 session

- [ ] **T8** V1-alias table + dispatcher integration
  - Files: `did-hosting-common/src/v1_aliases.rs` (new), `did-hosting-control/src/messaging.rs` (extend `dispatch_did_op()` at line 245 to canonicalise via the alias table before matching), `did-hosting-control/src/routes/didcomm.rs` (line 176–193 already shares; verify no changes needed), REST router setup in `did-hosting-server/src/server.rs` (wrap with `TrustTaskRouter`)
  - Acceptance:
    - Alias table maps every `MSG_*` const → its canonical Trust-Task URL
    - DIDComm dispatcher accepts both `MSG_*` and `TASK_*` as the `type` field, dispatches to same handler
    - REST router validates `Trust-Task:` header on every authed route via `TrustTaskRouter`
    - Health endpoint is the only exempt route
  - Verify: `cargo test --workspace` (existing tests still green — proves zero behaviour change)
  - Deps: T6, T7
  - Estimate: 1 session

- [ ] **T9** Trust-Tasks parity harness
  - Files: `did-hosting-server/tests/trust_task_parity.rs` (new), `did-hosting-control/tests/trust_task_parity.rs` (new)
  - Acceptance: For every operation, the harness sends two requests — one with the legacy `MSG_*` `type` (or no `Trust-Task` header on REST), and one with the canonical Trust-Task URL — and asserts byte-equivalent observable state (response body + store state)
  - Verify: `cargo test --workspace trust_task_parity`
  - Deps: T8
  - Estimate: 1 session

### Track 2: Method abstraction (WS-2)

- [ ] **T10** `DidMethod` trait + dispatcher
  - Files: `did-hosting-common/src/method/mod.rs` (new — `DidMethod` trait, `ParsedDid`, `MethodError`, `method_by_name`, `enabled_methods`), `did-hosting-common/src/method/parse.rs` (new — `parse_did_method`)
  - Acceptance:
    - Trait surface exactly as in `multi-method-hosting-spec.md` §6
    - `method_by_name` returns `Option<&'static dyn DidMethod>` gated by `#[cfg(feature = "method-{name}")]`
    - `enabled_methods` compile-time concatenated slice
  - Verify: `cargo test -p did-hosting-common method`
  - Deps: T3 (registry constants for storage)
  - Estimate: 1 session

- [ ] **T11** `methods/webvh.rs` impl wrapping existing webvh logic
  - Files: `did-hosting-common/src/method/webvh.rs` (new, gated `#[cfg(feature = "method-webvh")]`), refactor `did-hosting-server/src/did_ops.rs` (the parts that hardcode webvh format) to call through the trait
  - Acceptance:
    - Webvh impl satisfies `DidMethod` trait: parse identifier, build resolution URL, validate jsonl, apply_update appends
    - Existing webvh tests still pass against the trait-routed code path
    - No direct hardcoded `did:webvh:` string handling outside `methods/webvh.rs` (grep enforced — see Verify)
  - Verify: `cargo test --workspace` + `rg -n "did:webvh:" --type rust did-hosting-server/src/ did-hosting-control/src/ -g '!method/webvh.rs'` returns only references inside test fixtures or constants
  - Deps: T10
  - Estimate: 1–2 sessions

- [ ] **T12** `DidRecord` storage shape
  - Files: `did-hosting-common/src/server/store/dids.rs` (new), refactor `did-hosting-control/src/did_ops.rs:78–99` (`get_authorized_record`) and `webvh-server/src/routes/did_public.rs:150` to read/write `DidRecord` instead of raw bytes
  - Acceptance:
    - `DidRecord { method, domain, path, content_type, data, version, created_at, updated_at }` — `data: Vec<u8>` is method-specific bytes
    - Read path tolerates legacy values (raw bytes without wrapper) by detecting absence of `method` field and returning a "needs migration" error (caught and resurfaced as a clear startup failure)
    - Write path always writes the new wrapped shape
  - Verify: `cargo test --workspace` (existing tests pass after migration step T13 wires in)
  - Deps: T11
  - Estimate: 1 session

- [ ] **T13** Migration M-1: legacy `did_log` bytes → `DidRecord { method: "webvh", ... }`
  - Files: `did-hosting-common/src/migrations/m01_wrap_did_record.rs` (new), register in `did-hosting-common/src/migrations/mod.rs`
  - Acceptance:
    - Migration walks every `dids` entry, parses legacy shape, wraps as `DidRecord` with `method = "webvh"` and `domain`/`path` derived from the key
    - Idempotent: re-run skips entries that already deserialise as `DidRecord`
    - Audit-log entry records counts (wrapped / skipped / errored)
  - Verify: `cargo test -p did-hosting-server migration_m01` writes a legacy-shape fixture, runs migration, asserts the wrapped shape
  - Deps: T12, T2 (runner)
  - Estimate: 1 session

### Track 3: Domain model (WS-3)

- [ ] **T14** Domain-related keyspaces + types
  - Files: `did-hosting-common/src/server/store/keyspaces.rs` (already added the consts in T3; add types here or in a new file `did-hosting-common/src/server/domain/types.rs`), `did-hosting-common/src/server/domain/mod.rs` (new — `DomainEntry`, `DomainBranding`, `DomainQuota`, `DomainScope`)
  - Acceptance:
    - Types exactly per `multi-domain-spec.md` §3 design-decisions table
    - `DomainScope` enum has all three variants (`All`, `Allowed(Vec<String>)`, `AllowedWithDefault { allowed, default }`)
    - Serde round-trip tests cover every variant
  - Verify: `cargo test -p did-hosting-common domain`
  - Deps: T3
  - Estimate: 1 session

- [ ] **T15** `DomainEntry` CRUD + domain normalisation
  - Files: `did-hosting-common/src/server/domain/mod.rs` (extend with CRUD functions), `did-hosting-common/src/server/domain/normalize.rs` (new — lowercase + IDNA + path-prefix parser + validator)
  - Acceptance:
    - `create_domain`, `get_domain`, `list_domains`, `update_domain`, `disable_domain`, `set_default_domain` — all use the new `domains` keyspace
    - Normaliser rejects non-lowercase input with a clear 400 message pointing to the canonical form
    - Path-prefix parsing round-trips `example.com/webvh-a` correctly
    - Default-domain pointer stored in `meta:default_domain`; setting default to a disabled domain rejects with 400
  - Verify: `cargo test -p did-hosting-common domain` (extended cases)
  - Deps: T14
  - Estimate: 1 session

- [ ] **T16** `DomainScope` on `AclEntry` (additive, backwards-compat)
  - Files: `did-hosting-common/src/server/acl.rs` (extend `AclEntry`, `CreateAclRequest`, `UpdateAclRequest`, `AclEntryResponse`), `did-hosting-control/src/routes/acl.rs` (handlers carry new field through)
  - Acceptance:
    - `AclEntry.domains: DomainScope` with `#[serde(default)]` → missing field deserialises as `DomainScope::All`
    - Existing v0.6.0 ACL fixture loads cleanly with `domains = All` (test asserts)
    - Admin role implicitly `All` regardless of field value
    - New `Owner` entries created via the admin route default to `AllowedWithDefault { allowed: [system_default], default: system_default }`
  - Verify: `cargo test -p did-hosting-common acl` (extended)
  - Deps: T14
  - Estimate: 1 session

- [ ] **T17** `GET /api/domains` + `GET /api/me/domains` endpoints (no enforcement yet)
  - Files: `did-hosting-control/src/routes/domain.rs` (new), `did-hosting-control/src/routes/mod.rs` (register the new routes)
  - Acceptance:
    - `GET /api/domains` (Admin) returns the full domain list
    - `GET /api/me/domains` (any authed caller) returns the caller's ACL-scoped subset
    - Both endpoints behind `TrustTaskRouter::route_with_task` with the corresponding `TASK_*` URLs from T7
  - Verify: `cargo test -p did-hosting-control domain_routes` (new tests using existing harness pattern)
  - Deps: T15, T16, T8 (router)
  - Estimate: 1 session

- [ ] **T18** `bootstrap_domains` config seed + first-boot wiring
  - Files: `did-hosting-common/src/server/config.rs` (add `bootstrap_domains: Vec<String>`, `unassigned_purge_grace`, `trusted_proxy_cidrs`), `did-hosting-daemon/src/main.rs` (first-boot seed: if `domains` keyspace empty, seed from `bootstrap_domains`, else from legacy `public_url`'s host as a single default), wizard prompt in `did-hosting-daemon/src/setup.rs`
  - Acceptance:
    - Fresh daemon with `bootstrap_domains = ["example.com"]` boots and has exactly that one domain in the keyspace, marked as default
    - Upgrade path: deployment with legacy `public_url = "https://old.example.com"` and no `bootstrap_domains` set seeds `old.example.com` as default on first new-version boot
    - Loud `warn!` log if tier-3 fallback (empty) reached
  - Verify: `cargo test -p did-hosting-daemon bootstrap_domains`
  - Deps: T15, T4 (wizard helpers)
  - Estimate: 1 session

> **Checkpoint II (gate to Phase III)**: Parity harness (T9) green for all operations. `DidMethod` trait coverage ≥ 80%. ACL `DomainScope` round-trips every entry in a v0.6.0 fixture. Domain CRUD endpoints return correct ACL-scoped views. No enforcement of safety checks yet — that's Phase III. **Stop. Review. Confirm migration M-1 produced a valid `DidRecord` shape on a v0.6.0-restored store before continuing.**

---

## Phase III — Composition (WS-4, WS-5, WS-6, WS-9, WS-8 — partially sequential)

### Track: Enforcement (WS-4) — sequential, must precede WS-5/WS-8

- [ ] **T19** `Forwarded`/`X-Forwarded-Host`/`Host` extractor with `trusted_proxy_cidrs`
  - Files: `did-hosting-common/src/server/domain/detect.rs` (new), `did-hosting-server/src/server.rs` + `did-hosting-control/src/server.rs` (insert as Axum middleware that populates request extensions with the resolved domain)
  - Acceptance:
    - With `trusted_proxy_cidrs = ["10.0.0.0/8"]`, requests from a 10.x source honour `Forwarded` (RFC 7239 `host=`) then `X-Forwarded-Host` (first value) then `Host`
    - Requests from outside the CIDR always use `Host`
    - `Forwarded` parser handles quoted and unquoted host values per RFC 7239
    - Spoofed `X-Forwarded-Host` from a non-trusted source has no effect (asserted by integration test)
  - Verify: `cargo test -p did-hosting-common domain::detect` (table-driven) + `cargo test -p did-hosting-server xff_spoofing_test`
  - Deps: T18 (config field), T17 (routes mounted)
  - Estimate: 1–2 sessions

- [ ] **T20** Safety check on create / publish (`did.host` × active domain × ACL)
  - Files: `did-hosting-control/src/did_ops.rs:78–99` (`get_authorized_record` extended; add `assert_domain_allowed` helper), `did-hosting-common/src/server/domain/safety.rs` (new — encapsulates the check)
  - Acceptance:
    - On every create / publish, the embedded `did:{method}:…:<host>:…` host is parsed and matched against the active assigned-domain set; mismatch → 400 with explicit reason
    - Same host is matched against caller's ACL `DomainScope`; not-allowed → 403
    - Check runs **before** any storage write
    - Existing webvh create/publish tests updated to seed a domain
  - Verify: `cargo test --workspace` (the failure modes covered by new tests)
  - Deps: T15, T16, T11, T19
  - Estimate: 1 session

- [ ] **T21** Safety check on resolution (`Host` vs `did.host`, 503 on disabled)
  - Files: `did-hosting-server/src/routes/did_public.rs:150–196` (extend `serve_public()`), `did-hosting-common/src/server/domain/safety.rs` (add `assert_resolution_allowed`)
  - Acceptance:
    - Resolution request where `Host`-derived domain ≠ embedded `did.host` returns 404 (not 403)
    - Resolution against a disabled `DomainEntry` returns 503 with structured JSON `{ status, message?, eta? }`
    - Resolution-leakage integration test: domain-A request cannot fetch domain-B's DID
  - Verify: `cargo test -p did-hosting-server resolution_leakage_test`
  - Deps: T15, T19, T11
  - Estimate: 1 session

- [ ] **T22** Flip new-Owner ACL default to `AllowedWithDefault([default], default)`
  - Files: `did-hosting-control/src/routes/acl.rs` (handler that creates new ACL entries)
  - Acceptance:
    - New ACL entries with role `Owner` created via API default to `AllowedWithDefault { allowed: [system_default], default: system_default }`
    - Explicit `domains` in request body still honoured
    - Existing `Admin`/`Service` entries unaffected (implicit `All`)
    - Migration banner explicit on the dashboard: "N owner ACL entries are scoped to All domains" (banner UI added in T46; backend audit-log entry lands here)
  - Verify: `cargo test -p did-hosting-control acl_default_scope`
  - Deps: T16
  - Estimate: 0.5 session

### Track: did:web (WS-5) — after WS-2 + WS-4 enforcement

- [ ] **T23** Audit existing `serve_did_web()` and remove or wrap
  - Files: `did-hosting-server/src/routes/did_public.rs:182` (existing handler) + any callers
  - Acceptance:
    - Written audit in PR description: what the existing handler does, what its tests cover, how it interacts with storage
    - Decision recorded: remove and re-implement through the trait, OR keep as wrapper that calls into `methods/web.rs`
    - No-op landing PR if pure removal; otherwise the wrapped form is in place
  - Verify: `cargo test --workspace` (any existing did:web tests still pass after wrap)
  - Deps: T11
  - Estimate: 0.5–1 session

- [ ] **T24** `methods/web.rs` impl
  - Files: `did-hosting-common/src/method/web.rs` (new, gated `#[cfg(feature = "method-web")]`)
  - Acceptance:
    - Parser handles `did:web:{domain}[:{path}]` and the no-path form (path = `""`)
    - `__root` mnemonic sentinel for the no-path resolution case (resolves at `/.well-known/did.json`)
    - Validator parses JSON, asserts `id` field present and matches `did:web:{domain}{:{path}}` exactly (or `did:web:{domain}` for root)
    - `apply_update` ignores existing, returns new bytes (overwrite semantics)
    - Per-method content type `application/did+json`
  - Verify: `cargo test -p did-hosting-common method::web`
  - Deps: T10, T23
  - Estimate: 1 session

- [ ] **T25** Per-method resolution routes + ordering test
  - Files: `did-hosting-server/src/server.rs` (router build — explicit comment on registration order), `did-hosting-server/src/routes/resolve_web.rs` (new), `did-hosting-server/src/routes/resolve_webvh.rs` (extract from current `did_public.rs`)
  - Acceptance:
    - `GET /{*path}/did.json` + `GET /.well-known/did.json` registered behind `#[cfg(feature = "method-web")]`
    - `GET /{*mnemonic}/did.jsonl` (existing) extracted into its own handler module behind `#[cfg(feature = "method-webvh")]`
    - Router build order: `/api/...` and `/.well-known/...` (specific) → webvh catch-all → web catch-all (lowest priority)
    - Test asserts `/api/health` still resolves with both methods enabled, and `/api/health` does not get caught by the catch-alls
  - Verify: `cargo test -p did-hosting-server route_ordering`
  - Deps: T24
  - Estimate: 1 session

- [ ] **T26** Generalise request body fields (`did_log` → `did_data`, `method` field)
  - Files: `did-hosting-control/src/routes/dids.rs` (all DID management handlers), `did-hosting-control/src/did_ops.rs` (signatures change accordingly), update DTOs in `did-hosting-common/src/server/` (request types)
  - Acceptance:
    - `RegisterAtomicBody { method?, path, domain?, did_data: Value, force }` accepted on `POST /api/dids/register`
    - Old `did_log: String` field accepted as backwards-compat alias when `method = "webvh"` (deprecation note in error if used in v0.8)
    - `PUT /api/dids/{*mnemonic}` content-type discriminator: `application/jsonl` → webvh, `application/did+json` → web
    - Method-mismatch between `did_data.id` and explicit `method` → 400 with both values in the body
  - Verify: `cargo test -p did-hosting-control register_atomic_method_handling`
  - Deps: T11, T20, T24
  - Estimate: 1 session

### Track: Distributed assignment + unassignment (WS-6) — parallel after Phase II

- [ ] **T27** Extend server-register Trust Task with capability declaration
  - Files: `did-hosting-server/src/registry/handshake.rs` (extend the existing `MSG_SERVER_REGISTER` payload), `did-hosting-control/src/registry/mod.rs` (acceptance side)
  - Acceptance:
    - Outbound `server.register/1.0` payload carries `enabled_methods: Vec<String>`, `served_domains: Vec<String>` (initially empty), and protocol-version marker
    - Control plane registry stores capabilities per server
    - Backwards-compat: missing fields parse as `enabled_methods = ["webvh"]`, `served_domains = []`
  - Verify: `cargo test -p did-hosting-control server_register_capabilities`
  - Deps: T8 (Trust-Tasks dispatcher)
  - Estimate: 1 session

- [ ] **T28** `domain/assign/1.0` + `domain/unassign/1.0` Trust Tasks
  - Files: `did-hosting-control/src/routes/server_assignments.rs` (new), `did-hosting-server/src/task_dispatch.rs` (inbound handler for assignment payloads)
  - Acceptance:
    - Control plane can push `domain/assign/1.0 { domain }` and `domain/unassign/1.0 { domain }` to a registered server
    - Server persists the change in the new `assignments` keyspace
    - Idempotent: re-assigning an already-assigned domain is a no-op (no audit-log noise)
  - Verify: `cargo test -p did-hosting-control assign_unassign`
  - Deps: T27, T17
  - Estimate: 1 session

- [ ] **T29** Persistent local `assignments` cache + cold-start fallback
  - Files: `did-hosting-server/src/assignments.rs` (new — cached read from keyspace, tier fallback to `bootstrap_domains` then legacy `public_url`)
  - Acceptance:
    - Server restarted while control plane unreachable serves DIDs in persisted `assignments` set
    - Cold-start fallback chain: persisted `assignments` → `bootstrap_domains` → legacy `public_url` → empty (warn-log)
    - Once control plane reconnects, `assignments` keyspace gets refreshed and live-applied (no restart)
  - Verify: `cargo test -p did-hosting-server cold_start_fallback`
  - Deps: T28, T18
  - Estimate: 1 session

- [ ] **T30** Background purge sweep + admin "Purge now" Trust Task
  - Files: `did-hosting-server/src/assignments.rs` (extend with background task), `did-hosting-common/src/server/store/keyspaces.rs` (already has `pending_purges` const from T3), `did-hosting-control/src/routes/server_assignments.rs` (admin "Purge now" handler)
  - Acceptance:
    - Unassignment schedules a `pending_purges:{server,domain,scheduled_at}` entry with grace = `unassigned_purge_grace` (default `"2h"`)
    - Background sweep (interval = 60s) checks pending entries; if `scheduled_at + grace < now`, purge the domain's DIDs and audit-log `domain.purge { reason: "grace-expired" }`
    - Re-assigning a domain within the grace period removes the pending entry and audit-logs the cancellation
    - Admin "Purge now" Trust Task (`domain/purge/1.0`) skips the grace, audit-logs `reason: "admin-immediate"`
    - Per-(server, domain) safety: the purge is scoped only to the unassigned domain's DIDs on that server (multi-domain spec §3 retain-then-purge semantics)
  - Verify: `cargo test -p did-hosting-server unassignment_purge_lifecycle` (retain, grace-expired, re-assign-cancels, purge-now)
  - Deps: T29
  - Estimate: 2 sessions

### Track: Stubs + CI matrix (WS-9) — parallel, off critical path

- [ ] **T31** `methods/webs.rs` + `methods/webplus.rs` stubs
  - Files: `did-hosting-common/src/method/webs.rs` (new, gated `#[cfg(feature = "method-webs")]`, body = `compile_error!("method-webs is not implemented in this release; see docs/multi-method-hosting-spec.md §1")`), same for `webplus.rs`
  - Acceptance: enabling `--features method-webs` produces a clean compile error with the pointer message; defaults unchanged
  - Verify: `cargo build --workspace --features method-webs 2>&1 | grep -q "not implemented"`
  - Deps: T10
  - Estimate: 0.25 session

- [ ] **T32** CI matrix for feature combinations
  - Files: `.github/workflows/ci.yml` (or wherever CI is configured)
  - Acceptance:
    - Matrix entries: default features, `--no-default-features --features method-webvh`, `--no-default-features --features method-web`, `--features method-webs` (expected fail)
    - PR-level CI runs the matrix on every change touching `did-hosting-common/src/method/` or `did-hosting-*/src/`
  - Verify: dummy PR triggers matrix; output shows all four entries with expected pass/fail
  - Deps: T31
  - Estimate: 0.5 session

### Track: Domain-aware Trust Tasks (WS-8) — last in Phase III

- [ ] **T33** Register domain-management Trust Tasks
  - Files: `did-hosting-common/src/did_hosting_tasks.rs` (already has the URL consts from T7), `did-hosting-control/src/routes/domain.rs` (handlers wired through `TrustTaskRouter`)
  - Acceptance:
    - `domain/create/1.0`, `domain/update/1.0`, `domain/disable/1.0`, `domain/set_default/1.0`, `domain/purge/1.0` Trust Tasks wired and tested (admin only)
    - Each handler returns the updated `DomainEntry` (or empty body on disable/purge)
    - Admin auth assertion runs before any state change
  - Verify: `cargo test -p did-hosting-control domain_trust_tasks`
  - Deps: T15, T17, T30 (for purge)
  - Estimate: 1 session

- [ ] **T34** Optional `domain` + `method` params on DID-management Trust Tasks
  - Files: `did-hosting-control/src/routes/dids.rs` (extend request types — already done partially in T26), `did-hosting-control/src/did_ops.rs` (handler resolution rule per spec §3 ACL default)
  - Acceptance:
    - Resolution rule: explicit `domain` wins → caller ACL `AllowedWithDefault.default` → system default → 400 if caller is `Allowed([…])` with no default
    - Explicit `method` must match embedded identifier; mismatch → 400 with both values
    - Existing webvh integration tests pass with no `domain`/`method` fields set (backwards compat through resolution rule)
  - Verify: `cargo test --workspace dids_routes_method_domain` (covers all 4 resolution branches)
  - Deps: T20, T26
  - Estimate: 1 session

- [ ] **T35** Final integration test: domain-aware + method-aware end-to-end
  - Files: `did-hosting-server/tests/multi_method_multi_domain.rs` (new)
  - Acceptance:
    - Test creates two domains, one ACL Owner with `AllowedWithDefault([a,b], default=a)`, then in one session creates one did:webvh on domain-a and one did:web on domain-b, asserts isolated resolution
    - Same test asserts: a Plain `Allowed([a])` Owner cannot register on domain-b (403), and a missing-`domain` request without a default rejects (400)
  - Verify: `cargo test -p did-hosting-server multi_method_multi_domain`
  - Deps: T34, T25, T21
  - Estimate: 1 session

> **Checkpoint III (gate to Phase IV)**: Resolution-leakage test green. Method-mismatch test green. Two-server distributed assignment + failover green. Unassignment retain→purge→cancel lifecycle green. CI matrix green (incl. stub-fail). Every multi-domain Trust Task registered. **Stop. Review. Confirm dashboard data is sensible with two domains × two methods × two servers before opening UI work.**

---

## Phase IV — Surface (WS-10, WS-11, WS-7, WS-12)

### Track: UX (WS-10) — frontend lead

- [ ] **T36** Domains sidebar entry — list / create / disable / set-default (admin only)
  - Files: `did-hosting-ui/src/views/Domains.{ts,tsx,vue,svelte}` per actual UI framework, sidebar nav config
  - Acceptance: admin can list / create / disable / set-default via UI; non-admin sees no entry
  - Verify: manual checklist + Playwright/Cypress smoke if framework supports
  - Deps: T33 (backend endpoints)
  - Estimate: 1–2 sessions

- [ ] **T37** Domain selector on DID create + list views
  - Files: DID-create form component, DID-list component
  - Acceptance: pre-populated with caller's ACL default; dropdown filtered to ACL-allowed domains; hidden entirely when caller's scope is a single domain; per-call override on create
  - Verify: manual checklist
  - Deps: T34, T36
  - Estimate: 1 session

- [ ] **T38** Method selector on DID create flow + method badge on list / detail
  - Files: DID-create wizard component (with method-specific sub-forms), DID-list column, DID-detail header
  - Acceptance: method selector at top of create dialog; selecting webvh vs web changes the sub-form (webvh: SCID flow, web: upload did.json); badge with colour shown in list + detail
  - Verify: manual checklist
  - Deps: T36, T26
  - Estimate: 1–2 sessions

- [ ] **T39** Dashboard domain + method filters
  - Files: dashboard view, chart components
  - Acceptance: multi-select pill at top, default = All; charts split by domain when filter = All, focused when filtered; method axis same
  - Verify: manual checklist
  - Deps: T33
  - Estimate: 1 session

- [ ] **T40** Chrome domain switcher (GitHub-org style)
  - Files: sidebar/header chrome component
  - Acceptance: persistent in chrome; sets page-context domain across nav; hidden when single-domain; distinct from per-page dashboard filter
  - Verify: manual checklist + persistence-across-nav assertion
  - Deps: T36
  - Estimate: 1 session

- [ ] **T41** Per-(server, domain) "Purge now" + pending-purges view
  - Files: Domains → server detail view, confirmation modal (typed-confirmation: must type the domain name)
  - Acceptance: admin-only; behind typed-confirmation; pending purges shown with countdown
  - Verify: manual checklist
  - Deps: T30, T36
  - Estimate: 1 session

- [ ] **T42** Migration banner + ACL lockdown tool UI
  - Files: dashboard banner component, lockdown-tool dialog (calls a backend admin endpoint that bulk-converts `DomainScope::All` Owners to `AllowedWithDefault([default])`)
  - Acceptance: banner appears post-migration only when `All`-scoped Owners exist; dismissable; lockdown tool requires admin confirmation, shows preview of affected entries
  - Verify: manual checklist
  - Deps: T22, T36, plus a new backend admin endpoint (might warrant T42b)
  - Estimate: 1–2 sessions

- [ ] **T43** A11y pass on all new views
  - Files: all of T36–T42's components
  - Acceptance: keyboard-only navigable; screen-reader labels on switcher / selector / filter / dropdown; colour-contrast tested
  - Verify: manual a11y checklist + automated axe-core run if framework supports
  - Deps: T36–T42 all merged
  - Estimate: 1 session

### Track: Client crate (WS-11) — backend dev, parallel after Phase III

- [ ] **T44** New `did-hosting-client/` workspace member + Cargo.toml
  - Files: `did-hosting-client/Cargo.toml`, `did-hosting-client/src/lib.rs` (skeleton), update workspace `Cargo.toml`
  - Acceptance: builds clean; published name `did-hosting-client`; deps per `did-hosting-client-crate-spec.md` §3 (no `did-hosting-common` dep)
  - Verify: `cargo build -p did-hosting-client`
  - Deps: T1 (rename), T9 (parity harness so we know wire is stable)
  - Estimate: 0.5 session

- [ ] **T45** Port `auth/` (message construction + signing identity types) from VTI
  - Files: `did-hosting-client/src/auth/mod.rs`, `did-hosting-client/src/auth/message.rs`
  - Acceptance: `HostingSigningIdentity{,Owned}`, `build_authenticate_message`, `build_refresh_message` ported from `verifiable-trust-infrastructure/vta-service/src/webvh_auth.rs`; renamed `Vta` → `Hosting` prefix; golden JWS test passes
  - Verify: `cargo test -p did-hosting-client auth`
  - Deps: T44
  - Estimate: 1 session

- [ ] **T46** Port `transport.rs` + HTTPS enforcement
  - Files: `did-hosting-client/src/transport.rs`
  - Acceptance: `ServiceEntry` trait, `resolve_server_transport`, `enforce_transport_security`, `is_loopback_host` — exact behaviour from spec §5.4 source paths
  - Verify: `cargo test -p did-hosting-client transport`
  - Deps: T44
  - Estimate: 1 session

- [ ] **T47** `TokenData`, `HostingTokenStore`, `InMemoryTokenStore`, `ServerLocks`
  - Files: `did-hosting-client/src/token_store.rs`, `did-hosting-client/src/locks.rs`
  - Acceptance: `TokenData` is `ZeroizeOnDrop` + redacted `Debug` (test asserts neither token substring appears in debug output); `InMemoryTokenStore` over `DashMap`; `ServerLocks::for_server` returns `Arc<TokioMutex<()>>`
  - Verify: `cargo test -p did-hosting-client token_store && cargo test -p did-hosting-client locks`
  - Deps: T44
  - Estimate: 1 session

- [ ] **T48** `Client` impl with REST methods + `Trust-Task` header
  - Files: `did-hosting-client/src/client.rs`, `did-hosting-client/src/error.rs`
  - Acceptance: `Client::new` enforces HTTPS at construction; `challenge` / `authenticate` / `refresh` / `register_did_atomic` / `publish_did` / `delete_did` / `request_uri` / `check_path` / `get_did` implemented with `Trust-Task` header on every call; typed errors per spec §6.4
  - Verify: `cargo test -p did-hosting-client client_unit`
  - Deps: T45, T46, T47
  - Estimate: 2 sessions

- [ ] **T49** `ensure_token` decision ladder + `AuthedClient` wrapper
  - Files: `did-hosting-client/src/client.rs` (add `ensure_token`), `did-hosting-client/src/authed.rs` (new — `AuthedClient`)
  - Acceptance: decision ladder per spec §7 (fresh cache → refresh → reauth); per-server `ServerLocks` mutex around the entire RMW; `AuthedClient` wraps and exposes the same DID-ops minus the explicit token argument
  - Verify: `cargo test -p did-hosting-client ensure_token_ladder && cargo test -p did-hosting-client authed_client`
  - Deps: T48
  - Estimate: 1 session

- [ ] **T50** wiremock integration tests
  - Files: `did-hosting-client/tests/wiremock_integration.rs`
  - Acceptance: covers challenge/auth happy path, refresh happy path, 401-on-publish-triggers-reauth, 403 bubbles, network error, 5xx mapped, `domain` + `method` params forwarded; concurrency test asserts two parallel `ensure_token`s against same server-id serialise
  - Verify: `cargo test -p did-hosting-client --test wiremock_integration`
  - Deps: T49
  - Estimate: 1–2 sessions

- [ ] **T51** Cross-crate URL invariant test
  - Files: `did-hosting-common/tests/trust_task_url_consistency.rs`
  - Acceptance: every `TASK_*` const in `did-hosting-client::auth` and `did-hosting-client::client` matches the same-named const in `did-hosting-common/src/did_hosting_tasks.rs` byte-for-byte
  - Verify: `cargo test -p did-hosting-common trust_task_url_consistency`
  - Deps: T7 (daemon consts), T48 (client consts)
  - Estimate: 0.5 session

### Track: Composed migration finalisation (WS-7)

- [ ] **T52** Compose multi-domain migration first then multi-method
  - Files: `did-hosting-common/src/migrations/m02_assign_domain.rs` (new — multi-domain), order in registry ensures M02 runs before M01-rewrap
  - Acceptance:
    - M-02 assigns every existing DID a domain derived from the legacy `public_url`'s host
    - Re-ordering with M-01: M-02 must run **before** M-01 wraps to `DidRecord` (because the wrapper carries the `domain` field)
    - Migration emits dashboard banner mentioning `All`-scoped owner count
  - Verify: `cargo test -p did-hosting-server migration_compose` (fixture: v0.6.0-shape store → run all migrations → assert post-state)
  - Deps: T13, T18
  - Estimate: 1 session

- [ ] **T53** Migration replay test against three v0.6.0 backup fixtures
  - Files: `did-hosting-server/tests/migration_replay.rs` (new), fixtures committed under `did-hosting-server/tests/fixtures/v0.6.0/`
  - Acceptance:
    - Three fixtures: (a) empty store, (b) ~10 webvh DIDs, (c) mixed ACL entries with various owner counts
    - Migration replays cleanly on all three; idempotent on second run
    - Each post-migration store passes a smoke resolution + an admin list
  - Verify: `cargo test -p did-hosting-server migration_replay`
  - Deps: T52
  - Estimate: 1 session

- [ ] **T54** Backup/restore tooling for new shape
  - Files: `did-hosting-server/src/backup.rs:55–58` and surrounding restore code — extend dump format with `method` field; restore handles both legacy and new shapes
  - Acceptance: round-trip backup → restore → diff = empty for both legacy and new-shape stores
  - Verify: `cargo test -p did-hosting-server backup_restore_roundtrip`
  - Deps: T12
  - Estimate: 1 session

### Track: Registry submission (WS-12) — non-blocking, parallel

- [ ] **T55** PR to `dtgwg-trust-tasks-tf` registering URLs
  - Files: in the external repo `verifiable-trust-infrastructure/../dtgwg-trust-tasks-tf` (not in this repo)
  - Acceptance: every `https://trusttasks.org/did-hosting/...` and `https://trusttasks.org/webvh/...` URL we use is documented in the registry PR with params/result schemas
  - Verify: PR opened; link in our release notes
  - Deps: T7 (URL list stabilised)
  - Estimate: 1 session

### Release prep

- [ ] **T56** CHANGELOG + migration guide + rollback doc + release notes
  - Files: `CHANGELOG.md`, `docs/migrations/v0.6.0-to-v0.7.0.md` (new), `docs/rollback.md` (new)
  - Acceptance:
    - CHANGELOG entry covers: rename, multi-domain, multi-method, client crate, Trust-Tasks transport, env-var renames
    - Migration guide walks an operator through: backup → upgrade binary → run migration → verify → flip default domain if needed
    - Rollback doc covers: stop daemon → restore backup → downgrade binary → start daemon (and explicitly: forward-migrated stores cannot be downgraded — restore from backup is mandatory)
  - Verify: walk through the migration guide on a v0.6.0 fixture in a scratch dir, top to bottom, end with a working v0.7.0 daemon
  - Deps: T53, T54, all UX merged
  - Estimate: 1–2 sessions

> **Release gate (Checkpoint IV)**: Manual UX checklist green on Chrome + Safari. Client crate full test matrix green. Migration replay against three fixtures green. Pre-launch checklist run via the `agent-skills:ship` skill. Release notes / migration guide / rollback doc reviewed by ops + frontend leads. Tag the release.

---

## Quick summary

| Phase | Tasks | Critical-path estimate | Parallelisable |
|---|---|---|---|
| **Pre-flight** | P0 | 0.25 session | – |
| **I Foundation** | T1–T4 | 4 sessions | minimal (T1 atomic) |
| **II Substrate** | T5–T18 | 5 sessions (track 1) / 5 (track 2) / 5 (track 3) | 3 tracks ∥ |
| **III Composition** | T19–T35 | ~10 sessions | 2–3 tracks ∥ |
| **IV Surface** | T36–T56 | ~12 sessions | 3 tracks ∥ |
| **Total** | 56 tasks | ~31 sessions on critical path | typically 3 engineers |

**Tasks worth flagging early as the highest blast radius**: T1 (rename), T8 (dispatcher integration), T20 (safety check on create/publish), T26 (request body generalisation), T48 (client `Client` impl), T52 (composed migration).

**Tasks that can be picked up by a less-senior engineer**: T3 (keyspace registry), T4 (wizard helpers), T16 (`DomainScope` field on ACL), T31 (stub modules), T36–T42 (UX components — frontend dev).

---

## What's next

Approve this breakdown and the team picks up tasks in dependency order. P0 + T1–T4 are immediate first PRs. Workstream-track owners can begin parallel work after Checkpoint I clears.

If anything in this breakdown is wrong — wrong task split, wrong files, wrong sequence — say so before the team picks it up. Renaming a task in flight is fine; restructuring a phase is expensive.
