# Plan: did-hosting Rollout (Multi-Domain + Multi-Method + Rename + Client)

Specs:
- [`docs/multi-domain-spec.md`](../docs/multi-domain-spec.md)
- [`docs/multi-method-hosting-spec.md`](../docs/multi-method-hosting-spec.md)
- [`docs/did-hosting-client-crate-spec.md`](../docs/did-hosting-client-crate-spec.md)

Scope: One coordinated release that delivers all three specs as a single tagged version.

Branch base: `release/0.7.0` (or whichever release tag aligns with the multi-domain release; this plan assumes a fresh release cycle from current `main` at commit `5fdccf0`).

---

## Locked decisions (cross-spec consolidated)

Each row points back to the canonical spec section. The plan does **not** restate them in full.

- **Multi-domain**: see `multi-domain-spec.md` §3, §10 — domains are runtime-managed objects in a new `domains` keyspace, ACL gains `DomainScope`, control-plane drives server assignment, unassignment triggers retain → auto-purge after 2h (configurable) + admin "Purge now", `trusted_proxy_cidrs` for safe `Forwarded`/`X-Forwarded-Host`.
- **Multi-method**: see `multi-method-hosting-spec.md` §3 — `did-hosting-*` crate rename, `DidMethod` trait with compile-time feature flags (`method-webvh` + `method-web` default; `method-webs` + `method-webplus` stubs), unified `DidRecord` storage shape, per-method resolution endpoints, atomic single release with multi-domain.
- **Client crate**: see `did-hosting-client-crate-spec.md` §11 — sibling workspace member `did-hosting-client/` published as `did-hosting-client`, Trust-Tasks URLs only, `Client::with_default_domain` + optional per-call `domain` + optional per-call `method`, v0.1 admin-ops excluded.
- **Trust-Tasks transport**: `https://trusttasks.org/did-hosting/{path}/{maj}.{min}` for generic ops, `https://trusttasks.org/{method}/{path}/{maj}.{min}` for method-specific ops (witness, rollback). `affinidi/` segment dropped. Exact-match routing per VTI canonical impl.

---

## Code-shape facts verified during planning

Confirmed during the planning pass to prevent rework. Each citation is `file:line` against the current `main` (commit `5fdccf0`):

| Fact | Location | Why it matters |
|---|---|---|
| **No migration runner exists.** Workspace has no versioned-schema migrator; only DID-secrets import/export bundles. | grep across workspace returned nothing matching `migrations/` or `schema_version` patterns. | Two migrations (multi-domain `domains` tagging, multi-method `DidRecord` rewrap) need a runner from scratch. Lands as a foundation task. |
| **Keyspaces are opened ad-hoc**, not centrally registered. | `webvh-server/src/main.rs:644` (server's `dids` open), `webvh-daemon/src/main.rs:459–470` (daemon opens `dids`/`stats`/`timeseries`; others on-demand), `webvh-control/tests/change_owner_rest.rs:1–7` (tests open all). | No single registry. Each new keyspace (`domains`, `assignments`, `meta`, `pending_purges`) lands at multiple call sites. Foundation task adds a central registry so the spec's "all new keyspaces" lands once. |
| **DID resolution is at `GET /{*mnemonic}/did.jsonl`**, not `/log/{*mnemonic}`. Handler is a catch-all fallback. | `webvh-server/src/routes/did_public.rs:150–196` (`serve_public()`); webvh path matches `/{mnemonic}/did.jsonl` at line 154. | Both `multi-domain-spec.md` §5.1 and `did-hosting-client-crate-spec.md` §5.1 cite `/log/{*mnemonic}` — that's incorrect. Plan triggers a spec patch (see §4 below). |
| **`did:web` is partially implemented already.** Handler `serve_did_web()` exists; sibling fallback at `did_public.rs:182` strips `.json` and resolves. | `webvh-server/src/routes/did_public.rs:182`. | `multi-method-hosting-spec.md` §7.1 / Phase M2 said web resolution is **new**. Reality: we're hardening + formalising what's there, plus adding the storage/management surface around it. Reduces M2 scope. |
| **DIDComm dispatcher exists and is the seam for Trust-Tasks aliasing.** `dispatch_did_op()` matches on `msg.typ.as_str()` covering all `MSG_*` types. | `webvh-control/src/messaging.rs:245–450`. Shared by HTTP-signed transport via `webvh-control/src/routes/didcomm.rs:176–193`. | Confirms `multi-domain-spec.md` §6.1 Phase A wiring point. The Trust-Tasks alias layer plugs into this dispatcher with a one-line addition before the existing match. |
| **MSG_* constants enumerated.** Full list in one file. | `webvh-common/src/didcomm_types.rs:10–71` — 20+ const strings covering authenticate / refresh / DID lifecycle / witness / sync / server-register / stats / health. | Authoritative source for the Trust-Tasks alias mapping. Every `MSG_*` here needs a paired `TASK_*` URL. |
| **Setup wizards duplicate**, sharing only `prompt_secrets_backend()`. | Shared helper: `webvh-common/src/server/secret_store/wizard.rs:32–159`. Per-binary wizards: `webvh-server/src/setup.rs:39–95`, `webvh-control/src/setup.rs:*`, `webvh-daemon/src/setup.rs:*`, `webvh-witness/src/setup.rs:*` — each uses `dialoguer::{Confirm, Input, Select}` directly. | Adding the new prompts (domain seed, method enable, trusted-proxy-CIDR, bootstrap_domains) across four wizards = four-way duplication. Foundation task extracts more shared helpers before the multi-domain / multi-method prompts land. |
| **Owner / ACL check lives inside `did_ops`**, not at the route layer. | `webvh-control/src/did_ops.rs:78–99` — `get_authorized_record()` runs owner-or-admin assertion. | The domain safety check (`did.host` matches active assigned domain + caller ACL allows it) goes **inside** these functions, not in route handlers. Keeps the safety net consistent across REST + DIDComm. |
| **No runtime config reload.** Daemon handles `SIGINT`/`SIGTERM` only — no SIGHUP or file-watch. | `webvh-common/src/server/init.rs:94–116` (signal handler); `webvh-daemon/src/main.rs:718` (mount). | Multi-domain spec mandates runtime-managed domains. Per the spec they live in the `domains` keyspace, NOT in `config.toml`. So runtime mutability is via the storage API, which already supports live mutation. **No new reload mechanism needed.** Confirms spec §3 "Domain config model". |
| **Test harness pattern**: `make_state()` builds an in-process `AppState` with temp `fjall`, mount routes, `tower::ServiceExt::oneshot()` for requests. | `webvh-server/tests/smoke.rs:34–150` (server-side); `webvh-control/tests/change_owner_rest.rs` (control-side). | Reusable for all new multi-method / multi-domain / unassignment tests. No daemon-launcher needed. Plan budgets test work as "extend the harness" not "build new test infra". |

---

## Spec patches triggered by planning (must land in same release)

Two specs cite paths that don't match current code. These are routine corrections, not changes of intent. Patch in the same PR that lands the plan:

1. **`multi-domain-spec.md` §5.1, §6.3 + `did-hosting-client-crate-spec.md` §5.1**: `/log/{*mnemonic}` → `/{*mnemonic}/did.jsonl`. Add a note that webvh resolution is a catch-all fallback, not a prefix-mounted route.
2. **`multi-method-hosting-spec.md` §7.1, §9.3 (Phase M2)**: did:web resolution at `/{*path}/did.json` and `/.well-known/did.json` already exists at `webvh-server/src/routes/did_public.rs:182`. Phase M2 narrows from "implement" to "formalise + add storage/management surface".

I'll patch both before opening the first implementation PR, since they're contradicted by code and would mislead reviewers.

---

## Workstream decomposition

The work breaks into nine **workstreams**. Each is a logical unit roughly equivalent to a senior engineer's two-week chunk. Some are sequential, several run in parallel.

### WS-0: Foundation (PRE-WORK — must complete before anything else)

Mechanical + structural setup that every subsequent workstream relies on. Land first, in one tight focused branch.

- **WS-0.1** Repo rename: `affinidi-webvh-service` → `did-hosting-service`. Crate folders → `did-hosting-*`. Package names updated. `webvh-witness` / `webvh-watcher` keep their names. Env vars renamed (`WEBVH_*` → `DID_HOSTING_*`). CHANGELOG entry. Migration helper command stubbed.
- **WS-0.2** Migration-runner skeleton: tiny `did-hosting-common/src/migrations/` module with a `Migration` trait and an idempotent dispatcher that records applied versions in a `meta` keyspace. No actual migrations yet — just the runner.
- **WS-0.3** Centralised keyspace registry: `did-hosting-common/src/server/store/keyspaces.rs` enumerates every named keyspace (existing + new). Existing call sites refactored to use the registry constants.
- **WS-0.4** Shared wizard prompt helpers: extend `did-hosting-common/src/server/setup_prompts.rs` (new module, splitting off from the existing `secret_store/wizard.rs`) with `prompt_public_url`, `prompt_trusted_proxy_cidrs`, `prompt_bootstrap_domains`, `prompt_enabled_methods`. All four binary wizards refactor to call these.

### WS-1: Trust-Tasks transport (Phase A from multi-domain spec)

Land the Trust-Tasks primitive + dispatcher + alias layer. Zero observable behaviour change — every existing `MSG_*` call also accepts the new `TASK_*` URL. Reuse the VTI canonical impl (extract to `trust-tasks` crate or copy into `did-hosting-common`; decision in PR planning, leaning extract).

### WS-2: Method abstraction (Phase M1 from multi-method spec)

`DidMethod` trait + dispatcher + `methods/webvh.rs` impl wrapping existing webvh logic + `DidRecord` storage shape. Migration tags every existing DID record with `method = "webvh"`. Routes still hardcoded to webvh — no `did:web` yet.

### WS-3: Domain model (Phase B from multi-domain spec)

`domains`, `assignments`, `meta`, `pending_purges` keyspaces + `DomainEntry` + `DomainScope` on `AclEntry` (additive, backwards-compat default `All`) + `domain_normalize` + `well_known_enabled` toggle. No enforcement yet. `GET /api/domains` and `GET /api/me/domains` land. Domain seed via `config.toml`'s `bootstrap_domains` on first boot.

### WS-4: Enforcement layer

Domain detection (Forwarded/X-Forwarded-Host with `trusted_proxy_cidrs`) + safety check on create/publish + safety check on resolution (404 on host mismatch, 503 on disabled domain) + ACL default flip for **new** Owner entries. Composes WS-2 (method) and WS-3 (domain) — every operation now passes through `(method, domain)` validation.

### WS-5: did:web method (Phase M2 from multi-method spec)

Implement `methods/web.rs` — parser, validator, `apply_update` (replace), `__root` mnemonic for no-path did:web. **Formalise the existing `serve_did_web()`** handler (currently best-effort against the file store) by routing it through the `DidMethod` trait. Generalise request body fields (`did_log` → `did_data`). Compile-time feature flag wiring.

### WS-6: Distributed assignment + unassignment lifecycle (Phase D from multi-domain spec)

Server-register Trust Task carries capability declaration. Control plane responds with assignment. `domain/assign/1.0` + `domain/unassign/1.0` Trust Tasks. Background purge sweep (default 2h grace, configurable). Admin "Purge now" via Trust Task. Re-assign-within-grace cancels pending purge.

### WS-7: Backwards-compat migration (Phase E composed with M1's record-rewrap)

Composed migration: multi-domain first (assign every existing DID the legacy `public_url`-host as domain), then multi-method (rewrap as `DidRecord { method: "webvh", domain, path, data }`). Idempotent. Migration emits audit-log + dashboard banner.

### WS-8: Domain-aware Trust Tasks (Phase F from multi-domain spec)

`domain/list/1.0`, `domain/create/1.0`, `domain/update/1.0`, `domain/disable/1.0`, `domain/set_default/1.0`, `domain/purge/1.0`, `me/domains/1.0`. Add optional `domain` + optional `method` param to each DID-management Trust Task. Validation: explicit `method` must match embedded identifier; explicit `domain` must match `did.host`.

### WS-9: Stubs + CI matrix (Phase M4 from multi-method spec)

`methods/webs.rs` + `methods/webplus.rs` as compile-error stubs gated by their features. CI matrix in `.github/workflows/` covers: default features (webvh+web), webvh-only, web-only, and the expected failure mode for stubs.

### WS-10: UX (Phases G + M3 combined)

All UI work consolidated into one workstream to manage frontend complexity in one place:
- Top-level **Domains** sidebar item (admin only).
- **Domain selector** on DID create / list (auto = ACL default, ACL-filtered, hidden if scope = 1).
- **Method selector** on DID create flow.
- **Method badge / column** in DID list.
- **Dashboard domain filter** (multi-select, default = All) + **method filter**.
- **Chrome domain switcher** (GitHub-org style, hidden if single-domain).
- **Per-(server, domain) "Purge now"** button + pending-purge view.
- **Migration banner** post-upgrade for ACL lockdown tool.
- **A11y**: keyboard-nav + screen reader on all new views.

### WS-11: Client crate (`did-hosting-client/`)

Lands as a sibling workspace member. Ports from VTI's `feat/webvh-rest-auth-hardened` branch per `did-hosting-client-crate-spec.md` §5.4. Multi-method aware from day one (`method: Option<&str>` per call). Multi-domain aware from day one (`with_default_domain` + per-call). Cross-crate URL invariant test against `did_hosting_tasks.rs`.

### WS-12: Trust-Tasks registry submission (Phase H, parallel, non-blocking)

Submit a PR to `dtgwg-trust-tasks-tf` registering every `did-hosting/` and `webvh/` URL with params/result schemas. Doesn't block ship.

---

## Dependency graph

```
WS-0 (Foundation: rename, migration runner, keyspace registry, shared prompts)
  │
  ├──► WS-1 (Trust-Tasks transport — zero behaviour change)
  │       │
  │       ├──► WS-8 (domain-aware Trust Tasks)
  │       │       │
  │       └──► WS-11 (client crate — needs the wire surface)
  │
  ├──► WS-2 (Method abstraction + DidRecord wrapping migration)
  │       │
  │       ├──► WS-4 (enforcement — needs both method and domain)
  │       │       │
  │       │       └──► WS-8 (domain-aware Trust Tasks)
  │       │
  │       └──► WS-5 (did:web method — needs the trait)
  │               │
  │               └──► WS-8
  │
  ├──► WS-3 (Domain model — keyspaces + DomainScope, no enforcement yet)
  │       │
  │       ├──► WS-4 (enforcement)
  │       │
  │       └──► WS-6 (distributed assignment — needs domain model)
  │
  └──► WS-7 (composed migration — needs WS-2 and WS-3 storage shapes locked)
              │
              └──► (gates the release)

WS-9 (stubs + CI matrix) — parallel after WS-2; not on critical path.
WS-10 (UX) — starts when WS-3 + WS-5 land enough surface to wire to (~mid-rollout).
WS-12 (registry submission) — parallel after WS-1 publishes the URL list. Non-blocking.
```

Critical path (longest sequence to ship):
```
WS-0  →  WS-2  →  WS-3  →  WS-4  →  WS-8  →  WS-10  →  WS-7  →  release
```

---

## Phasing strategy

Three **planning phases** group the workstreams by when they need to land relative to each other. Each phase ends with a checkpoint.

### Planning Phase I — Foundation (must complete first)

- **WS-0** Rename + migration runner + keyspace registry + shared prompts.

**Checkpoint I**: `cargo build --workspace` succeeds under both old and new crate names from a clean checkout (the rename PR atomic). Existing tests pass. CHANGELOG entry merged. Migration-runner skeleton merged with a test that asserts the empty migration set runs cleanly on a fresh store.

### Planning Phase II — Substrate (parallel after Foundation)

Three workstreams can begin concurrently once foundation lands. They don't conflict at the file level.

- **WS-1** Trust-Tasks transport (depends on `trust-tasks` crate decision in WS-0 planning).
- **WS-2** Method abstraction.
- **WS-3** Domain model.

**Checkpoint II**: Trust-Tasks alias works for every operation (parity harness green). `DidMethod` trait + webvh impl is the only path code takes (no direct webvh hardcoding). Domain CRUD endpoints work; ACL `DomainScope` field deserialises safely on every legacy entry. All three workstreams' tests green. No enforcement of safety checks yet.

### Planning Phase III — Composition (sequential within phase)

These build on Phase II's substrate. Sequential because they touch overlapping code paths in `did_ops.rs` and `routes/dids.rs`.

- **WS-4** Enforcement layer (must precede the method-aware ops).
- **WS-5** did:web method (slots into the trait — now both methods exist).
- **WS-6** Distributed assignment + unassignment lifecycle.
- **WS-9** Stubs + CI matrix (parallel, off critical path).
- **WS-8** Domain-aware + method-aware Trust Tasks (final surface area).

**Checkpoint III**: Resolution-leakage test passes (cross-domain isolation). Method-mismatch test passes (`did.method` vs `method` field). Two-server distributed assignment integration test passes. CI matrix passes including stub failure modes. Every multi-domain Trust Task registered.

### Planning Phase IV — Surface (parallel after Phase III)

- **WS-10** UX.
- **WS-11** Client crate.
- **WS-7** Composed migration (timing here is deliberate: locks the on-disk shape after WS-2/WS-3 settled, before release).
- **WS-12** Registry submission (non-blocking).

**Checkpoint IV (Release Gate)**: Manual UI checklist green on dev browser (Chrome + Safari). Client crate's wiremock + concurrency tests green. Migration runs on a v0.6.0 backup-restored store and produces a valid post-rename, post-multi-domain, post-multi-method state. Release notes drafted. Migration guide published. Rollback path documented.

---

## Parallelism plan

How many engineers can be working concurrently?

- **Phase I**: 1 engineer (foundation is a tight, atomic merge).
- **Phase II**: 3 engineers — one per workstream (WS-1, WS-2, WS-3). Frontend dev not yet engaged.
- **Phase III**: 2–3 engineers — WS-4 → WS-5 → WS-8 is essentially sequential, but WS-6 (distributed assignment) and WS-9 (stubs + CI) run independently in parallel. Frontend dev can begin scaffolding WS-10 against mock data here.
- **Phase IV**: 3–4 engineers — UX, client crate, migration finalisation, registry PR all parallel.

Minimum viable team: 1 senior backend + 1 frontend. Faster with 2 backend + 1 frontend.

---

## Verification checkpoints

Each phase has a hard verification gate before the next phase opens. No checkpoint may be skipped.

| Gate | Tests that must pass | Manual signals |
|---|---|---|
| **I** end | `cargo build --workspace`, full existing test suite, migration-runner empty-set test. | One clean rename PR. CHANGELOG entry. Operator-facing rename migration helper compiles. |
| **II** end | Trust-Tasks parity harness (every operation succeeds with both `MSG_*` and `TASK_*`). `DidMethod` trait coverage ≥ 80%. ACL `DomainScope` deserialises every entry in a v0.6.0-backup fixture. | Trust-Tasks URL list ratified — same set on daemon and client crate (cross-crate test stub in place). |
| **III** end | Resolution leakage test (Host = b.example.com cannot resolve a:… DID). Method-mismatch test. Two-server distributed assignment + failover test. Unassignment-retain → grace-expired purge test. CI matrix (4 feature combos). | Release-candidate binary boots against migrated store and serves both webvh and web DIDs on multiple domains. |
| **IV** end (Release gate) | Manual UX checklist passes. Client crate full test matrix (wiremock + concurrency + cross-crate URL invariant). Migration replay test against three v0.6.0 backup fixtures. Pre-launch checklist via the `agent-skills:ship` skill. | Release notes + migration guide drafted. Rollback path documented and validated against a fixture (downgrade-then-upgrade round-trip). |

---

## Risks (consolidated, with mitigations)

| # | Risk | Source | Mitigation |
|---|---|---|---|
| R1 | **Atomic rename causes merge conflicts** on every in-flight branch. | WS-0 | Foundation PR lands first, gets called out internally a week in advance, and we explicitly pause other PR merges for the 24h around the rename. |
| R2 | **VTI `trust_task` extraction blocked** by VTI team's release cadence. | WS-1 | Copy-and-converge as fallback (option B in `multi-domain-spec.md` §4). Plan-time decision in WS-0 planning rather than mid-WS-1. |
| R3 | **Migration ordering bug** corrupts existing webvh data. | WS-7 | Migration is idempotent; pre-flight backup is mandatory; CI runs migration against three different fixture states; rollback path documented. |
| R4 | **Domain detection misconfig** in operator environments behind proxies. | WS-4 | Setup wizard probes "looks behind a proxy" and seeds CIDR; daemon emits a loud warn if all Host values look identical at startup (`multi-domain-spec.md` §11). |
| R5 | **`/{*path}/did.json` route shadows `/api/...`** if router merge order is wrong. | WS-5 | Codified order in `did-hosting-server/src/server.rs` with inline comment + explicit test asserting `/api/health` still resolves with both methods enabled. |
| R6 | **Cross-crate URL drift** between client and daemon. | WS-1, WS-11 | Cross-crate invariant test in `did-hosting-common/tests/` checks every `TASK_*` const matches daemon-side. |
| R7 | **Reference impl drift** while porting client. | WS-11 | Pin source commit in WS-11 PR description. Do the port in one focused session. Audit doc (`webvh-rest-auth-audit.md`) is the canonical statement of intent. |
| R8 | **Existing `did:web` handler at `did_public.rs:182`** already serves did:web in a best-effort form. Could conflict with the new trait-routed impl. | WS-5 | WS-5 starts with an explicit audit of the existing handler before any code change; either remove it (preferred) or wire it through the trait as a wrapper. |
| R9 | **Aggressive 2h purge default surprises ops** when re-assignment is delayed. | WS-6 | Default is configurable; admin UI surfaces "Pending purges" with countdown; loud audit log on every grace-expired purge. |
| R10 | **Phase III sequential chain blocks parallelism** if WS-4 enforcement work uncovers an edge case requiring spec change. | Phasing | WS-4 acceptance pre-defined with concrete test cases (resolution leakage, ACL mismatch). If a spec change is needed, escalate before sinking time into a workaround. |

---

## Suggested PR shape

Eleven PRs in a rough sequence. Each gated by the verification checkpoint above; no PR opens until its phase's checkpoint clears.

| # | PR | Phase | Notes |
|---|---|---|---|
| **PR 1** | WS-0.1 Repo rename (mechanical) | I | Atomic; pause other merges during review. |
| **PR 2** | WS-0.2 Migration runner skeleton | I | Idempotent dispatcher + meta-keyspace tracking. Empty migration set. |
| **PR 3** | WS-0.3 Keyspace registry + WS-0.4 shared prompts | I | Two small refactors landing together. |
| **PR 4** | WS-1 Trust-Tasks transport (alias layer) | II | Zero behaviour change. Largest single PR — needs deep review. |
| **PR 5** | WS-2 Method abstraction + `DidRecord` migration | II | Migration is the load-bearing part; backups before merge. |
| **PR 6** | WS-3 Domain model (keyspaces, ACL field, listing endpoints) | II | Additive; no enforcement. |
| **PR 7** | WS-4 Enforcement layer (safety checks) | III | Largest behavioural change. Resolution-leakage test mandatory. |
| **PR 8** | WS-5 did:web method | III | Audit existing handler first; landing PR removes/wraps it. |
| **PR 9** | WS-6 Distributed assignment + unassignment lifecycle | III | Two-server integration test; purge-sweep background task. |
| **PR 10** | WS-8 Domain-aware Trust Tasks + WS-9 stubs + CI matrix | III | Final wire surface. |
| **PR 11** | WS-10 UX | IV | Multiple commits; reviewed by frontend lead. May split further if needed. |
| **PR 12** | WS-11 Client crate | IV | Sibling workspace member. Cross-crate URL invariant test must be green. |
| **PR 13** | WS-7 Composed migration finalisation | IV | Replay-against-fixture test before merge. |
| **PR 14** | Release prep: CHANGELOG, migration guide, rollback doc | IV | Includes WS-12 registry PR link. Release-tag commit. |

Three PRs (Phase I) → three PRs (Phase II) → four PRs (Phase III) → four PRs (Phase IV) = 14 total. PR 7 and PR 11 are the biggest review surfaces.

---

## Out of scope (deferred to a future release)

These are explicitly **not** in this rollout. Spec authors should resist pulling them in.

- Wildcard / pattern-based domains (`*.tenant.example.com`). Multi-domain spec §1.
- `did:webs` and `did:webplus` implementation (only stubs + features land). Multi-method spec §1.
- Cross-method DID portability. Multi-method spec §2.
- Resolution gateway for *external* DIDs (we host what's registered here, not resolve arbitrary DIDs from elsewhere).
- Per-domain witness/watcher enforcement (schema only in this release).
- Per-method protocol gateway for witness, watcher, rollback on non-webvh methods.
- Admin operations in the v0.1 client crate (no `AdminClient` type).
- CLI binary for the client crate.
- Token-store backends beyond `InMemoryTokenStore`.
- Runtime DID method registry (compile-time only in this release).
- Pre-multi-domain daemon compatibility in the client crate (Trust-Tasks URLs only).

---

## What's next

Approve this plan and the next artifact is `tasks/did-hosting-rollout-todo.md` — the Phase 3 task breakdown. Each workstream above becomes 3–7 discrete tasks, each one-PR-sized, with files / acceptance / verify-command / dependencies / estimate. That artifact is what engineers actually pick up and execute against.

If anything in this plan is wrong — wrong workstream boundary, wrong phase, wrong parallelism assumption, missing risk — say so before I expand into tasks. Easier to redraw the dependency graph than to undo a bad task split.
