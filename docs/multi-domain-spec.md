# Spec: Multi-Domain Hosting

Status: Draft — awaiting review
Scope: All workspace crates (`did-hosting-common`, `did-hosting-server`, `did-hosting-control`, `did-hosting-daemon`, `did-hosting-ui`, plus the method-specific `webvh-witness` and `webvh-watcher`)
Author: glenn.gore@gmail.com
Bundled work: This release atomically delivers **multi-domain hosting** and the **Trust Tasks transport** (ToIP DTGWG canonical spec, per `https://trusttasks.org/`). The two ship as one tagged version. They are sequenced internally for development purposes (see §6) but tagged together.

## 1. Objective

Allow a single hosting deployment — daemon or distributed — to host DIDs (any enabled method, see `docs/multi-method-hosting-spec.md`) across **multiple operator-controlled domain names**, with first-class management, ACL-scoped visibility, and strict per-domain isolation at resolution time. Replace today's "one `public_url` per process" model with "many domains, all observable, individually governed."

In distributed mode, the control plane assigns domains to servers so an operator can shard a high-traffic domain onto dedicated hardware while colocating low-traffic tenants. In daemon mode the same data model applies, but every domain is served by the single binary all the time.

Bundled with this work, adopt the **Trust Tasks** specification (ToIP DTGWG, registry at `https://trusttasks.org/`) as the transport convention for webvh operations going forward. A Trust Task is a JSON-based, transport-agnostic specification with a stable URL identifier of the form `https://trusttasks.org/{org}/{path}/{maj}.{min}` — example: `https://trusttasks.org/did-hosting/did/request/1.0`. We use the Trust-Task URL **directly** as the wire identifier:

- **REST**: HTTP `Trust-Task:` header carries the URL. Routing is exact-match, byte-strict, per the VTI canonical implementation (`verifiable-trust-infrastructure/vti-common/src/trust_task/`).
- **DIDComm**: The Trust-Task URL **is** the DIDComm message `type`. No envelope-with-discriminator wrapper.

All new multi-domain capabilities are registered as Trust Tasks under `trusttasks.org/did-hosting/...`. The existing `v1.0` `MSG_*` constants under `affinidi.com/webvh/1.0/...` remain operational; each is reimplemented as a thin alias of the equivalent Trust-Task handler so v1.0 clients keep working. No message is removed in this release.

### Why

- **Multi-tenant hosting.** A single operator wants to host `did:webvh:…:tenant-a.example.com:…` and `…:tenant-b.example.com:…` from the same infrastructure without provisioning two stacks.
- **Domain failover and migration.** Operators need to migrate a brand from one hostname to another over time, run dual hostnames in parallel during cutover, and disable a hostname for offboarding without losing data.
- **Scaling and isolation.** A noisy tenant should be containable on its own server. A regulated tenant should be containable on dedicated hardware. Both are server-grouping problems the current model can't express.
- **Discovery.** Callers need to know which domains they're allowed to use before they make a request — today the answer is implicit in `public_url` and undiscoverable by clients.
- **Protocol evolution.** Adopting Trust Tasks aligns webvh with the ToIP DTGWG convention already in production for `openvtc` (VTI workspace). New features ship as registered Trust Tasks with their own versioned identifiers; we stop inventing per-product message URIs under `affinidi.com/`.

### Non-goals

- Cross-domain DID portability. `did:webvh` embeds the host; "move my DID to domain X" creates a new DID with a new SCID. This is a property of the method, not a missing feature.
- TLS termination by webvh. Operators continue to terminate TLS upstream (load balancer, ingress). webvh records the scheme (`http`/`https`) per domain for URL construction but does not bind TLS certificates.
- Removing or deprecating the `v1.0` `MSG_*` DIDComm protocol. v1.0 stays operational; each `MSG_*` is reimplemented as an alias for the equivalent Trust-Task handler.
- Wildcard / pattern-based domains (`*.tenant.example.com`). Deferred to a follow-on; literal hostnames (including path-prefix hostnames like `example.com/webvh-a`) are fully supported.
- Domain rename. Names are stable identifiers embedded in every `did:webvh` under them; rename is permanently disallowed.
- Per-domain witness/watcher **enforcement**. Schema fields land in this release for forward compatibility; actual per-domain federation enforcement is deferred.

## 2. Success criteria

1. **Multiple domains on one daemon.** A fresh `did-hosting-daemon` configured with `domain-a.example.com` (default) and `domain-b.example.com` can provision a DID under each, and each DID resolves successfully on its own hostname (`GET /` with that `Host` header) and **fails with 404** on the other hostname.
2. **Distributed assignment.** In a control plane + two servers setup, the operator can assign `domain-a` to server-1 only and `domain-b` to both servers. Provisioning routed through the control plane lands on a correctly eligible server; resolution via DNS reaches the correct server.
3. **Cold-start resilience.** A server restarted while the control plane is unreachable serves all DIDs in its persisted-cache domain set without degradation. Domain assignments only update once the control plane reconnects.
4. **ACL scoping.** An `Owner` ACL entry with `domains: Allowed([\"a\"])` can list/create DIDs only under domain `a`. Attempts to operate under domain `b` are rejected with `403`. `Admin` entries are implicitly scoped to `All`.
5. **Backwards compat.** A pre-upgrade deployment with `public_url = https://old.example.com` and 100 existing DIDs upgrades cleanly: a one-shot migration tags every existing DID with `domain = "old.example.com"`, that domain is registered as the default, and every pre-existing REST + DIDComm call continues to succeed without modification.
6. **Trust Tasks as the transport.** Every hosting operation has a registered Trust-Task URL under `trusttasks.org/did-hosting/{path}/{maj}.{min}` (method-agnostic) or `trusttasks.org/{method}/{path}/{maj}.{min}` (method-specific). The URL appears in the `Trust-Task:` HTTP header on REST calls and as the DIDComm message `type` on DIDComm calls. Routing is exact-match per the VTI canonical implementation; no version-family heuristics. Existing `v1.0` `MSG_*` handlers are reimplemented as aliases of the same Trust-Task handlers; integration tests cover both call-styles producing identical observable state.
7. **Domain discovery.**
   - `GET /api/domains` (Admin) with `Trust-Task: https://trusttasks.org/did-hosting/domain/list/1.0` lists all configured domains with full metadata.
   - `GET /api/me/domains` (any authed caller) with `Trust-Task: https://trusttasks.org/did-hosting/me/domains/1.0` lists domains visible/allowed to caller per ACL.
   - DIDComm equivalents use the same URLs as the message `type`.
   - Opt-in `/.well-known/did-hosting-domain.json` per-domain endpoint (off by default per-domain) surfaces public branding metadata when enabled.
8. **Safety check.** A provisioning request whose embedded `did:webvh:…:host:…` host is **not** an active domain on the receiving server — or **not** allowed by the caller's ACL — is rejected at the create endpoint, before any storage write. A resolution request where `did.host != request.host` returns 404 with a structured reason. A resolution against a *disabled* domain returns 503 with a structured maintenance-status JSON body.
9. **Reverse-proxy-safe host detection.** With `server.trusted_proxy_cidrs = ["10.0.0.0/8"]` configured, the server honours `Forwarded`/`X-Forwarded-Host` only from upstreams in that range and uses `Host` otherwise. An integration test asserts that a request from an untrusted CIDR with a spoofed `X-Forwarded-Host` does **not** cause the response to leak DIDs from another domain.
10. **UX in this release.** Control + daemon UIs gain:
    - Top-level sidebar **Domains** entry: list / create / disable / set-default.
    - Domain selector on DID create / list views, **auto-populated with the caller's ACL default** and filtered by ACL scope.
    - Dashboard gains a **domain filter** (multi-select, default = All) that splits aggregate charts by domain or focuses on the selection.
    - GitHub-org-style **domain switcher** in the global chrome (sidebar/header); persists across pages in session; hidden when caller has access to a single domain.
    - For Admin: a per-server **"Purge now"** button on unassigned domains (default purge-after = 2h, configurable in settings).
11. **Unassignment lifecycle.** When the control plane unassigns a domain from a server, the server stops serving that domain but **retains** its data. After a configurable grace period (default 2h, `server.unassigned_purge_grace = "2h"`), a background sweep purges it. Admin UI exposes an immediate "Purge now" action per (server, domain) pair, audited.

## 3. Design decisions (resolved)

| Question | Decision |
|---|---|
| Domain definition | The host portion of `did:webvh:{scid}:{host}:{path}` — hostname, optionally `host:port` for non-default ports, optionally a path-prefix segment. **Path-prefix domains** (`example.com/webvh-a`, `example.com/webvh-b`) are **fully supported at all layers** in this release — storage, API, CLI, UI. |
| Domain name normalization | Force lowercase + IDNA-normalize on input (REST + DIDComm + CLI + UI). Reject non-normalized input with a 400 explaining the canonical form. `Example.com` is stored as `example.com`. Per DNS and the `did:webvh` spec, hostnames are case-insensitive. |
| Domain rename | **Permanently disallowed.** Names are stable identifiers embedded in every `did:webvh` under them. Admin UI offers add-new + offboard-old as the migration path. |
| Storage | New `domains` keyspace (`{name → DomainEntry}`). DIDs and stats partitioned by domain via composite keys: `did:{domain}:{slug}`, `stats:{domain}:{counter}`. Migration path covered in §6. |
| Domain config model | Runtime-managed via REST + UI + DIDComm Trust Tasks. `config.toml` may seed the **initial** default domain and `bootstrap_domains` list on first boot only; on subsequent boots config is ignored if the `domains` keyspace is populated. |
| Default domain | Exactly one default at any time. Stored as `meta:default_domain` (single-key value). **Default must point to an active domain** — setting default to a disabled domain is rejected with 400. Admin can re-point; existing DIDs are **not** re-homed. |
| ACL domain scope | New field on `AclEntry`: `domains: DomainScope`, where `DomainScope ::= All \| Allowed(Vec<String>) \| AllowedWithDefault { allowed: Vec<String>, default: String }`. Admin implicit `All`. Service implicit `All`. New Owner default: `AllowedWithDefault { allowed: [system_default], default: system_default }`. |
| Server-domain assignment | **Control-plane-driven push.** Control plane is authoritative on assignment; servers act on what they're told. Each server persists its current set in a local `assignments` keyspace and serves from that on cold start before the control plane is reachable. |
| Cold-start bootstrap | Three-tier fallback when `assignments` keyspace is empty: (1) `bootstrap_domains` from `config.toml`, (2) legacy single `public_url` value (seamless upgrade), (3) empty — server boots but registers no DIDs until control plane reconnects. Resolution path serves whatever is in `assignments` regardless. Loud `warn!` log when falling through to tier 2 or 3. |
| Daemon mode | Always serves every domain in the `domains` keyspace. The `assignments` keyspace exists in daemon mode for code-path symmetry but is treated as "always = all". |
| Default-domain selection on provisioning with no `domain` field | Caller's ACL `default` (per `AllowedWithDefault`). Falls back to system default if the ACL entry is plain `Allowed`. **Reject with 400** if the caller is `Allowed([…])` with no default and the request omits `domain`. Error body names the allowed domains. |
| Trust Tasks transport | Per `https://trusttasks.org/` and `verifiable-trust-infrastructure/vti-common/src/trust_task/`. URL shape `https://trusttasks.org/{org}/{path}/{maj}.{min}`. Versioning is `{maj}.{min}` only — no patch component (per canonical spec). Each operation is its own registered Trust Task with its own URL. The URL is treated as opaque — used as the `Trust-Task:` HTTP header on REST and as the DIDComm message `type` on DIDComm. Routing is exact-match, byte-strict — `1.0` and `1.1` are completely separate identifiers. Health endpoint is the only Trust-Task-exempt route, per VTI spec §16.2. |
| Trust-Task namespace | Method-agnostic ops registered under `https://trusttasks.org/did-hosting/...`; method-specific ops under `https://trusttasks.org/{method}/...` (see `docs/multi-method-hosting-spec.md`). Registration on the public registry is a separate ToIP task-force PR run in parallel — does not block code shipping under the chosen URLs. |
| v1.0 `MSG_*` constants | Kept as-is. Each is paired with a Trust-Task URL of the same operation; the DIDComm dispatcher accepts either `type` value for the same handler. Integration tests assert both styles produce identical observable state. No `MSG_*` is removed in this release. |
| Domain field on Trust Task params | Optional, additive on existing operations (e.g. `did/request/1.0` gains an optional `domain`). New operations are domain-aware from the start. When `domain` is absent, the resolution rule above applies. |
| Safety check on resolution | If `Host`-derived domain does not match the `did.host` embedded in the requested DID's identifier, return 404 (not 403 — avoids confirming the DID exists elsewhere). Structured log at warn level. Disabled domains return 503 with JSON `{ status: "disabled", message?, eta? }`. |
| Reverse proxy trust | New config `server.trusted_proxy_cidrs: Vec<String>` (default `[]`). Inside this set, honour `Forwarded` (RFC 7239) `host=` first, then `X-Forwarded-Host` (first value), else `Host`. Outside the set, always `Host`. `x-forwarded-host` parsing must take the **first** value, not last (last is closest to the server and attacker-controllable). |
| Per-domain metadata | `DomainEntry { name, label, scheme, status, created_at, default_domain: bool, branding: DomainBranding, witnesses: Option<Vec<String>>, watchers: Option<Vec<String>>, quota: Option<DomainQuota>, well_known_enabled: bool }`. `branding`, `witnesses`, `watchers`, `quota` are optional overrides; fall back to global config when unset. `well_known_enabled` toggles the per-domain `/.well-known/did-hosting-domain.json` endpoint (default **off**). |
| Per-domain witness/watcher | Schema lands now (`witnesses`/`watchers` fields on `DomainEntry`). **Enforcement deferred**: in this release witness/watcher daemons treat the per-domain lists as advisory; global config remains authoritative. Future release flips enforcement. |
| Per-domain stats | Counter keys include the domain. Existing per-DID counters unaffected. Dashboard gains a domain filter (multi-select, default = All). |
| Audit log | Every domain mgmt action (`domain.create`, `domain.disable`, `domain.set_default`, `domain.purge`, etc.) recorded. Every DID action carries `domain` in its audit record. |
| Cross-domain DIDComm | A single authenticated session can target any domain the ACL allows; each message names its target domain in params. No session-scoped domain binding. |
| Unassignment lifecycle | Server stops serving the unassigned domain immediately but **retains** the data. Background sweep purges after `server.unassigned_purge_grace` (default `"2h"`, configurable). Admin UI exposes "Purge now" per (server, domain), audited; emits `domain.purge` audit event with `reason: "admin-immediate"` or `reason: "grace-expired"`. |
| DID portability | Not supported. Spec documents this explicitly; admin tooling rejects attempts to "move" a DID across domains. |
| Local IP / `localhost` domains | Permitted in dev. Soft warning at boot. Hard reject only if `features.production = true` **and** the domain resolves to a private/loopback range. |

## 4. Tech stack

- Rust 2024, rust-version 1.94
- Existing crates: `did-hosting-common`, all webvh-* crates, `axum 0.8`, `affinidi-tdk`, `fjall`/`firestore`/`dynamodb`/`redis` (existing store backends), `tracing`
- New dependency: `ipnetwork` for CIDR matching (`trusted_proxy_cidrs`). Single dependency, no transitive bloat.
- **Reuse from VTI workspace**: the canonical Trust-Task primitive (`TrustTask` newtype + `TrustTaskRouter` builder + `Trust-Task` header extractor) already exists at `verifiable-trust-infrastructure/vti-common/src/trust_task/`. We either (a) extract it to a small published crate (`trust-tasks` or `trust-tasks`) consumed by both VTI and webvh, or (b) copy the small module into `did-hosting-common` and keep parity by hand. Decision deferred to Phase A planning — leaning (a) to avoid two-source-of-truth.
- No new database backends.

## 5. Project structure (files touched)

```
trust-tasks/         → NEW workspace member (option A) OR copied into did-hosting-common (option B).
  src/
    mod.rs                    → TrustTask newtype, HEADER_NAME = "Trust-Task", validation
    router.rs                 → TrustTaskRouter (Axum builder); route_with_task + route_exempt
    extractor.rs              → Trust-Task header extractor; TrustTaskHeader, validate_header
    didcomm.rs                → NEW (not in VTI today): map DIDComm `type` → TrustTask, dispatch helper
  → Identical surface to verifiable-trust-infrastructure/vti-common/src/trust_task/ plus DIDComm dispatch.

did-hosting-common/src/
  did_hosting_tasks.rs               → NEW. const TASK_DID_REQUEST_1_0 = TrustTask::from_static(
                                 "https://trusttasks.org/did-hosting/did/request/1.0") …
                                 One const per registered task. Single source of truth.
  v1_aliases.rs                → NEW. const-table mapping `MSG_*` strings ↔ Trust-Task URLs.
                                 Dispatcher accepts either as DIDComm `type`.
  tasks/                       → NEW. Per-task handler modules.
    did/{request,publish,confirm,list,delete,change_owner,witness,info,resolve}.rs
    domain/{list,create,update,disable,set_default,purge}.rs
    me/domains.rs
    server/{register,health_ping,stats_sync}.rs
  server/
    acl.rs                     → DomainScope enum on AclEntry (additive, backwards-compat deserialization)
    domain.rs                  → NEW. DomainEntry, CRUD, ACL-scoped listing, default-domain tracking
    domain_normalize.rs        → NEW. lowercase + IDNA + path-prefix parse/validate
    domain_detection.rs        → NEW. Host extractor + Forwarded/X-Forwarded-Host with trusted CIDRs
    assignments.rs             → NEW. Persistent local cache of "domains this server serves"
                                 + grace-period purge background task
    store/mod.rs               → register new keyspaces: `domains`, `assignments`, `meta`,
                                 `pending_purges` (key: {server,domain,scheduled_at})
    config.rs                  → trusted_proxy_cidrs, bootstrap_domains, unassigned_purge_grace
  did/encode.rs                → split/validate did:webvh host segment (host + optional path-prefix)
  didcomm_types.rs             → unchanged constants; new code prefers TASK_* from did_hosting_tasks.rs

did-hosting-server/src/
  config.rs                    → trusted_proxy_cidrs, bootstrap_domains, unassigned_purge_grace
  setup.rs                     → wizard collects initial default domain + optional extra bootstrap_domains
  did_ops.rs                   → all create/publish paths take a Domain argument; safety check before write
  routes/
    config.rs                  → expose served domains in /api/config
    resolve.rs                 → Host-extractor; reject if did.host != request.host; 503 on disabled
    acl.rs                     → CreateAclRequest/UpdateAclRequest carry DomainScope (optional, defaults preserved)
    domain.rs                  → NEW. /api/domains (admin) + /api/me/domains (any auth) — both via TrustTaskRouter
  server.rs                    → Host-extractor middleware; pass Domain through request extensions;
                                 main router becomes TrustTaskRouter::new()…into_router()
  registry/handshake.rs        → server-register Trust Task includes capabilities; assignment response
  task_dispatch.rs             → NEW. Inbound DIDComm handler: look up handler by Trust-Task URL or v1 alias

did-hosting-control/src/
  config.rs                    → registry stores per-server served_domains
  routes/
    domains.rs                 → NEW. Admin endpoints for managing domains (Trust-Task wired)
    server_assignments.rs      → NEW. Push assignments to registered servers
  registry/                    → domain-aware sticky selection + failover; tracks per-server purge state
  task_dispatch.rs             → NEW. Mirrors server's; control plane is authoritative for domain CRUD

did-hosting-daemon/src/
  main.rs                      → run_daemon mirrors all of the above; assignments treated as "all";
                                 unassignment cannot happen in daemon mode (no remote control plane);
                                 the purge sweep still runs (no-op when assignments = all)
  setup.rs                     → wizard prompts for default domain; offer to add additional domains

webvh-witness/src/             → per-domain witness fields materialized per request (advisory only — see §3)
webvh-watcher/src/             → per-domain watcher fields materialized (advisory only)

did-hosting-ui/                      → IN-SCOPE for this release:
                                 - Top-level Domains view (list / create / disable / set-default)
                                 - Domain selector on DID create/list (auto = ACL default, filtered by ACL)
                                 - Dashboard domain filter (multi-select, default = All)
                                 - Chrome domain switcher (GitHub-org style; hidden when scope = 1)
                                 - Per-(server, domain) "Purge now" button on the Domains → Server detail view

migrations/                    → NEW. One-shot upgrade migration (§6.5)

docs/
  multi-domain-spec.md         → this doc
  trust-tasks-registry.md      → NEW. Catalogue of every webvh-registered Trust-Task URL with params/result schemas
```

## 6. Implementation phases

The work ships as **one tagged release**. Phases below are a development sequence for internal review, branch organisation, and CI gating; they are **not** independently releasable to users.

### 6.1 Phase A — Trust Tasks transport (foundation, no-op behavior)

Reuse the VTI `TrustTask` newtype, `TrustTaskRouter`, and `Trust-Task` header extractor. Decision: either extract VTI's `vti-common/src/trust_task/` into a shared crate (`trust-tasks`) or copy it into `did-hosting-common`. Add the missing DIDComm dispatch helper (VTI is REST-only today). Register every existing operation under `trusttasks.org/did-hosting/{path}/1.0`. Reimplement every `MSG_*` handler as an alias that resolves the same Trust-Task handler. Zero observable behavior change.

Acceptance:
- All existing DIDComm and REST integration tests pass unmodified.
- A new test asserts that for every operation, a request sent with the new Trust-Task URL (DIDComm `type` or REST header) produces byte-equivalent output to the same request sent with the legacy `MSG_*` / route.
- The Trust-Tasks registry document (`docs/trust-tasks-registry.md`) lists every webvh-registered URL with params/result schemas.

### 6.2 Phase B — Domain model + storage + ACL field (no enforcement yet)

Introduce the `domains`, `assignments`, `meta`, `pending_purges` keyspaces, the `DomainEntry` type with all fields (including `well_known_enabled`), the `DomainScope` enum on `AclEntry` (deserializing missing-field as `All` for backwards compat), and the domain name normalizer (lowercase + IDNA). Path-prefix domain parsing lands here.

Acceptance:
- New keyspaces created on first boot post-upgrade; idempotent on rerun.
- All ACL entries deserialize without error and continue to grant access to all DIDs (since `DomainScope` defaults to `All` when absent).
- Normalizer rejects `Example.com` with a clear error pointing to `example.com`.
- Path-prefix parsing round-trips `example.com/webvh-a` correctly.

### 6.3 Phase C — Domain detection + safety check (enforcement)

Add the `Forwarded`/`X-Forwarded-Host`/`Host` extractor with `trusted_proxy_cidrs`. Enforce create/publish safety check (`did.host` must equal an active assigned domain **and** be in caller ACL). Enforce resolution check (`Host` must equal `did.host`). Disabled-domain resolution returns 503 with structured JSON. Flip ACL `DomainScope` default for **new** Owner entries to `AllowedWithDefault { allowed: [default], default }`.

Acceptance:
- Resolution leakage test passes (request on `b.example.com` cannot resolve a `…:a.example.com:…` DID).
- Spoofed `X-Forwarded-Host` from untrusted CIDR has no effect.
- Existing Owner ACL entries (carrying `All`) continue to grant unrestricted access — no surprises for upgraded deployments.
- Disabled-domain resolution returns 503 with maintenance-status JSON.

### 6.4 Phase D — Distributed assignment + unassignment lifecycle

Extend the server-register Trust Task to include a server's capability declaration. Control plane responds with the server's domain assignment (set of domain names). Add `domain/assign/1.0` / `domain/unassign/1.0` Trust Tasks for runtime updates. Persist assignments locally. Domain-aware sticky selection on the control-plane outbound routing path. Background sweep purges unassigned domains after grace period (default 2h); admin "Purge now" Trust Task wired.

Acceptance:
- Two-server integration test: assign `domain-a` to server-1, `domain-b` to server-2, provisioning via control plane lands on the correct server.
- Server-restart-while-control-plane-down test: server serves from persisted assignments without degradation.
- Unassign + wait > grace = data is purged; `domain.purge` audit event fired with `reason: "grace-expired"`.
- Unassign + admin "Purge now" = data is purged immediately; audit event with `reason: "admin-immediate"`.
- Re-assign within grace = data is preserved; pending purge cancelled, audited.

### 6.5 Phase E — Backwards-compat migration

One-shot migration runs on first boot at the new version when the `domains` keyspace is empty and the `dids` keyspace is non-empty:
1. Register `<host(public_url)>` as the sole, default `DomainEntry`.
2. Rewrite every DID's storage key to the new `did:{domain}:{slug}` shape.
3. Leave existing `AclEntry`s with `DomainScope::All` implicit (deserialization default).
4. Audit-log the migration with counts.

Migration is idempotent (second run is a no-op). Backup-then-migrate flow in `did-hosting-server/src/backup.rs` updated to dump the new shape and to restore-into-current-version cleanly. Migration emits a one-line dashboard banner listing affected ACL entry count and a link to the "lockdown" admin tool that converts `All` → `AllowedWithDefault([default])` in bulk with confirmation.

### 6.6 Phase F — Domain-aware Trust Tasks

Register the domain-aware Trust Tasks: `domain/list/1.0`, `domain/create/1.0`, `domain/update/1.0`, `domain/disable/1.0`, `domain/set_default/1.0`, `domain/purge/1.0`, `domain/assign/1.0`, `domain/unassign/1.0`, `me/domains/1.0`. Add an optional `domain` param to each DID-management Trust Task (`did/request/1.0`, `did/publish/1.0`, etc.) — additive only, no `min` bump because the Trust-Tasks spec considers added optional fields backwards-compatible; new tasks that require domain (e.g. `domain/list/1.0`) are version `1.0` as first registrations. Resolve domain via ACL default when absent per §3.

Acceptance:
- DIDComm + REST integration tests exercise both legacy `MSG_*` and new Trust-Task URLs for every operation; both produce identical observable state.
- A client with `Allowed(["a","b"])` ACL can create one DID per domain in a single authenticated session by varying `domain` on each request.
- A client with `Allowed(["a","b"])` ACL and no `default` who omits `domain` gets a 400 with the allowed-list in the error body.

### 6.7 Phase G — UX

Land in the same release tag as phases A–F. Built incrementally as each backend phase stabilises so UI work doesn't pile up at the end.

- **Domains view** as a top-level sidebar item: list, create, disable/enable, set default, edit metadata, view per-(server, domain) assignment state. Admin-only.
- **Domain selector** on DID create and DID list pages: auto-populated with caller's ACL default, filtered to ACL-allowed domains, hidden entirely when caller has access to exactly one domain.
- **Dashboard domain filter**: multi-select pill at the top of the dashboard, default = All; charts split by domain when filter = All, focused when filtered.
- **Chrome domain switcher**: persistent in sidebar/header, GitHub-org-style. Sets the page-context domain across navigation. Hidden when caller scope = single domain. Distinct from the dashboard filter (the switcher sets default context; the dashboard filter overrides locally).
- **Per-(server, domain) Purge now**: button on the Domains → Server detail view, admin-only, behind a typed-confirmation modal (operator must type the domain name).
- **Migration banner**: shown post-upgrade on the dashboard until dismissed, naming the count of `DomainScope::All` ACL entries and linking to the lockdown tool.

Acceptance:
- Manual checklist run in dev browser (Chrome + Safari) for every flow above.
- Per the project CLAUDE.md, daemon UI mirrors control UI; no parity drift between standalone and daemon modes.
- A11y: keyboard-navigable, screen-reader labels on switcher / selector / filter.

### 6.8 Phase H — Trust-Tasks registry registration (parallel, non-blocking)

Submit a PR to `dtgwg-trust-tasks-tf` registering every `did-hosting/...` URL with its params/result schema. Does not block the webvh release: we ship under the chosen URLs and registry-side registration follows.

Acceptance:
- PR opened against the registry repo.
- Registry maintainers' feedback is incorporated; URLs stay stable through review (we own the `did-hosting/` path subtree).

## 7. Code style

Existing repo conventions — example of a Trust-Task-bound webvh operation (illustrative, not literal):

```rust
// did-hosting-common/src/did_hosting_tasks.rs
use affinidi_trust_tasks::TrustTask;
use std::sync::LazyLock;

pub static TASK_DID_REQUEST_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/did/request/1.0")
        .expect("static literal")
});

pub static TASK_DOMAIN_LIST_1_0: LazyLock<TrustTask> = LazyLock::new(|| {
    TrustTask::new("https://trusttasks.org/did-hosting/domain/list/1.0")
        .expect("static literal")
});
// … one const per registered task. Grep `TASK_` for the full set.
```

```rust
// did-hosting-common/src/tasks/did/request.rs
use serde::{Deserialize, Serialize};
use super::super::{TaskCtx, TaskErr};

#[derive(Debug, Deserialize)]
pub struct Params {
    pub did: String,
    #[serde(default)]
    pub domain: Option<String>,
    pub did_document: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct Output {
    pub did: String,
    pub domain: String,
}

pub async fn handle(ctx: &TaskCtx, params: Params) -> Result<Output, TaskErr> {
    let domain = ctx.resolve_domain(params.domain.as_deref()).await?;
    ctx.check_did_host_matches(&params.did, &domain)?;
    ctx.acl_assert_domain_allowed(&domain)?;
    ctx.dids.request(&params.did, &params.did_document, &domain).await?;
    Ok(Output { did: params.did, domain: domain.name })
}
```

```rust
// did-hosting-server/src/routes/did.rs — REST wiring
use affinidi_trust_tasks::TrustTaskRouter;
use crate::did_hosting_tasks::TASK_DID_REQUEST_1_0;

let router = TrustTaskRouter::new()
    .route_with_task("/api/did", post(did_request_handler), TASK_DID_REQUEST_1_0.clone())
    .route_with_task("/api/domains", get(domain_list_handler), TASK_DOMAIN_LIST_1_0.clone())
    .route_exempt("/health", get(health))
    .into_router();
```

```rust
// did-hosting-server/src/task_dispatch.rs — DIDComm wiring
async fn dispatch(msg_type: &str, body: Value, ctx: &TaskCtx) -> Result<Value, TaskErr> {
    // Accept either the canonical Trust-Task URL or the legacy MSG_* alias.
    let canonical = v1_aliases::canonicalize(msg_type)?;
    match canonical.as_str() {
        url if url == TASK_DID_REQUEST_1_0.as_str() =>
            json_wrap(tasks::did::request::handle(ctx, serde_json::from_value(body)?).await),
        url if url == TASK_DOMAIN_LIST_1_0.as_str() =>
            json_wrap(tasks::domain::list::handle(ctx, serde_json::from_value(body)?).await),
        // … exact-match table; no prefix / version-family logic.
        other => Err(TaskErr::TrustTaskMismatch(other.to_string())),
    }
}
```

Style notes:
- **One Trust Task = one URL = one handler function.** No version-family routing. New `min` version of a task = new URL = new const = new handler (which may call into the old one if behavior is unchanged for shared paths).
- **Trust-Task URLs are static `LazyLock<TrustTask>` consts** in `did_hosting_tasks.rs`. One file lists every URL the workspace knows about — grep `TASK_` to enumerate the surface.
- **Params/Output types live with the handler**, not in a shared types crate tier.
- `TaskCtx` carries auth, store handles, and the resolved caller ACL. It exposes the small set of cross-cutting helpers (`resolve_domain`, `acl_assert_domain_allowed`, `check_did_host_matches`, …) so handlers don't reimplement them.
- **v1 alias table is a single small const map** in `v1_aliases.rs`; the dispatcher canonicalises before lookup. No alias chains, no dynamic registration.
- Errors map to `TaskErr` variants that the dispatcher translates to HTTP response codes (REST) or DIDComm problem-report messages.

## 8. Testing strategy

- **Unit:** Each Trust-Task handler has table-driven tests in its own module (`#[cfg(test)] mod tests`). `DomainScope` parsing/serialization round-trip tested across all enum variants. `domain_detection.rs` has table tests covering Host/Forwarded/X-Forwarded-Host across trusted-CIDR yes/no. `domain_normalize.rs` covers uppercase, IDN (`xn--`), trailing dot, path-prefix.
- **Integration:** Existing `did-hosting-server/tests/smoke.rs` extended with multi-domain coverage: two domains, ACL-scoped owner, resolve-leakage assertion, default-fallback assertion. New `did-hosting-daemon/tests/multi_domain.rs` and `did-hosting-control/tests/server_assignment.rs`. New `did-hosting-server/tests/unassignment_purge.rs` covers retain-then-purge, admin "Purge now", and re-assign-within-grace cases.
- **Migration:** New `did-hosting-server/tests/upgrade_migration.rs` writes a v0.7-shape store, runs the migration, asserts shape and idempotency.
- **Legacy / Trust-Task parity:** A shared test harness sends every operation twice — once with the legacy `MSG_*` DIDComm `type` and once with the `trusttasks.org/did-hosting/...` URL — and asserts byte-equivalent observable state. Same harness covers REST under the `Trust-Task:` header.
- **Trust-Task router:** Test against the rules from `verifiable-trust-infrastructure/vti-common/src/trust_task/router.rs`: exact-match success, missing-header 400, mismatch 415 with expected/received fields, `1.0` vs `1.1` are not interchangeable.
- **Coverage expectation:** No regression on existing coverage; new modules ≥ 80% line coverage.
- **Manual:** UI flows verified in a real browser (control + daemon) before the release tag. A11y verified with keyboard-only navigation and a screen reader on each new view.

## 9. Boundaries

**Always:**
- Run `cargo fmt`, `cargo clippy --workspace --all-targets`, and the full test suite before committing (per repo CLAUDE.md).
- Sign commits with `-s` (DCO).
- Keep the daemon's run-loop parity rules (project CLAUDE.md) intact: any new domain-aware background task or startup step (including the purge sweep) must land in `run_daemon()` and `run_daemon_storage_task` as well.
- Treat the `v1.0` `MSG_*` protocol and existing REST routes as load-bearing public surface — every alias must be regression-tested with the parity harness.
- Normalize every domain at the input boundary (REST handler, DIDComm handler, CLI). Never store or compare un-normalized names.
- Validate every domain input via the `domain_normalize` helper before letting it touch storage — never trust caller-supplied names.

**Ask first:**
- Removing or renaming any `MSG_*` constant.
- Changing the on-disk storage key shape (the migration in §6.5 is the only authorised change in this release).
- Adding a new store backend or new external network dependency.
- Changing public REST routes or response shapes (additive only is fine; renames need approval).
- Bumping a Trust-Task version (`1.0` → `1.1` or `2.0`) — the URL is part of the public wire surface.
- Touching CI config.
- Modifying `dtgwg-trust-tasks-tf` or `verifiable-trust-infrastructure` from this repo (cross-repo coordination required).

**Never:**
- Strip the v1.0 protocol or rip out the alias layer in this release.
- Auto-rehome an existing DID across domains (DIDs are immutable on their host).
- Rename a domain after creation — fields are immutable; offer add-new + offboard-old instead.
- Trust `X-Forwarded-Host` from outside `trusted_proxy_cidrs`.
- Persist a domain assignment that wasn't acknowledged from the control plane (servers may serve from a persisted cache during outage but never invent new assignments).
- Use Trust-Task version-family routing or prefix matching — exact-match only, per VTI canonical impl.
- Set the system default to a disabled domain.
- Commit secrets or rotate workspace-wide dependency versions as part of this work.

## 10. Decision log

All §10 questions from the original draft have been resolved. Recorded here for traceability:

| # | Question | Resolution |
|---|---|---|
| Q1 | `DomainScope::Allowed([…])` without explicit `default` + request omits `domain`? | **Reject with 400.** Error body names the allowed-list. |
| Q2 | Unassigned domain data lifecycle? | **Retain → auto-purge after grace period (default 2h, `server.unassigned_purge_grace`).** Admin "Purge now" button skips the grace. Re-assign within grace cancels the pending purge. |
| Q3 | Per-domain witness/watcher overrides — enforce now? | **Schema only.** Fields on `DomainEntry`; enforcement deferred to a follow-on release. |
| Q4 | `/.well-known/did-hosting-domain.json` — default state? | **Opt-in per domain.** `DomainEntry.well_known_enabled = false` by default. |
| Q5 | Trust-Task versioning scheme? | **`{maj}.{min}` per canonical Trust-Tasks spec.** No patch component. Exact-match routing per VTI. (User initially asked for `maj.min.patch`; pushed back, user concurred.) |
| Q6 | UI in this release? | **Yes — Phase G ships in the same release tag.** |
| Q7 | Trust-Task namespace? | **`https://trusttasks.org/did-hosting/...`** Registry-side registration is parallel (Phase H), non-blocking. |
| Q8 | Trust-Task wire mapping for DIDComm? | **Trust-Task URL used directly as the DIDComm `type` field.** No envelope-with-discriminator. |
| Q9 | Trust-Task wire mapping for REST? | **`Trust-Task:` HTTP header carrying the URL**, per VTI canonical impl. Exact-match validation via `TrustTaskRouter`. |
| Q10 | Default domain on a disabled domain — allowed? | **Reject.** Default must be an active domain. |
| Q11 | Domain name normalization? | **Lowercase + IDNA at every input boundary.** Reject non-normalized input with 400. |
| Q12 | Domain rename? | **Permanently disallowed.** Add-new + offboard-old is the only path. |
| Q13 | Path-prefix domains (`example.com/webvh-a`)? | **Fully supported at all layers** in this release. |
| Q14 | Cold-start fallback order? | **`assignments` keyspace → `bootstrap_domains` from `config.toml` → legacy `public_url` → empty.** Warn-log on tier 2 or 3 fallback. |
| Q15 | Disabled domain resolution response? | **503 with structured JSON** `{ status: "disabled", message?, eta? }`. |
| Q16 | Trust Tasks vs multi-domain release shape? | **Atomic single release.** Phases A–H form one tag. |
| Q17 | Where does the Domains admin surface live in UI? | **Top-level sidebar item.** |
| Q18 | Domain UX in main views (selector / filter / switcher)? | **Auto-default selector + dashboard multi-filter + chrome switcher (GitHub-org style).** Switcher hidden when caller scope = 1. |

No open questions remain at the time of this draft.

## 11. Risks

- **Scope.** Atomic Trust-Tasks + multi-domain release is large. Mitigation: Phase A lands first with zero behavior change (parity-tested against legacy `MSG_*`), so any Trust-Tasks bug surfaces before the domain semantics are bolted on. Each phase has gated acceptance criteria before the next builds on it; main is always green.
- **Storage migration.** Rewriting `did:*` keys on first boot at new version is unfamiliar territory for several existing operators. Mitigation: pre-migration backup is mandatory; migration is idempotent; rollback path documented (restore + downgrade binary).
- **Reverse-proxy misconfig.** If an operator deploys behind a proxy without setting `trusted_proxy_cidrs`, all requests fall back to `Host` from the proxy itself — which collapses every domain to the same value and breaks resolution. Mitigation: setup wizard detects "looks behind a proxy" (asks operator) and seeds a CIDR; runtime detects "all Hosts look identical" and emits a loud warning.
- **Control-plane outage during initial deployment.** A fresh server can't get its assignment if the control plane never finished registering it. Mitigation: `bootstrap_domains` config seed (used only when local `assignments` keyspace is empty).
- **ACL upgrade silently grants too much.** Existing Owner entries become `DomainScope::All` on upgrade. Mitigation: post-migration audit-log entry plus a one-line dashboard banner ("N owner ACL entries are scoped to All domains; review under Domains → ACL"). Admin can run a `me.domains.lockdown` admin tool to convert all `All` entries to `AllowedWithDefault([default])` in one shot, with confirmation prompt.
- **VTI `trust_task` module copied vs shared.** Two copies (one in VTI, one in webvh) drift over time. Mitigation: prefer extracting to a published `trust-tasks` crate consumed by both workspaces. Done in Phase A planning; not a blocker for shipping if (b) chosen with TODO to converge.
- **Trust-Tasks registry maintainers push back on `did-hosting/` URLs.** Mitigation: webvh code is independent of registry acceptance — we own the URL subtree by convention; registry is for discoverability, not authorisation. Worst case: URLs ship unregistered.
- **Aggressive purge default surprises operators.** A 2h grace is short for ops teams that occasionally need to revert an unassignment. Mitigation: configurable; loud audit-log entry on every grace-expired purge; admin UI surfaces "Pending purges" with countdown so operators can see what's about to disappear.

## 12. References

- `docs/multi-method-hosting-spec.md` — companion spec covering the repo rename + multi-DID-method support; ships in the same release tag.
- `docs/did-hosting-client-crate-spec.md` — companion `did-hosting-client` library spec; ships in the same release tag.
- `https://trusttasks.org/` — ToIP DTGWG Trust Tasks reference registry.
- `https://github.com/trustoverip/dtgwg-trust-tasks-tf` — Trust Tasks specification source (task force repo).
- `verifiable-trust-infrastructure/vti-common/src/trust_task/` — canonical Trust-Task Rust implementation (newtype + router + extractor) we reuse / extract.
- `docs/didcomm-did-management-protocol.md` — current v1.0 `MSG_*` protocol; the alias layer must preserve it.
- `docs/self-managed-mode-spec.md` — companion spec style.
- `docs/bootstrap_startup.md` — boot ordering this spec extends with `assignments` resolution.
- `CLAUDE.md` (root) — daemon parity rules referenced in §9.
- RFC 7239 — `Forwarded` header semantics.
- RFC 5891 — IDNA normalization rules applied by `domain_normalize`.
