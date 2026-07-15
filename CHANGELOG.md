# Changelog

## 0.8.2 (2026-07-15)

### Fixed

- **Enforce the `?domain=` cross-tenant safety check on publish/delete.** The
  VTA sends `?domain=` on `PUT`/`DELETE /api/dids/{mnemonic}` (and documents a
  `did-management:unknown_domain` rejection), but the control-plane handlers had
  no `Query` extractor, so axum silently dropped it — the advertised
  cross-tenant protection did not exist on the wire. `upload_did`/`delete_did`
  now read the parameter and `did_ops` cross-checks it against the DID's host
  (a DID's host *is* its domain) / the slot's persisted domain, rejecting a
  mismatch with `did-management:unknown_domain` before the log lands. Covers the
  DIDComm trust-task path too (it resolves the domain separately and passes
  none). The standalone `did-hosting-server` direct-publish handler is unchanged
  (the daemon and standalone-control deployments route management through the
  control plane).

- **A metadata-only identity change no longer triggers a key rotation.** The
  service treated any change to a generation's `protocols` or `mediator_did` —
  e.g. enabling TSP (`features.tsp = true`) — as a rotation, because
  `differs_from` compares those fields. With no key change, this took the
  retirement path: it retired the current generation (starting a grace window)
  and installed a "new" generation sharing the **same** `ka_kid`. When that
  retired generation's grace expired, `expire_generation` deleted the key
  material for a kid the current generation was still using — leaving the
  service with `sender has no usable key agreement key` and a permanent mediator
  reconnect loop, ~one grace period after the change.

  A rotation (retire + grace + eventual key deletion) now happens **only when
  the key-agreement key actually changes**. A `protocols`/`mediator_did` change
  updates the current generation in place — same id, same keys, no retirement,
  no grace window — and rebuilds the listener so a transport change takes
  effect. New `ReloadOutcome::MetadataUpdated` and
  `update_current_generation_in_place`; tests cover that the retired generation
  and every key survive an in-place update.

- **Two safety nets around identity key material** (defence-in-depth for the
  above). (1) Boot now validates that the secret store holds the private half of
  the current generation's advertised key-agreement kid — the guard
  `reload_service_identity` applies to a rotation, which boot lacked — and logs
  loudly on a mismatch instead of running on a retired key and collapsing a
  grace period later. (2) The expiry sweep never expires a generation whose
  `ka_kid` is still used by a surviving generation, so a grace expiry can never
  strip the key in active use and leave the service with no usable
  key-agreement key.

- **Registration no longer re-syncs every DID on every boot.** A server
  registering over TSP/DIDComm hit `sync_all_dids_to_server`, a full push of
  every DID, regardless of what the server already had — so a reboot re-synced
  the whole set (and re-triggered the server's own-DID identity-rotation check
  each time). The server now reports what it holds in `preloaded_dids`
  (mnemonic → version), and the control plane pushes only the delta; an older
  server that sends none still gets a full push. This is what lets the edge
  sync scale to thousands of DIDs.
- **The server resolves its own DID from the local store, not the network.** At
  cold boot the identity load resolved the server's own DID over its public URL
  — through a load balancer that hadn't marked the instance healthy yet — and
  logged a spurious `502`/`ERROR` before falling back. It now reads the
  authoritative `did.jsonl` from the local store first
  (`resolve_identity_doc_from_log`), falling back to the network only when the
  local copy is missing.
- **Quieter sync logging.** The per-DID `inbound TSP: server sync/domain
  message` receipt and the duplicate `applied DID sync update … via mediator`
  line drop to `debug`; each applied update logs once at `info`.

## 0.8.0 (2026-07-15)

The theme of this release is **transport as a first-class, negotiable property
of every node**. DIDComm, TSP, and HTTPS all carry the same Trust-Task
documents, each node's **DID document is the authoritative source of how to
reach it**, and the transport a message actually travelled on is recorded
rather than assumed.

### Added — Transport-agnostic Trust Tasks (TSP + DIDComm + HTTPS)

- TSP transport alongside DIDComm — everything is a Trust Task (#58), with TSP
  decoupled from DIDComm: TSP-only transport, a three-way transport selection,
  and TSP→DIDComm send fallback (#64).
- Outbound control→server sync push over TSP (#62); server registration and
  health routed as transport-agnostic Trust Tasks (#70).
- HTTPS Trust-Task DID-management parity (#60, #31).
- TSP-only VTA DID template selected for TSP-only nodes (#65).
- The observed control-plane link transport is recorded and surfaced, distinct
  from what a document advertises (#71).

### Added — The DID document is authoritative for transport

- Send-transport selection follows an explicit **document → config → fail**
  precedence; the former blind-DIDComm default is gone (#86).
- The standalone server advertises its own messaging transports on its DID
  (#87), and mediator-configured node DIDs **omit the `WebVHHosting` service**
  entirely — advertising only `TSPTransport` / `DIDCommMessaging` (#88).
- DID-document services surface as badges across the controller UI (#67), with
  resolver-implicit `#whois` / `#files` excluded (#68) and the badge cache
  backfilled on standalone control boot (#69).

### Added — Typed did-hosting DID-management protocol

- Typed `did-hosting/1.0` DID-management Trust-Task protocol — eight operations
  (#61) — accepting canonical spec URIs for did-management, webvh, and
  info/list/change-owner/me-domains (#25, #26, #27), converging on canonical
  URIs only with the alias bridge dropped (#28).
- Trust-Tasks 0.2 specs with 0.1 back-compat; in-band recipient required on
  every envelope (#40, #41).

### Added — Service-identity key rotation

- `identity-rotate-keys` rotates the service's own key-agreement key onto a
  fresh fragment with a working grace period and old-mediator drain (#82, #84).

### Added — Runtime DID management, delegated updates, secret backends

- DID changes are picked up at runtime instead of requiring a restart (#78);
  a DID document can be edited through the user's agent (#77), and the
  delegated DID-update path is wired end-to-end (#79).
- HashiCorp Vault and native Kubernetes Secret store backends (#53).
- Discover-first daemon online setup with a webvh publication choice (#33); a
  VTA-provisioned daemon trusts its provisioning VTA to publish (#55); DID-path
  folding unified through one shared provision-ask builder (#34).

### Fixed

- Identity rotation: importing keys no longer destroys a live rotation's grace
  period (#83), and a kid-reusing rotation is no longer misreported as
  "unchanged" (#81).
- A root DID must not carry `.well-known` in its identifier (#80); the root DID
  registers correctly at the `.well-known` slot (#72).
- Proxy-login / SIOP: camelCase `secretKind` on `vault/list` (#85), runtime RP
  DID resolution (#51), session-key proofs without an in-band issuer (#44),
  canonical camelCase log/owner wire fields (#39), and assorted demo fixes
  (#17, #18, #19, #20, #23).
- `host:port` domains resolve consistently end-to-end (#24); did:webvh host
  authority is percent-decoded before domain validation (#56); `check-name`
  probe/reserve/auto-assign contract implemented (#38).
- CI and advisory maintenance (#43, #48, #49, #54, #73).

### Dependencies

- Aligned to `vti-common` 0.11.5 / `vta-sdk` 0.19 (#74) and refreshed the
  lockfile to the latest compatible releases — `affinidi-messaging-*`,
  `google-cloud-*`, `http-body(-util)`, `rustls`, `redis`, `jsonpath-rust`.

### Versions

- Workspace crates `0.7.0` → `0.8.0`; `did-hosting-client` `0.1.0` → `0.1.1`;
  `did-hosting-ui` `1.0.0` → `1.1.0`.

## 0.7.0 (2026-05-24)

### Added — Trust Tasks framework adoption

- **Trust Tasks ACL surface (`POST /api/trust-tasks`).** New wire
  shape for ACL administration built on the
  [Trust Tasks framework](https://trusttasks.org/) at the registry's
  `acl/*/0.1` family. Six operations live behind one endpoint
  (envelope `type` member discriminates):
  - `acl/grant/0.1` — idempotent insert; role-change attempts rejected
    with `permission_denied` + `details.reason = "role_change_required"`.
  - `acl/revoke/0.1` — full removal **or** scope reduction (`scopes`
    items in `domain:<name>` shape); `last-authority` guard refuses
    revocations that would leave zero Admin entries.
  - `acl/change-role/0.1` — state-checked (`fromRole`/`toRole`);
    rejects concurrent overwrites with `acl/change-role:state_mismatch`.
  - `acl/show/0.1` — single-entry lookup; self-lookup permitted for
    non-Admin callers.
  - `acl/list/0.1` — conjunctive filters (`role`, `scope`,
    `subjectPrefix`) + opaque base64 cursor paging; pageSize ceiling 500.
  - `trust-task-discovery/0.1` — advertises all six types, declares
    `frameworkVersion: "0.1"`, and pins
    `requiredExt: ["vnd.affinidi.webvh"]` on `acl/grant` + `acl/change-role`.
- **DIDComm trust-tasks envelope route.** The control plane's DIDComm
  router accepts inbound messages of type
  `https://trusttasks.org/binding/didcomm/0.1/envelope`. Both
  transports share one async dispatch core (handlers don't care which
  transport delivered the document).
- **`trust-tasks-proof` verifier wired through `AppState`.** When
  `state.trust_tasks_verifier` is configured (a `DIDCacheClient` is
  available) AND the new `trust_tasks.enforce_proofs` config flag is
  `true`, the maintainer verifies a present Data Integrity proof and
  rejects an absent proof on a non-bearer spec with `proof_required`.
- **Vendor extension shape (`ext.vnd.affinidi.webvh`).** webvh-
  specific fields (quota + domain scope) live in the spec's `ext`
  slot under a reverse-DNS namespace. See
  [`docs/trust-tasks-acl-migration.md`](docs/trust-tasks-acl-migration.md)
  for the wire shape.
- **Daemon parity.** `did-hosting-daemon` automatically picks up the
  new HTTPS route AND the new DIDComm envelope handler — the daemon
  builds its routers via the control plane's `routes::router_without_fallback()`
  and `messaging::build_control_router()`, so there is no separate
  wiring to maintain (CLAUDE.md §What the daemon mirrors).
- **`AppState` gains `trust_tasks_verifier: Option<Arc<trust_tasks_proof::affinidi::Verifier>>`.**
  Constructed at startup when `did_resolver` is configured (the
  verifier shares the same DID-resolver cache as the DIDComm path).
- **`AppConfig` gains `trust_tasks: TrustTasksConfig`.** New section
  with a single `enforce_proofs: bool` knob (initial default `false`;
  flipped to `true` later in this release — see *Upstream alignment*
  below).
- **UI ACL surface (`did-hosting-ui`) routes through `/api/trust-tasks`.**
  The four `api.{list,create,update,delete}Acl` methods plus a new
  `api.aclShow` now POST trust-task envelopes. Wire-shape translation
  between the spec's `AclEntry` and the existing TypeScript `AclEntry`
  type is invisible to screen code.
- New [`docs/trust-tasks-acl-migration.md`](docs/trust-tasks-acl-migration.md)
  — client migration guide (old vs. new wire shape, proof policy,
  worked examples for both HTTPS and DIDComm, error-code mapping).
- New [`docs/trust-tasks-registry-gaps.md`](docs/trust-tasks-registry-gaps.md)
  — catalogue of webvh ops not yet in the public Trust Tasks
  registry, grouped by reusability tier with proposed slugs + payload
  sketches per type. ~50 ops across 8 groups, ready to file upstream.

### Deprecated — legacy ACL REST surface

- **`GET/POST /api/acl`, `PUT/DELETE /api/acl/{did}`** — every legacy
  ACL route now emits:
  - `Deprecation: true`
  - `Sunset: Mon, 01 Dec 2026 00:00:00 GMT`
  - `Link: </api/trust-tasks>; rel="successor-version"`
  - Structured `warn`-level log line per call identifying caller +
    successor URL (grep for `legacy_route=`).
  Removal target: **v0.8.0**. See
  [`docs/trust-tasks-acl-migration.md`](docs/trust-tasks-acl-migration.md)
  for migration guidance.

### Hardening (review-driven)

A multi-axis review of the trust-tasks adoption (security,
correctness, tests, documentation) surfaced a set of issues; the
fixes landed before the v0.7.0 cut. The wire shape and the
operator-facing config didn't change — these are correctness +
safety fixes.

- **ACL writes serialise through a single global lock.** Without
  this, two concurrent `acl/revoke` requests targeting the two
  remaining Admins could each pass the last-authority guard (each
  saw the *other* still present) and both commit, emptying the
  Admin set. The new `acl_locks: PathLocks` on `AppState` is a
  separate registry from the existing `path_locks` (which serialises
  DID-mnemonic writes); the three ACL-write handlers (`grant`,
  `change-role`, `revoke`) acquire one fixed key
  (`ACL_WRITE_LOCK_KEY`) so the read-then-write critical section is
  race-free across concurrent admins targeting different subjects.
  `PathLocks` itself is hoisted from `did-hosting-control` into
  `did-hosting-common::server::path_locks` so the dispatcher (in
  the common crate) can construct one.
- **`acl/grant` same-role regrant now persists metadata updates.**
  The UI's `updateAcl` relies on "same-role grant = idempotent
  metadata update" semantics; the previous implementation returned
  the existing entry verbatim, silently dropping label/quota/domain
  changes. The handler now merges the producer's non-role fields
  onto the existing entry, preserves `created_at`, and persists
  only when at least one field actually changed.
- **`acl/change-role` last-authority code re-namespaced.** The
  handler previously raised `acl/revoke:last_authority_protected`
  on the change-role path — cross-slug. Now raises
  `acl/change-role:last_authority_protected` (extended code per
  SPEC.md §8.5) so the slug matches the request's `type` URI.
- **`POST /api/trust-tasks` body is parsed by hand.** Replaces the
  `axum::Json` extractor whose text/plain 400 violated the spec's
  "malformed_request → `trust-task-error/0.1` document" contract.
  Body-shape failures now emit the routed error document with the
  spec-correct code.
- **64 KB body limit** on `/api/trust-tasks` caps an
  authenticated-Owner DoS class. Constant
  `routes::TRUST_TASKS_BODY_LIMIT_BYTES`.
- **`proof` carried with `enforce_proofs = false` is rejected, not
  silently dropped.** A producer who signed the envelope believed
  their signing key was authenticating; only the bearer JWT was. The
  new `(Some(proof), None)` arm of `run_pipeline` returns
  `malformed_request` with an operator-actionable message.
- **`NoVerifier` is now an uninhabited `enum NoVerifier {}`.** The
  previous unit-struct + panic-on-call carried the "bad call" risk
  as a runtime trap; the enum makes `Some(&NoVerifier)`
  uninstantiable.
- **`acl/list` cursor encodes `last_seen` DID** instead of a
  positional offset. Offset-based pagination skipped/repeated
  entries across concurrent deletes; `last_seen` is stable. The
  cursor stays opaque to consumers per spec.
- **`acl/list` `domain:` filter matches `All`-scoped entries.**
  `All` semantically operates on any domain; a "show me everyone
  who can publish to alpha.example" query now correctly includes
  `All`-scoped Admins.
- **`Suppressed` outcome promoted to `error!` log** (was `warn!`).
  The DIDComm gate `require_sender_did(true)` makes this branch
  unreachable in practice; the `should_not_happen=true` field
  surfaces an invariant violation to error dashboards if it ever
  fires.
- **Documentation fixes**: migration doc's worked example now
  distinguishes the caller (admin) from the grant's subject
  (alice); pre-publication crates.io links repointed at the
  upstream GitHub source; orphan doc block on `dispatch_inbound`
  attached.

### Upstream alignment — trust-tasks 0.1.1

The framework consumed our v0.7.0 review feedback in
[PR #33](https://github.com/trustoverip/dtgwg-trust-tasks-tf/pull/33);
v0.7.0 adopts the resulting 0.1.1 surface. Behavioural-equivalent
where the old code was correct, and a strict simplification of the
dispatch core:

- **`run_pipeline` is now a thin shim over
  `trust_tasks_rs::consume_inbound`.** ~110 lines of hand-rolled
  §7.2 pipeline replaced by ~20 lines of adapter. The framework
  owns expiry, recipient enforcement, party resolution, proof
  policy, and audience binding; our shim adapts `ConsumeOutcome` →
  `DispatchOutcome` and re-encodes the typed response as
  `TrustTask<Value>`.
- **`ProofPolicy` replaces `Option<&V>`.** Three explicit variants
  (`Verify(&v)`, `RejectIfPresent`, `AcceptUnverified`) make the
  consumer's posture audit-able at the call site. The control
  plane's `enforce_proofs` toggle maps to `Verify(&verifier)` /
  `RejectIfPresent`.
- **`Payload::IS_PROOF_REQUIRED` enforced authoritatively.**
  Codegen reads each spec's `proofRequirement.requirement` from
  front matter; `consume_inbound` checks the const independently of
  the consumer's `ProofPolicy`. `acl/grant`, `acl/revoke`,
  `acl/change-role` (all REQUIRED) refuse proofless documents
  regardless of policy; `acl/list`, `acl/show`, and
  `trust-task-discovery` (RECOMMENDED / OPTIONAL) accept them.
- **`Payload::extended_code(local)` helper** replaces every hand-
  rolled `TrustTaskCode::Extended { slug, local }` literal across
  `change_role.rs` and `revoke.rs`. Slug is sourced from
  `TYPE_URI` and can't drift.
- **`NoVerifier` uninhabited enum + `verification_error_to_reason`
  helper removed.** Framework handles both. Pipeline is generic in
  `V: ProofVerifier + ?Sized` and the `RejectIfPresent` /
  `AcceptUnverified` variants don't carry a verifier reference.
- **Sanitised wire-rejection diagnostic.** The
  `RejectIfPresent` path now emits the framework-shared
  `PROOF_NOT_ACCEPTED_BY_POLICY` constant ("in-band proof not
  accepted by consumer policy (SPEC §7.2 item 7)") rather than the
  previous verbose form. The verbose operator-actionable form
  ("flip `enforce_proofs = true`") lives in a `tracing::warn!` in
  `dispatch_inbound`. Sanitising the wire prevents an unauth
  probe from enumerating verifier coverage across a fleet.
- **`enforce_proofs` default flipped from `false` to `true`.** With
  the framework enforcing IS_PROOF_REQUIRED authoritatively,
  REQUIRED specs (grant/revoke/change-role) are unreachable
  without a verified proof. The new default produces the
  framework-correct shape for both backend-only callers (CLI,
  service-to-service) and the Web UI (browser-side signing —
  see next entry).

- **Browser-side Data Integrity signing for the Web UI.** Closes
  the "Web UI can't sign in-band" gap that was the original
  reason `enforce_proofs` defaulted to `false`. Ephemeral
  Ed25519 keypair generated via WebCrypto on each `passkey/login/
  finish`; public multikey (base58btc, `z6Mk…`) sent to the
  server and stored on the session record. Every REQUIRED-spec
  envelope carries an `eddsa-jcs-2022` proof whose
  `verificationMethod` is the matching `did:key` —
  `did-hosting-ui/lib/session-key.ts` implements the cryptosuite
  inline (~280 LOC, no npm deps for JCS or base58btc; uses
  WebCrypto `crypto.subtle.sign`). Private key stays as a
  non-extractable `CryptoKey` and never leaves the tab.

  Server side wires the binding in three places:
   * `Session.session_pubkey_b58btc` field carries the bound
     pubkey across requests (stored in the existing sessions
     keyspace).
   * `AuthClaims.session_pubkey_b58btc` surfaces it to
     `dispatch_trust_task`.
   * Pre-check in `dispatch_trust_task` (SECURITY): when the JWT
     carries a session pubkey, the proof's `verificationMethod`
     MUST be the matching `did:key:{pk}#{pk}`. Mismatch →
     `proof_invalid` rejection. Closes the "JWT subject A signs
     with B's session key to forge requests as A" attack — the
     framework's verifier would verify the cryptographic
     signature successfully but wouldn't enforce the JWT-binding
     itself.
   * The framework's `AffinidiVerifier` then does the actual
     signature verification (via the existing
     `CachedDidResolver` which already supports `did:key`).
- **`trust-tasks` family pinned to `0.1.1` on crates.io.** The PR #33
  changes shipped upstream as `trust-tasks-rs` 0.1.1 (published
  2026-05-24); the workspace dep moves to the crates.io pin and the
  transitional `[patch.crates-io]` block has been removed.

### Auth-architecture consolidation with vti-common

did-hosting's `/auth/*` surface now dispatches through the canonical
handlers in `vti_common::auth::handlers`. Closes the structural
follow-ups from the May 2026 cross-system auth security review.

#### Added

- **`did_hosting_common::server::auth::DidHostingSessionStore`** —
  `vti_common::auth::SessionStore` adapter over did-hosting's
  `KeyspaceHandle`. Honours did-hosting's separate storage trait
  (fjall, Redis, DynamoDB backends) while consuming the canonical
  `Session` type from vti-common.
- **`AuthBackend` impls per service**:
  - `did_hosting_control::auth::DidHostingControlAuthBackend`
    (REST SIOPv2; per-DID rate-limiting via the existing O(1)
    `PendingChallengeTracker`, canonical handler's limit disabled
    via `max_pending_challenges_per_did = 0`).
  - `did_hosting_server::auth::DidHostingServerAuthBackend`
    (DIDComm-only; canonical per-DID limit replaces the previous
    O(N) prefix-scan).
  - `webvh_witness::auth::WebvhWitnessAuthBackend`
    (DIDComm-only; canonical per-DID limit replaces the previous
    O(N) prefix-scan).
- **Re-exported `Session` + `SessionState` from vti-common** —
  `did_hosting_common::server::auth::session` now thin-wraps
  `vti_common::auth::session::{Session, SessionState}`. Field
  shape unchanged (the canonical type's `tee_attested` is
  `#[serde(default)]`; did-hosting never sets it). The wire-shape
  `Session` in `did_hosting_common::types` (the OIDC Core §2
  response body) is a distinct type and is unchanged.
- **Trust-Task URI dual-accept** — `did-hosting-server` and
  `webvh-witness` `/auth/` + `/auth/refresh` accept both the
  legacy `affinidi.com/webvh/1.0/...` URIs and the canonical
  `trusttasks.org/spec/auth/{authenticate,refresh}/0.1` URIs.
  Migration-window behaviour; drop the alias one minor release
  after every client upgrades.

#### Changed

- **`From<AuthError> for AppError`** — the canonical handler's
  typed `vti_common::auth::AuthError` variants render through
  did-hosting's existing `IntoResponse` plumbing without
  backend-specific glue.
- **Cross-repo dependency** — `did-hosting-common` (and consumer
  crates) now depend on `vti-common = "0.7"` from crates.io
  (published 2026-05-24 alongside this release).
- **Workspace `vta-sdk` pin** moved to `version = "0.7"` on
  crates.io so the two repos resolve to a single `vta-sdk`
  version (rather than two co-existing copies — the workspace
  pin + the vti-common-internal pin).

#### Removed

- did-hosting-common's local *storage-side* `Session` +
  `SessionState` definitions. Replaced by re-export from
  vti-common. (The wire-shape `Session` in
  `did_hosting_common::types` is unrelated and remains.)
- did-hosting-{control,server,witness}'s in-line `/auth/*` flow
  logic (~250 lines). Each handler is now a thin dispatcher
  around the canonical handler.

#### Note

The full operator-side documentation update — runtime config
keys, `pnm services` topology, the new `trust_xff` flag, the
`step_up_required` body shape — lands in v0.8.0 alongside the
broader did-hosting docs refresh.

### Changed — **BREAKING**

- **Repo and workspace renamed.** `affinidi-webvh-service` →
  `did-hosting-service`. Method-agnostic crates renamed to
  `did-hosting-*`:
  - `affinidi-webvh-common`  → `did-hosting-common`
  - `affinidi-webvh-server`  → `did-hosting-server`
  - `affinidi-webvh-control` → `did-hosting-control`
  - `affinidi-webvh-daemon`  → `did-hosting-daemon`
  Method-specific crates drop the `affinidi-` prefix but keep their
  method name:
  - `affinidi-webvh-witness` → `webvh-witness`
  - `affinidi-webvh-watcher` → `webvh-watcher`
  Binaries follow crate names. Cargo `name`, library names (snake-case),
  binary names, and folder paths all change together. Bumps every
  workspace member's import statement; downstream consumers must
  update their `Cargo.toml` dependency names. See
  `tasks/did-hosting-rollout-plan.md` for the rollout context.
- **Env-var rename: `WEBVH_*` → `DID_HOSTING_*`.** Affects every legacy
  webvh-server env var. The other per-binary prefixes (`DAEMON_*`,
  `CONTROL_*`, `WITNESS_*`, `WATCHER_*`) are unchanged.
- **New CLI subcommand stub: `did-hosting-daemon migrate-from-webvh-config
  --input <FILE> [--output <FILE>] [--force]`.** Operators can script
  against the invocation now; the rewriter implementation lands in a
  follow-up release (see `tasks/did-hosting-rollout-plan.md` WS-7).
- **Multi-domain hosting.** Domains are now first-class objects.
  The daemon stores `DomainEntry { name, label, scheme, status,
  default_domain, branding, witnesses, watchers, quota,
  well_known_enabled }` records in a new `domains` keyspace and
  enforces per-domain isolation on every resolve:
  - **Resolve-side safety** — every `GET /{mnemonic}/did.jsonl`
    (and the did:web / witness siblings) checks the request's
    `Host` against the embedded `did_id`'s host. Mismatch → 404
    (hides off-domain DIDs from cross-domain probes); disabled
    domain → 503 with structured maintenance body
    `{ "status": "disabled", "domain": "<name>", "message": ... }`.
  - **ACL domain scope** — `AclEntry` gains a `domains` field
    (`All` / `Allowed([…])` / `AllowedWithDefault { domains,
    default }`). New `Owner` entries default to
    `AllowedWithDefault`. Existing v0.6 entries deserialise as
    `All` for backwards-compat (run the ACL-lockdown admin tool
    in T42 to migrate).
  - **Request resolution rule** — `POST /api/dids/register`'s
    new `domain` field follows: explicit → ACL default → system
    default → reject. `Allowed([…])` callers without a default
    must declare a domain on every call.
  - **Domain admin surface** — `GET /api/domains` (Admin),
    `GET /api/me/domains` (per-caller scoped), `POST /api/domains`
    (create + optional set-as-default), `PUT /api/domains/{name}`
    (update metadata), `POST /api/domains/{name}/disable`,
    `POST /api/domains/{name}/enable`,
    `POST /api/domains/{name}/set-default`. All Trust-Task-bound
    via `TASK_DOMAIN_*` URLs.
  - **Trusted-proxy CIDR config** — `server.trusted_proxy_cidrs`
    controls which peers can override the `Host` header via
    `Forwarded` / `X-Forwarded-Host`. Outside the CIDR set, the
    daemon always uses the literal `Host`. RFC 7239 parsed.
- **Multi-method DID hosting.** Compile-time feature gates
  `method-webvh` + `method-web` (default) + `method-webs` /
  `method-webplus` (compile-error stubs for future work). Per-
  method resolution routes (`/{mnemonic}/did.jsonl` →
  `resolve_webvh`; `/{mnemonic}/did.json` → `resolve_web`)
  feature-gated; a method-webvh-only build doesn't compile (or
  register) the web routes.
  - `POST /api/dids/register` accepts the new
    `{ path, method?, did_data, domain?, force? }` body shape.
    `method` is optional and inferred from `did_data.id` when
    absent; explicit mismatch → 400.
  - `PUT /api/dids/{mnemonic}` content-type discriminator:
    `application/jsonl` → webvh, `application/did+json` → web.
  - Legacy `did_log: String` field accepted as a backwards-
    compat alias for webvh-only callers; will be removed in a
    future release.
- **Distributed domain assignment + retain-then-purge lifecycle.**
  The control plane is now the source of truth for which domains
  each server hosts.
  - `MSG_SERVER_REGISTER` carries `enabled_methods` +
    `served_domains` + `protocol_version` so the control plane
    can route method-aware requests.
  - `MSG_DOMAIN_ASSIGN { domain }` / `MSG_DOMAIN_UNASSIGN { domain }`
    + admin REST triggers at
    `POST /api/control/registry/{instance_id}/domains/{domain}/{assign,unassign}`.
    Idempotent on the server side.
  - Unassignment schedules a `PendingPurge { domain, scheduled_at,
    grace_seconds, reason, scheduled_by }` row with grace from
    `[hosting] unassigned_purge_grace` (default `"2h"`). The
    background sweep (60s tick) walks ripe entries and purges
    the matching DID records.
  - `MSG_DOMAIN_PURGE` + admin
    `POST /api/control/registry/{instance_id}/domains/{domain}/purge`
    bypass the grace for immediate cleanup
    (audit-log `reason: "admin-immediate"`).
  - Server cold-start fallback chain (T29): persisted
    `KS_ASSIGNMENTS` → `bootstrap_domains` config →
    legacy `public_url` host → empty (warn-log).
- **Trust-Tasks transport.** Every DIDComm message type and
  every authed REST route now has a canonical
  `https://trusttasks.org/did-hosting/...` URL.
  - DIDComm dispatcher accepts both legacy `MSG_*` and canonical
    `TASK_*` as `typ`; `v1_aliases` table provides the bijection.
    Existing clients keep working unchanged.
  - REST routes register through `TrustTaskRouter::route_with_task_permissive`
    — a client that sends the `Trust-Task:` header gets exact-
    match validation (415 on drift), a client that doesn't passes
    through (v0.7 → v0.8 migration window).
- **Companion client library `did-hosting-client`.** New
  workspace member exposing a thin REST + DIDComm client.
  Public surface includes `Client`, `AuthedClient`,
  `HostingSigningIdentity{,Owned}`, `HostingTokenStore` +
  `InMemoryTokenStore`, `ServerLocks`, `ClientError`,
  `ServiceEntry`, and all `TASK_*` URL constants. HTTPS enforced
  at construction (loopback exempt for dev). Decision ladder
  (cached → refresh → reauth) runs under per-server async mutex.
  Cross-crate parity test pins URL constants byte-for-byte
  against the daemon (T51).
- **Web UI catches up to the multi-domain + multi-method surface.**
  - New admin pages: `/domains` (catalog CRUD with create / set-default /
    disable / enable) and `/servers` (registry view with per-instance
    health, enabled methods, served-domain chips, assign / unassign /
    purge-now actions).
  - `DomainProvider` + nav-bar `DomainSwitcher` make a domain the
    active context across the app; admins also see an "All domains"
    pseudo-selection. Non-admin views are filtered through
    `GET /api/me/domains`.
  - ACL page gains a `DomainScope` editor (All / Specific / Specific +
    default) with chip selection and a separate default picker; the
    row read view shows the current scope as chips. Both the new-entry
    form and inline edit write through `createAcl` / `updateAcl`.
  - DID list filters by the active domain and renders per-row method +
    domain badges; DID detail shows the method and domain pulled from
    the new wire fields (T12 / M-01), with a graceful fallback to
    `log.method` on legacy records.
  - Dashboard surfaces the active-domain caption and an admin-only
    migration banner counting owners still on legacy "All" scope —
    deep-links to `/acl` for cleanup. Count is derived locally from
    `listAcl` (no new endpoint).

### Added

- **Non-interactive setup for every service.** Every `setup` subcommand
  on `did-hosting-{daemon,server,control}` + `webvh-{witness,watcher}` accepts a
  declarative `--from <recipe.toml>` recipe — drives the wizard with
  zero TTY interaction. The recipe contains no secrets; cloud creds
  come from the environment and crypto material is generated at setup
  time.
- **Full air-gapped install runs both phases non-interactively.** The
  same recipe file drives `offline-prepare` (writes the sealed-bundle
  request + persists the ephemeral seed in the configured secret
  backend) and `offline-complete` (opens the VTA admin's sealed reply).
  The recipe is the only state file — no separate state TOML needed.
- **`--force-reprovision` flag + reprovision-refusal scan.** Before
  any non-interactive run rotates credentials, the wizard probes the
  configured secret backend for an existing `ServerSecrets` entry. If
  one is present it refuses with exit 4 unless `--force-reprovision`
  is set. Backs up `config.toml` to `config.toml.bak` on overwrite.
- **`uninstall` subcommand** on `did-hosting-{daemon,server,control}` + `webvh-witness`
  — clears managed secrets from the configured backend and removes the
  config file plus companion DID-log files. Prompts for a typed
  `DELETE` confirmation; CI passes `--yes` to skip.
- **Env-var overlay on recipes.** `DAEMON_*` / `DID_HOSTING_*` / `CONTROL_*`
  / `WITNESS_*` / `WATCHER_*` env vars override recipe values at load
  time — one recipe template can ship across dev/staging/prod.
- **Stable exit codes for headless mode.** 0 success, 2 no-transport
  (VTA), 3 post-auth body rejected, 4 reprovision refused, 5 recipe
  parse/validation failed. Matches the mediator-setup wizard.
- **Example recipes** in `examples/` for every service, plus CI smoke
  tests that load + validate each one.

### Security

- **DIDComm `MSG_SERVER_REGISTER` now applies the registry URL allowlist.**
  The REST `POST /api/control/register-service` route already enforced
  `registry.url_allowlist`, but the DIDComm handler did not — any
  Service-role caller could register an attacker-controlled URL,
  including cloud-metadata / loopback / RFC1918 addresses. When an
  admin then hit `/api/proxy/server/{instance_id}/...`, the proxy
  forwarded the admin's bearer token to the registered URL (SSRF +
  token exfil). The allowlist gate is now lifted into a shared
  `registry::validate_registered_url` helper called by both transports.
  Empty allowlists preserve the prior "operator opted out" behaviour;
  any operator running the proxy route should configure one.
- **List-DIDs DID-prefix-collision IDOR closed.** Owner-index keys are
  `owner:{did}:{mnemonic}` and DIDs naturally contain colons. A DID
  that was a string-prefix of another (e.g. `did:web:tenant` vs
  `did:web:tenant:server`) leaked the longer-DID owner's mnemonics,
  did_id, timestamps, and resolve counts via prefix iteration in
  `list_dids`. Fixed by re-checking `record.owner == target_owner`
  after the iteration. Read-only — no write paths were affected.
- **Error sanitisation rebuilt on stable per-variant messages.** The
  prior `IntoResponse for AppError` used substring matches
  (`msg.contains("ACL") || msg.contains("did:")`) to decide whether to
  redact `Forbidden`, leaving brittle gaps (`"not the owner of this
  DID"` leaked through; `"is not in the ACL"` got caught) and ignored
  `Validation` entirely. Replaced with `AppError::user_message()` per
  variant: `Forbidden` always collapses to `"forbidden"`, and
  `Validation`/`Conflict`/`QuotaExceeded` strip ASCII control chars
  and cap at 256 bytes to prevent reflection of caller-supplied
  newlines/control bytes.
- **`now_epoch` and JWT issue path no longer panic on clock skew.** A
  system clock set before 1970 (e.g. a misconfigured embedded host)
  used to panic in `SystemTime::now().duration_since(UNIX_EPOCH).unwrap()`.
  Switched to `unwrap_or_default()` to match `didcomm_unpack`'s
  existing pattern.
- **Stricter DID-format validation on admin write surfaces.** New
  `validate_did_format` helper used by ACL create/update/delete and
  by `change_did_owner::new_owner`. Trims surrounding whitespace,
  rejects empty / oversized (>2048 bytes) / missing-`did:`-prefix /
  contains-control-character. The most common failure mode this
  prevents is silent: a typo with trailing whitespace lands as a
  storage key that no later `check_acl` lookup will match.

### Added

- **DID ownership transfer.** New `PUT /api/owner/{*mnemonic}` REST
  endpoint and `MSG_DID_CHANGE_OWNER` / `MSG_DID_CHANGE_OWNER_CONFIRM`
  DIDComm message types let an admin or the current owner re-assign a
  DID slot to another identity. New owner must already be in the ACL.
  Web UI exposes the transfer flow on the DID detail screen, gated to
  admins or the current owner.
- **Atomic claim-and-publish.** New `POST /api/dids/register` route
  and `register_did_atomic` operation that claims a path and publishes
  the first signed log entry in a single fjall batch — closes the
  resolvability gap between path reservation and first publish that
  the previous two-step `request_uri` + `publish_did` flow exposed.
  Idempotent for same-owner re-publish; admin force-takeover requires
  an explicit `force=true` flag.
- **`force` flag on `MSG_DID_REQUEST` / `POST /api/dids`.** Lets the
  current owner or an admin override the "DID already exists" error
  to claim the slot. Wipes prior log/witness/owner-index in a single
  batch.

### Fixed

- **Stats counter advances on control-plane writes.** Previously
  `total_updates` and `last_updated_at` only moved via stats-sync
  messages from remote `did-hosting-server` instances; in self-hosted /
  daemon deployments where the control plane is authoritative, the
  counters never advanced. Added `record_update` calls to
  `publish_did` and `register_did_atomic` after the storage commit
  succeeds.
- **`force=true` create no longer fans out a stale delete.** All three
  create call sites (REST `request_uri`, framework DIDComm dispatcher,
  signed-HTTP DIDComm dispatcher) used to push `notify_servers_delete`
  on force-replace, which made downstream resolvers serve 404 until
  the operator's follow-up `publish_did` arrived. Removed; the
  publish step's own `notify_servers_did` fans out the new content.
  Operators wanting an atomic ownership-takeover should use
  `register_did_atomic`.
- **`did-hosting-daemon::run_recreate_did`** now removes the owner-index
  entry under the *actual* owner DID rather than the hard-coded
  literal `"system"` (which only worked because `auto_bootstrap_dids`
  happened to use that owner string).

### Changed

- **Bumped `affinidi-messaging-didcomm-service` 0.3.0 → 0.3.1 and
  `affinidi-messaging-sdk` 0.17/0.18 → 0.18.2.** Picks up the
  upstream fix for the orphaned `WebSocketTransport` task bug
  diagnosed during testing: when the mediator's HTTP auth endpoint
  was briefly unreachable at startup, prior versions leaked one
  transport task per failed `Listener::connect()` attempt via a
  self-sustaining `Arc` cycle, producing a duplicate-channel storm
  once the mediator recovered.
- **CLAUDE.md daemon-parity rules clarified.** Restructured into
  three explicit sections: positioning, what the daemon mirrors, and
  what it intentionally does NOT mirror. Calls out registry health-
  check loop, HTTP stats sync, server's own DIDComm listener, and
  outbound ATM as deliberate omissions in the all-in-one model.

### Documentation

- npm `overrides` for `postcss` (≥8.5.10) and `@xmldom/xmldom`
  (≥0.8.13) close 5 dependabot alerts on the UI side.
- `cargo update` plus the SDK upgrade close the high-severity
  `openssl 0.10.79` and `rustls-webpki 0.103.13` advisories on the
  default-features Rust build.

### Follow-ups — security review + domain UX (2026-05-25)

A second pass over the v0.7.0 cut against an external security-patch
series, plus operator-driven UX gaps surfaced once the multi-domain
features were exercised end-to-end. The wire shape and operator-
facing config are unchanged; these are correctness, authz, and
log-hygiene fixes.

#### Security

- **DIDComm `MSG_SERVER_REGISTER` / `MSG_STATS_SYNC` now require the
  `Service` role exactly.** Both control-plane handlers previously
  accepted any sender in the ACL (Owner / Service / Admin). The
  REST equivalents (`POST /api/control/register-service` /
  `POST /api/control/stats`) are gated on `ServiceAuth` (Service-only);
  the DIDComm transports are now aligned. The `handle_server_register`
  case is the higher-impact half: success calls `sync_all_dids_to_server`,
  which pushes every tenant's DID log + witness content to the caller
  and subscribes them to all future updates — an Owner-role DID could
  enumerate the entire fleet's hosted data via a single forged register.
- **`MSG_SYNC_UPDATE` / `MSG_SYNC_DELETE` bound to the configured
  `control_did`, not any Service-role DID.** `did-hosting-server`'s
  sync handlers overwrite or delete arbitrary DIDs by body-supplied
  mnemonic. The previous `Role::Admin | Role::Service` gate let any
  peer server, witness, or stale Service ACL entry wipe or replace
  any hosted DID's log/witness content. New `require_control_plane`
  helper enforces an exact match against `config.control_did`; missing
  `control_did` rejects all sync messages (correct — a server without
  a control plane has no legitimate sender).
- **`GET /api/services/overview` now requires `AdminAuth`.** Previously
  any authenticated `AuthClaims` caller could enumerate the backend
  service registry — internal instance URLs, instance IDs, server
  DIDs, health status, registration timestamps. The equivalent
  `/api/control/registry` routes have always required `AdminAuth`; the
  overview gate is brought in line.
- **Manual `Debug` impls on credential-bearing config types.**
  `StoreConfig` (`redis_url`, `cosmosdb_connection_string`),
  `WatcherEndpoint.token`, `SyncConfig.push_tokens`,
  `SourceConfig.token`, `EnrollStartRequest.token`, and
  `CreateInviteResponse.{token, enrollment_url}` previously
  derived `Debug` and would render the live credential verbatim
  in any startup `tracing::info!(?config, …)` or error-path debug
  format. Each now redacts via `<redacted>` (count-only for the
  `push_tokens` slice). `PlaintextSecrets` already redacted; this
  closes the gap on every related struct.
- **Regression test guards the DIDComm refresh signer-binding.** The
  fix that pins a refresh token to the DIDComm sender DID lives in
  the upstream `vti-common` crate. Added
  `did-hosting-server/tests/refresh_signer_binding.rs` — seeds an
  Alice-owned session, calls `handle_refresh` with a mismatched
  signer, asserts `AppError::Authentication`. Catches a future
  backend swap silently dropping the binding parameter.

#### Fixed — domain assignment surfaces correctly in the UI

- **`POST /api/control/registry/{id}/domains/{domain}/{op}` now returns
  JSON on 202.** All three handlers (`assign`, `unassign`, `purge`)
  previously returned bare `StatusCode::ACCEPTED` with no body. The
  UI's `request()` helper short-circuits 204 only — on any other
  status it validates `application/json` and throws
  `"Expected JSON response but got unknown content type"`. Each
  handler now returns `(StatusCode::ACCEPTED, Json(json!({…})))`
  with the operation, instance ID, and domain so the UI gets a
  structured ack.
- **Control-plane DIDComm router handles `domain/{assign,unassign,purge}-ack`.**
  Servers send these after applying the matching outbound op. The
  router had no entries, so each ack fell through to `handle_fallback`
  and logged `inbound DIDComm: unhandled message type — ignoring`.
  A new `handle_domain_ack` records the ack at info-level (parallel
  to the existing `handle_sync_ack`).
- **`served_domains` populated end-to-end.** The control plane's
  registry view (and the UI's "domains assigned to this server"
  panel) showed nothing after a successful domain assign. Two-part
  fix: `did-hosting-server`'s `register_via_didcomm` no longer
  hardcodes `served_domains: []` (it now lists active local domains
  from `list_domains(&state.store)`), and `handle_domain_ack` mirrors
  each ack into the matching `ServiceInstance.served_domains` so the
  registry updates immediately without waiting for the next server
  boot. Restart-recovery and live-update paths converge on the same
  identity (`sender.replace(':', "_")`, the same derivation
  `handle_server_register` already uses).

#### Added — admin escape hatch for disabled domains

- **`DELETE /api/domains/{name}` (Admin-only) force-deletes a disabled
  domain**, bypassing the `hosting.disable_purge_grace` cooling-off
  window the background sweep otherwise waits out. Refuses when the
  domain is Active (operator must disable first — same two-step safety
  the UI already enforces) or when it's the current default
  (`delete_domain_record` already gates this and surfaces as
  `Conflict`). The pending-purge row is cancelled after the record
  is removed so the next sweep doesn't try to delete a row that's
  already gone. Mounted alongside the existing `PUT /domains/{name}`
  under `TASK_DOMAIN_UPDATE_1_0` (same pattern as `/registry/{id}`
  chaining GET+DELETE under one Trust-Task URI).
- **`?purge_servers=true` adds one-click fleet-wide purge.** When set,
  every registry instance whose `served_domains` lists the domain
  receives a `domain.purge/1.0` (T30) DIDComm message before the
  control-plane record is removed. Fire-and-forget over DIDComm;
  the local delete proceeds without waiting for acks, and
  `handle_domain_ack` drops the domain from `served_domains` as
  servers ack back. Per-instance failures during fanout are logged
  but never block the overall delete — operators can re-run the
  per-server "Purge now" on any that missed.
- **Three buttons on disabled domain cards.** UI gains "Delete now"
  (record-only) and "Purge & delete" (fleet-wide) destructive buttons
  alongside the existing "Enable". Each has a confirm dialog that
  spells out the blast radius. The "Delete now" path is the
  recovery route for legacy disabled domains whose `purge_at` was
  never populated and would otherwise stay stuck forever.

#### Changed

- **Login UI: "Login with VTA Wallet"** replaces "Login with VTI
  Wallet" on the button + install hint + the two extension-missing
  error messages. Aligns the user-facing strings with the rest of
  the codebase (`window.vtaWallet`, etc.).

### Follow-ups — UX polish, branding, and dashboard scoping (2026-05-25)

A third pass over the v0.7.0 cut driven by hands-on operator use of
the new multi-domain features. No wire changes; everything below is
text, layout, or client-side filtering. Same v0.7.0 dated section is
extended because the tag still hasn't moved.

#### Changed — product naming aligned to "DID Hosting"

- **User-facing "WebVH" → "DID Hosting" rename.** Setup-wizard
  headers, CLI `about` strings, the daemon/server/control ASCII-banner
  subtitles, `Cargo.toml` `description` fields, README titles and
  body, the DIDComm DID-management protocol document's prose and
  Mermaid participant labels, the WebAuthn `rp_name` ("DID Hosting
  Server"), and the `OperatorMessages` integration labels passed
  through to the VTA's `pnm contexts create --name "..."` hint all
  say "DID Hosting" now. Kept "WebVH" where it refers to the DID
  method itself (`did:webvh`, WebVH log entries, WebVH spec links),
  code identifiers (`WebVHClient`, `WebVHError`, `WebVHHosting`
  service-type string), wire constants (JWT `aud: "WebVH"`,
  message-type URIs under `https://affinidi.com/webvh/1.0/...`), and
  the `webvh-watcher` / `webvh-witness` crate directories whose
  witness/watcher concepts are themselves method-specific. The
  rebrand is text-only — no API, ABI, or on-disk format changes.
- **UI title "DID Hosting Manager".** Expo manifest `name`
  (`did-hosting-ui/app.json`) updated, which drives the browser tab
  `<title>` rendered from `dist/index.html`.

#### Fixed

- **Duplicate "Mediator DID" prompt during daemon setup.** Both the
  offline-prepare and self-managed flows rendered the prompt twice
  when the operator pasted a long mediator DID. Root cause:
  `dialoguer`'s `Input::interact_text()` re-renders the prompt after
  Enter to drop the bracketed default indicator, and its line-clear
  counts logical newlines rather than terminal-wrapped visual rows
  — so a wrapped input left the original prompt on screen while the
  re-render landed below as if it were a second prompt. Replaced the
  single `Input` (`.default(String::new()) + .allow_empty(true)`)
  with a `Confirm`-then-`Input` pair: the Confirm "Configure a
  DIDComm mediator?" is short enough to never wrap, and the
  follow-up `Mediator DID:` Input has a short label so the re-render
  lines up cleanly. Same shape as the existing online flow's
  mediator selection.
- **Domain switcher now actually scopes the DIDs list.** The
  client-side filter accepted any DID whose `domain` field was
  empty, so tenants whose records pre-date the M-01 migration (or
  whose DIDs were assigned cross-domain) saw the switcher silently
  no-op. Tightened to a strict `d.domain === currentDomain`; the
  list page surfaces an `N unassigned DIDs hidden` hint next to the
  filter caption so a user staring at an unexpectedly short list
  knows there are legacy records to triage (or to switch to "All
  domains").
- **Dashboard stats now react to the domain switcher.** The
  dashboard previously read `/api/stats` and rendered the
  server-wide aggregate regardless of the active domain. When a
  specific domain is pinned the dashboard now derives per-domain
  numbers from the DID list: DIDs in `{domain}`, scoped resolves,
  and scoped updates (sum of `versionCount - 1` clamped to ≥0 — the
  in-memory updates counter isn't broken out per-domain yet).
  "All domains" (admin) keeps the cheap `/api/stats` fast-path.

#### Added — dashboard

- **Domains stat card.** New card between "Total DIDs" and
  "Total Resolves" reading the count from the existing
  `useDomains()` provider. Always shows the total configured count;
  it's a system-level fact rather than a per-view stat.
- **Wider dashboard layout.** `statusRow`, `errorCard`, `section`,
  `migrationBanner`, and the `ServiceOverview` container bumped from
  `maxWidth: 500/800` to `1200` to match `NavBar` and the DID detail
  page. The dashboard was the only screen still rendering inside a
  narrow centered column on wide viewports.

#### Build

- **`cargo update`.** `affinidi-messaging-didcomm` 0.13.2 → 0.13.3,
  `affinidi-messaging-mediator` 0.15.4 → 0.15.5,
  `affinidi-messaging-sdk` 0.18.2 → 0.18.3,
  `windows-native-keyring-store` 1.0.0 → 1.1.0. Drops unused
  transitive deps (`aes 0.9`, `cipher 0.5`, `cpubits 0.1`,
  `inout 0.2`, `vta-sdk 0.6` — workspace already pins 0.7).

### Follow-ups — affinidi-messaging-didcomm 0.15 ecosystem bump (2026-06-03)

A dependency-only pass over the v0.7.0 cut. No wire, API, ABI, or
on-disk format changes; the entire move is version alignment in the
lockfile plus three stale test assertions. Same v0.7.0 dated section
is extended because the tag still hasn't moved.

#### Build

- **`affinidi-messaging-didcomm` 0.14 → 0.15.** The whole Affinidi
  stack has to move in lockstep, otherwise two didcomm versions coexist
  and `Message` / `UnpackMetadata` stop unifying across crate
  boundaries (`did-hosting-control` failed to compile: the DIDComm
  service router operates on `affinidi_tdk`'s re-export while our direct
  dep stayed on 0.14). Only `Cargo.toml` changed (`affinidi-messaging-didcomm
  = "0.15"`); everything else was re-locked under the existing
  `"0.7"`/`"0.3"`/`"0.9"`/`"0.1"` pins:
  - `affinidi-messaging-didcomm-service` 0.3.2 → 0.3.3
  - `affinidi-tdk` 0.7.2 → 0.7.3
  - `affinidi-messaging-sdk` 0.18.4 → 0.18.6
  - `affinidi-did-authentication` 0.3.4 → 0.3.5,
    `affinidi-meeting-place` 0.4.1 → 0.4.2 (both inside the tdk subtree)
  - `trust-tasks-didcomm` 0.1.3 → 0.1.4 (the last crate holding a stray
    didcomm 0.14.0; the lock now carries a single didcomm 0.15.0)
  - dev-deps: `affinidi-messaging-mediator` 0.15.7 → 0.15.12 (drops the
    stale `vta-sdk 0.7.0` + `affinidi-messaging-didcomm 0.13.3` chain),
    `affinidi-messaging-mediator-common` 0.15.1 → 0.15.3,
    `affinidi-messaging-test-mediator` 0.2.3 → 0.2.4

#### Fixed

- **Stale provision-ask template assertions.** Three
  `did-hosting-common::server::vta_setup` tests still expected the
  pre-rename service-named templates (`did-hosting-{control,daemon,server}`)
  after the v0.7.0 repipe to vta-sdk's capability-named builders. Updated
  to the values the production code now emits — `did-host-http-didcomm`,
  `did-host-http`, `did-host-didcomm`. Pre-existing failures, unrelated
  to the didcomm bump.

## 0.6.0 (2026-05-05)

### Security

- **All three refresh handlers (control, server, witness) now require a
  JWS-signed DIDComm envelope and bind the signer to the session DID.**
  did-hosting-control was the last hold-out — it accepted a raw refresh-token
  string in the body. Refresh now requires possession of both the refresh
  token *and* the session-DID's signing key on every service.
- **Offline-bootstrap latent-bug fix.** `open_offline_bootstrap_response`
  used `BTreeMap::iter().next()` to pick "the" DidKeyMaterial entry from
  the sealed payload's secrets map. With admin rollover enabled (the
  production-recommended VTA config), payloads carry two entries —
  integration and admin — and the alphabetical iteration order silently
  picked the wrong one (`did:key:...` admin sorts before `did:webvh:...`
  integration). The open path now matches by `config.did_document.id`
  with a logged forward-compat fallback. New
  `offline_bootstrap_full_webvh_to_vta_roundtrip` integration test
  exercises the full webvh ↔ VTA seal/open path in-process and would
  have caught this regression before publish.
- **Refresh-token rotation TOCTOU closed end-to-end.** Two concurrent
  requests with the same leaked refresh token used to both pass the
  lookup before either deleted the session. The fix is a new
  `KeyspaceOps::take_raw_atomic` primitive — Redis `GETDEL` /
  DynamoDB `DeleteItem` with `ReturnValues=ALL_OLD` / fjall mutex /
  per-keyspace mutex on Firestore + Cosmos DB. All three refresh
  handlers (control, server, witness) now atomically consume the
  refresh-index entry as part of the lookup, so exactly one concurrent
  caller wins — even across multiple webvh replicas backed by Redis
  or DynamoDB. The previous in-process `RefreshClaim` workaround is
  removed.
- **Refresh handlers (server, witness) now bind the JWS signer to the session
  DID.** Previously a leaked refresh token plus any attacker-controlled DID
  could rotate the victim's tokens — the signed envelope only proved
  possession of *some* key. Both handlers now reject when the verified
  signer DID does not equal `session.did`.
- **Empty-`jti` rotation bypass closed.** The extractor used to short-circuit
  the rotation check when `claims.jti.is_empty()`. Any session with a
  `token_id` now requires a non-empty matching `jti`, regardless of how
  the token was minted.
- **Registry / proxy trust chain hardened in did-hosting-control.** The audit
  found a Service-role JWT could register an attacker URL as a backend
  instance, and the proxy would then forward an Admin caller's
  Authorization header to it on the next proxy hit:
  - `RegistryConfig` gains an optional `url_allowlist` for backend hostnames.
  - `did-hosting-control`'s reqwest client is built with `Policy::none()` so
    a malicious backend cannot redirect the proxy onto a third-party host.
  - The proxy strips RFC 7230 §6.1 hop-by-hop headers and `Set-Cookie`
    from upstream responses before forwarding.
- **Watcher `/api/sync/did` body limited to 4 MiB** via a tower-http
  `RequestBodyLimitLayer`, and `validate_did_jsonl` now requires the
  latest entry's `state.id` to start with `did:webvh:`. Closes a leaked-
  push-token DoS / arbitrary-content republish vector.
- **Manual `Debug` redaction extended** to `Session` (refresh_token,
  token_id, challenge), `Enrollment` (invite token), `StoredSecrets`
  (bootstrap_seed), and `SecretsConfig` (plaintext_bootstrap_seed).
- **Multi-signature JWS envelopes are rejected** by `unpack_signed`. The
  threat model assumes single-signer messages; accepting additional
  signatures silently created surprising states.
- **X25519 verification methods rejected** by `resolve_verifying_key` —
  Ed25519 signing keys and X25519 key-agreement keys are both 32 bytes,
  so the previous length check would not catch a kid pointing at the
  wrong key class.
- **Keyring init no longer poisons the process** on transient failures.
  Only the success case is cached; transient failures (dbus not yet up,
  etc.) are allowed to retry on the next constructor call.
- **`write_secret_file_0600` is now atomic-rename safe** — uses a
  sibling tempfile with mode 0600 set before data is written, then
  rename. Re-runs of the offline-bootstrap CLI no longer fail with
  EEXIST when the seed file already exists.
- **DIDComm authentication closed an auth-bypass on every REST `/api/auth/`
  endpoint.** `unpack_signed` now returns the JWS-verified signer DID and
  rejects envelopes whose `from` field disagrees. Previously an attacker
  controlling any DID could mint a JWT for any ACL'd DID on the server,
  control plane, or witness REST surface. The mediator-driven inbound DIDComm
  path was unaffected.
- **Stats-sync endpoint requires Service-role auth** and binds the payload's
  `server_did` to the JWT-authenticated caller. Closes a counter-poisoning
  vector on the public control-plane surface.
- **Watcher sync now runs `validate_did_jsonl`** before storing pushed log
  content. A leaked push token can no longer republish arbitrary JSON
  masquerading as a DID document.
- **Witness `sign_proof` is now Admin-only** and emits an audit log on every
  signed proof. Previously any authenticated caller could request a witness
  proof for any version_id.
- **Reverse proxy in did-hosting-control requires Admin role** rather than any
  authenticated user.
- **Refresh handlers rotate everything.** The control / server / witness
  refresh endpoints now mint a fresh `session_id`, access token and refresh
  token on every refresh; the old session is deleted atomically. The
  `RefreshData` response shape gains `refresh_token` + `refresh_expires_at`
  so callers can drive the next refresh.
- **Private key files are written atomically** with mode 0600 using
  `OpenOptions::create_new`. Closes a TOCTOU window between `fs::write` and
  `set_permissions`.
- **`ServerSecrets`, `WitnessRecord`, `PlaintextSecrets` redact `Debug`** so
  `tracing::debug!(?secrets, …)` no longer leaks key material.
- **`PlaintextSecretStore::set` now persists `vta_credential`** instead of
  silently dropping it. Plaintext-backed deployments could previously lose
  their VTA credential on any wizard-driven config rewrite.
- **HTTP responses carry CSP, Referrer-Policy, HSTS** in addition to the
  existing X-Frame-Options / X-Content-Type-Options / Cache-Control.
- **Invite tokens** are now logged as a token-prefix only (revoke / update
  handlers in the passkey module). The token itself is no longer committed
  to operator log streams.
- **`KeyringSecretStore::try_new`** surfaces backend-registration failure as
  a structured `AppError::SecretStore` instead of warning-then-mystery-error.

### Added
- **did-hosting-daemon**: Self-managed identity mode. The setup wizard now
  offers a fourth choice ("Self-managed — no VTA — daemon manages its
  own DID") that skips every VTA prompt and instead generates the
  daemon's Ed25519 + X25519 keys locally and self-hosts a `did:webvh`
  identifier. Config gains an `[identity] mode = "vta" | "self-managed"`
  field (default `"vta"` for back-compat — existing configs without
  the section continue to load unchanged). Admin enrolment in
  self-managed mode uses passkey-invite only via the existing
  `did-hosting-daemon invite --did <DID> --role admin` CLI; the wizard does
  not seed any admin DID into the ACL. Tenant DID provisioning over
  DIDComm is unchanged — external tenant VTAs can still provision
  DIDs into a self-managed daemon. Daemon-only in v1; standalone
  `did-hosting-server` / `did-hosting-control` / `webvh-witness` setup wizards
  reject the self-managed choice with a clear "daemon-only" error
  pointing at `did-hosting-daemon`. See `docs/self-managed-mode-spec.md`.
- **did-hosting-control**: Web UI for creating enrollment invites. The Access
  Control page now has an "Invite by Link" card that generates an
  enrollment URL for a given DID and role, removing the need to drop to
  the `did-hosting-control invite` CLI to onboard new users. The invitee opens
  the link, registers a passkey, and is added to the ACL automatically.

### Fixed
- **Offline-bootstrap phase 2 fails with "bootstrap seed missing from
  secret store" in plaintext mode.** Phase 1 wrote the seed to
  `[secrets].plaintext_bootstrap_seed` in `config.toml` and serialised
  the wizard's `SecretsConfig` snapshot — captured *before* the seed was
  written — into `setup-offline-state.toml`. Phase 2 reconstructed the
  store from that stale snapshot and reported the seed missing even
  though it was sitting on disk. Affected all four wizards (daemon,
  control, server, witness) when built without a secure secrets backend
  (no `keyring` / `aws-secrets` / `gcp-secrets` / `azure-secrets`
  feature). `PlaintextSecretStore::get_bootstrap_seed` now reads
  directly from the config file rather than caching at construction;
  the file is the source of truth, matching how the cloud and keyring
  backends already worked. Regression tests cover the wizard's exact
  serialise-snapshot-then-reload flow plus the malformed-seed
  operator-edit case.
- **Setup wizards**: the offline-bootstrap "Next steps" output printed
  an incorrect VTA-host CLI hint
  (`vta context provision --context X --admin Y`). The actual command
  is `vta context create --id X` with no `--admin` flag. Updated all
  five wizards (common, server, control, witness, daemon).

### Changed
- **Keyring backend**: migrated from the `keyring` 3.x facade crate to
  `keyring-core` 1.x with platform-specific backend stores
  (`apple-native-keyring-store`, `windows-native-keyring-store`,
  `dbus-secret-service-keyring-store`) selected by target cfg. The
  default credential store is registered once at first
  `KeyringSecretStore::new()` call. No on-disk format changes — entries
  written by the previous build are still readable.
- **vta-sdk integration**: adapted to upstream `ProvisionAsk` builder
  renames — `webvh_hosting_server` → `did_hosting_daemon`, `webvh_service`
  → `did_hosting_server` for witness-style consumers, and a new
  `did_hosting_control(context, host_url, mediator_did)` builder for the
  control plane (now requires `host_url` since the upstream template
  embeds it as the `WebVHHosting` service endpoint). The control-plane
  wizard now collects `did_hosting_url` before the VTA round-trip.
- **did-hosting-ui**: Login page "need access?" section no longer surfaces the
  CLI command — it now instructs users to request an invite link from an
  admin, matching the new web-based flow.
- **MSRV**: raised from 1.91.0 to 1.94.0. Required by the updated
  affinidi-tdk / affinidi-messaging / affinidi-secrets-resolver /
  affinidi-data-integrity stacks, all of which declared 1.94+ in their
  latest releases.
- **Witness proof signing**: migrated to the new async `Signer`-based API
  in affinidi-data-integrity 0.6. The `WitnessSigner` trait is now async
  (returns a `BoxFuture`) — any external signer implementations must be
  updated accordingly.
- **CosmosDB store**: migrated to azure_data_cosmos's required
  `RoutingStrategy` parameter and the now-async `container_client()`.
  Region is configurable via new `store.cosmosdb_region` setting (env:
  `*_STORE_COSMOSDB_REGION`), accepting any Azure region name — display
  form (`"West US 2"`) or normalized (`"westus2"`). Defaults to
  `"eastus"` when unset.

### Tests
- **DIDComm dispatcher coverage** in `did-hosting-control`. Added 22 unit tests
  exercising the wire-level contract: every `dispatch_did_op` arm
  (validation, success, conflict, not-found, cross-owner forbidden), the
  authenticate flow end-to-end with JWT decode-back assertions, and the
  ACL gate at the dispatcher level. Refactored `handle_authenticate` and
  `handle_webvh_message` to delegate to `(String, Value)`-returning
  helpers (`run_authenticate`, `run_webvh_dispatch`) so the wire-level
  responses are testable without an `ATM`-backed `HandlerContext`. Also
  added `affinidi-messaging-test-mediator` (0.2) as a dev-dep for
  in-process embedded mediator tests. Smoke tests validate the
  fixture spawns, provisions distinct DIDs via the new
  `TestMediator::with_users` helper, and supports incremental
  `TestMediatorHandle::add_user` post-spawn — the lighter-weight
  alternative to `TestEnvironment` for handler-level scenarios that
  don't need an ATM-bound profile.
- **JWT crypto provider unification fix.** `JwtKeys::from_ed25519_bytes`
  now idempotently installs `jsonwebtoken::crypto::rust_crypto` as the
  process-level provider before encode/decode. Required because
  workspace-feature unification (e.g. when a dev-dep transitively pulls
  in `aws_lc_rs`) made `jsonwebtoken` 10.x refuse to auto-pick a
  provider and panic on first use. The install is a no-op on subsequent
  calls so it's safe across any thread.

### Build
- **UI build now requires Node.js 20+.** Metro/Expo's loader uses
  `Array.prototype.toReversed()`, which landed in Node 20 — older
  toolchains fail deep inside `expo export` with
  `TypeError: configs.toReversed is not a function`.
  `did-hosting-control/build.rs` now preflights `node --version` and fails
  with an actionable message when Node is missing or too old.
  `did-hosting-ui/package.json` also declares `engines.node >= 20`. README
  prerequisites updated from Node 18+ to Node 20+.

### Dependencies
- affinidi-tdk 0.5 → 0.7
- affinidi-tdk-common 0.4 → 0.6
- affinidi-messaging-didcomm 0.13.1 → 0.13.2
- affinidi-messaging-didcomm-service 0.2 → 0.3
- affinidi-messaging-sdk 0.16 → 0.17
- affinidi-secrets-resolver 0.5.3 → 0.5.5
- affinidi-did-resolver-cache-sdk 0.8.4 → 0.8.6
- affinidi-data-integrity 0.3 → 0.6 (breaking API — see note above)
- vta-sdk 0.4 → 0.5 (template-driven provisioning)
- didwebvh-rs 0.4 → 0.5 (transitive)
- firestore 0.47 → 0.48
- azure_core 0.32 → 0.35
- azure_data_cosmos 0.31 → 0.33 (breaking API)
- azure_security_keyvault_secrets 0.13 → 0.14
- azure_identity 0.34 → 0.35
- redis 1.0 → 1.2 (breaking `AsyncIter::next_item` now returns
  `Option<RedisResult<T>>`)
- aws-sdk-* and aws-config patch bumps
- keyring 3 → keyring-core 1 (see Changed)

## 0.5.0 (2026-04-13)

### Added
- **did-hosting-server**: DIDComm-based server registration with control plane,
  replacing HTTP-based registration. Servers now authenticate and register
  via DIDComm messages over a persistent websocket connection.
- **did-hosting-server**: DIDComm health ping/pong replaces HTTP health checks,
  providing reliable liveness monitoring over the existing DIDComm channel.
- **did-hosting-server**: `list-dids` and `remove-did` CLI commands for managing
  DIDs directly from the server command line.
- **did-hosting-control**: Consolidated VTA provisioning protocol — the control
  plane now handles the full DIDComm VTA flow (did/request, did/publish)
  for all registered servers.
- **did-hosting-control**: Auto-adds its own DID to server ACL on registration,
  enabling seamless DID sync without manual ACL configuration.
- **did-hosting-common**: Shared DIDComm message type constants for health,
  stats, and DID sync protocols.

### Changed
- **did-hosting-server**: Management routes removed from server edge nodes.
  All DID management is now done through the control plane; servers are
  read-only edge nodes that serve DID documents.
- **did-hosting-server**: Single DIDComm connection per service using
  `DIDCommService` v0.2.0, replacing per-operation connections.
- **did-hosting-server**: Setup wizard simplified for read-only edge node role —
  asks only for DID hosting URL instead of full server configuration.
- **did-hosting-server**: DID path derived from URL instead of hardcoded
  `.well-known`, supporting flexible DID hosting configurations.
- **did-hosting-control**: DIDComm service and handlers restructured for
  improved message routing and handler visibility.
- **did-hosting-daemon**: DIDComm config flag now read from `[features]` section.
  HTTP server starts before DIDComm to avoid self-resolution race condition.

### Fixed
- **did-hosting-server**: Always serve HTTP for public DID resolution regardless
  of `rest_api` flag — DID documents must remain publicly accessible.
- **did-hosting-server**: Websocket connection established before sending
  registration message, preventing message loss.
- **did-hosting-control**: DID sync and stats flow now works reliably between
  control plane and registered servers.
- **did-hosting-control**: DIDComm service properly visible to route handlers.
- Improved DIDComm error logging across all services.

### Performance
- Suppressed noisy health-ping/pong and stats-ack request logs to reduce
  log volume in production.

### Dependencies
- `affinidi-messaging-didcomm-service` 0.1 → 0.2

## 0.4.2 (2026-04-13)

### Added
- **did-hosting-daemon**: Full parity with standalone did-hosting-server + did-hosting-control.
  The daemon now includes all lifecycle management that was previously only
  available in standalone mode:
  - Background storage task: session cleanup, DID cleanup, stats flush to
    persistent store, and service health checks
  - Auto-bootstrap of root DID on startup when `public_url` is configured
  - Stats collector seeded from persisted store (stats survive restarts)
  - Registry seeding from static config on startup
  - DIDComm support via new `didcomm` config field — inbound listener for VTA
    integration and outbound ATM for sync push messages
  - Ordered shutdown: DIDComm → HTTP → storage flush → persist
- **did-hosting-daemon**: New CLI commands from did-hosting-server: `bootstrap-did`,
  `recreate-did`, `recover-did`, `load-did`, `import-secrets`, `backup`,
  `restore`
- **did-hosting-daemon**: DID store integrity check on startup

### Fixed
- **did-hosting-daemon**: fjall `Locked` error on startup — server, watcher, and
  control all share the same store path but each opened it independently.
  Stores are now opened once and shared.
- **did-hosting-daemon**: Enrollment invite URLs returned 404 — the control plane
  was nested at `/control` but enrollment URLs pointed to `/enroll`. Control
  plane is now merged at root so URLs work identically in daemon and
  standalone modes.
- **did-hosting-daemon**: DID resolve stats were not recorded — the server's
  stats collector was `None`. Now a shared `Arc<StatsCollector>` is used by
  both server and control plane.
- **did-hosting-daemon**: HTTP client had no timeouts — now uses 30s request /
  10s connect timeouts matching standalone server.
- **did-hosting-control**: Time-series graphs showed zero — `flush_stats_to_store`
  wrote aggregate totals but never wrote time-series bucket entries
  (`ts:{mnemonic}:{epoch}`). Now writes per-DID and server-wide (`_all`)
  5-minute buckets on each flush cycle. This fix applies to both daemon
  and standalone control plane modes.

### Changed
- **did-hosting-server**: `start_didcomm_service` is now `pub` for daemon reuse.
- **did-hosting-control**: `flush_stats_to_store`, `run_health_checks`, and
  `seed_registry` are now `pub` for daemon reuse.

## 0.4.1 (2026-04-13)

### Added
- **did-hosting-daemon**: Restore unified CLI management commands (`add-acl`,
  `list-acl`, `remove-acl`, `invite`) so operators can manage ACLs and create
  passkey enrollment invites directly from the daemon binary without needing to
  run `did-hosting-control` separately.

## 0.4.0 (2026-04-13)

### Added
- **did-hosting-server**: Restore `import-secrets` CLI command for importing server
  secrets from a VTA secrets bundle or individual multibase-encoded keys. This
  is required for cold-start bootstrap scenarios where no VTA service is running.

## 0.3.0 (2026-04-12)

### Changed
- Simplified architecture: removed shared CLI module, VTA-cache layer, and
  background task infrastructure from did-hosting-common
- Each service binary now owns its CLI directly instead of delegating to
  `did-hosting-common::server::cli`
- Switched from local-path `vta-sdk` to crates.io published version (0.3.x)

### Removed
- `did-hosting-common::server::cli` module (CLI logic moved into each binary)
- `did-hosting-common::server::vta_cache` module (VTA key refresh on startup removed)
- `import-secrets` CLI command from did-hosting-server (restored in 0.4.0)

## 0.2.0 (2026-04-08)

### Changed
- Version bump release for crates.io publishing

## 0.1.0 (2026-03-31)

First production-hardened release. Major improvements across all services in
security, performance, scalability, and operational readiness.

### Breaking Changes

- **affinidi-messaging-didcomm 0.13 migration**: `Message.type_` renamed to
  `Message.typ`; `pack_signed` and `unpack_string` replaced with new sync APIs
- **StatsSyncPayload**: Now carries per-DID deltas instead of aggregate totals;
  includes monotonic sequence number for idempotency
- **Stats persistence removed from did-hosting-server**: Stats are in-memory only;
  control plane is the single source of truth
- **DID delete is now soft-delete**: Content preserved for 30-day recovery
  period; hard delete happens via cleanup thread

### New Features

#### did-hosting-common (0.1.0)
- `StatsCollector`: Simplified to per-DID delta tracking with `drain_for_sync()`
  and `record_deltas()` for control plane ingestion
- `ServiceAuth` extractor for service-role-only endpoints
- `Role::Service` ACL role for service accounts
- `DidDocumentOptions`: DID documents now support `keyAgreement` (X25519) and
  `DIDCommMessaging` service endpoints
- `ContentCache`: In-memory TTL cache with Arc-based zero-copy reads
- `didcomm_unpack`: JWS unpacking with DID resolution and message freshness
  validation (5-minute window)
- Prometheus metrics module (behind `metrics` feature flag)
- Session `token_id` (jti) for JWT revocation on refresh
- Store `verify_integrity()` method for startup corruption detection
- `QuotaIndex` for O(1) per-owner DID count and size tracking
- Input bounds validation (DID length, path length)
- Error sanitization — 4xx responses no longer leak internal DIDs/paths

#### did-hosting-server (0.1.0)
- Multi-threaded REST executor (4 Tokio workers)
- DID resolution cache with TTL and write-through invalidation
- Per-DID stats sync to control plane (delta-based, no double-counting)
- Background control plane registration with retry and circuit breaker
- `recreate-did` CLI command for DID regeneration with config update
- `recover-did` CLI command for soft-delete recovery
- DID list pagination (`?limit=N&offset=M`)
- Rate limiting on auth challenge endpoint (10 pending per DID)
- DIDComm mediator discovery from VTA DID document
- Audit logging (`audit=true` field on security-critical events)
- Shutdown timeout (30s) on thread joins
- Store integrity check on startup

#### did-hosting-control (0.1.0)
- Per-DID stats storage with in-memory collector and periodic flush
- Stats sync authentication (ACL validation on incoming payloads)
- Stats idempotency (sequence number deduplication)
- Parallel health checks (tokio::spawn instead of sequential)
- Per-DID stats and timeseries API endpoints
- `ServiceAuth`-protected register-service endpoint
- DID list pagination
- Soft-delete recovery endpoint (`POST /api/recover/{mnemonic}`)

#### webvh-witness (0.1.0)
- Multi-threaded REST executor
- DIDComm API migration (0.13)

#### webvh-watcher (0.1.0)
- HTTP trace logging reduced to DEBUG level

#### did-hosting-daemon (0.1.0)
- Aligned with did-hosting-server AppState changes (cache, signing key)

### Security
- Session fixation prevention via JWT `jti` rotation on refresh
- DIDComm message freshness validation (rejects messages >5 min old)
- Input bounds: DID length capped at 512 bytes
- Auth challenge rate limiting (max 10 pending per DID)
- Stats sync endpoint authenticated against ACL
- Error responses sanitized (no internal DID/path leakage)
- Fjall batch errors logged instead of silently dropped

### Performance
- DID resolution cache reduces store load by ~80% for stable DIDs
- O(1) quota checks via `QuotaIndex` (was O(n) prefix scan)
- Incremental DID count tracking (was O(n) periodic scan)
- Arc-based cache entries avoid cloning large documents
- Empty stats syncs skipped (zero cost when idle)
- DID list pagination prevents unbounded response materialization

### Operations
- Prometheus metrics endpoint (`GET /metrics`, `metrics` feature flag)
- Configuration validation on load (auth TTLs, URL format, DID format)
- Structured audit logging for DID and auth operations
- HTTP trace logging moved to DEBUG level (reduces log noise)
- DID store status logged at startup (count, paths)
- Graceful shutdown with 30s timeout

### Dependencies
- `affinidi-messaging-didcomm` 0.12 → 0.13
- `vta-sdk` switched from local path to crates.io (0.2.x)
- `prometheus` 0.13 (optional, behind `metrics` feature)
