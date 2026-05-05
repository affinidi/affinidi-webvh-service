# Changelog

## 0.6.0 (2026-05-05)

### Security

- **All three refresh handlers (control, server, witness) now require a
  JWS-signed DIDComm envelope and bind the signer to the session DID.**
  webvh-control was the last hold-out — it accepted a raw refresh-token
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
- **Registry / proxy trust chain hardened in webvh-control.** The audit
  found a Service-role JWT could register an attacker URL as a backend
  instance, and the proxy would then forward an Admin caller's
  Authorization header to it on the next proxy hit:
  - `RegistryConfig` gains an optional `url_allowlist` for backend hostnames.
  - `webvh-control`'s reqwest client is built with `Policy::none()` so
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
- **Reverse proxy in webvh-control requires Admin role** rather than any
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
- **webvh-daemon**: Self-managed identity mode. The setup wizard now
  offers a fourth choice ("Self-managed — no VTA — daemon manages its
  own DID") that skips every VTA prompt and instead generates the
  daemon's Ed25519 + X25519 keys locally and self-hosts a `did:webvh`
  identifier. Config gains an `[identity] mode = "vta" | "self-managed"`
  field (default `"vta"` for back-compat — existing configs without
  the section continue to load unchanged). Admin enrolment in
  self-managed mode uses passkey-invite only via the existing
  `webvh-daemon invite --did <DID> --role admin` CLI; the wizard does
  not seed any admin DID into the ACL. Tenant DID provisioning over
  DIDComm is unchanged — external tenant VTAs can still provision
  DIDs into a self-managed daemon. Daemon-only in v1; standalone
  `webvh-server` / `webvh-control` / `webvh-witness` setup wizards
  reject the self-managed choice with a clear "daemon-only" error
  pointing at `webvh-daemon`. See `docs/self-managed-mode-spec.md`.
- **webvh-control**: Web UI for creating enrollment invites. The Access
  Control page now has an "Invite by Link" card that generates an
  enrollment URL for a given DID and role, removing the need to drop to
  the `webvh-control invite` CLI to onboard new users. The invitee opens
  the link, registers a passkey, and is added to the ACL automatically.

### Fixed
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
  renames — `webvh_hosting_server` → `webvh_daemon`, `webvh_service`
  → `webvh_server` for witness-style consumers, and a new
  `webvh_control(context, host_url, mediator_did)` builder for the
  control plane (now requires `host_url` since the upstream template
  embeds it as the `WebVHHosting` service endpoint). The control-plane
  wizard now collects `did_hosting_url` before the VTA round-trip.
- **webvh-ui**: Login page "need access?" section no longer surfaces the
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

### Build
- **UI build now requires Node.js 20+.** Metro/Expo's loader uses
  `Array.prototype.toReversed()`, which landed in Node 20 — older
  toolchains fail deep inside `expo export` with
  `TypeError: configs.toReversed is not a function`.
  `webvh-control/build.rs` now preflights `node --version` and fails
  with an actionable message when Node is missing or too old.
  `webvh-ui/package.json` also declares `engines.node >= 20`. README
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
- **webvh-server**: DIDComm-based server registration with control plane,
  replacing HTTP-based registration. Servers now authenticate and register
  via DIDComm messages over a persistent websocket connection.
- **webvh-server**: DIDComm health ping/pong replaces HTTP health checks,
  providing reliable liveness monitoring over the existing DIDComm channel.
- **webvh-server**: `list-dids` and `remove-did` CLI commands for managing
  DIDs directly from the server command line.
- **webvh-control**: Consolidated VTA provisioning protocol — the control
  plane now handles the full DIDComm VTA flow (did/request, did/publish)
  for all registered servers.
- **webvh-control**: Auto-adds its own DID to server ACL on registration,
  enabling seamless DID sync without manual ACL configuration.
- **webvh-common**: Shared DIDComm message type constants for health,
  stats, and DID sync protocols.

### Changed
- **webvh-server**: Management routes removed from server edge nodes.
  All DID management is now done through the control plane; servers are
  read-only edge nodes that serve DID documents.
- **webvh-server**: Single DIDComm connection per service using
  `DIDCommService` v0.2.0, replacing per-operation connections.
- **webvh-server**: Setup wizard simplified for read-only edge node role —
  asks only for DID hosting URL instead of full server configuration.
- **webvh-server**: DID path derived from URL instead of hardcoded
  `.well-known`, supporting flexible DID hosting configurations.
- **webvh-control**: DIDComm service and handlers restructured for
  improved message routing and handler visibility.
- **webvh-daemon**: DIDComm config flag now read from `[features]` section.
  HTTP server starts before DIDComm to avoid self-resolution race condition.

### Fixed
- **webvh-server**: Always serve HTTP for public DID resolution regardless
  of `rest_api` flag — DID documents must remain publicly accessible.
- **webvh-server**: Websocket connection established before sending
  registration message, preventing message loss.
- **webvh-control**: DID sync and stats flow now works reliably between
  control plane and registered servers.
- **webvh-control**: DIDComm service properly visible to route handlers.
- Improved DIDComm error logging across all services.

### Performance
- Suppressed noisy health-ping/pong and stats-ack request logs to reduce
  log volume in production.

### Dependencies
- `affinidi-messaging-didcomm-service` 0.1 → 0.2

## 0.4.2 (2026-04-13)

### Added
- **webvh-daemon**: Full parity with standalone webvh-server + webvh-control.
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
- **webvh-daemon**: New CLI commands from webvh-server: `bootstrap-did`,
  `recreate-did`, `recover-did`, `load-did`, `import-secrets`, `backup`,
  `restore`
- **webvh-daemon**: DID store integrity check on startup

### Fixed
- **webvh-daemon**: fjall `Locked` error on startup — server, watcher, and
  control all share the same store path but each opened it independently.
  Stores are now opened once and shared.
- **webvh-daemon**: Enrollment invite URLs returned 404 — the control plane
  was nested at `/control` but enrollment URLs pointed to `/enroll`. Control
  plane is now merged at root so URLs work identically in daemon and
  standalone modes.
- **webvh-daemon**: DID resolve stats were not recorded — the server's
  stats collector was `None`. Now a shared `Arc<StatsCollector>` is used by
  both server and control plane.
- **webvh-daemon**: HTTP client had no timeouts — now uses 30s request /
  10s connect timeouts matching standalone server.
- **webvh-control**: Time-series graphs showed zero — `flush_stats_to_store`
  wrote aggregate totals but never wrote time-series bucket entries
  (`ts:{mnemonic}:{epoch}`). Now writes per-DID and server-wide (`_all`)
  5-minute buckets on each flush cycle. This fix applies to both daemon
  and standalone control plane modes.

### Changed
- **webvh-server**: `start_didcomm_service` is now `pub` for daemon reuse.
- **webvh-control**: `flush_stats_to_store`, `run_health_checks`, and
  `seed_registry` are now `pub` for daemon reuse.

## 0.4.1 (2026-04-13)

### Added
- **webvh-daemon**: Restore unified CLI management commands (`add-acl`,
  `list-acl`, `remove-acl`, `invite`) so operators can manage ACLs and create
  passkey enrollment invites directly from the daemon binary without needing to
  run `webvh-control` separately.

## 0.4.0 (2026-04-13)

### Added
- **webvh-server**: Restore `import-secrets` CLI command for importing server
  secrets from a VTA secrets bundle or individual multibase-encoded keys. This
  is required for cold-start bootstrap scenarios where no VTA service is running.

## 0.3.0 (2026-04-12)

### Changed
- Simplified architecture: removed shared CLI module, VTA-cache layer, and
  background task infrastructure from webvh-common
- Each service binary now owns its CLI directly instead of delegating to
  `webvh-common::server::cli`
- Switched from local-path `vta-sdk` to crates.io published version (0.3.x)

### Removed
- `webvh-common::server::cli` module (CLI logic moved into each binary)
- `webvh-common::server::vta_cache` module (VTA key refresh on startup removed)
- `import-secrets` CLI command from webvh-server (restored in 0.4.0)

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
- **Stats persistence removed from webvh-server**: Stats are in-memory only;
  control plane is the single source of truth
- **DID delete is now soft-delete**: Content preserved for 30-day recovery
  period; hard delete happens via cleanup thread

### New Features

#### webvh-common (0.1.0)
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

#### webvh-server (0.1.0)
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

#### webvh-control (0.1.0)
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

#### webvh-daemon (0.1.0)
- Aligned with webvh-server AppState changes (cache, signing key)

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
