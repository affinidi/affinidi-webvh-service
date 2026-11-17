# Configuration reference

> **Status:** current — every key and variable below is read from the config structs; the struct named in each section is the source of truth.

Every binary reads one TOML file and then applies environment-variable
overrides. This page lists, for each binary, the file's sections and keys
and the variables that override them. The `setup` wizard and
`setup --from <recipe>` write a working file; this page is for reading and
hand-editing it. For the recipe format see
[bootstrap_startup.md](bootstrap_startup.md); for deployment advice
(TLS, proxies, ports) see [deployment.md](deployment.md).

## How a configuration is loaded

1. **The file.** `--config <path>` (every subcommand accepts `-c, --config`),
   else the binary's config-path variable (below), else `config.toml` in the
   working directory. A missing file is a startup error.
2. **Unknown keys are refused.** Every table is `deny_unknown_fields`: a
   misspelt key (`health_check_intreval`, `[witness_sync]`, an `[auth]` table
   on a witness) stops the service at load with the key's name, rather than
   being silently ignored. The only accepted alias is
   `features.rest_api`, the former name of `features.http_listener`.
3. **Environment overrides** are applied after the file, so a set variable
   wins. Boolean variables accept `1`/`true`/`yes`/`on` or
   `0`/`false`/`no`/`off` (any case); anything else is refused at startup,
   naming the variable. Numeric variables that do not parse are refused the
   same way.
4. **Validation.** Durations, byte sizes, rate limits, replay bounds and the
   `[auth]` lifetimes are range-checked at load; a bad value stops the
   service with a message naming the key.

## The binaries at a glance

| Binary | Default port | Config-path variable | Env prefix | Default `store.data_dir` |
| --- | --- | --- | --- | --- |
| `did-hosting-server` (edge) | 8530 | `DID_HOSTING_CONFIG_PATH` | `DID_HOSTING_` (`WEBVH_` still read, deprecated) | `data/did-hosting-server` |
| `webvh-witness` | 8531 | `WITNESS_CONFIG_PATH` | `WITNESS_` | `data/webvh-witness` |
| `did-hosting-control` | 8532 | `CONTROL_CONFIG_PATH` | `CONTROL_` | `data/did-hosting-control` |
| `webvh-watcher` | 8533 (written by setup) | `WATCHER_CONFIG_PATH` | `WATCHER_` | `data/webvh-watcher` (written by setup) |
| `did-hosting-daemon` | 8534 | `DAEMON_CONFIG_PATH` | `DAEMON_` | `data/daemon/store` (+ `data/daemon/witness`) |

The watcher's port and data directory are the values `webvh-watcher setup`
writes. A hand-written watcher config with no `[server]` or `[store]` table
falls back to the shared defaults (`0.0.0.0:8530`, `data/did-hosting-server`),
so write both tables out.

Below, `<P>` stands for a binary's env prefix.

## Top-level keys

| Key | Read by | Env | Meaning |
| --- | --- | --- | --- |
| `server_did` | all | `<P>_SERVER_DID` | **This node's own DID**, whatever the node is (the name is historical: on the control plane, witness and watcher it is that service's DID). Every signed request is addressed to it and every reply signed by it. Written by setup. |
| `mediator_did` | all | `<P>_MEDIATOR_DID` | The mediator the node's TSP / DIDComm listener connects through. Unset: the node is HTTP-only. |
| `public_url` | server, control, daemon | `<P>_PUBLIC_URL` | The node's public base URL. On the control plane and daemon it is also the WebAuthn origin (passkeys are enabled only when it is set) and, without `did_hosting_url`, the hosting base a published DID's host is checked against. |
| `did_hosting_url` | control, daemon | `CONTROL_DID_HOSTING_URL`, `DAEMON_DID_HOSTING_URL` | The base URL DIDs are hosted at, when it differs from `public_url`. |
| `control_did` | server | `DID_HOSTING_CONTROL_DID` | **Required.** The DID of the control plane that drives this edge; the only signer whose Trust Tasks it applies. The edge does not start without it. |

## `[features]` — `FeaturesConfig`

| Key | Default | Env | Meaning |
| --- | --- | --- | --- |
| `didcomm` | `false` | `<P>_FEATURES_DIDCOMM` | Carry DIDComm on the mediator connection (needs `mediator_did`). |
| `tsp` | `false` | `<P>_FEATURES_TSP` | Carry TSP on the same mediator socket; the DID advertises `TSPTransport`. Preferred over DIDComm when a peer advertises both. |
| `http_listener` | `false` | `<P>_FEATURES_HTTP_LISTENER` (former `<P>_FEATURES_REST_API` still read; the new name wins) | Run the HTTP listener: the UI, `POST /api/trust-tasks`, `/api/health`, and a witness's or watcher's public routes. Read by control, witness and watcher. A control plane needs at least one of `http_listener`, `didcomm`, `tsp`. The edge and the daemon always serve HTTP and do not read it. Alias: `rest_api`. |
| `agent_names` | `true` | `<P>_FEATURES_AGENT_NAMES` | Serve the `/@{name}` redirects. Off: every `/@…` path is 404. |
| `deployment_mode` | `standalone` | — | Set to `daemon` by the daemon itself; changes only UI behaviour. |

## `[server]` — `ServerConfig`

| Key | Default | Env | Meaning |
| --- | --- | --- | --- |
| `host` | `0.0.0.0` | `<P>_SERVER_HOST` | Bind address. |
| `port` | per binary (table above) | `<P>_SERVER_PORT` | Bind port. |
| `trusted_proxies` | `[]` | `<P>_SERVER_TRUSTED_PROXIES` (comma-separated; empty clears) | Addresses or CIDR ranges whose `X-Forwarded-For` is trusted for the **client address** (rate limits, connection caps, GeoIP). A bad entry, or a range covering every address (`0.0.0.0/0`), is refused at load. These peers are also exempt from the per-address connection cap. |
| `client_ipv6_prefix` | `64` | — | Prefix length an IPv6 client is counted by in every per-address limit (1–128). |
| `trusted_proxy_cidrs` | `[]` | — | Addresses or CIDR ranges whose `Forwarded` / `X-Forwarded-Host` is trusted for the **request host** (which hosting domain a resolution addresses). Read by the edge and the daemon's resolution. A bad entry, or a range covering every address, is refused at load, naming the key and the entry. See [deployment.md](deployment.md#two-proxy-lists). |

### `[server.resolve_cache]` — `ResolveCacheConfig`

`Cache-Control` on successful resolution responses. Read by the edge, the
watcher and the daemon. Each value at most one year.

| Key | Default | Env |
| --- | --- | --- |
| `max_age_secs` | `300` (`0` sends `no-cache`) | `<P>_SERVER_RESOLVE_CACHE_MAX_AGE_SECS` |
| `shared_max_age_secs` | unset | `<P>_SERVER_RESOLVE_CACHE_SHARED_MAX_AGE_SECS` (empty clears) |
| `stale_while_revalidate_secs` | unset | `<P>_SERVER_RESOLVE_CACHE_STALE_WHILE_REVALIDATE_SECS` (empty clears) |

### `[server.resolve_rate_limit]` — `ResolveRateLimitConfig`

Per-client-address limit on public resolution; off by default. Read by the
edge, the watcher and the daemon (one budget across the daemon's server,
watcher and root fallback, which also serves the UI).

| Key | Default | Env |
| --- | --- | --- |
| `max_per_window` | unset (no limit) | `<P>_SERVER_RESOLVE_RATE_LIMIT_MAX_PER_WINDOW` (empty clears) |
| `window_secs` | `10` (1–3600) | `<P>_SERVER_RESOLVE_RATE_LIMIT_WINDOW_SECS` (empty restores default) |

A refused client gets `429` with `Retry-After`. Behind a load balancer set
`trusted_proxies` first, or every client shares the balancer's budget. The
budget is per process: N replicas give a client up to N times the limit.

## `[log]` — `LogConfig`

| Key | Default | Env |
| --- | --- | --- |
| `level` | `info` | `<P>_LOG_LEVEL` (and `RUST_LOG`, which takes precedence when set) |
| `format` | `text` | `<P>_LOG_FORMAT` (`text` or `json`) |

## `[store]` — `StoreConfig`

Exactly one storage backend is compiled in (`store-*` feature; see the
crate READMEs). Keys for the other backends are accepted and ignored.

| Key | Backend | Default | Env (`<P>_STORE_…`) |
| --- | --- | --- | --- |
| `data_dir` | fjall | per binary | `_DATA_DIR` |
| `redis_url` | redis | — | `_REDIS_URL` |
| `dynamodb_table_prefix` | dynamodb | `webvh` | `_DYNAMODB_TABLE_PREFIX` |
| `dynamodb_region` | dynamodb | SDK default | `_DYNAMODB_REGION` |
| `dynamodb_billing_mode` | dynamodb | `pay_per_request` (or `provisioned:<read>:<write>`); applies only to tables the service creates | `_DYNAMODB_BILLING_MODE` |
| `dynamodb_auto_create` | dynamodb | `true`; `false` refuses to start on a missing table (for pre-provisioned tables and roles without `dynamodb:CreateTable`) | `_DYNAMODB_AUTO_CREATE` (boolean) |
| `firestore_project` | firestore | — | `_FIRESTORE_PROJECT` |
| `firestore_database` | firestore | `(default)` | `_FIRESTORE_DATABASE` |
| `cosmosdb_connection_string` | cosmosdb | — | `_COSMOSDB_CONNECTION_STRING` |
| `cosmosdb_database` | cosmosdb | `webvh` | `_COSMOSDB_DATABASE` |
| `cosmosdb_container` | cosmosdb | `kv`: one container holds every keyspace (partitioned on `/pk`, created if missing), so a batch is one transactional batch | `_COSMOSDB_CONTAINER` |
| `cosmosdb_region` | cosmosdb | `eastus` | `_COSMOSDB_REGION` |

`redis_url` and `cosmosdb_connection_string` can carry credentials and are
redacted from logs.

**Backend maturity.** CI runs the full unit suite on fjall (the default and
the most exercised backend), and a shared store-conformance suite against
real Redis, DynamoDB Local and the Cosmos DB SDK emulator on every pull
request. Firestore is build-only on pull requests and runs its conformance
suite on a schedule against the Firestore emulator. Backend item-size and
transaction limits (DynamoDB ~400 KB per log, Firestore ~750 KB) are
described in the [server README](../did-hosting-server/README.md#storage-backends).

### `[witness_store]` (daemon only)

The embedded witness's own store: the same keys as `[store]`, default
`data_dir = "data/daemon/witness"`, env `DAEMON_WITNESS_STORE_…` with the
same suffixes. It must reach different data from `[store]`; the daemon
refuses to start otherwise (it writes a probe through `[store]` and looks for
it through `[witness_store]`).

## `[fjall]` — `FjallTuning`

Memory caps for the embedded fjall store, shared by every binary (the daemon
applies one setting to both its stores). Values are a byte count or a string
such as `"64MiB"`, `"512MB"`. The variables have **no** service prefix: they
are a pod-level knob.

| Key | Default | Minimum | Env |
| --- | --- | --- | --- |
| `block_cache` | fjall's own (32 MiB) | 1 MiB | `STORAGE_FJALL_BLOCK_CACHE` |
| `write_buffer` | **8 MiB**, enforced by the store's background flusher (fjall 3.1 stores but does not enforce its own write-buffer limit) | 1 MiB | `STORAGE_FJALL_WRITE_BUFFER` |
| `max_journal` | fjall's own (512 MiB) | 64 MiB | `STORAGE_FJALL_MAX_JOURNAL` |

Zero, a value below the minimum, or anything that does not parse is refused
at startup.

## `[secrets]` — `SecretsConfig`

Where the node's private keys live. Exactly the backends compiled in
(`keyring` by default; `aws-secrets`, `gcp-secrets`, `azure-secrets`,
`vault-secrets`, `k8s-secrets` as features) can be selected.

| Key | Default | Env (`<P>_SECRETS_…`) |
| --- | --- | --- |
| `backend` | inferred (see below) | — |
| `keyring_service` | `webvh` | `_KEYRING_SERVICE` |
| `aws_secret_name`, `aws_region` | — | `_AWS_SECRET_NAME`, `_AWS_REGION` |
| `gcp_project`, `gcp_secret_name` | — | `_GCP_PROJECT`, `_GCP_SECRET_NAME` |
| `azure_vault_url`, `azure_secret_name` | — | `_AZURE_VAULT_URL`, `_AZURE_SECRET_NAME` |
| `vault_addr` | — (setting it selects Vault) | `_VAULT_ADDR` |
| `vault_kv_mount` | `secret` | `_VAULT_KV_MOUNT` |
| `vault_secret_path` | — (required with `vault_addr`) | `_VAULT_SECRET_PATH` |
| `vault_secret_key` | `seed` | `_VAULT_SECRET_KEY` |
| `vault_namespace` | — | `_VAULT_NAMESPACE` |
| `vault_auth_method` | `kubernetes` (`token`, `approle`) | `_VAULT_AUTH_METHOD` |
| `vault_k8s_role`, `vault_k8s_mount`, `vault_k8s_jwt_path` | —, `kubernetes`, the projected ServiceAccount token path | `_VAULT_K8S_ROLE`, `_VAULT_K8S_MOUNT`, `_VAULT_K8S_JWT_PATH` |
| `vault_token` | — (prefer `VAULT_TOKEN`) | `_VAULT_TOKEN` |
| `vault_approle_role_id`, `vault_approle_secret_id`, `vault_approle_mount` | —, —, `approle` | `_VAULT_APPROLE_ROLE_ID`, `_VAULT_APPROLE_SECRET_ID`, `_VAULT_APPROLE_MOUNT` |
| `vault_skip_verify` | `false` (dev only) | `_VAULT_SKIP_VERIFY` (boolean) |
| `k8s_secret_name` | — (setting it selects Kubernetes) | `_K8S_SECRET_NAME` |
| `k8s_namespace` | the pod's namespace | `_K8S_NAMESPACE` |
| `k8s_secret_key` | `seed` | `_K8S_SECRET_KEY` |
| `confirm_plaintext` | `false` | — |

`backend` is one of `keyring`, `aws`, `gcp`, `azure`, `vault`, `kubernetes`,
`plaintext`. Unset, the backend whose selector field is set is used, and
failing that the OS keyring. `plaintext` keeps keys in a clear-text file
beside the config and refuses to build without `confirm_plaintext = true`:
tests only. Nothing falls back to plaintext when the keyring is unavailable.

## `[auth]` — `AuthConfig`

Read by the control plane and the daemon (sessions, sign-in, passkeys). The
edge reads only `cleanup_ttl_minutes`. The witness and watcher have no
`[auth]` table: one in their config is refused.

| Key | Default | Env | Meaning |
| --- | --- | --- | --- |
| `access_token_expiry` | `900` | `<P>_AUTH_ACCESS_EXPIRY` | Console access-token lifetime, seconds (≥ 30). |
| `refresh_token_expiry` | `86400` | `<P>_AUTH_REFRESH_EXPIRY` | Refresh-token lifetime, seconds. |
| `absolute_session_lifetime` | `2592000` (30 days) | — | No refresh extends a session past this from sign-in (≥ `refresh_token_expiry`). |
| `admin_idle_timeout` | `900` | `<P>_AUTH_ADMIN_IDLE_TIMEOUT` | A session idle this long may not be renewed (≥ 60). |
| `challenge_ttl` | `30` | `<P>_AUTH_CHALLENGE_TTL` | Sign-in challenge lifetime (≥ 10). |
| `session_cleanup_interval` | `600` | `<P>_AUTH_SESSION_CLEANUP_INTERVAL` | Expired-session sweep interval (≥ 10). |
| `passkey_enrollment_ttl` | `86400` | `<P>_AUTH_PASSKEY_ENROLLMENT_TTL` | Default passkey-invite lifetime. |
| `claim_code_hash_wait_ms` | `5000` | `<P>_AUTH_CLAIM_CODE_HASH_WAIT_MS` | Longest an invite's claim-code check waits for a hashing slot (≤ 60000). |
| `max_global_pending_challenges` | `10000` | `<P>_AUTH_MAX_GLOBAL_PENDING_CHALLENGES` | Live sign-in challenges across all DIDs (≥ 1). |
| `max_pending_challenges_per_did` | `10` | `<P>_AUTH_MAX_PENDING_CHALLENGES_PER_DID` | Live sign-in challenges per DID (≥ 1). |
| `cleanup_ttl_minutes` | `60` | `<P>_CLEANUP_TTL_MINUTES` (no `AUTH_`) | How long an empty DID slot is kept before cleanup. |

## `[hosting]` — `HostingConfig`

Read by the control plane, the edge and the daemon.

| Key | Default | Env | Meaning |
| --- | --- | --- | --- |
| `bootstrap_domains` | `[]` | — | Domains seeded on first boot when none exist; the first is the default. Empty: derived from `public_url`'s host. |
| `unassigned_purge_grace` | `"2h"` | — | How long an edge keeps a domain's data after it is unassigned before the purge sweep removes it. |
| `disable_purge_grace` | `"30d"` | — | How long a disabled domain (and its DIDs) is kept before permanent removal. |
| `scid_also_known_as` | `true` | `<P>_HOSTING_SCID_ALSO_KNOWN_AS` | A DID the service creates for itself lists its `did:scid` alias in `alsoKnownAs`. |
| `[[hosting.webs_self_register]]` | none | — | Domains on which a `did:webs` may register itself (`domain`, `path_prefixes`, `max_registrations` default 100, `max_dids_per_identifier` default 1). `method-webs` builds only; see [did-webs-hosting.md](did-webs-hosting.md). |

Grace periods are an integer with an optional unit `s`, `m`, `h` or `d`
(bare seconds otherwise), parsed at load: a value that is not a duration
stops the service, naming the key.

## `[identity]` — `IdentityConfig`

| Key | Default | Meaning |
| --- | --- | --- |
| `mode` | `vta` | `vta`: a VTA provisions the node's keys. `self-managed`: the node mints its own keys and self-hosts its `did:webvh` (daemon only; env `DID_HOSTING_IDENTITY_MODE` on the daemon). |
| `rotation_grace_period` | `"1h"` | How long a superseded identity generation stays usable after a rotation; `"0"` retires at once (for a compromised key). A value that does not parse is refused at load, naming the key. |

See [identity-rotation-design.md](identity-rotation-design.md).

## `[replay]` — `ReplayConfig`

Bounds of the anti-replay cache for signed Trust Tasks. Every service that
accepts them has one (the daemon up to three). Leave the table out to take
the defaults; setup does not write it.

| Key | Default | Env |
| --- | --- | --- |
| `max_entries` | `1000000` (≈ 32 MB; ≤ 10,000,000) | `<P>_REPLAY_MAX_ENTRIES` |
| `max_entries_per_signer` | `250000` (≈ 600 signed requests/s sustained per signer; ≤ `max_entries`) | `<P>_REPLAY_MAX_ENTRIES_PER_SIGNER` |

At a bound the cache refuses new requests (`unavailable`, retryable) rather
than forget one. The [control plane README](../did-hosting-control/README.md#replay-cache-bounds)
explains how to size them.

## `[vta]` — `VtaConfig`

| Key | Env (server / control / witness) |
| --- | --- |
| `url` | `DID_HOSTING_VTA_URL`, `CONTROL_VTA_URL`, `WITNESS_VTA_URL` |
| `did` | `…_VTA_DID` |
| `context_id` | `…_VTA_CONTEXT_ID` |

Written by setup; used by setup-time and CLI paths, not by the running
service. A self-managed daemon has no `[vta]`.

## Edge server only (`did-hosting-server`)

### `[replication]` — `ReplicationConfig`

| Key | Default | Env |
| --- | --- | --- |
| `staleness_bound_secs` | `300` | `DID_HOSTING_REPLICATION_STALENESS_BOUND_SECS` |
| `reconcile_interval_secs` | `60` (must be below the bound) | `DID_HOSTING_REPLICATION_RECONCILE_INTERVAL_SECS` |

The edge reconciles with its control plane every interval; past the bound
without a clean reconcile, `/api/health` answers `503`.

### `[limits]` — `LimitsConfig`

| Key | Default | Env | Meaning |
| --- | --- | --- | --- |
| `upload_body_limit` | `102400` | `DID_HOSTING_LIMITS_UPLOAD_BODY_LIMIT` | Largest `POST /api/trust-tasks` body; never below 1 MiB in effect. |
| `default_max_total_size`, `default_max_did_count` | `1048576`, `20` | `DID_HOSTING_LIMITS_DEFAULT_MAX_TOTAL_SIZE`, `…_DEFAULT_MAX_DID_COUNT` | Accepted for compatibility; nothing on the edge reads them (quotas are the control plane's concern). |
| `content_cache_bytes` | `268435456` (256 MiB) | — | The most resolved DID content held in memory (served with a strong `ETag`; past the limit the oldest entries are dropped). |
| `http_worker_threads` | one per available core | — | Worker threads of the edge's HTTP (resolution) runtime. |

The daemon accepts a `[limits]` table too. Its embedded edge mounts no
listener of its own, so only `content_cache_bytes` (the resolution cache)
has an effect there.

### `[stats]` — `StatsConfig` (edge)

| Key | Default | Env |
| --- | --- | --- |
| `flush_interval_secs` | `5` | `DID_HOSTING_STATS_FLUSH_INTERVAL_SECS` |
| `sync_interval_secs` | `1` (`0` disables) | `DID_HOSTING_STATS_SYNC_INTERVAL_SECS` |

`sync_interval_secs` is how often the edge sends its counters to the control
plane as a signed `server/stats-sync` Trust Task.

## Control plane only (`did-hosting-control`; most also in the daemon)

### `[registry]` — `RegistryConfig`

| Key | Default | Env | Meaning |
| --- | --- | --- | --- |
| `[[registry.instances]]` | none | — | Static service instances: `label`, `service_type` (`server`, `witness`, `watcher`), `url`. |
| `health_check_interval` | `60` | `CONTROL_REGISTRY_HEALTH_CHECK_INTERVAL` | Seconds between registry health checks (standalone control only; the daemon does not run the loop). |
| `url_allowlist` | `[]` | — | Hosts that may be registered. Empty: internal literal hosts (loopback, RFC 1918, link-local, CGNAT, ULA) are refused, public hosts accepted. Non-empty: only listed hosts (exact, case-insensitive, host only). |
| `[[registry.watchers]]` | none | — | `url` and `did` of each watcher this control plane pushes to (a DID's log names watchers by URL). |

### `[trust_tasks]`

`enforce_proofs` defaults to `true`; `false` is refused at startup. The table
exists only so an old config that sets `true` still loads.

### `[geoip]` — `GeoIpConfig`

`database` (a MaxMind DB `.mmdb` file; env `CONTROL_GEOIP_DATABASE`,
`DAEMON_GEOIP_DATABASE`; empty clears) and `[[geoip.networks]]` (`cidr`,
`location`). See [geoip.md](geoip.md).

### `[stats_flush]` — `StatsFlushConfig`

`max_rows_per_second` (default `20`, 1–10,000; env
`<P>_STATS_FLUSH_MAX_ROWS_PER_SECOND`): the statistics flush's write budget.

### `[stats]` — `StatsTierConfig` (control plane and daemon)

| Key | Default | Env |
| --- | --- | --- |
| `mode` | `auto` (`fine`, `coarse`) | `<P>_STATS_MODE` |
| `promote_per_hour` | `60` | `<P>_STATS_PROMOTE_PER_HOUR` |
| `demote_per_hour` | `20` (below `promote_per_hour`) | `<P>_STATS_DEMOTE_PER_HOUR` |
| `max_fine_dids` | `1000` (≤ 1,000,000) | `<P>_STATS_MAX_FINE_DIDS` |

See [stats-tiers.md](stats-tiers.md).

## Daemon only (`did-hosting-daemon`)

The daemon's file is `DaemonConfig`: the shared tables above (`[server]`,
`[log]`, `[auth]`, `[secrets]`, `[store]`, `[fjall]`, `[features]`,
`[identity]`, `[replay]`, `[hosting]`, `[vta]`), the control plane's
`[registry]`, `[geoip]`, `[stats_flush]`, `[stats]`, the edge's `[limits]`,
plus:

| Section | Meaning |
| --- | --- |
| `[witness_store]` | The embedded witness's store (above). |
| `[enable]` | `server = true`, `witness = true`, `watcher = false`, `control = true`: which embedded services start. |

There is no `[replication]`, `[sync]` or edge `[stats]` table in the daemon:
its services share one process and one store. Its env overrides are the
`DAEMON_` forms of the shared variables, `DAEMON_WITNESS_STORE_*`,
`DAEMON_SERVER_DID`, `DAEMON_MEDIATOR_DID`, `DAEMON_PUBLIC_URL`,
`DAEMON_DID_HOSTING_URL`, and `DID_HOSTING_IDENTITY_MODE`.

## Watcher only (`webvh-watcher`)

### `[sync]` — `SyncConfig`

| Key | Env | Meaning |
| --- | --- | --- |
| `source_dids` | `WATCHER_SOURCE_DIDS` (comma-separated) | Control planes whose signed `webvh/sync/*` documents are applied. Empty: nothing is applied. |
| `[[sync.sources]]` | — | `did` and `domains`: a source restricted to the hosts it may sync. |

## Which tables each binary accepts

| Table | server | control | daemon | witness | watcher |
| --- | --- | --- | --- | --- | --- |
| `[features]`, `[server]`, `[log]`, `[store]`, `[fjall]`, `[secrets]`, `[vta]`, `[identity]`, `[replay]` | yes | yes | yes | yes | yes |
| `[auth]` | yes (`cleanup_ttl_minutes` only) | yes | yes | — | — |
| `[hosting]` | yes | yes | yes | — | — |
| `[replication]`, `[limits]`, edge `[stats]` | yes | — | `[limits]` only | — | — |
| `[registry]`, `[geoip]`, `[stats_flush]`, tier `[stats]` | — | yes | yes | — | — |
| `[trust_tasks]` | — | yes | — | — | — |
| `[witness_store]`, `[enable]` | — | — | yes | — | — |
| `[sync]` | — | — | — | — | yes |

A table a binary does not accept is refused at load.
