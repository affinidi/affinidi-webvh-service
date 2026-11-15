# Affinidi DID Hosting Server

The DID Hosting Server is a read-only DID hosting **edge** for
[WebVH](https://www.w3.org/TR/did-web-vh/) (and `did:web` / `did:webs`)
DIDs. It serves DID documents publicly and is fed by its
[control plane](../did-hosting-control/) with signed Trust Tasks —
`webvh/sync/*` and `did-management/replica/domain/*` — over TSP,
DIDComm or HTTPS (`POST /api/trust-tasks`), whichever the edge's DID document
advertises.

All DID lifecycle management (create, publish, delete) is handled
by the control plane. The edge has no management API, no sessions and
no ACL: the only party it takes directives from is its configured
`control_did`, established from each document's proof. It does not
start without one. An edge is a cache: it can be wiped and rebuilt from its
control plane. For a single-host deployment, use the
[daemon](../did-hosting-daemon/) instead. See
[docs/architecture.md](../docs/architecture.md) for how the pieces fit.

> **IMPORTANT:**
> did-hosting-service crates are provided "as is" without any
> warranties or guarantees, and by using this framework, users
> agree to assume all risks associated with its deployment and
> use including implementing security, and privacy measures in
> their applications. Affinidi assumes no liability for any
> issues arising from the use or modification of the project.

## Getting Started

### Prerequisites

- Rust: the workspace MSRV is `rust-version` in the root
  [`Cargo.toml`](../Cargo.toml) (2024 edition).
- A VTA context for the edge's own DID, and the DID of the control plane
  that will drive it.

### 1. Build

```bash
git clone https://github.com/affinidi/affinidi-webvh-service.git
cd affinidi-webvh-service
cargo build --locked -p did-hosting-server --release
```

The binary is produced at `target/release/did-hosting-server`. Or install
it with `cargo install did-hosting-server --locked` (`--locked` installs the
dependency versions this release was tested against).

### 2. Run setup

```bash
did-hosting-server setup                                   # interactive
did-hosting-server setup --from examples/did-hosting-server-build.toml \
                         --setup-key-file setup.key        # non-interactive
```

The wizard asks how to reach the VTA (online, or the two air-gapped
phases), provisions the edge's own `did:webvh` from its public URL, and asks
for the **control plane's DID** (required), the listen address (default
`0.0.0.0:8530`), logging, the data directory and the secrets backend. It
writes `config.toml` (no key material) and stores the keys in the secrets
backend. Recipes, the air-gapped flow and exit codes are in
[docs/bootstrap_startup.md](../docs/bootstrap_startup.md#non-interactive-setup-recipe-driven).

### 3. Start the server

```bash
did-hosting-server --config config.toml
```

The edge registers itself with its control plane: it sends a signed
`server/register` on startup over its mediator connection, and the control plane's administrator assigns
it domains (see [bootstrap_startup.md](../docs/bootstrap_startup.md)).

## Configuration

Every key and environment variable is listed in
[docs/configuration.md](../docs/configuration.md). The env prefix is
`DID_HOSTING_` (the deprecated `WEBVH_` names are still read; the
`DID_HOSTING_` name wins). A minimal edge:

```toml
server_did = "did:webvh:<scid>:edge1.example.com"   # written by setup
mediator_did = "did:webvh:mediator.example.com"     # omit for HTTP-only
public_url = "https://edge1.example.com"
control_did = "did:webvh:<scid>:control.example.com"  # required

[features]
didcomm = true
tsp = true

[server]
host = "0.0.0.0"
port = 8530
# Behind a reverse proxy, list it in both (see docs/deployment.md):
# trusted_proxies = ["10.0.0.0/20"]
# trusted_proxy_cidrs = ["10.0.0.0/20"]

[store]
data_dir = "data/did-hosting-server"

[secrets]
keyring_service = "webvh"
```

### Replication

The control plane delivers every change through its durable outbox and
retries until the edge acknowledges it. As the backstop, the edge
reconciles against the control plane's `did-management/did/list` every
`reconcile_interval_secs` (default 60), as a signed Trust Task whose
signed reply must come from its configured `control_did`:

- a slot whose **disabled** state differs is repaired on the spot, so a
  DID the control plane disabled stops resolving here even if the push
  was lost;
- a slot the edge is missing, holds behind, or holds but the control
  plane no longer lists makes the edge re-register, and the control plane
  queues exactly the updates and deletes it needs.

When the edge has not completed a clean reconcile within
`staleness_bound_secs` (default **300 seconds**, which must exceed the
interval), `GET /api/health` answers `503`, so a load balancer drains
it rather than let it serve state that may be out of date. The reconcile
age is reported to the control plane in `did-management/server/metrics/0.1`;
the control plane's own `server/metrics` carries each edge's outbox
depth, the age of its oldest unacknowledged directive, and the time
since its last acknowledgement and last reconcile, labelled by edge DID.
Both are also settable as `DID_HOSTING_REPLICATION_STALENESS_BOUND_SECS`
and `DID_HOSTING_REPLICATION_RECONCILE_INTERVAL_SECS`.

**A restart resets the grace period.** The staleness clock counts from the
last *clean* reconcile, or, when there has not been one yet this process,
from when the process started — so a freshly started edge answers healthy
for a full `staleness_bound_secs` even before its first reconcile completes.
Restarting the process (a crash loop, a bad deploy repeatedly bounced by a
supervisor, a manual restart) resets that clock every time: `/api/health`
can read healthy indefinitely across repeated restarts even if the edge
never actually completes a clean reconcile — e.g. because its control plane
has been unreachable the whole time. A load balancer or supervisor relying
solely on `/api/health` to detect a genuinely stuck edge should also watch
for repeated restarts, not just probe failures.

### Resolution rate limit

Resolution is public and unauthenticated, and each request reads the store.
`[server.resolve_rate_limit]` caps how many resolution requests one client
may make per window. A client may spend the whole allowance at once, and
regains one request every `window_secs / max_per_window`; past it the client
gets `429 Too Many Requests` with `Retry-After` until its next request, and
the service logs one warning per client per window. It is off by default. The Trust Task listener has its
own limiter and is not counted.

A client is its address, and an IPv6 client its network of
`server.client_ipv6_prefix` bits (default 64), as in every other
per-address limit. The address is the TCP
peer unless the peer is in `server.trusted_proxies`, in which case it is
read from `X-Forwarded-For`. Behind a load balancer, set `trusted_proxies`
first, to the load balancer's addresses or subnets (CIDR ranges such as
`10.0.0.0/20`); otherwise every client shares the load balancer's address
and one budget, and the service warns at startup. Trust only ranges from
which nothing but the load balancer can reach the service (a subnet that
holds only the load balancer, or a wider range when a firewall or security
group admits only the load balancer): anything else could set
`X-Forwarded-For` to dodge the limit.

When sizing `max_per_window`:

- The budget is per process. With N replicas behind a load balancer, one
  client gets up to N times the limit.
- In the daemon one budget covers the server's and watcher's resolution and
  the root fallback, which also serves the UI; one UI page load takes several
  dozen requests.
- At most 250,000 clients are tracked, and idle ones are swept every minute.
  When that many are live, a new client is refused until room frees up, so a
  flood from that many addresses (or IPv6 /64s) also delays new clients. A
  CDN or web application firewall is the defence against that.

## Secrets backends

Private key material (the edge's signing and key-agreement keys) is kept
outside the config file, in the backend `[secrets]` names. The OS keyring is
the default; the others are build features:

| Backend | Feature | Config fields |
| --- | --- | --- |
| OS keyring (default) | `keyring` | `keyring_service` |
| AWS Secrets Manager | `aws-secrets` | `aws_secret_name`, `aws_region` |
| GCP Secret Manager | `gcp-secrets` | `gcp_project`, `gcp_secret_name` |
| Azure Key Vault | `azure-secrets` | `azure_vault_url`, `azure_secret_name` |
| HashiCorp Vault | `vault-secrets` | `vault_addr`, `vault_secret_path`, `vault_auth_method` |
| Kubernetes Secret | `k8s-secrets` | `k8s_secret_name`, `k8s_namespace` |
| Plaintext (tests only) | always | `backend = "plaintext"` + `confirm_plaintext = true` |

Every backend is the published [`vti-secrets`](https://crates.io/crates/vti-secrets)
crate, shared with the VTA and VTC. A host where the keyring cannot be
opened is refused at setup: nothing falls back to plaintext.

```bash
cargo build --locked -p did-hosting-server --release --features vault-secrets
```

## Storage backends

The storage layer is pluggable — exactly one backend must be
selected at compile time via feature flags. The default backend
is **fjall**, an embedded key-value store that requires no
external services.

| Backend                   | Feature flag      | Config fields                                                                                                |
| ------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------ |
| Fjall (default, embedded) | `store-fjall`     | `store.data_dir`                                                                                             |
| Redis                     | `store-redis`     | `store.redis_url`                                                                                            |
| AWS DynamoDB              | `store-dynamodb`  | `store.dynamodb_table_prefix`, `store.dynamodb_region`, `store.dynamodb_billing_mode`, `store.dynamodb_auto_create` |
| Google Firestore          | `store-firestore` | `store.firestore_project`, `store.firestore_database`                                                        |
| Azure Cosmos DB           | `store-cosmosdb`  | `store.cosmosdb_connection_string`, `store.cosmosdb_database`, `store.cosmosdb_container`, `store.cosmosdb_region` |

A DID's whole log is stored as one item, so a backend's item size limit is
the largest log it can hold: about 400 KB on DynamoDB, and about 750 KB on
Firestore (1 MiB, with the log stored base64-encoded). The other backends hold
any log `did/register` accepts (1 MiB). An update that would take a log past
the limit is refused with the size in its message, and the DID keeps its last
version; with 2.3 KB entries, a DynamoDB-backed DID takes about 170 updates.
A DID at its limit takes no further entry, a deactivation or key rotation
included. An edge whose store holds less than its control plane's refuses
the larger logs and keeps serving the versions it had (the control plane logs
a warning), so give edges a store whose limit is at least the control
plane's.

A change that spans several items (a DID's record, log, witness file and
agent names) is written atomically. On DynamoDB that is one transaction,
which takes at most 100 writes and 4 MB, so a single change over either is
refused with nothing written rather than split. Only a DID with close to 100
agent names, or with a log and witness file together near 4 MB, comes near
it. On Firestore it is one commit, of at most 500 writes and about 10 MB.
`backup restore` is a bulk load and is split across as many transactions as
it needs.

## DID method features

| Feature | Default | Serves |
| --- | --- | --- |
| `method-webvh` | on | `did.jsonl`, `did-witness.json` |
| `method-web` | on | `did.json` (a `did:web` record, or the `did:web` form of a `did:webvh`) |
| `method-webs` | off | `keri.cesr`, and `did.json` for `did:webs` records (pulls the KERI stack; see [did-webs-hosting.md](../docs/did-webs-hosting.md)) |

A build with `--no-default-features` drops the method features too, and an
edge with no method compiled in 404s every resolution. Opt them back in:

```bash
cargo build --locked -p did-hosting-server --release \
  --no-default-features --features "keyring,store-fjall,method-webvh,method-web"
```

## HTTP endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/health` | Liveness probe; `503` when the edge's own DID is not served locally or it is past the staleness bound |
| `POST` | `/api/trust-tasks` | The HTTPS binding of the edge's Trust Task listener (its control plane only) |
| `GET` | `/{mnemonic}/did.jsonl`, `/.well-known/did.jsonl` | `did:webvh` log |
| `GET` | `/{mnemonic}/did-witness.json`, `/.well-known/did-witness.json` | `did:webvh` witness proofs |
| `GET` | `/{mnemonic}/did.json`, `/.well-known/did.json` | `did:web` document (`method-web`; `did:webs` with `method-webs`) |
| `GET` | `/{mnemonic}/keri.cesr` | `did:webs` key event log (`method-webs`) |
| `GET` | `/@`, `/@{name}`, `/@{name}/{context}` | Agent-name redirect (`302` to the DID); `404` when unbound or `features.agent_names` is off |

[`docs/openapi.json`](../docs/openapi.json) is generated from these handlers
(a test keeps it current). There is no management API, and no metrics scrape
endpoint: the control plane reads an edge's metrics with the signed
`server/metrics` Trust Task (see [docs/metrics.md](../docs/metrics.md)).

## CLI commands

Every subcommand, with its full `--help`, is in
[`docs/cli-reference.md`](../docs/cli-reference.md). `health` exits non-zero
when a check fails (`--strict`: also when one warns).

```
did-hosting-server                      # Run server (default)
did-hosting-server setup                # Interactive or --from <recipe> setup
did-hosting-server uninstall            # Clear managed secrets + remove config
did-hosting-server health [--strict]    # Diagnostics
did-hosting-server identity-list        # This node's identity generations
did-hosting-server list-dids | dump-did | load-did | remove-did | recover-did
did-hosting-server bootstrap-did | recreate-did
did-hosting-server backup | restore
did-hosting-server export-sealed | import-sealed | import-secrets
```

### Backup and restore

```bash
did-hosting-server backup --output /path/to/backup.json
did-hosting-server restore --input /path/to/backup.json
```

The backup (format version 3) is one JSON document holding the effective
configuration and the edge's keyspaces: `dids`, `stats`, `domains`,
`assignments`, `pending_purges`, `registry`, `timeseries`, `meta` and
`witnesses`. It holds no ACL and no sessions (an edge has neither) and no
private keys (those live in the secrets backend). A restore checks the whole
backup before writing anything: each log must verify, match its record and
extend what the store already holds. Re-running an interrupted restore is
safe. Since an edge is a cache, rebuilding it from its control plane
(register it again on an empty store) is usually simpler than restoring it;
see [docs/backup-and-upgrade.md](../docs/backup-and-upgrade.md).

## Performance testing

The `perf_test` example is an interactive TUI benchmarking tool
for load-testing a running DID Hosting server. It sends concurrent DID
resolution requests and displays real-time metrics including
throughput, latency percentiles, network bandwidth, active
workers, and error rates.

### Building

```bash
cargo build --locked --example perf_test -p did-hosting-server
```

### Usage

```bash
cargo run --example perf_test -p did-hosting-server -- [OPTIONS]
```

The tool supports two modes. **Server mode** (default) signs Trust Tasks
to a DID Hosting control plane (`did-hosting-control`, or a
`did-hosting-daemon`'s embedded one) over `POST /api/trust-tasks`, lists
its active DIDs and resolves each at its hosting URL; it needs
`--webvh-did` (the service's DID, which every request is addressed to and
every reply must be signed by) and, when DIDs resolve on a different
origin than the management URL, `--hosting-url`. **File mode**
(`--did-file`) reads `did:webvh:...` identifiers from a file and works
against any hosted WebVH DID without needing ACL access.

### Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--server-url` | `-s` | `http://localhost:8530` | Management URL (the control plane's, or the daemon's) |
| `--hosting-url` | | `--server-url` | Public URL DID logs are served from, when it differs from the management URL |
| `--webvh-did` | | | The service's DID (required in server mode) |
| `--rate` | `-r` | `10` | Target requests per second (adjustable at runtime) |
| `--workers` | `-w` | `64` | Maximum concurrent in-flight requests |
| `--threads` | `-T` | CPU cores | Tokio worker threads |
| `--timeout` | `-t` | `5` | Request timeout in seconds |
| `--create-dids` | | `0` | Number of random DIDs to create on startup |
| `--create-parallel` | | `4` | Parallel concurrency for DID creation |
| `--seed` | | random | Ed25519 seed as 64 hex characters |
| `--did-file` | `-f` | | File of `did:webvh:...` identifiers (skips auth) |

### Keyboard Controls

| Key | Action |
| --- | ------ |
| `q` / `Esc` | Quit |
| `+` / `=` / `Up` | Increase target rate by 10 req/s |
| `-` / `Down` | Decrease target rate by 10 req/s |
| `]` | Double target rate |
| `[` | Halve target rate |

## Library Usage

The did-hosting-server crate can be used as a library (e.g., by the
[did-hosting-daemon](../did-hosting-daemon/)). It exposes:

- `did_hosting_server::config::AppConfig` — configuration
- `did_hosting_server::server::AppState` — application state
- `did_hosting_server::routes::router()` — Axum router
- `did_hosting_server::server::run()` — standalone entry point

## Support & feedback

If you face any issues or have suggestions, please don't
hesitate to contact us using
[this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

If you have a technical issue with the codebase, search the
[issues](https://github.com/affinidi/affinidi-webvh-service/issues) and, if
it is not there,
[open a new one](https://github.com/affinidi/affinidi-webvh-service/issues/new)
with a clear description and, ideally, a failing test.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md).
