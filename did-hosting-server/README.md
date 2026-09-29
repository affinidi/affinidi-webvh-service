# Affinidi DID Hosting Server

The DID Hosting Server is a read-only DID hosting edge node for
[WebVH](https://www.w3.org/TR/did-web-vh/) DIDs. It serves DID
documents publicly and is fed by its
[control plane](../did-hosting-control/) with signed Trust Tasks —
`webvh/sync/*` and `did-management/replica/domain/*` — over TSP,
DIDComm or HTTPS (`POST /api/trust-tasks`).

All DID lifecycle management (create, publish, delete) is handled
by the control plane. The edge has no management API, no sessions and
no ACL: the only party it takes directives from is its configured
`control_did`, established from each document's proof. It does not
start without one. For a single-host deployment, use the
[daemon](../did-hosting-daemon/) instead.

> **IMPORTANT:**
> did-hosting-service crates are provided "as is" without any
> warranties or guarantees, and by using this framework, users
> agree to assume all risks associated with its deployment and
> use including implementing security, and privacy measures in
> their applications. Affinidi assumes no liability for any
> issues arising from the use or modification of the project.

## Getting Started

This guide walks you through building the server, obtaining
credentials from your Affinidi Trust Context (VTA), and running
the interactive setup wizard.

### Prerequisites

- Rust 1.94.0+ (2024 Edition)
- A VTA credential (base64url string) for the server's VTA context

### 1. Clone and build

```bash
git clone https://github.com/affinidi/did-hosting-service.git
cd did-hosting-service
cargo build --locked -p did-hosting-server --release
```

The binary is produced at `target/release/did-hosting-server`.

Alternatively, you can install the server directly with Cargo:

```bash
cargo install did-hosting-server --locked
```

`--locked` installs the exact dependency versions this release was built
and tested against. Without it, Cargo ignores the published lockfile and
re-resolves to the newest semver-compatible versions of every dependency,
which can pull in an upstream release that has not been tested against
this one.

### 2. Run the setup wizard

```bash
did-hosting-server setup
```

For CI / scripted deployments, drop the wizard prompts and use a
declarative recipe:

```bash
# Online (after `setup --setup-key-out` enrolment of an ephemeral did:key):
did-hosting-server setup --from examples/did-hosting-server-build.toml \
                   --setup-key-file setup.key

# Air-gapped (both phases non-interactive):
did-hosting-server setup --from recipe.toml   # phase 1: writes bootstrap-request.json
# (operator ferries to VTA admin, gets sealed bundle back)
did-hosting-server setup --from recipe.toml   # phase 2 (vta_mode = "offline-complete"
                                        # + bundle_path + expect_digest set)
```

See [docs/bootstrap_startup.md](../docs/bootstrap_startup.md#non-interactive-setup-recipe-driven)
for the recipe schema, env-var overlay, exit codes, and reprovision
safety.

The wizard walks you through all required configuration:

- **VTA credential** — authenticates with the server's VTA
  context and creates the root DID automatically
- **Features** — enable DIDComm messaging and/or REST API
- **Public URL** — the externally reachable URL of this server
- **Control plane** — URL and DID of the did-hosting-control service
- **Host / port** — listen address (default: `0.0.0.0:8530`)
- **Log level / format** — logging configuration
- **Data directory** — persistent storage path
- **Secrets backend** — where to store private key material
  (OS keyring, AWS Secrets Manager, or GCP Secret Manager)
- **Admin bootstrap** — enter an existing DID or generate a
  new `did:key` identity

The wizard writes `config.toml` (without any key material) and
stores the server's private keys in the chosen secrets backend.

### 3. Start the server

```bash
did-hosting-server --config config.toml
```

On startup the server loads secrets from the configured backend.
If no secrets are found it exits with an error directing you to
run `did-hosting-server setup` first.

## Configuration

The server is configured via a TOML file. By default it looks
for `config.toml` in the current directory. You can specify a
different path with the `--config` flag or the
`DID_HOSTING_CONFIG_PATH` environment variable.

### Example `config.toml`

```toml
# Server DID identity (required: the control plane addresses and verifies it)
server_did = "did:webvh:webvh.example.com"
mediator_did = "did:webvh:mediator.example.com"
public_url = "https://webvh.example.com"
# The control plane that drives this edge (required)
control_did = "did:webvh:control.example.com"

[features]
didcomm = true
# agent_names = true   # serve GET /@alice -> 302 to the DID. On by default;
                       # set false to leave the /@… namespace unserved.

[server]
host = "0.0.0.0"    # Bind address
port = 8530          # Bind port

[log]
level = "info"       # trace, debug, info, warn, error
format = "text"      # text or json

[store]
data_dir = "data/did-hosting-server"   # Persistent data directory (fjall)

[auth]
cleanup_ttl_minutes = 60                    # Empty DID cleanup (minutes)

[secrets]
keyring_service = "webvh"                   # OS keyring service name (default backend)
# aws_secret_name = "did-hosting-server-secrets"  # Use AWS Secrets Manager instead
# aws_region = "us-east-1"
# gcp_project = "my-project"               # Use GCP Secret Manager instead
# gcp_secret_name = "did-hosting-server-secrets"
# vault_addr = "https://vault.example.com:8200"    # Use HashiCorp Vault instead
# vault_secret_path = "webvh/server-secrets"       # KV v2 path (mount defaults to "secret")
# vault_auth_method = "kubernetes"                 # kubernetes (default) | token | approle
# vault_k8s_role = "did-hosting-server"            # Vault role, for kubernetes auth
# k8s_secret_name = "did-hosting-server-secrets"   # Use a native Kubernetes Secret instead
# k8s_namespace = "webvh"                          # optional; defaults to the pod's namespace

[limits]
upload_body_limit = 102400                  # Max Trust Task body over HTTPS (floor 1 MiB)

[replication]
staleness_bound_secs = 300                  # /api/health answers 503 past this (default 5 min)
reconcile_interval_secs = 60                # How often to reconcile with the control plane
```

Private keys (signing, key agreement, JWT signing) are **not**
stored in the config file. They are managed by the secrets
backend selected during `did-hosting-server setup`. See
[Secrets Backends](#secrets-backends) below.

#### Replication staleness bound

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

#### Limits

- **`upload_body_limit`** — Maximum body of a `POST /api/trust-tasks`
  request. Never below 1 MiB, so the control plane's largest
  `sync/batch` always fits.

Per-account quotas are the control plane's concern: an edge serves
whatever its control plane has accepted.

### Secrets Backends

Private key material is stored outside the config file in a
pluggable secrets backend. The backend is selected at compile
time via feature flags and at runtime via config/env vars.

| Backend              | Feature flag    | Config fields                                                                  |
| -------------------- | --------------- | ------------------------------------------------------------------------------ |
| OS Keyring (default) | `keyring`       | `secrets.keyring_service`                                                      |
| AWS Secrets Manager  | `aws-secrets`   | `secrets.aws_secret_name`, `secrets.aws_region`                                |
| GCP Secret Manager   | `gcp-secrets`   | `secrets.gcp_project`, `secrets.gcp_secret_name`                               |
| Azure Key Vault      | `azure-secrets` | `secrets.azure_vault_url`, `secrets.azure_secret_name`                         |
| HashiCorp Vault      | `vault-secrets` | `secrets.vault_addr`, `secrets.vault_secret_path`, `secrets.vault_auth_method` (`kubernetes`/`token`/`approle`) |
| Kubernetes Secret    | `k8s-secrets`   | `secrets.k8s_secret_name`, `secrets.k8s_namespace`                             |
| Plaintext (tests)    | *(always)*      | `secrets.backend = "plaintext"` + `secrets.confirm_plaintext = true` — **tests only**, keys in a clear-text file beside the config |

Every backend is the published [`vti-secrets`](https://crates.io/crates/vti-secrets)
crate, shared with the VTA and VTC. The OS keyring is the default. A host
where it cannot be opened (a headless Linux box with no Secret Service) is
refused at setup with the list of secure backends above: nothing falls back
to plaintext. Set `secrets.backend` to name the backend explicitly.

The server stores its key material as a JSON-serialized record
in the backend:

- **signing_key** — Ed25519 private key for server DID signing
- **key_agreement_key** — X25519 private key for DIDComm
  encryption
- **jwt_signing_key** — Ed25519 private key for JWT token
  signing
- **vta_credential** — VTA credential for re-authentication
  (optional)

Keys are stored in multibase format (Base58BTC with multicodec
type prefix), which is self-describing and can be directly
loaded as `Secret` objects.

To compile with a non-default backend:

```bash
# AWS Secrets Manager
cargo build --locked -p did-hosting-server --release --features aws-secrets

# GCP Secret Manager
cargo build --locked -p did-hosting-server --release --features gcp-secrets

# HashiCorp Vault (Kubernetes / token / AppRole auth)
cargo build --locked -p did-hosting-server --release --features vault-secrets

# Native Kubernetes Secret
cargo build --locked -p did-hosting-server --release --features k8s-secrets

# Multiple backends
cargo build --locked -p did-hosting-server --release --features "keyring,aws-secrets"
```

### Storage Backends

The storage layer is pluggable — exactly one backend must be
selected at compile time via feature flags. The default backend
is **fjall**, an embedded key-value store that requires no
external services.

| Backend                   | Feature flag      | Config fields                                                                                                |
| ------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------ |
| Fjall (default, embedded) | `store-fjall`     | `store.data_dir`                                                                                             |
| Redis                     | `store-redis`     | `store.redis_url`                                                                                            |
| AWS DynamoDB              | `store-dynamodb`  | `store.dynamodb_table`, `store.dynamodb_region`                                                              |
| Google Firestore          | `store-firestore` | `store.firestore_project`, `store.firestore_database`                                                        |
| Azure Cosmos DB           | `store-cosmosdb`  | `store.cosmosdb_endpoint`, `store.cosmosdb_database`, `store.cosmosdb_container`, `store.cosmosdb_region`    |

To build with a non-default storage backend:

```bash
cargo build --locked -p did-hosting-server --release \
  --no-default-features --features "keyring,store-redis"
```

> **Note:** Enabling more than one `store-*` feature or zero
> `store-*` features will produce a compile error (enforced by
> `did-hosting-server/build.rs`).

### DID method features

The public DID-resolution routes (`GET /{mnemonic}/did.jsonl`,
`GET /{mnemonic}/did.json`, the `.well-known` variants) are gated
at compile time by **method features**. At least one must be
enabled for any DID to be resolvable.

| Feature        | What it enables                                       |
| -------------- | ----------------------------------------------------- |
| `method-webvh` | did:webvh resolution (`/did.jsonl`, `/did-witness.json`) |
| `method-web`   | did:web resolution (`/did.json`)                      |

Both ship in the default feature set, so the most common builds
need no special handling:

```bash
cargo build --locked -p did-hosting-server --release
cargo install did-hosting-server --locked
```

> **Heads-up if you build with `--no-default-features`:** the
> method gates come off too. A build that drops `method-webvh`
> will compile, start, load DIDs from the store, and then 404
> every `/{mnemonic}/did.jsonl` request with an **empty response
> body** (the per-method dispatcher in
> `did_public::serve_public` is `#[cfg]`-gated out). If you go
> minimal, opt the methods back in explicitly:
>
> ```bash
> cargo build --locked -p did-hosting-server --release \
>   --no-default-features \
>   --features "keyring,store-fjall,method-webvh,method-web"
> ```

### Environment Variable Overrides

Every config field can be overridden via environment variables
with the `DID_HOSTING_` prefix:

| Variable                              | Description                        |
| ------------------------------------- | ---------------------------------- |
| `DID_HOSTING_CONFIG_PATH`                   | Path to config file                |
| `DID_HOSTING_SERVER_DID`                    | Server DID identifier              |
| `DID_HOSTING_PUBLIC_URL`                    | Public URL of the server           |
| `DID_HOSTING_MEDIATOR_DID`                  | Mediator DID identifier            |
| `DID_HOSTING_FEATURES_DIDCOMM`             | Enable DIDComm (`true` / `1`)      |
| `DID_HOSTING_FEATURES_REST_API`            | Enable REST API (`true` / `1`)     |
| `DID_HOSTING_SERVER_HOST`                   | Bind host                          |
| `DID_HOSTING_SERVER_PORT`                   | Bind port                          |
| `DID_HOSTING_LOG_LEVEL`                     | Log level                          |
| `DID_HOSTING_LOG_FORMAT`                    | Log format (`text` / `json`)       |
| `DID_HOSTING_STORE_DATA_DIR`               | Data directory path (fjall)        |
| `DID_HOSTING_AUTH_ACCESS_EXPIRY`            | Access token expiry (sec)          |
| `DID_HOSTING_AUTH_REFRESH_EXPIRY`           | Refresh token expiry (sec)         |
| `DID_HOSTING_AUTH_CHALLENGE_TTL`            | Auth challenge TTL (sec)           |
| `DID_HOSTING_AUTH_SESSION_CLEANUP_INTERVAL` | Session cleanup interval (sec)     |
| `DID_HOSTING_CLEANUP_TTL_MINUTES`          | Empty DID cleanup TTL (min)        |
| `DID_HOSTING_SECRETS_KEYRING_SERVICE`       | Keyring service name               |
| `DID_HOSTING_SECRETS_AWS_SECRET_NAME`       | AWS Secrets Manager secret name    |
| `DID_HOSTING_SECRETS_AWS_REGION`            | AWS region                         |
| `DID_HOSTING_SECRETS_GCP_PROJECT`           | GCP project ID                     |
| `DID_HOSTING_SECRETS_GCP_SECRET_NAME`       | GCP Secret Manager secret name     |
| `DID_HOSTING_LIMITS_UPLOAD_BODY_LIMIT`      | Max upload body size (bytes)       |
| `DID_HOSTING_LIMITS_DEFAULT_MAX_TOTAL_SIZE` | Per-account total DID size (bytes) |
| `DID_HOSTING_LIMITS_DEFAULT_MAX_DID_COUNT`  | Per-account max DID count          |

## Building

### Default (with OS keyring)

```bash
cargo build --locked -p did-hosting-server --release
```

This builds with the `keyring` and `store-fjall` features
enabled by default.

## CLI Commands

```
did-hosting-server                      # Run server (default)
did-hosting-server setup                # Interactive config wizard
did-hosting-server setup --from <recipe.toml>  # Non-interactive — see below
did-hosting-server uninstall            # Teardown: clear secrets + remove config
did-hosting-server health               # Run health check diagnostics
did-hosting-server list-dids            # List all DIDs in the store
did-hosting-server remove-did           # Remove a DID from the store
did-hosting-server dump-did             # Dump DID log for a path
did-hosting-server load-did             # Load a DID at an arbitrary path
did-hosting-server bootstrap-did        # Bootstrap a DID (defaults to .well-known)
did-hosting-server recreate-did         # Recreate a DID at a given path
did-hosting-server recover-did          # Recover a soft-deleted DID
did-hosting-server import-secrets       # Import secrets from VTA bundle or keys
did-hosting-server backup               # Export data to backup file
did-hosting-server restore              # Restore data from backup file
```

### Backup & Restore

```bash
# Backup to default file (webvh-backup.json)
did-hosting-server backup

# Backup to a specific file
did-hosting-server backup --output /path/to/backup.json

# Restore data and config.toml
did-hosting-server restore --input /path/to/backup.json
```

The backup file is a single JSON document containing:

- **config** — the effective server configuration at backup time
- **dids** — all DID documents and logs
- **acl** — access control entries
- **stats** — DID resolution statistics

Ephemeral data (active sessions, refresh tokens, auth
challenges) is excluded. All keys and values are base64url
encoded.

## HTTP Endpoints

| Method | Path                            | Description     |
| ------ | ------------------------------- | --------------- |
| `GET`  | `/api/health`                   | Liveness probe; 503 past the staleness bound |
| `POST` | `/api/trust-tasks`              | Trust Task listener (HTTPS binding) |
| `GET`  | `/{mnemonic}/did.jsonl`         | Resolve DID log |
| `GET`  | `/{mnemonic}/did-witness.json`  | Resolve witness |
| `GET`  | `/.well-known/did.jsonl`        | Root DID log    |
| `GET`  | `/.well-known/did-witness.json` | Root witness    |

There is no management API. DIDs, domains and their state reach the
edge only as Trust Tasks signed by its control plane.

## Performance Testing

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

The tool supports two modes: **server mode** (default) authenticates
with a DID Hosting server and discovers DIDs automatically, while
**file mode** (`--did-file`) reads `did:webvh:...` identifiers from
a file and works against any hosted WebVH DID without needing
ACL access.

### Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--server-url` | `-s` | `http://localhost:8530` | DID Hosting server URL |
| `--rate` | `-r` | `10` | Target requests per second (adjustable at runtime) |
| `--workers` | `-w` | `64` | Maximum concurrent in-flight requests |
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

### Reporting technical issues

If you have a technical issue with the Affinidi DID Hosting Service
codebase, you can also create an issue directly in GitHub.

1. Ensure the bug was not already reported by searching on
   GitHub under
   [Issues](https://github.com/affinidi/did-hosting-service/issues).

2. If you're unable to find an open issue addressing the
   problem,
   [open a new one](https://github.com/affinidi/did-hosting-service/issues/new).
   Be sure to include a **title and clear description**, as
   much relevant information as possible, and a **code sample**
   or an **executable test case** demonstrating the expected
   behaviour that is not occurring.

## Contributing

Want to contribute? Head over to our
[CONTRIBUTING](https://github.com/affinidi/did-hosting-service/blob/main/CONTRIBUTING.md)
guidelines.
