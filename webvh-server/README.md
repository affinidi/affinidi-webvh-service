# Affinidi WebVH Server

The WebVH Server hosts and manages
[WebVH](https://www.w3.org/TR/did-web-vh/) DIDs. It provides a
REST API for DID lifecycle management (create, upload, delete),
access control, statistics, and public DID resolution endpoints.
An optional built-in management UI can be embedded directly into
the binary.

> **IMPORTANT:**
> affinidi-webvh-service crates are provided "as is" without any
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

- Rust 1.91.0+ (2024 Edition)
- Node.js 18+ (only if building with the management UI)
- A running [VTA](https://github.com/nicktho/vtc-vta-rs) instance
  with admin access (optional — needed to import a DID secrets
  bundle; you can also generate keys during setup)

### 1. Clone and build

```bash
git clone https://github.com/affinidi/affinidi-webvh-service.git
cd affinidi-webvh-service
cargo build -p webvh-server --release
```

The binary is produced at `target/release/webvh-server`.

Alternatively, you can install the server directly with Cargo:

```bash
cargo install -p webvh-server
```

### 2. Obtain server DID credentials (optional)

The WebVH server needs its own DID identity for DIDComm
authentication. The setup wizard can either import credentials
from your VTA or generate fresh keys.

**Option A — Import from VTA (recommended):** Export a DID
secrets bundle from your VTA instance:

```bash
vta export-admin
```

This prints output like:

```
VTA DID: did:webvh:vta.example.com
Mediator DID: did:webvh:mediator.example.com

Admin DID: did:key:z6Mk...
  Label: webvh-server

  Credential:
  eyJkaWQiOiJkaWQ6a2V5Ono2TWsu...
```

Copy the base64url credential string — the setup wizard will
ask for it.

**Option B — Manual entry:** If you don't have a VTA instance,
the setup wizard can generate new Ed25519 and X25519 keys for
you, or you can paste your own multibase-encoded private keys.

### 3. Run the setup wizard

```bash
webvh-server setup
```

The wizard walks you through all required configuration:

- **Configuration file path** — where to write `config.toml`
- **Features** — enable DIDComm messaging and/or REST API
- **Server DID identity** — import a VTA secrets bundle *or*
  enter the server DID and keys manually (generate or paste)
- **Mediator DID** — the DIDComm mediator to route messages
  through
- **Public URL** — the externally reachable URL of this server
- **Host / port** — listen address (default: `0.0.0.0:8101`)
- **Log level / format** — logging configuration
- **Data directory** — persistent storage path
- **Secrets backend** — where to store private key material
  (OS keyring, AWS Secrets Manager, or GCP Secret Manager)
- **Admin bootstrap** — optionally create an initial admin
  ACL entry and passkey enrollment link

The wizard writes `config.toml` (without any key material) and
stores the server's private keys in the chosen secrets backend.

### 4. Start the server

```bash
webvh-server --config config.toml
```

On startup the server loads secrets from the configured backend.
If no secrets are found it exits with an error directing you to
run `webvh-server setup` first.

## Configuration

The server is configured via a TOML file. By default it looks
for `config.toml` in the current directory. You can specify a
different path with the `--config` flag or the
`WEBVH_CONFIG_PATH` environment variable.

### Example `config.toml`

```toml
# Server DID identity (required for DIDComm auth)
server_did = "did:webvh:webvh.example.com"
mediator_did = "did:webvh:mediator.example.com"
public_url = "https://webvh.example.com"

[features]
didcomm = true
rest_api = true

[server]
host = "0.0.0.0"    # Bind address
port = 8101          # Bind port

[log]
level = "info"       # trace, debug, info, warn, error
format = "text"      # text or json

[store]
data_dir = "data/webvh-server"   # Persistent data directory (fjall)
# redis_url = "redis://localhost:6379"           # Redis backend
# dynamodb_table_prefix = "webvh"                # DynamoDB backend
# dynamodb_region = "us-east-1"
# firestore_project = "my-gcp-project"           # Firestore backend
# firestore_database = "(default)"
# cosmosdb_connection_string = "AccountEndpoint=...;AccountKey=..."  # Cosmos DB
# cosmosdb_database = "webvh"

[auth]
access_token_expiry = 900                   # 15 minutes
refresh_token_expiry = 86400                # 24 hours
challenge_ttl = 300                         # 5 minutes
session_cleanup_interval = 600              # 10 minutes
passkey_enrollment_ttl = 86400              # 24 hours
cleanup_ttl_minutes = 60                    # Empty DID cleanup (minutes)

[secrets]
keyring_service = "webvh"                   # OS keyring service name (default backend)
# aws_secret_name = "webvh-server-secrets"  # Use AWS Secrets Manager instead
# aws_region = "us-east-1"
# gcp_project = "my-project"               # Use GCP Secret Manager instead
# gcp_secret_name = "webvh-server-secrets"

[limits]
upload_body_limit = 102400                  # Max upload body size (bytes), default 100KB
default_max_total_size = 1048576            # Per-account total DID size (bytes), default 1MB
default_max_did_count = 20                  # Per-account max number of DIDs
```

Private keys (signing, key agreement, JWT signing) are **not**
stored in the config file. They are managed by the secrets
backend selected during `webvh-server setup`. See
[Secrets Backends](#secrets-backends) below.

#### Resource Limits

The `[limits]` section controls per-account resource quotas:

- **`upload_body_limit`** — Maximum request body size for
  `did.jsonl` and witness uploads. Requests exceeding this are
  rejected with `413 Payload Too Large`. Default: `102400`
  (100 KB).

- **`default_max_total_size`** — Default per-account total size
  across all DID documents. When an upload would push an
  account's combined DID content above this limit, the request
  is rejected. Default: `1048576` (1 MB).

- **`default_max_did_count`** — Default per-account maximum
  number of DIDs. Once reached, new DID creation requests are
  rejected. Default: `20`.

Admins are exempt from all quota checks. Per-account overrides
can be set via the ACL API by including `max_total_size` and/or
`max_did_count` in the ACL entry — these take precedence over
the global defaults.

### Secrets Backends

Private key material is stored outside the config file in a
pluggable secrets backend. The backend is selected at compile
time via feature flags and at runtime via config/env vars.

| Backend              | Feature flag  | Config fields                                    |
| -------------------- | ------------- | ------------------------------------------------ |
| OS Keyring (default) | `keyring`     | `secrets.keyring_service`                        |
| AWS Secrets Manager  | `aws-secrets` | `secrets.aws_secret_name`, `secrets.aws_region`  |
| GCP Secret Manager   | `gcp-secrets` | `secrets.gcp_project`, `secrets.gcp_secret_name` |

The server stores three keys as a JSON-serialized bundle in the
backend:

- **signing_key** — Ed25519 private key for server DID signing
- **key_agreement_key** — X25519 private key for DIDComm
  encryption
- **jwt_signing_key** — Ed25519 private key for JWT token
  signing

Keys are stored in multibase format (Base58BTC with multicodec
type prefix), which is self-describing and can be directly
loaded as `Secret` objects.

To compile with a non-default backend:

```bash
# AWS Secrets Manager
cargo build -p affinidi-webvh-server --release --features aws-secrets

# GCP Secret Manager
cargo build -p affinidi-webvh-server --release --features gcp-secrets

# Multiple backends
cargo build -p affinidi-webvh-server --release --features "keyring,aws-secrets"
```

### Storage Backends

The storage layer is pluggable — exactly one backend must be
selected at compile time via feature flags. The default backend
is **fjall**, an embedded key-value store that requires no
external services.

| Backend                   | Feature flag     | Config fields                                                  |
| ------------------------- | ---------------- | -------------------------------------------------------------- |
| Fjall (default, embedded) | `store-fjall`    | `store.data_dir`                                               |
| Redis                     | `store-redis`    | `store.redis_url`                                              |
| AWS DynamoDB              | `store-dynamodb` | `store.dynamodb_table_prefix`, `store.dynamodb_region`         |
| GCP Firestore             | `store-firestore`| `store.firestore_project`, `store.firestore_database`          |
| Azure Cosmos DB           | `store-cosmosdb` | `store.cosmosdb_connection_string`, `store.cosmosdb_database`  |

To build with a non-default storage backend:

```bash
# Redis
cargo build -p affinidi-webvh-server --release \
  --no-default-features --features "keyring,store-redis"

# DynamoDB
cargo build -p affinidi-webvh-server --release \
  --no-default-features --features "keyring,store-dynamodb"

# Firestore
cargo build -p affinidi-webvh-server --release \
  --no-default-features --features "keyring,store-firestore"

# Cosmos DB
cargo build -p affinidi-webvh-server --release \
  --no-default-features --features "keyring,store-cosmosdb"
```

> **Note:** Enabling more than one `store-*` feature or zero
> `store-*` features will produce a compile error. Fjall provides
> full ACID transactions; cloud backends provide best-effort
> batched writes.

### Environment Variable Overrides

Every config field can be overridden via environment variables:

| Variable                              | Description                        |
| ------------------------------------- | ---------------------------------- |
| `WEBVH_CONFIG_PATH`                   | Path to config file                |
| `WEBVH_SERVER_DID`                    | Server DID identifier              |
| `WEBVH_PUBLIC_URL`                    | Public URL of the server           |
| `WEBVH_MEDIATOR_DID`                  | Mediator DID identifier            |
| `WEBVH_FEATURES_DIDCOMM`              | Enable DIDComm (`true` / `1`)      |
| `WEBVH_FEATURES_REST_API`             | Enable REST API (`true` / `1`)     |
| `WEBVH_SERVER_HOST`                   | Bind host                          |
| `WEBVH_SERVER_PORT`                   | Bind port                          |
| `WEBVH_LOG_LEVEL`                     | Log level                          |
| `WEBVH_LOG_FORMAT`                    | Log format (`text` / `json`)       |
| `WEBVH_STORE_DATA_DIR`                | Data directory path (fjall)        |
| `WEBVH_STORE_REDIS_URL`               | Redis connection URL               |
| `WEBVH_STORE_DYNAMODB_TABLE_PREFIX`   | DynamoDB table name prefix         |
| `WEBVH_STORE_DYNAMODB_REGION`         | AWS region for DynamoDB            |
| `WEBVH_STORE_FIRESTORE_PROJECT`       | GCP project ID for Firestore       |
| `WEBVH_STORE_FIRESTORE_DATABASE`      | Firestore database name            |
| `WEBVH_STORE_COSMOSDB_CONNECTION_STRING` | Cosmos DB connection string     |
| `WEBVH_STORE_COSMOSDB_DATABASE`       | Cosmos DB database name            |
| `WEBVH_AUTH_ACCESS_EXPIRY`            | Access token expiry (sec)          |
| `WEBVH_AUTH_REFRESH_EXPIRY`           | Refresh token expiry (sec)         |
| `WEBVH_AUTH_CHALLENGE_TTL`            | Auth challenge TTL (sec)           |
| `WEBVH_AUTH_SESSION_CLEANUP_INTERVAL` | Session cleanup interval (sec)     |
| `WEBVH_AUTH_PASSKEY_ENROLLMENT_TTL`   | Passkey enrollment TTL (sec)       |
| `WEBVH_CLEANUP_TTL_MINUTES`           | Empty DID cleanup TTL (min)        |
| `WEBVH_SECRETS_KEYRING_SERVICE`       | Keyring service name               |
| `WEBVH_SECRETS_AWS_SECRET_NAME`       | AWS Secrets Manager secret name    |
| `WEBVH_SECRETS_AWS_REGION`            | AWS region                         |
| `WEBVH_SECRETS_GCP_PROJECT`           | GCP project ID                     |
| `WEBVH_SECRETS_GCP_SECRET_NAME`       | GCP Secret Manager secret name     |
| `WEBVH_LIMITS_UPLOAD_BODY_LIMIT`      | Max upload body size (bytes)       |
| `WEBVH_LIMITS_DEFAULT_MAX_TOTAL_SIZE` | Per-account total DID size (bytes) |
| `WEBVH_LIMITS_DEFAULT_MAX_DID_COUNT`  | Per-account max DID count          |

## Building

### Default (with OS keyring)

```bash
cargo build -p affinidi-webvh-server --release
```

This builds with the `keyring` feature enabled by default.

### With Management UI

The `ui` feature flag embeds a web-based management interface
directly into the server binary using `rust-embed`. When
enabled, the server serves the UI as a fallback for any
unmatched GET requests, alongside the API — no separate web
server needed.

First, build the UI:

```bash
cd webvh-ui
npm install
npm run build:web
cd ..
```

Then build the server with the `ui` feature:

```bash
cargo build -p affinidi-webvh-server --release --features ui
```

The `webvh-ui/dist/` output is compiled into the binary at
build time — the dist directory is not needed at runtime.

## Running

Before starting the server for the first time, run the setup
wizard to generate `config.toml` and store secrets (see
[Getting Started](#getting-started)).

```bash
# With default config.toml in current directory
./target/release/webvh-server

# With a specific config file
./target/release/webvh-server --config /path/to/config.toml
```

If the server was built with `--features ui`, browse to
`http://localhost:8101/` to access the management UI. The UI
lets you:

- View server health and DID counts
- Authenticate with a Bearer token
- Create, upload, and delete DIDs
- Upload witness proofs
- View DID resolution statistics
- Manage access control entries (admin only)

All API endpoints continue to work at their normal paths
regardless of whether the UI is enabled.

## Access Control

The `add-acl` command lets you create ACL entries directly from
the command line, without needing a running server or
authenticated API call. This is useful for bootstrapping the
first admin account or granting access during initial setup.

```bash
# Add an admin
webvh-server add-acl --did did:key:z6Mk... --role admin

# Add an owner (default role)
webvh-server add-acl --did did:key:z6Mk...

# Add an owner with per-account quota overrides
webvh-server add-acl --did did:key:z6Mk... --max-total-size 2097152 --max-did-count 50

# With a specific config file
webvh-server --config /path/to/config.toml add-acl --did did:key:z6Mk... --role admin
```

The command will refuse to overwrite an existing entry — delete
it via the API first if you need to change a role.

### Listing ACL entries

The `list-acl` command prints all ACL entries in the store:

```bash
webvh-server list-acl

# With a specific config file
webvh-server --config /path/to/config.toml list-acl
```

## Backup & Restore

The server includes built-in backup and restore commands for
migrating data between instances, disaster recovery, or
environment cloning.

### Creating a backup

```bash
# Backup to default file (webvh-backup.json)
webvh-server backup

# Backup to a specific file
webvh-server backup --output /path/to/backup.json

# Backup to stdout (e.g. for piping)
webvh-server backup --output -

# With a specific config file
webvh-server --config /path/to/config.toml backup
```

### Restoring from a backup

Restore writes `config.toml` from the backup and imports all
keyspace data into the store.

```bash
# Restore data and config.toml
webvh-server restore --input /path/to/backup.json

# Write config.toml to a specific path
webvh-server --config /path/to/config.toml restore --input /path/to/backup.json
```

### What's included

The backup file is a single JSON document containing:

- **config** — the effective server configuration at backup time
- **dids** — all DID documents and logs
- **acl** — access control entries
- **stats** — DID resolution statistics
- **sessions** — durable passkey data only (`pk_user:`,
  `pk_cred:`, `pk_did:`, `enroll:` prefixes)

Ephemeral data (active sessions, refresh tokens, auth
challenges, WebAuthn ceremony state) is excluded.

All keys and values are base64url-no-pad encoded in the backup
file.

## Performance Testing

The `perf_test` example is an interactive TUI benchmarking tool
for load-testing a running WebVH server. It sends concurrent DID
resolution requests and displays real-time metrics including
throughput, latency percentiles, network bandwidth, active
workers, and error rates.

### Building

```bash
cargo build --example perf_test -p affinidi-webvh-server
```

### Usage

```bash
cargo run --example perf_test -p affinidi-webvh-server -- [OPTIONS]
```

The tool supports two modes: **server mode** (default) authenticates
with a WebVH server and discovers DIDs automatically, while
**file mode** (`--did-file`) reads `did:webvh:...` identifiers from
a file and works against any hosted WebVH DID without needing
ACL access.

### Options

| Flag | Short | Default | Description |
| ---- | ----- | ------- | ----------- |
| `--server-url` | `-s` | `http://localhost:8101` | WebVH server URL |
| `--rate` | `-r` | `10` | Target requests per second (adjustable at runtime) |
| `--workers` | `-w` | `64` | Maximum concurrent in-flight requests |
| `--timeout` | `-t` | `5` | Request timeout in seconds |
| `--create-dids` | | `0` | Number of random DIDs to create on startup |
| `--create-parallel` | | `4` | Parallel concurrency for DID creation |
| `--seed` | | random | Ed25519 seed as 64 hex characters |
| `--did-file` | `-f` | | File of `did:webvh:...` identifiers (skips auth) |
| `--mediator-did` | | | Mediator DID (reserved for future use) |
| `--webvh-did` | | | Server DID (reserved for future use) |

### Examples

```bash
# Basic: 50 req/s against local server
cargo run --example perf_test -p affinidi-webvh-server -- \
  --rate 50

# Create 10 test DIDs on startup, then benchmark at 200 req/s
cargo run --example perf_test -p affinidi-webvh-server -- \
  --create-dids 10 --rate 200

# Remote server with higher concurrency and longer timeout
cargo run --example perf_test -p affinidi-webvh-server -- \
  -s https://webvh.example.com -r 500 -w 128 -t 10

# Create DIDs faster with more parallelism
cargo run --example perf_test -p affinidi-webvh-server -- \
  --create-dids 50 --create-parallel 8 --rate 100

# File mode: test against any hosted DIDs without ACL access
cargo run --example perf_test -p affinidi-webvh-server -- \
  --did-file my-dids.txt --rate 200
```

#### File mode

When `--did-file` / `-f` is provided, the tool reads `did:webvh:...`
identifiers from the file (one per line) and derives HTTPS resolution
URLs directly. No authentication or server connection is needed —
this works against any hosted WebVH DID.

The file format is simple:

```text
# Production DIDs
did:webvh:Qm...:example.com:my-did
did:webvh:Qm...:example.com:another-did

# Staging
did:webvh:Qm...:staging.example.com%3A8085:test-did
```

Blank lines and lines starting with `#` are ignored.

### Keyboard Controls

| Key | Action |
| --- | ------ |
| `q` / `Esc` | Quit |
| `+` / `=` / `Up` | Increase target rate by 10 req/s |
| `-` / `Down` | Decrease target rate by 10 req/s |
| `]` | Double target rate |
| `[` | Halve target rate |

Rate changes are smoothed over a few seconds to avoid shocking
the server with sudden load spikes.

### Dashboard

The TUI displays four quadrants plus a summary panel:

- **Throughput** (top-left) — sparkline of requests per second
  over the last 120 seconds
- **Latency** (top-right) — sparkline of p99 latency over the
  last 120 seconds
- **Workers** (bottom-left top) — sparkline of active concurrent
  workers showing current, max, and peak utilization
- **Errors** (bottom-left bottom) — sparkline of errors per
  second
- **Summary** (right panel) — current totals, latency
  percentiles (p50/p95/p99/max), network bandwidth (outbound
  and inbound with peak values), and test duration

### Warmup

The tool includes a 3-second warmup period on startup:

- Request rate ramps linearly from 0 to the target rate
- A popup overlay shows the warmup countdown
- All metrics collected during warmup are discarded so that
  graphs and statistics start clean

### Notes

- Timed-out requests count as errors but are excluded from
  latency statistics to avoid skewing percentiles
- In server mode, the tool authenticates with the server using
  DIDComm challenge-response before starting the benchmark
- In file mode (`--did-file`), no authentication is needed
- Network traffic shows actual bytes transferred (response
  bodies are fully consumed)

## API Endpoints

### Public

| Method | Path                            | Description     |
| ------ | ------------------------------- | --------------- |
| `GET`  | `/health`                       | Health check    |
| `GET`  | `/{mnemonic}/did.jsonl`         | Resolve DID log |
| `GET`  | `/{mnemonic}/did-witness.json`  | Resolve witness |
| `GET`  | `/.well-known/did.jsonl`        | Root DID log    |
| `GET`  | `/.well-known/did-witness.json` | Root witness    |

### Authentication

| Method | Path              | Description         |
| ------ | ----------------- | ------------------- |
| `POST` | `/auth/challenge` | Request challenge   |
| `POST` | `/auth/`          | Submit DIDComm auth |
| `POST` | `/auth/refresh`   | Refresh token       |

### DID Management (authenticated)

| Method   | Path                       | Description         |
| -------- | -------------------------- | ------------------- |
| `GET`    | `/dids`                    | List your DIDs      |
| `POST`   | `/dids`                    | Request new DID URI |
| `PUT`    | `/dids/{mnemonic}`         | Upload DID log      |
| `PUT`    | `/dids/{mnemonic}/witness` | Upload witness      |
| `PUT`    | `/disable/{mnemonic}`      | Disable a DID       |
| `PUT`    | `/enable/{mnemonic}`       | Enable a DID        |
| `DELETE` | `/dids/{mnemonic}`         | Delete a DID        |

### Statistics (authenticated)

| Method | Path                | Description |
| ------ | ------------------- | ----------- |
| `GET`  | `/stats/{mnemonic}` | DID stats   |

### Access Control (admin only)

| Method   | Path         | Description      |
| -------- | ------------ | ---------------- |
| `GET`    | `/acl`       | List ACL entries |
| `POST`   | `/acl`       | Create ACL entry |
| `DELETE` | `/acl/{did}` | Remove ACL entry |

## Support & feedback

If you face any issues or have suggestions, please don't
hesitate to contact us using
[this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting technical issues

If you have a technical issue with the Affinidi WebVH Service
codebase, you can also create an issue directly in GitHub.

1. Ensure the bug was not already reported by searching on
   GitHub under
   [Issues](https://github.com/affinidi/affinidi-webvh-service/issues).

2. If you're unable to find an open issue addressing the
   problem,
   [open a new one](https://github.com/affinidi/affinidi-webvh-service/issues/new).
   Be sure to include a **title and clear description**, as
   much relevant information as possible, and a **code sample**
   or an **executable test case** demonstrating the expected
   behaviour that is not occurring.

## Contributing

Want to contribute? Head over to our
[CONTRIBUTING](https://github.com/affinidi/affinidi-webvh-service/blob/main/CONTRIBUTING.md)
guidelines.
