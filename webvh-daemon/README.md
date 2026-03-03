# Affinidi WebVH Daemon

The WebVH Daemon is a unified binary that embeds all four WebVH
services — [server](../webvh-server/),
[witness](../webvh-witness/), [watcher](../webvh-watcher/), and
[control plane](../webvh-control/) — behind a single TCP listener.
This is the easiest way to get started with a complete WebVH
deployment.

Each service is mounted at a path prefix:

| Service | Path prefix | Description |
| ------- | ----------- | ----------- |
| Server  | `/`         | DID hosting and management |
| Witness | `/witness`  | Witness proof signing |
| Watcher | `/watcher`  | Read-only DID mirror |
| Control | `/control`  | Management UI and service registry |

> **IMPORTANT:**
> affinidi-webvh-service crates are provided "as is" without any
> warranties or guarantees, and by using this framework, users
> agree to assume all risks associated with its deployment and
> use including implementing security, and privacy measures in
> their applications. Affinidi assumes no liability for any
> issues arising from the use or modification of the project.

## Getting Started

### Prerequisites

- Rust 1.91.0+ (2024 Edition)
- Node.js 18+ (only if building with the management UI)

### 1. Build

```bash
# Without UI
cargo build -p affinidi-webvh-daemon --release

# With embedded management UI
cd webvh-ui && npm install && npm run build:web && cd ..
cargo build -p affinidi-webvh-daemon --release --features ui
```

The binary is produced at `target/release/webvh-daemon`.

### 2. Configure

Create a `config.toml`:

```toml
server_did = "did:webvh:example.com"
mediator_did = "did:webvh:mediator.example.com"
public_url = "https://example.com"

[server]
host = "0.0.0.0"
port = 8100

[log]
level = "info"

[auth]
access_token_expiry = 900
refresh_token_expiry = 86400

[secrets]
keyring_service = "webvh-daemon"

# Per-service data directories (kept separate to avoid
# keyspace collisions)
[server_store]
data_dir = "data/daemon/server"

[witness_store]
data_dir = "data/daemon/witness"

[watcher_store]
data_dir = "data/daemon/watcher"

[control_store]
data_dir = "data/daemon/control"

# Which services to enable (all default to true except watcher)
[enable]
server = true
witness = true
watcher = false
control = true
```

### 3. Start the daemon

```bash
webvh-daemon --config config.toml
```

The daemon starts all enabled services on a single port and
logs which services are active:

```
--- daemon services ---
  server (/)
  witness (/witness)
  control (/control)
daemon listening on 0.0.0.0:8100
```

## Configuration

The daemon is configured via a TOML file. By default it looks
for `config.toml` in the current directory. You can specify a
different path with the `--config` flag or the
`DAEMON_CONFIG_PATH` environment variable.

### Shared vs Per-Service Settings

Settings like `server_did`, `mediator_did`, `public_url`,
`[auth]`, `[secrets]`, and `[log]` are shared across all
services. Each service gets its own store directory to avoid
keyspace name collisions (both server and witness use `sessions`
and `acl` keyspaces).

### Service-Specific Settings

| Section          | Service | Description |
| ---------------- | ------- | ----------- |
| `[limits]`       | Server  | Upload body limit, per-account quotas |
| `[[watchers]]`   | Server  | Watcher push endpoints |
| `[vta]`          | Witness | VTA remote key management |
| `[watcher_sync]` | Watcher | Push tokens and source servers |
| `[registry]`     | Control | Service instance registry |

### Enable/Disable Services

The `[enable]` section controls which services start:

```toml
[enable]
server = true    # DID hosting (default: true)
witness = true   # Witness proofs (default: true)
watcher = false  # DID mirror (default: false)
control = true   # Management UI (default: true)
```

### Environment Variable Overrides

Environment variables use the `DAEMON_` prefix:

| Variable              | Description             |
| --------------------- | ----------------------- |
| `DAEMON_CONFIG_PATH`  | Path to config file     |
| `DAEMON_SERVER_DID`   | Server DID identifier   |
| `DAEMON_MEDIATOR_DID` | Mediator DID identifier |
| `DAEMON_PUBLIC_URL`   | Public URL              |
| `DAEMON_SERVER_HOST`  | Bind host               |
| `DAEMON_SERVER_PORT`  | Bind port               |
| `DAEMON_LOG_LEVEL`    | Log level               |

## CLI Commands

```
webvh-daemon                      # Run daemon (default)
webvh-daemon setup                # Interactive config wizard (coming soon)
```

## API Path Mapping

When all services are enabled, the daemon exposes endpoints
at the following paths:

### Server (root)

| Path | Description |
| ---- | ----------- |
| `/api/health` | Server health |
| `/api/auth/*` | Server authentication |
| `/api/dids/*` | DID management |
| `/api/acl/*` | Server ACL |
| `/{mnemonic}/did.jsonl` | DID resolution |

### Witness (`/witness`)

| Path | Description |
| ---- | ----------- |
| `/witness/api/health` | Witness health |
| `/witness/api/auth/*` | Witness authentication |
| `/witness/api/witnesses/*` | Witness management |
| `/witness/api/proof/*` | Proof signing |

### Watcher (`/watcher`)

| Path | Description |
| ---- | ----------- |
| `/watcher/api/health` | Watcher health |
| `/watcher/api/sync/*` | Sync endpoints |

### Control (`/control`)

| Path | Description |
| ---- | ----------- |
| `/control/api/health` | Control plane health |
| `/control/api/auth/*` | Control plane auth (DIDComm + passkey) |
| `/control/api/acl/*` | Control plane ACL |
| `/control/api/control/registry/*` | Service registry |

### Daemon

| Path | Description |
| ---- | ----------- |
| `/health` | Daemon-level health |

## Graceful Shutdown

The daemon handles `SIGINT` (Ctrl+C) and `SIGTERM` for graceful
shutdown. On shutdown, all service stores are persisted before
the process exits.

## Feature Flags

Features propagate to the underlying service crates:

| Feature | Description |
| ------- | ----------- |
| `ui` | Embed the management UI in webvh-control |
| `passkey` | Enable WebAuthn passkey auth in webvh-control |
| `keyring` | OS keyring secrets backend |
| `store-fjall` | Fjall embedded storage backend |

Default features: `keyring`, `store-fjall`, `ui`, `passkey`.

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
