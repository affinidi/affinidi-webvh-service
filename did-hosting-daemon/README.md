# Affinidi DID Hosting Daemon

The DID Hosting Daemon is a unified binary that embeds all four
services — [server](../did-hosting-server/),
[witness](../webvh-witness/), [watcher](../webvh-watcher/), and
[control plane](../did-hosting-control/) — behind a single TCP listener.
This is the easiest way to get started with a complete DID Hosting
deployment.

Each service is mounted at a path prefix:

| Service | Path prefix | Description |
| ------- | ----------- | ----------- |
| Server  | `/`         | Public DID hosting and resolution |
| Witness | `/witness`  | Witness proof signing |
| Watcher | `/watcher`  | Read-only DID mirror |
| Control | `/`         | DID management (DIDComm + REST API), management UI |

> **IMPORTANT:**
> did-hosting-service crates are provided "as is" without any
> warranties or guarantees, and by using this framework, users
> agree to assume all risks associated with its deployment and
> use including implementing security, and privacy measures in
> their applications. Affinidi assumes no liability for any
> issues arising from the use or modification of the project.

## Getting Started

### Prerequisites

- Rust 1.94.0+ (2024 Edition)
- Node.js 20+ (only if building with the management UI)

### 1. Build

```bash
# Without UI
cargo build -p did-hosting-daemon --release

# With embedded management UI
cd did-hosting-ui && npm install && npm run build:web && cd ..
cargo build -p did-hosting-daemon --release --features ui
```

The binary is produced at `target/release/did-hosting-daemon`.

### 2. Configure

The fastest way to produce a working `config.toml` is to run
`did-hosting-daemon setup`, which prompts for the values below and emits a
file you can hand-edit later. A worked example follows for reference:

```toml
server_did = "did:webvh:example.com"
mediator_did = "did:webvh:mediator.example.com"
public_url = "https://example.com"

# Identity mode. Default: "vta". Set to "self-managed" to skip the
# VTA round-trip and have the daemon self-host its own did:webvh
# identifier. See docs/self-managed-mode-spec.md for the trade-offs.
[identity]
mode = "vta"

[server]
host = "0.0.0.0"
port = 8534

[log]
level = "info"

[auth]
access_token_expiry = 900
refresh_token_expiry = 86400

# Secret backend. Pick one — features are mutually exclusive at compile
# time. The daemon's default features include `keyring`; cloud secret
# backends require recompiling with `--features aws-secrets|gcp-secrets|
# azure-secrets` and a corresponding [secrets.<backend>] section.
[secrets]
keyring_service = "did-hosting-daemon"

# Main store (server, watcher, control share this)
[store]
data_dir = "data/daemon/store"

# Witness store (separate to avoid keyspace collisions)
[witness_store]
data_dir = "data/daemon/witness"

# Which services to enable (all default to true except watcher)
[enable]
server = true
witness = true
watcher = false
control = true
```

For self-managed mode (no VTA), set `[identity] mode = "self-managed"`
and omit the `[vta]` section entirely. The daemon will mint its own
Ed25519 + X25519 keys at first run, host its own `did:webvh`
identifier on `public_url`, and seed an empty ACL — admin enrolment is
done through `did-hosting-daemon invite --did <DID> --role admin` and the
passkey enrolment flow. See [docs/self-managed-mode-spec.md](../docs/self-managed-mode-spec.md)
for the full walkthrough.

### Non-interactive setup (CI / scripted)

`did-hosting-daemon setup --from <recipe.toml>` drives the wizard with no
TTY. Recipe is declarative TOML; no secrets inside. Example:

```bash
# VTA-managed (after `--setup-key-out` enrolment elsewhere):
did-hosting-daemon setup --from examples/did-hosting-daemon-build.toml \
                   --setup-key-file setup.key

# Self-managed (no VTA, no phase-1 needed):
did-hosting-daemon setup --from examples/did-hosting-daemon-build.toml
# → recipe has [deployment].vta_mode = "self-managed"

# Air-gapped (no VTA network access from CI):
did-hosting-daemon setup --from recipe.toml   # phase 1: writes request file
# (operator ferries to VTA admin, gets sealed bundle back)
did-hosting-daemon setup --from recipe.toml   # phase 2: opens sealed bundle
```

Other flags: `--force-reprovision` rotates an existing install (backs
up `config.toml` first), `did-hosting-daemon uninstall` tears down (clears
managed secrets + removes config). See
[docs/bootstrap_startup.md](../docs/bootstrap_startup.md#non-interactive-setup-recipe-driven)
for the recipe schema and exit codes.

### 3. Start the daemon

```bash
did-hosting-daemon --config config.toml
```

The daemon starts all enabled services on a single port and logs which
services are active. The control plane and `did-hosting-server` (public DID
resolver) both merge at root; `webvh-witness` and `webvh-watcher` nest
under their own prefixes:

```
--- daemon services ---
  server (/)
  witness (/witness)
  control (/)
daemon listening on 0.0.0.0:8534
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
did-hosting-daemon                      # Run daemon (default)
did-hosting-daemon setup                # Interactive config wizard
did-hosting-daemon health               # Run health check diagnostics
did-hosting-daemon add-acl              # Add ACL entry
did-hosting-daemon list-acl             # List ACL entries
did-hosting-daemon remove-acl           # Remove ACL entry
did-hosting-daemon invite               # Create passkey enrollment invite
did-hosting-daemon list-dids            # List all DIDs in the store
did-hosting-daemon remove-did           # Remove a DID from the store
did-hosting-daemon load-did             # Load a DID from existing files
did-hosting-daemon bootstrap-did        # Bootstrap a DID (defaults to .well-known)
did-hosting-daemon recreate-did         # Recreate a DID at a given path
did-hosting-daemon recover-did          # Recover a soft-deleted DID
did-hosting-daemon import-secrets       # Import secrets from VTA bundle or keys
did-hosting-daemon backup               # Export data to backup file
did-hosting-daemon restore              # Restore data from backup file
```

## API Path Mapping

When all services are enabled, the daemon exposes endpoints
at the following paths. `did-hosting-server` (the public-DID-resolver edge
node) and `did-hosting-control` (the management API + UI) both merge at
root — the daemon is a unified front door rather than a multiplexer.
Witness and watcher are nested under their own prefixes because their
APIs are operator-facing and benefit from a clean URL boundary.

### Server + Control plane (root, merged)

| Path | Description | Source |
| ---- | ----------- | ------ |
| `/api/health` | Combined health endpoint | server / control |
| `/api/auth/*` | DIDComm auth + passkey auth | control plane |
| `/api/dids/*` | DID lifecycle management | control plane |
| `/api/acl/*` | ACL management | control plane |
| `/api/server/{instance_id}/*` | Reverse proxy to a registered server | control plane |
| `/api/witness/{instance_id}/*` | Reverse proxy to a registered witness | control plane |
| `/api/control/registry/*` | Service registry CRUD | control plane |
| `/api/control/stats` | Service-role stats sync ingest | control plane |
| `/{mnemonic}/did.jsonl` | Public DID resolution | server |
| `/.well-known/did.jsonl` | Service-DID resolution | server |
| `/`, `/assets/*` | Management UI (when `ui` feature enabled) | control plane |

### Witness (nested at `/witness`)

| Path | Description |
| ---- | ----------- |
| `/witness/api/health` | Witness health |
| `/witness/api/auth/*` | Witness authentication |
| `/witness/api/witnesses/*` | Witness management |
| `/witness/api/proof/*` | Proof signing |

### Watcher (nested at `/watcher`)

| Path | Description |
| ---- | ----------- |
| `/watcher/api/health` | Watcher health |
| `/watcher/api/sync/*` | Server → watcher sync endpoints |
| `/watcher/{mnemonic}/did.jsonl` | Mirrored public DID resolution |

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
| `ui` | Embed the management UI in did-hosting-control |
| `passkey` | Enable WebAuthn passkey auth in did-hosting-control |
| `keyring` | OS keyring secrets backend |
| `store-fjall` | Fjall embedded storage backend |
| `did-methods` | Enable did:webvh + did:web resolution (route + dispatcher) |

Default features: `keyring`, `store-fjall`, `ui`, `passkey`, `did-methods`.

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
