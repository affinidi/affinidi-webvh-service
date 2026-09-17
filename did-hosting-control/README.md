# Affinidi DID Hosting Control Plane

The DID Hosting Control Plane is the authoritative source of truth for
all DID management. It handles DID lifecycle operations (create,
publish, delete) via DIDComm and optional REST API, and pushes
updates to server edge nodes via DIDComm through a mediator.
It also hosts an optional web-based management UI, maintains a
service registry, acts as a reverse proxy to backend service
instances, and supports DIDComm v2 and passkey (WebAuthn)
authentication.

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
cargo build --locked -p did-hosting-control --release

# With embedded management UI
cd did-hosting-ui && npm install && npm run build:web && cd ..
cargo build --locked -p did-hosting-control --release --features ui
```

The binary is produced at `target/release/did-hosting-control`.

### 2. Run the setup wizard

```bash
did-hosting-control setup                          # interactive
did-hosting-control setup --from <recipe.toml>     # non-interactive (CI / scripted)
```

For non-interactive runs see
[docs/bootstrap_startup.md](../docs/bootstrap_startup.md#non-interactive-setup-recipe-driven)
and the example recipe at `examples/did-hosting-control-build.toml`. The
recipe handles online VTA flow (with `--setup-key-file`), the
air-gapped `offline-prepare` / `offline-complete` pair, env-var
overlays, and reprovision safety.

The interactive wizard configures:

- **Configuration file path** — where to write `config.toml`
- **Server DID identity** — for DIDComm authentication
- **Public URL** — for passkey (WebAuthn) RP origin
- **Host / port** — listen address (default: `0.0.0.0:8532`)
- **Log level / format** — logging configuration
- **Data directory** — persistent storage path
- **Secrets backend** — where to store private key material
- **Admin bootstrap** — create an initial admin ACL entry

### 3. Start the control plane

```bash
did-hosting-control --config config.toml
```

If built with `--features ui`, browse to
`http://localhost:8532/` to access the management UI.

## Configuration

The control plane is configured via a TOML file. By default it
looks for `config.toml` in the current directory. You can specify
a different path with the `--config` flag or the
`CONTROL_CONFIG_PATH` environment variable.

### Example `config.toml`

```toml
server_did = "did:webvh:control.example.com"
mediator_did = "did:webvh:mediator.example.com"
public_url = "https://control.example.com"

[features]
rest_api = true

[server]
host = "0.0.0.0"
port = 8532

[log]
level = "info"

[store]
data_dir = "data/did-hosting-control"

[auth]
access_token_expiry = 900
refresh_token_expiry = 86400
challenge_ttl = 300
passkey_enrollment_ttl = 86400

[secrets]
keyring_service = "did-hosting-control"

# Service registry — register backend instances
# [[registry.instances]]
# label = "Primary Server"
# service_type = "server"
# url = "http://localhost:8530"
#
# [[registry.instances]]
# label = "Witness"
# service_type = "witness"
# url = "http://localhost:8531"

[registry]
health_check_interval = 60    # seconds
# Hosts the control plane may register and PROXY TO. Required if you use the
# reverse proxy — see "Reverse proxy & the registry allowlist" below.
url_allowlist = ["server-eu.internal", "witness-eu.internal"]
```

### Service Registry

The `[registry]` section configures backend service instances
that the control plane manages and proxies requests to.

Static instances can be defined in `config.toml`:

```toml
[[registry.instances]]
label = "Primary Server"
service_type = "server"         # server, witness, or watcher
url = "http://localhost:8530"

[[registry.instances]]
label = "Witness Node"
service_type = "witness"
url = "http://localhost:8531"

[[registry.instances]]
label = "EU Watcher"
service_type = "watcher"
url = "http://watcher-eu:8533"
```

Instances can also be managed dynamically via the registry API.

### Reverse proxy & the registry allowlist (security-critical)

The control plane exposes an **Admin-only reverse proxy** at
`/api/server/{instance}/{*path}` and `/api/witness/{instance}/{*path}`. It
forwards the request to a registered instance's `url` **and forwards the
caller's `Authorization` header** (the Admin bearer) to that backend, since the
control plane and its backends typically share JWT keys.

Because a live Admin credential is forwarded, the target host is gated by
`registry.url_allowlist`:

- **Empty allowlist (the default) ⇒ the proxy is disabled (fail-closed).** A
  proxy request returns `403` (`"proxy refused: no registry.url_allowlist is
  configured…"`). Registration itself still refuses non-routable / internal
  *literal* hosts (loopback, RFC1918, `169.254.169.254`, CGNAT, …) even with an
  empty allowlist, but a public host can be registered — it just cannot be
  proxied to.
- **Non-empty allowlist ⇒ the proxy forwards only to listed hosts.** Any other
  target (a public attacker host, or a name that isn't listed) is refused, so
  the Admin credential can only ever reach a host you explicitly trust.

> **⚠️ Behaviour change (SEC-4045 W6).** Earlier releases forwarded the Admin
> credential to **any** registered URL when the allowlist was empty. If you use
> the reverse proxy and have not set `registry.url_allowlist`, the proxy will now
> return `403` until you configure it. This is intentional: an unset allowlist
> previously let a `service`-role registrant point the proxy at an
> attacker-controlled host and receive an Admin token.

**Configure it securely:**

1. **List every backend host you proxy to**, and nothing else:
   ```toml
   [registry]
   url_allowlist = ["server-eu.internal", "witness-eu.internal"]
   ```
   Matching is on the URL **host only** (scheme and port are ignored),
   case-insensitive, and **exact** — `example.com` does not match
   `sub.example.com`. If a backend is on an internal IP literal (e.g.
   `10.0.0.5`), list that literal exactly (it is otherwise refused as
   non-routable).
2. **Prefer hostnames you control end-to-end** (private DNS / service names)
   over raw IPs, and terminate the backends over **TLS** so the forwarded
   credential is not sent in clear text.
3. **Keep the list minimal.** Every entry is a host the control plane will hand
   an Admin credential to; treat it like an egress allowlist.
4. **Daemon (all-in-one) deployments need no allowlist** — the registry is empty
   and the proxy is unused, so leaving `url_allowlist` unset is correct and
   safe. Only *standalone control planes that manage remote instances through
   the proxy* must set it.

### Environment Variable Overrides

Environment variables use the `CONTROL_` prefix:

| Variable                                   | Description                  |
| ------------------------------------------ | ---------------------------- |
| `CONTROL_CONFIG_PATH`                      | Path to config file          |
| `CONTROL_SERVER_DID`                       | Control plane DID            |
| `CONTROL_MEDIATOR_DID`                     | Mediator DID                 |
| `CONTROL_PUBLIC_URL`                       | Public URL (passkey origin)  |
| `CONTROL_SERVER_HOST`                      | Bind host                    |
| `CONTROL_SERVER_PORT`                      | Bind port                    |
| `CONTROL_LOG_LEVEL`                        | Log level                    |
| `CONTROL_REGISTRY_HEALTH_CHECK_INTERVAL`   | Health check interval (sec)  |

## CLI Commands

```
did-hosting-control                                    # Run control plane (default)
did-hosting-control setup                              # Interactive config wizard
did-hosting-control add-acl --did <DID> [--role admin|owner] [--label <name>]  # Add ACL entry
did-hosting-control list-acl                           # List ACL entries
```

## Features

### Management UI

When built with the `ui` feature, the control plane embeds a
web-based management interface using `rust-embed`. The UI is
served as a fallback for any non-API GET requests — no separate
web server needed.

The UI provides:

- Server health and DID counts
- DID creation, upload, and deletion
- Witness proof management
- Access control management (admin only)
- Service instance overview

### Passkey Authentication

Passkey/WebAuthn support is always compiled into the control plane.
It is activated at runtime when a `public_url` is configured: the
control plane then supports WebAuthn passkey enrollment and login,
providing browser-based passwordless authentication alongside DIDComm
challenge-response auth. Without a `public_url`, WebAuthn is not
initialised and authentication falls back to DID challenge-response.

### Reverse Proxy

The control plane proxies requests to registered backend
service instances. This allows the UI to communicate with
all services through a single origin (no CORS issues):

```
UI → /api/server/{instance_id}/dids → did-hosting-server
UI → /api/witness/{instance_id}/witnesses → webvh-witness
```

### Health Checking

Registered service instances are periodically health-checked.
The health check interval is configurable via
`registry.health_check_interval` (default: 60 seconds).

## API Endpoints

All API endpoints are under the `/api` prefix.

### Authentication

| Method | Path                              | Description            |
| ------ | --------------------------------- | ---------------------- |
| `POST` | `/api/auth/challenge`             | Request challenge      |
| `POST` | `/api/auth/`                      | Submit DIDComm auth    |
| `POST` | `/api/auth/refresh`               | Refresh token          |
| `POST` | `/api/auth/passkey/enroll/start`  | Start passkey enroll   |
| `POST` | `/api/auth/passkey/enroll/finish` | Finish passkey enroll  |
| `POST` | `/api/auth/passkey/login/start`   | Start passkey login    |
| `POST` | `/api/auth/passkey/login/finish`  | Finish passkey login   |

### Access Control (admin only)

| Method   | Path             | Description      |
| -------- | ---------------- | ---------------- |
| `GET`    | `/api/acl`       | List ACL entries |
| `POST`   | `/api/acl`       | Create ACL entry |
| `PUT`    | `/api/acl/{did}` | Update ACL entry |
| `DELETE` | `/api/acl/{did}` | Remove ACL entry |

### DID Management

All routes require Bearer-token authentication; ownership and admin
gating is enforced per-handler.

| Method   | Path                            | Description |
| -------- | ------------------------------- | ----------- |
| `GET`    | `/api/dids`                     | List DIDs (owners see their own; admins see all, or filter by `?owner=did:...`). |
| `POST`   | `/api/dids`                     | Reserve a DID slot (mnemonic + URL). Body: `{ "path"?: string, "force"?: bool }`. |
| `POST`   | `/api/dids/check`               | Check whether a custom path is available. Body: `{ "path": string }`. |
| `POST`   | `/api/dids/register`            | Atomic claim-and-publish (closes the resolvability gap of `POST /api/dids` + `PUT /api/dids/{m}`). Body: `{ "path": string, "did_log": string, "force"?: bool }`. |
| `GET`    | `/api/dids/{*mnemonic}`         | Get DID record + log metadata. |
| `PUT`    | `/api/dids/{*mnemonic}`         | Publish a signed `did.jsonl` log. Body: `text/plain` JSONL. |
| `DELETE` | `/api/dids/{*mnemonic}`         | Delete a DID and its associated content. |
| `PUT`    | `/api/owner/{*mnemonic}`        | Transfer ownership. Body: `{ "new_owner": string }`. New owner must be in the ACL. |
| `PUT`    | `/api/disable/{*mnemonic}`      | Toggle `disabled = true` on the record (resolvers serve gone). |
| `PUT`    | `/api/enable/{*mnemonic}`       | Toggle `disabled = false`. |
| `POST`   | `/api/rollback/{*mnemonic}`     | Remove the last log entry (decrements `version_count`). |
| `GET`    | `/api/log/{*mnemonic}`          | Parsed log entries as structured JSON. |
| `GET`    | `/api/raw/{*mnemonic}`          | Raw `did.jsonl` content as `text/plain`. |
| `PUT`    | `/api/witness/{*mnemonic}`      | Upload a witness proof file. Body: `application/json`. |

### Statistics & Time-series

| Method | Path                              | Description |
| ------ | --------------------------------- | ----------- |
| `GET`  | `/api/stats`                      | Aggregate stats across the control plane. |
| `GET`  | `/api/stats/{*mnemonic}`          | Per-DID stats. |
| `GET`  | `/api/timeseries`                 | Server-wide time-series buckets. Query: `?range=1h\|24h\|7d\|30d` (default `24h`). |
| `GET`  | `/api/timeseries/{*mnemonic}`     | Per-DID time-series. Same `range` query. |

### Service Topology & Configuration

| Method | Path                       | Description |
| ------ | -------------------------- | ----------- |
| `GET`  | `/api/services/overview`   | Full topology: control plane info + every registered service + aggregate stats. |
| `GET`  | `/api/config`              | Non-sensitive control-plane configuration (DIDs, URLs, feature flags). |

### Service Registry (admin only)

| Method   | Path                                         | Description          |
| -------- | -------------------------------------------- | -------------------- |
| `GET`    | `/api/control/registry`                      | List instances       |
| `POST`   | `/api/control/registry`                      | Register instance    |
| `GET`    | `/api/control/registry/{instance_id}`        | Get instance         |
| `DELETE` | `/api/control/registry/{instance_id}`        | Deregister instance  |
| `POST`   | `/api/control/registry/{instance_id}/health` | Trigger health check |

### Reverse Proxy

| Method | Path                                       | Description              |
| ------ | ------------------------------------------ | ------------------------ |
| `*`    | `/api/server/{instance_id}/{path}`         | Proxy to server instance |
| `*`    | `/api/witness/{instance_id}/{path}`        | Proxy to witness instance|

### Health

| Method | Path          | Description  |
| ------ | ------------- | ------------ |
| `GET`  | `/api/health` | Health check |

## Library Usage

The did-hosting-control crate can be used as a library (e.g., by the
[did-hosting-daemon](../did-hosting-daemon/)). It exposes:

- `did_hosting_control::config::AppConfig` — configuration
- `did_hosting_control::server::AppState` — application state
- `did_hosting_control::routes::router()` — Axum router
- `did_hosting_control::server::run()` — standalone entry point

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
