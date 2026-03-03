# Affinidi WebVH Control Plane

The WebVH Control Plane provides a unified management interface
for all WebVH services. It hosts an optional web-based management
UI, maintains a service registry, acts as a reverse proxy to
backend service instances, and supports both DIDComm v2 and
passkey (WebAuthn) authentication.

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
cargo build -p affinidi-webvh-control --release

# With embedded management UI
cd webvh-ui && npm install && npm run build:web && cd ..
cargo build -p affinidi-webvh-control --release --features ui
```

The binary is produced at `target/release/webvh-control`.

### 2. Run the setup wizard

```bash
webvh-control setup
```

The wizard configures:

- **Configuration file path** — where to write `config.toml`
- **Server DID identity** — for DIDComm authentication
- **Public URL** — for passkey (WebAuthn) RP origin
- **Host / port** — listen address (default: `0.0.0.0:8100`)
- **Log level / format** — logging configuration
- **Data directory** — persistent storage path
- **Secrets backend** — where to store private key material
- **Admin bootstrap** — create an initial admin ACL entry

### 3. Start the control plane

```bash
webvh-control --config config.toml
```

If built with `--features ui`, browse to
`http://localhost:8100/` to access the management UI.

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
port = 8100

[log]
level = "info"

[store]
data_dir = "data/webvh-control"

[auth]
access_token_expiry = 900
refresh_token_expiry = 86400
challenge_ttl = 300
passkey_enrollment_ttl = 86400

[secrets]
keyring_service = "webvh-control"

# Service registry — register backend instances
# [[registry.instances]]
# label = "Primary Server"
# service_type = "server"
# url = "http://localhost:8101"
#
# [[registry.instances]]
# label = "Witness"
# service_type = "witness"
# url = "http://localhost:8102"

[registry]
health_check_interval = 60    # seconds
```

### Service Registry

The `[registry]` section configures backend service instances
that the control plane manages and proxies requests to.

Static instances can be defined in `config.toml`:

```toml
[[registry.instances]]
label = "Primary Server"
service_type = "server"         # server, witness, or watcher
url = "http://localhost:8101"

[[registry.instances]]
label = "Witness Node"
service_type = "witness"
url = "http://localhost:8102"

[[registry.instances]]
label = "EU Watcher"
service_type = "watcher"
url = "http://watcher-eu:8103"
```

Instances can also be managed dynamically via the registry API.

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
webvh-control                                    # Run control plane (default)
webvh-control setup                              # Interactive config wizard
webvh-control add-acl --did <DID> [--role admin|owner] [--label <name>]  # Add ACL entry
webvh-control list-acl                           # List ACL entries
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

When built with the `passkey` feature and a `public_url` is
configured, the control plane supports WebAuthn passkey
enrollment and login. This provides browser-based passwordless
authentication alongside DIDComm challenge-response auth.

### Reverse Proxy

The control plane proxies requests to registered backend
service instances. This allows the UI to communicate with
all services through a single origin (no CORS issues):

```
UI → /api/server/{instance_id}/dids → webvh-server
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

The webvh-control crate can be used as a library (e.g., by the
[webvh-daemon](../webvh-daemon/)). It exposes:

- `affinidi_webvh_control::config::AppConfig` — configuration
- `affinidi_webvh_control::server::AppState` — application state
- `affinidi_webvh_control::routes::router()` — Axum router
- `affinidi_webvh_control::server::run()` — standalone entry point

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
