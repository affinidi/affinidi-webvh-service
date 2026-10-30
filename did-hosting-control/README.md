# Affinidi DID Hosting Control Plane

The DID Hosting Control Plane is the authoritative source of truth for
all DID management. Every management operation (DID lifecycle, agent
names, domains, ACL, the service registry, stats) is a signed Trust Task,
served the same over TSP, DIDComm and HTTPS (`POST /api/trust-tasks`); there
is no REST management API. It pushes updates to server edge nodes as signed
Trust Tasks, hosts an optional web-based management UI, maintains a service
registry, and supports passkey (WebAuthn) sign-in.

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
# Hosts the control plane may register — see "Registry allowlist" below.
url_allowlist = ["server-eu.internal", "witness-eu.internal"]

# Watchers: a DID whose log names this URL in its `watchers` parameter is
# pushed there (signed webvh/sync/* Trust Tasks, through the outbox). The DID
# may acknowledge those syncs and nothing else.
# [[registry.watchers]]
# url = "https://watcher1.example.com"
# did = "did:webvh:...:watcher1.example.com"
```

### Service Registry

The `[registry]` section configures backend service instances
that the control plane manages.

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

Instances can also be managed dynamically with the `registry/*` Trust Tasks.

### Registry allowlist

`registry.url_allowlist` bounds which hosts may be registered (by an
administrator's `registry/admin-register`, or a server's `server/register`).
Matching is on the URL **host only** (scheme and port are ignored),
case-insensitive, and **exact** — `example.com` does not match
`sub.example.com`.

- **Empty (the default):** registration refuses non-routable / internal
  *literal* hosts (loopback, RFC1918, `169.254.169.254`, CGNAT, …); a public
  host is accepted.
- **Non-empty:** only listed hosts may be registered. If a backend is on an
  internal IP literal (e.g. `10.0.0.5`), list that literal exactly.

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
| `CONTROL_SERVER_TRUSTED_PROXIES`           | Comma-separated proxy addresses or CIDR ranges whose `X-Forwarded-For` is trusted |
| `CONTROL_REGISTRY_HEALTH_CHECK_INTERVAL`   | Health check interval (sec)  |
| `CONTROL_REPLAY_MAX_ENTRIES`               | Replay cache records, all signers (default 1,000,000, about 32 MB) |
| `CONTROL_REPLAY_MAX_ENTRIES_PER_SIGNER`    | Replay cache records per signer (default 250,000, about 600 signed requests a second) |
| `CONTROL_GEOIP_DATABASE`                   | Local GeoIP `.mmdb` file for wallet sign-in locations (empty clears) |

The replay settings live in `[replay]` (`max_entries`,
`max_entries_per_signer`); see "Replay cache bounds" below.

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

### Replay cache bounds

Every service that accepts signed Trust Tasks (control plane, edge server,
watcher, witness and daemon) remembers each one as `(signer, id)` for as
long as its `issuedAt` is inside the freshness window (up to about 7
minutes), so a captured request cannot be submitted again. A record is a
fixed-size hash, about 32 bytes whatever the DID and id, filed by the
document's signed `issuedAt` so whole minutes are dropped as they leave the
window.

At a bound the cache refuses new requests (`unavailable`, retryable) rather
than forget a record:

- `max_entries` (default 1,000,000, about 32 MB) bounds all signers
  together, and so the cache's memory. It may be at most 10,000,000
  (about 320 MB).
- `max_entries_per_signer` (default 250,000) bounds one signer, so one
  authorised signer cannot fill the cache for the others. It caps that
  signer's sustained rate at about `max_entries_per_signer / 420` requests
  a second: about 600 at the default.
- The last 10% of `max_entries` is kept for signers holding fewer than 100
  records, so several busy signers together cannot lock out a quiet one.

The defaults suit most deployments. Raise `max_entries_per_signer` wherever
one signer sends faster than that:

- On the control plane, for a VTA that creates DIDs at a high rate, and for
  each edge's sync acknowledgements, which are counted against that edge.
- On each edge server and watcher, by the same rate: every DID change
  reaches them as a sync document signed by the control plane, so their
  per-signer bound caps how fast they can follow it.
- On a witness, for a VTA that has each new DID witnessed.

```toml
[replay]
max_entries = 4000000             # all signers, about 128 MB
max_entries_per_signer = 1000000  # about 2,400 signed requests a second per signer
```

Leave the table out to take the defaults; setup does not write it, so a
later release's defaults apply. Wallet sign-in (`auth/oob/*`) keeps its own,
separate replay record, because its signers are fresh keys anyone can mint;
`[replay]` does not change it.

### Wallet sign-in locations (GeoIP)

When someone signs in with their wallet (`auth/oob`), the wallet shows where
the request came from, for example `Vienna, AT`. The control plane looks the
browser's address up in a **local** MaxMind DB (`.mmdb`) file and never calls
a third-party service. Without one every location is `unknown`, which the
wallet shows as a warning.

```toml
[geoip]
database = "/var/lib/did-hosting/geoip/dbip-city-lite.mmdb"
```

Private ranges (an office LAN, a VPN) can be named with
`[[geoip.networks]]` (`cidr`, `location`). Behind a reverse proxy, list it in
`[server] trusted_proxies` (addresses or CIDR ranges) so the real client
address is used. A missing or unreadable file is a warning, not a startup
failure, and a replaced file is picked up within a minute without a restart.
See
[`docs/geoip.md`](../docs/geoip.md) for choosing a database (DB-IP City Lite
or MaxMind GeoLite2 City), attribution and a monthly update job.

### Health Checking

Registered service instances are periodically health-checked.
The health check interval is configurable via
`registry.health_check_interval` (default: 60 seconds).

## HTTP surface

The control plane has no REST management API. Its HTTP surface is:

| Method | Path | Description |
| ------ | ---- | ----------- |
| `POST` | `/api/trust-tasks` | The HTTPS binding of the Trust Task listener: the same dispatch TSP and DIDComm reach. Every management operation arrives here, authorised on the document's own proof. |
| `GET` | `/api/health` | Unauthenticated liveness probe |
| `POST` | `/api/auth/challenge` | Browser sign-in, step 1: a challenge for a SIOPv2 `id_token` |
| `POST` | `/api/auth/` | Browser sign-in, step 2: redeem a SIOPv2 `id_token` minted by the holder's VTA |
| `POST` | `/api/auth/refresh` | Renew a console session: its refresh token, plus a proof from the browser's bound session key |
| `GET` | `/*` | The management UI (`ui` feature), for any path outside `/api` |

The three `/api/auth/*` routes are the one sign-in with no Trust Task form:
`auth/authenticate/0.3` carries no `id_token`, and a browser session does not
hold the subject key a Trust Task `auth/refresh` must be signed with. A peer
that signs its own documents signs in with `auth/challenge/0.1` and
`auth/authenticate/0.3` on `POST /api/trust-tasks`.

Operational metrics are the admin-only `did-management/server/metrics/0.1`
Trust Task; there is no Prometheus scrape endpoint.

### Passkeys

Enrolment and login are Trust Tasks on `POST /api/trust-tasks` (and TSP and
DIDComm), with WebAuthn's ceremony data inside their payloads:

| Trust Task | Proof | Purpose |
| --- | --- | --- |
| `auth/passkey/enroll/invite/0.3` | administrator | Issue an invite: a URL token and a separate claim code, stored only as hashes |
| `auth/passkey/enroll/redeem/start/0.1` | optional | Present token + claim code; get creation options (and `uvOptions` over existing passkeys of the purpose) |
| `auth/passkey/enroll/redeem/finish/0.1` | optional | Bind the passkey to the invite's subject and consume the invite |
| `auth/passkey/enroll/start/0.2`, `finish/0.2` | the subject | Add a login passkey to your own VID (re-verified with an existing one) |
| `auth/passkey/enroll/invite/{list,update,revoke}/0.1` | administrator | Manage invites by `inviteId` |
| `auth/passkey/login/start/0.2`, `finish/0.2` | optional / session key | Sign in, or step a session up |

A `stepUp` invite enrols a step-up-only passkey, kept in its own keyspace
(`passkey_step_up`) that the login ceremony never reads.

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
