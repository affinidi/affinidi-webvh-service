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

- Rust: the workspace MSRV is `rust-version` in the root
  [`Cargo.toml`](../Cargo.toml) (2024 edition).
- Node.js: `engines.node` in
  [`did-hosting-ui/package.json`](../did-hosting-ui/package.json)
  (currently >= 24.3). The default build needs it: `ui` is a default
  feature, and the build script runs `npm` to bundle the console when
  `../did-hosting-ui` is present and the bundle is stale.

### 1. Build

```bash
# Default: with the embedded management UI (needs Node.js)
cargo build --locked -p did-hosting-control --release

# Without the UI (no Node.js needed)
cargo build --locked -p did-hosting-control --release \
  --no-default-features --features keyring,store-fjall
```

The binary is produced at `target/release/did-hosting-control`. A crate
installed from crates.io (`cargo install did-hosting-control --locked`)
carries a pre-built UI bundle and never runs Node.

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

The interactive wizard asks how to reach the VTA (online, or the two
air-gapped phases), provisions the control plane's own `did:webvh` (hosting
URL and path, messaging transport), then the public URL (the passkey
origin), listen address (default `0.0.0.0:8532`), logging, data directory,
secrets backend, and an initial admin ACL entry.

### 3. Start the control plane

```bash
did-hosting-control --config config.toml
```

With the default `ui` feature, browse to `http://localhost:8532/` for the
management console (put TLS in front for anything but local use; see
[docs/deployment.md](../docs/deployment.md)).

## Configuration

Every key and environment variable (prefix `CONTROL_`) is listed in
[docs/configuration.md](../docs/configuration.md). The file is
`config.toml` in the working directory unless `--config` or
`CONTROL_CONFIG_PATH` names another; unknown keys are refused at load.

### Example `config.toml`

```toml
server_did = "did:webvh:control.example.com"
mediator_did = "did:webvh:mediator.example.com"
public_url = "https://control.example.com"

[features]
# Run the HTTP listener: the management UI, POST /api/trust-tasks and
# /api/health. (Formerly `rest_api`, still accepted.) At least one of
# http_listener, didcomm and tsp must be on.
http_listener = true

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
challenge_ttl = 30
passkey_enrollment_ttl = 86400
# Longest a passkey invite's claim-code check waits for a free hashing slot
# before it is answered `unavailable` with a retry time (milliseconds).
claim_code_hash_wait_ms = 5000

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

### Environment variable overrides

Every setting above has a `CONTROL_`-prefixed variable (`CONTROL_SERVER_PORT`,
`CONTROL_STORE_REDIS_URL`, `CONTROL_REPLAY_MAX_ENTRIES`, …); the full list is
in [docs/configuration.md](../docs/configuration.md).

### Statistics flush budget

`[stats_flush] max_rows_per_second` (1 to 10,000, default 20) bounds how fast
the control plane writes statistics. Every 10 seconds it takes the per-DID
counters gathered since the last flush and writes at most that many rows a
second, paced across the interval. Each row is a read and a write. The
budget counts rows, not table units: on DynamoDB a row costs one or more
units by size, up to about three write units for a DID's row; see "Costs" in
[`docs/stats-tiers.md`](../docs/stats-tiers.md).

Rows past the budget wait for the next flush. What waits too long is dropped,
with a warning: time-series buckets older than an hour, and rows past the
collector's caps (100,000 DIDs, 200,000 buckets). Per-DID totals are never
dropped by age. A DID's row is written once per 5-minute bucket it was active
in, plus one ring row per bucket if it keeps 5-minute statistics, so set the
budget above the rows produced: about the distinct DIDs resolved in 5
minutes, plus the fine ones among them, divided by 300. Lower it to leave a
small table's capacity for resolutions and creations; raise it to drain a
backlog sooner.

### Tiered statistics

Every DID keeps hourly (7 days) and daily (30 days) statistics in one row;
busy DIDs also keep a 5-minute ring for the last day. `[stats]` sets who is
busy (`mode`, `promote_per_hour`, `demote_per_hour`, `max_fine_dids`), and a
per-DID override (`auto`, `fine`, `coarse`, `off`; `fine` is admin only)
overrides it. Legacy statistics are migrated automatically at startup. See
[`docs/stats-tiers.md`](../docs/stats-tiers.md).

## CLI Commands

Every subcommand, with its full `--help`, is in
[`docs/cli-reference.md`](../docs/cli-reference.md), generated from the CLI
(a test keeps it current). Below is a summary. `health` exits non-zero when a
check fails (`--strict`: also when one warns).

```
did-hosting-control                                    # Run control plane (default)
did-hosting-control setup                              # Interactive or --from <recipe> setup
did-hosting-control add-acl --did <DID> [--role admin|owner|service|metricsReader]  # Add ACL entry (offline)
did-hosting-control list-acl | remove-acl --did <DID>  # (offline)
did-hosting-control invite --did <DID>                 # Create a passkey enrolment invite
did-hosting-control health [--strict]                  # Health check (non-zero exit on failure)
did-hosting-control uninstall                          # Teardown: clear secrets + remove config
did-hosting-control stats-show | stats-set | stats-purge-legacy  # Statistics tiers (offline)
did-hosting-control identity-list | identity-rotate-keys | identity-scid-alias | identity-retire-now
did-hosting-control tsp-relationship-list | tsp-relationship-reset | tsp-relationship-delete
did-hosting-control fetch-metrics --key <key.json>     # Read counters over the signed server/metrics task
```

Everything an operator does to a running control plane beyond these is a
Trust Task: through the console, or signed from the command line as
[docs/sending-trust-tasks.md](../docs/sending-trust-tasks.md) describes. The
catalogue of tasks is [docs/trust-tasks.md](../docs/trust-tasks.md).

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
control plane then supports passkey enrolment and login alongside wallet
and DID sign-in. Without a `public_url`, WebAuthn is not initialised.

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

### Connection limits

The HTTPS listener applies the same limits as the edge's: at most 256
connections are served at once, at most 32 of them from one IPv4 address or
IPv6 /64 (addresses in `[server] trusted_proxies` are exempt); a request's
headers must arrive within 20 seconds of its first byte; a connection idle
for 60 seconds is closed; and a `POST /api/trust-tasks` body must arrive
within 30 seconds (`408`). They are a backstop: put a reverse proxy in front
for TLS and its own limits.

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
| `GET` | `/api/sign-in/readiness` | Whether this service's DID lists the services wallet sign-in needs (read by the login page) |
| `POST` | `/api/auth/challenge` | Mint a sign-in challenge nonce, for a browser that holds no key to sign a Trust Task with yet. The same challenge is the `auth/challenge/0.1` Trust Task. |
| `GET` | `/*` | The management UI (`ui` feature), for any other path |

Signing in completes over Trust Tasks on `POST /api/trust-tasks`:
`auth/authenticate/0.3`, and `auth/refresh/0.2` to renew a console session.
Operational metrics are the `did-management/server/metrics/0.1` Trust Task
(see [docs/metrics.md](../docs/metrics.md)); there is no Prometheus scrape
endpoint. Every task the control plane serves, with its proof rule, is in
[docs/trust-tasks.md](../docs/trust-tasks.md).

### Passkeys

Enrolment and login are Trust Tasks on `POST /api/trust-tasks` (and TSP and
DIDComm), with WebAuthn's ceremony data inside their payloads:

| Trust Task | Proof | Purpose |
| --- | --- | --- |
| `auth/passkey/enroll/invite/0.3` | administrator | Issue an invite: a URL token and a separate claim code, stored only as hashes |
| `auth/passkey/enroll/redeem/start/0.1` | optional | Present token + claim code; get creation options (and `uvOptions` over existing passkeys of the purpose) |
| `auth/passkey/enroll/redeem/finish/0.1` | optional | Bind the passkey to the invite's subject and consume the invite |
| `auth/passkey/enroll/start/0.2`, `finish/0.2` | the subject | Add a login passkey to your own VID (re-verified with an existing one; a first one needs an `aal2` session or your own DID key's signature, else an invite) |
| `auth/passkey/enroll/invite/{list,update,revoke}/0.1` | administrator | Manage invites by `inviteId` |
| `auth/passkey/login/start/0.2`, `finish/0.2` | optional / session key | Sign in, or step a session up. The start lists no credentials (the authenticator offers its discoverable ones) unless the request carries the named subject's own session; 30 starts per source a minute |

A `stepUp` invite enrols a step-up-only passkey, kept in its own keyspace
(`passkey_step_up`) that the login ceremony never reads.

### Stepped-up sessions

A request that presents a console session (a bearer token on
`POST /api/trust-tasks`) needs that session at `aal2` for the destructive and
privilege-raising tasks below. A wallet session is stepped up with
`auth/step-up/start/0.2` and the wallet's `auth/step-up/approve-response/0.7`;
a passkey login is `aal2` from the start.

| Trust Task | Needs `aal2` from a session |
| --- | --- |
| `did-management/domain/purge/0.1` | always (also from a request with no session) |
| `did-management/registry/purge-domain/0.1` | yes |
| `did-management/did/delete/0.1` | yes |
| `did-management/identity/retire/0.1` | yes |
| `acl/grant/0.2` | when the entry's role is `admin` or `service` |
| `acl/change-role/0.2` | when `toRole` is `admin` or `service` |
| `auth/passkey/enroll/invite/0.3` | yes, unless the request is signed with the administrator's own DID key |

The refusal is `permissionDenied` with the message `step_up_required`; the
console answers it by stepping the session up and sending the request again.
A request with no session — a VTA sending signed Trust Tasks over DIDComm,
TSP or HTTPS — is authorised by its own proof and is not asked for one
(`domain/purge` aside).

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
[CONTRIBUTING](../CONTRIBUTING.md) guidelines.
