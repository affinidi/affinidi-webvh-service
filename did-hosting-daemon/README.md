# Affinidi DID Hosting Daemon

The DID Hosting Daemon is a single binary that embeds the main features of
the [control plane](../did-hosting-control/), the
[hosting server](../did-hosting-server/), the
[witness](../webvh-witness/) and the [watcher](../webvh-watcher/) behind one
listener and one store. It is the recommended deployment for a single host.

The daemon coordinates its services in-process rather than over the network:
the control plane runs the only Trust Task listener (TSP, DIDComm and
`POST /api/trust-tasks`) on the authoritative store, and the embedded server
serves public resolution from that same store. It does not register with an
external control plane — it *is* the control plane. See
[docs/architecture.md](../docs/architecture.md).

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
  feature, and the build bundles the console when `../did-hosting-ui` is
  present and the bundle is stale.

### 1. Build

```bash
# Default: with the embedded management UI (needs Node.js)
cargo build --locked -p did-hosting-daemon --release

# Without the UI (no Node.js needed)
cargo build --locked -p did-hosting-daemon --release \
  --no-default-features --features keyring,store-fjall,did-methods
```

The binary is produced at `target/release/did-hosting-daemon`.

### 2. Set up

```bash
did-hosting-daemon setup                       # interactive
did-hosting-daemon setup --from examples/did-hosting-daemon-self-managed.toml
                                               # self-managed: no VTA, runs as shipped
did-hosting-daemon setup --from examples/did-hosting-daemon-build.toml \
                         --setup-key-file setup.key   # VTA-managed (online)
```

A **self-managed** daemon (`[identity] mode = "self-managed"`) mints its own
Ed25519 and X25519 keys, self-hosts its `did:webvh` at `public_url`, and
needs no VTA. A **VTA-managed** daemon has its keys provisioned from a VTA
context (online, or the two air-gapped phases `setup-offline-prepare` /
`setup-offline-complete`). Recipes, exit codes and reprovisioning
(`--force-reprovision`) are in
[docs/bootstrap_startup.md](../docs/bootstrap_startup.md#non-interactive-setup-recipe-driven).

Admit your first administrator with `did-hosting-daemon add-acl --did <DID>
--role admin` (offline, before starting) or a passkey invite
(`did-hosting-daemon invite --did <DID> --role admin`).

### 3. Start the daemon

```bash
did-hosting-daemon --config config.toml
```

It logs which services are active:

```
--- daemon services ---
  server (/)
  witness (/witness)
  control (/)
```

## Configuration

Every key and environment variable (prefix `DAEMON_`) is listed in
[docs/configuration.md](../docs/configuration.md#daemon-only-did-hosting-daemon).
The file is `config.toml` in the working directory unless `--config` or
`DAEMON_CONFIG_PATH` names another; unknown keys and tables are refused at
load. An outline:

```toml
server_did = "did:webvh:<scid>:example.com"   # written by setup
mediator_did = "did:webvh:mediator.example.com" # omit for HTTP-only
public_url = "https://example.com"             # also the passkey origin

[identity]
mode = "self-managed"   # or "vta"

[features]
didcomm = true
tsp = true

[server]
host = "0.0.0.0"
port = 8534

[secrets]
keyring_service = "did-hosting-daemon"

[store]                 # control plane, server and watcher
data_dir = "data/daemon/store"

[witness_store]         # the embedded witness; must be separate data
data_dir = "data/daemon/witness"

[enable]
server = true
witness = true
watcher = false
control = true
```

The daemon reads the shared tables, the control plane's `[registry]`,
`[geoip]`, `[stats_flush]` and `[stats]`, and its own `[witness_store]` and
`[enable]`. It has no `[sync]`, `[replication]` or edge `[stats]` table:
its services share one process. `[witness_store]` must reach different data
from `[store]` (the witness keeps its own ACL there); the daemon refuses to
start otherwise.

A default daemon's registry is empty. It *can* hold remote instances
(`[[registry.instances]]`, or edges that register themselves), but the
daemon does not run the registry health-check loop; use a standalone
control plane to manage remote services.

## HTTP routes

One listener serves everything. The control plane and the server merge at
the root; the witness and watcher nest under prefixes.

| Path | Source | Description |
| --- | --- | --- |
| `GET /health` | daemon | Daemon liveness: `200` while the daemon's own DID is served from its store, `503` (`"status": "degraded"`) otherwise — the control plane's `/api/health` check |
| `GET /api/health` | control plane | Service health (checks the service's own DID resolves) |
| `POST /api/trust-tasks` | control plane | Every management operation, as a signed Trust Task (the HTTPS binding) |
| `GET /api/sign-in/readiness` | control plane | Whether the service DID lists the services wallet sign-in needs |
| `POST /api/auth/challenge` | control plane | Sign-in challenge nonce for a browser with no key yet |
| `GET /{mnemonic}/did.jsonl`, `/did-witness.json`, `/did.json` and the `/.well-known/…` forms | server | Public DID resolution |
| `GET /@`, `/@{name}` | server | Agent-name redirects |
| `POST /witness/api/trust-tasks` | witness | The witness's Trust Tasks (`webvh/witness/*`, `acl/*`) |
| `GET /watcher/{mnemonic}/did.jsonl`, … | watcher | Resolution through the embedded watcher (`[enable] watcher = true`) |
| anything else | control plane | The management UI (`ui` feature) |

The embedded witness and watcher have **no health route of their own**
(`/witness/api/health` and `/watcher/api/health` are not served); probe
`/health` or `/api/health`. The embedded watcher serves resolution only: it
has no DID and runs no listener, so nothing syncs into it. A watcher that
mirrors control planes is a standalone `webvh-watcher`. A test
(`documented_daemon_routes_are_served` in `tests/e2e_daemon.rs`) holds this
table.

## CLI commands

Every subcommand, with its full `--help`, is in
[`docs/cli-reference.md`](../docs/cli-reference.md). `health` exits non-zero
when a check fails (`--strict`: also when one warns).

```
did-hosting-daemon                      # Run the daemon (default)
did-hosting-daemon setup | uninstall | setup-offline-prepare | setup-offline-complete
did-hosting-daemon health [--strict]
did-hosting-daemon add-acl | list-acl | remove-acl   # --witness: the embedded witness's ACL (add/list)
did-hosting-daemon invite               # Passkey enrolment invite
did-hosting-daemon reset-witness-kek-claim
did-hosting-daemon stats-show | stats-set | stats-purge-legacy
did-hosting-daemon fetch-metrics --key <key.json>
did-hosting-daemon send-trust-task --key <key.json> --type <task>
did-hosting-daemon identity-list | identity-rotate-keys | identity-scid-alias | identity-retire-now
did-hosting-daemon tsp-relationship-list | tsp-relationship-reset | tsp-relationship-delete
did-hosting-daemon list-dids | dump-did | load-did | remove-did | recover-did | bootstrap-did | recreate-did
did-hosting-daemon import-secrets | export-sealed | import-sealed
did-hosting-daemon vta-request | vta-open
did-hosting-daemon backup | restore
```

Management of a running daemon beyond these is a Trust Task: through the
console, or signed from the command line as
[docs/sending-trust-tasks.md](../docs/sending-trust-tasks.md) describes.

### Backup and restore

`did-hosting-daemon backup` writes its own format (`"format":
"did-hosting-daemon"`, version 1), not the edge's: both stores (`main` and
`witness`), with an explicit keyspace list for each — the DIDs, the ACLs,
passkeys, identity generations, `did:scid` floors, the outbound queue and
the witness identities — and the configuration file verbatim. Live sessions
and TSP relationship state are left out (a test holds that every keyspace is
either backed up or excluded with a reason). Private keys are not in it:
back up the secrets backend too, including the witness key-encryption key's
entry. See [docs/backup-and-upgrade.md](../docs/backup-and-upgrade.md).

## What the daemon does not do

These are deliberate (see the "did-hosting-daemon" section of
[CLAUDE.md](../CLAUDE.md)):

- The embedded server runs no DIDComm/TSP listener; the control plane's
  handles every inbound document.
- No stats sync: statistics are shared in-process.
- No registry health-check loop, and no self-registration anywhere.

Identity rotation of the daemon's own DID is owned by its control plane.

## Feature flags

| Feature | Default | Description |
| --- | --- | --- |
| `ui` | on | Embed the management UI |
| `keyring` | on | OS keyring secrets backend |
| `store-fjall` | on | Embedded fjall store |
| `did-methods` | on | `did:webvh` + `did:web` resolution |
| `method-webs` | off | `did:webs` publication and resolution (pulls the KERI stack) |
| `aws-secrets`, `gcp-secrets`, `azure-secrets`, `vault-secrets`, `k8s-secrets` | off | Other secrets backends |
| `store-redis`, `store-dynamodb`, `store-firestore`, `store-cosmosdb` | off | Other store backends (exactly one store backend) |
| `metrics` | off | Process counters, read with `fetch-metrics` (see [docs/metrics.md](../docs/metrics.md)) |

Passkey/WebAuthn is always compiled in; it activates when `public_url` is
set.

## Graceful shutdown

The daemon handles `SIGINT` and `SIGTERM` in stages, each given at most 30
seconds: the background workers (outbox, sweeps), then the messaging service,
then HTTP (a connection still open at the deadline is dropped, so one stalled
client cannot hold up a `SIGTERM`), then the storage task's last statistics
flush and the store's persist, then the witness store's.

A background task that stops on its own while the daemon runs is logged at
`error`: a restartable one (the outbox, the sweeps) is restarted with backoff,
and a critical one (the HTTP listener, the storage task) shuts the daemon down
with a non-zero exit, so a supervisor or orchestrator restarts it.

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
