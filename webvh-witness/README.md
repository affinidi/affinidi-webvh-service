# Affinidi WebVH Witness

The WebVH Witness node generates and manages cryptographic witness
proofs for [WebVH](https://www.w3.org/TR/did-web-vh/) DID integrity
verification. Witness proofs provide third-party attestation that a
DID document was observed at a specific point in time.

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

### 1. Build

```bash
cargo build --locked -p webvh-witness --release
```

The binary is produced at `target/release/webvh-witness`.

### 2. Run the setup wizard

```bash
webvh-witness setup                          # interactive
webvh-witness setup --from <recipe.toml>     # non-interactive (CI / scripted)
```

For non-interactive runs see
[docs/bootstrap_startup.md](../docs/bootstrap_startup.md#non-interactive-setup-recipe-driven)
and the example recipe at `examples/webvh-witness-build.toml`.

The interactive wizard walks you through configuration:

- **VTA credential** — authenticates with the witness's VTA
  context and creates the witness DID automatically
- **Features** — enable DIDComm messaging and/or REST API
- **DID hosting** — URL and path where did-hosting-server will host
  the witness DID
- **Host / port** — listen address (default: `0.0.0.0:8102`)
- **Log level / format** — logging configuration
- **Data directory** — persistent storage path
- **Secrets backend** — where to store private key material
- **Admin bootstrap** — enter an existing DID or generate a
  new `did:key` identity

### 3. Start the witness

```bash
webvh-witness --config config.toml
```

## Configuration

The witness is configured via a TOML file. By default it looks
for `config.toml` in the current directory. You can specify a
different path with the `--config` flag or the
`WITNESS_CONFIG_PATH` environment variable.

### Example `config.toml`

```toml
server_did = "did:webvh:witness.example.com"
mediator_did = "did:webvh:mediator.example.com"

[features]
didcomm = true
rest_api = true

[server]
host = "0.0.0.0"
port = 8531

[log]
level = "info"
format = "text"

[store]
data_dir = "data/webvh-witness"

[auth]
access_token_expiry = 900
refresh_token_expiry = 86400
challenge_ttl = 300

[secrets]
keyring_service = "webvh-witness"

# Optional: VTA integration for remote key management
# [vta]
# url = "https://vta.example.com"
# did = "did:webvh:vta.example.com"
# context_id = "witness-context"
```

### Environment Variable Overrides

Environment variables use the `WITNESS_` prefix:

| Variable                    | Description               |
| --------------------------- | ------------------------- |
| `WITNESS_CONFIG_PATH`       | Path to config file       |
| `WITNESS_SERVER_DID`        | Witness DID identifier    |
| `WITNESS_MEDIATOR_DID`      | Mediator DID identifier   |
| `WITNESS_SERVER_HOST`       | Bind host                 |
| `WITNESS_SERVER_PORT`       | Bind port                 |
| `WITNESS_LOG_LEVEL`         | Log level                 |
| `WITNESS_SERVER_TRUSTED_PROXIES` | Comma-separated proxy addresses or CIDR ranges whose `X-Forwarded-For` is trusted |
| `WITNESS_VTA_URL`           | VTA REST URL              |
| `WITNESS_VTA_DID`           | VTA DID                   |
| `WITNESS_VTA_CONTEXT_ID`    | VTA context ID            |
| `WITNESS_REPLAY_MAX_ENTRIES` | Replay cache records, all signers (default 1,000,000, about 32 MB) |
| `WITNESS_REPLAY_MAX_ENTRIES_PER_SIGNER` | Replay cache records per signer (default 250,000, about 600 signed requests a second) |

The replay settings live in `[replay]` (`max_entries`,
`max_entries_per_signer`). The per-signer bound caps how fast one caller, such as a VTA, can have
entries witnessed (about 600 a second at the default). The control plane's README explains the
bounds ("Replay cache bounds").

### Connection limits and a reverse proxy

The HTTP listener applies its own limits: at most 256 connections are
served at once (more wait for a free slot), at most 32 of them from one
IPv4 address or IPv6 /64 (more are closed at once; addresses in
`server.trusted_proxies` are exempt); a request's headers must arrive
within 20 seconds of its first byte; a connection waiting for its next
request, or not reading its response, is closed after 60 seconds; and a
`POST /api/trust-tasks` body is read only after the sender's address passes
its rate limit, at most 1 MiB and within 30 seconds (`413` / `408`
otherwise). These are a backstop. The listener binds `0.0.0.0` by default;
put a reverse proxy in front of it for TLS and its own limits, and list the
proxy in `server.trusted_proxies` so per-address limits apply to clients
rather than to the proxy.

## CLI Commands

```
webvh-witness                                  # Run witness (default)
webvh-witness setup                            # Interactive config wizard
webvh-witness add-acl --did <DID> --role admin|service  # Add ACL entry
webvh-witness list-acl                         # List ACL entries
webvh-witness create-witness [--label <name>]  # Create witness identity
webvh-witness list-witnesses                   # List witness identities
webvh-witness delete-witness --id <ID>         # Delete witness identity
```

### Witness Identity Management

Before the witness can sign proofs, you need to create at least
one witness identity:

```bash
# Create a witness identity
webvh-witness create-witness --label "primary"

# List all witness identities
webvh-witness list-witnesses

# Delete a witness identity
webvh-witness delete-witness --id z6Mk...
```

#### Where the signing keys are kept

A witness identity's record in the data store (`[store]`) holds its public
metadata (`witness_id`, DID, label, counters) and its Ed25519 private key
**sealed** (HPKE: X25519, HKDF-SHA256, ChaCha20-Poly1305) to the witness
key-encryption key. That key is held in the secret store configured under
`[secrets]`, in an entry of its own beside the service's keys:

| Backend | Service keys | Witness key-encryption key |
| ------- | ------------ | -------------------------- |
| keyring | account `server_secrets` | account `witness_key_encryption_key` (same service) |
| aws / gcp / azure | `<secret name>` | `<secret name>-witness-kek` |
| vault | `<secret path>` | `<secret path>-witness-kek` |
| kubernetes | Secret `<name>` | Secret `<name>-witness-kek` |
| plaintext (tests) | `<config>.secrets.plaintext` | `<config>.witness-kek.plaintext` |

The witness creates the key on its first start (or the first
`create-witness`) and only reads it afterwards. On the cloud, Vault and
Kubernetes backends, the witness's credentials need permission to create and
read that second entry. So:

- A data-store backup (or a copy of `data_dir`, or a table export) holds no
  usable signing key. Back up the key-encryption key's entry as well:
  without it no identity can sign after a restore.
- The data store records the key-encryption key's public half. A witness
  whose secret store holds no key, or a different one, while its identities
  are sealed to the recorded key refuses to start and names the entry to
  restore. It does not create a new one over them.
- `setup` re-run with another backend, and `export-sealed` /
  `import-sealed`, move the service's own keys only, not the key-encryption
  key: copy its entry across yourself.
- If a first start stops after claiming the key's creation but before
  writing it, the next start waits 30 s and then says so; run
  `webvh-witness reset-witness-kek-claim` (`did-hosting-daemon
  reset-witness-kek-claim` for the embedded witness; refused once a key is
  held or recorded) and start again. A first write the secret store refuses
  releases the claim itself.
- Earlier releases kept each private key in clear in the record. On its
  first start after the upgrade, the witness seals every such key in place,
  checking first that each key belongs to its identity (startup is refused,
  naming the identity and changing nothing, if one does not). It logs the
  witness ids sealed, never keys. Keys are not changed, so no DID's witness
  list needs updating. Copies of the old records in earlier backups or
  snapshots still hold the keys in clear, and restoring one brings clear
  keys back into the store until the witness next starts. An identity whose
  key cannot be opened is named in a warning at startup.
- Rolling back to an earlier release after the upgrade does not work: an
  earlier release cannot read a sealed record. Nothing is lost; upgrading
  again works.

## Trust Tasks

The witness has no REST management API. Every operation is a
[Trust Task](https://trusttasks.org) document signed by its requester
(`proofPurpose: authentication`, by one of the requester's `authentication`
keys) and addressed to the witness's DID. The same documents are served on
every transport:

- **TSP** and **DIDComm**, on the witness's mediator connection;
- **HTTPS**, `POST /api/trust-tasks`.

| Task | Who may send it |
| ---- | --------------- |
| `webvh/witness/key/create/0.1` | an Admin |
| `webvh/witness/key/list/0.1` | an Admin |
| `webvh/witness/key/delete/0.1` | an Admin |
| `webvh/witness/sign/0.1` | an Admin or a Service |
| `acl/grant\|revoke\|change-role\|show/0.2`, `acl/list/0.3` | an Admin; any member may also show or revoke its own entry |

Enter a caller that only needs proofs — a control plane, a VTA, an edge
bootstrapping its DID — with role `service`: it can request signatures with
any of the witness's identities (its ACL entry states `keys: all`) and
cannot create or delete identities or change the ACL. Keep `admin` for the
operators who manage the witness. An `owner` or `metricsReader` entry can do
nothing on a witness, and `add-acl` accepts only `admin` and `service`.

In `did-hosting-daemon` the embedded witness's ACL is kept in
`[witness_store]`, apart from the control plane's. Add the first entry with
`did-hosting-daemon add-acl --witness --did <DID> --role admin|service` (and
list it with `list-acl --witness`); after that the ACL Trust Tasks on
`/witness/api/trust-tasks` manage it. There is no daemon CLI to remove a
witness entry; use `acl/revoke`. The daemon refuses to start if `[witness_store]`
reaches the same data as `[store]`, since the witness would then share the
control plane's ACL. It checks by writing a probe value through `[store]` and
looking for it through `[witness_store]`, so any spelling of the same Redis
database, DynamoDB prefix and region, or Firestore or Cosmos DB database is
caught. The CHANGELOG describes how to move a deployment that shares one.

`webvh/witness/sign` carries the DID log up to and including the entry to
witness, and the witness verifies it before signing: the chain must verify,
`versionId` must be the last entry, the DID must not be deactivated, and the
witness parameter in force for the entry must name the witness identity.

A document that does not verify — unsigned, signed with the wrong proof
purpose, not addressed to this witness, stale, or a replay — gets no reply
(HTTPS answers `403` with an unsigned, detail-free body). A verified document
from a DID the witness does not authorise is refused with a signed
`permissionDenied`. Every other reply is signed by the witness.

`GET /api/health` stays a plain, unauthenticated liveness probe.

## Library Usage

The webvh-witness crate can be used as a library (e.g., by the
[did-hosting-daemon](../did-hosting-daemon/)). It exposes:

- `webvh_witness::config::AppConfig` — configuration
- `webvh_witness::server::AppState` — application state
- `webvh_witness::routes::router()` — Axum router (`POST /api/trust-tasks`)
- `webvh_witness::trust_tasks::dispatch_inbound_document` — the one inbound dispatch
- `webvh_witness::server::run()` — standalone entry point
- `webvh_witness::signing::LocalSigner` — witness proof signing

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
