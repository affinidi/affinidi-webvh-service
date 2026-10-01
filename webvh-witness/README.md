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
| `WITNESS_VTA_URL`           | VTA REST URL              |
| `WITNESS_VTA_DID`           | VTA DID                   |
| `WITNESS_VTA_CONTEXT_ID`    | VTA context ID            |

## CLI Commands

```
webvh-witness                                  # Run witness (default)
webvh-witness setup                            # Interactive config wizard
webvh-witness add-acl --did <DID> [--role admin|owner]  # Add ACL entry
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
| `webvh/witness/sign/0.1` | an Admin |
| `acl/grant\|revoke\|change-role\|show\|list/0.1` | per the ACL family's rules |

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
