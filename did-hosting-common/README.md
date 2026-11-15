# Affinidi DID Hosting Common

The shared library under every DID Hosting binary, and the client crate for
anything that talks to a DID Hosting control plane. It carries the
generated Trust Task types, the Trust Task client and transport machinery,
DID-method support, and (behind `server-core`) the server infrastructure the
services share.

> **IMPORTANT:**
> did-hosting-service crates are provided "as is" without any
> warranties or guarantees, and by using this framework, users
> agree to assume all risks associated with its deployment and
> use including implementing security, and privacy measures in
> their applications. Affinidi assumes no liability for any
> issues arising from the use or modification of the project.

## What is in it

### For clients (behind `server-core`)

- **`WebVHClient`** — a client for a control plane's
  `POST /api/trust-tasks`: it signs each request as your DID
  (`sign_as`), verifies that every reply is signed by the service, and wraps
  the DID-management tasks (`check_name`, `request_uri`, `upload_did`,
  `list_dids`, `delete_did`, `create_did`, agent-name operations). See
  `did-hosting-server/examples/client.rs`.
- **`WitnessClient`** — the same for a `webvh-witness`.
- **`tasks`** — the Trust Task request and response types this workspace
  speaks, generated at build time from the versions pinned in
  [`trust-tasks.lock`](trust-tasks.lock) (`tasks::did_management::did::register::v0_1`,
  `tasks::acl::grant::v0_2`, …). Each `Payload::TYPE_URI` is the task's Type
  URI; name tasks by it, never by a hand-written string.
- **`server::trust_tasks`** — the shared Trust Task machinery: the inbound
  gate (`bound::verify_sender_bound`), the proof verifier
  (`TransportBoundVerifier`), the ACL family's handlers, document size
  limits, and `send` (`build_signed_request`,
  `post_trust_task_https_verified`) for signing and sending a document over
  HTTPS and verifying its signed reply.

### Always available

- **`did`**, **`did_ops`** — DID helpers and the shared DID-record model.
- **`method`** — DID-method support: `webvh`, `web` and `webs`, each behind
  its `method-*` feature (`webplus` is a stub that does not compile).
- **`scid`** — `did:scid` identity and alias helpers.
- **`cli_reference`** — renders `docs/cli-reference.md` from each binary's
  clap definition, with the drift test every binary carries.
- Wire types shared with older clients (`types`): auth, DID-registration and
  stats-sync payloads.

### Server infrastructure (`server/`, behind `server-core`)

- **`config`** — the shared config tables (`ServerConfig`, `StoreConfig`,
  `AuthConfig`, `SecretsConfig`, `FeaturesConfig`, `HostingConfig`,
  `IdentityConfig`, `ReplayConfig`, `FjallTuning`) and their env overrides;
  documented in [docs/configuration.md](../docs/configuration.md).
- **`store`** — the storage abstraction and its five backends (fjall, Redis,
  DynamoDB, Firestore, Cosmos DB), with a shared conformance suite
  (`store::conformance`).
- **`secret_store`** — the node's key envelope over the `vti-secrets`
  backends.
- **`acl`** — ACL entries and their four roles: `Admin`, `Owner`, `Service`
  and `MetricsReader`.
- **`auth`**, **`passkey`** — session and challenge handling and WebAuthn
  (passkeys behind `passkey`).
- **`identity`**, **`identity_rotate`**, **`identity_drain`** — the node's
  own identity generations and rotation.
- **`didcomm_profile`**, **`tsp_binding`**, **`tsp_relationship`** — the
  messaging transports, and `resolve_send_binding`, which picks how to reach
  a peer from its DID document.
- **`rate_limit`**, **`listener`**, **`replay`** — per-address limits, the
  HTTP listener's connection limits, and the anti-replay cache.
- **`backup`**, **`domain`**, **`domain_purge`**, **`pending_purge`**,
  **`stats_collector`**, **`stats_tiers`**, **`metrics`**, **`health`**,
  **`setup_recipe`**, **`vta_setup`**, and the `cli_*` modules each binary's
  subcommands share.

## Feature flags

| Feature | Default | Description |
| --- | --- | --- |
| `method-webvh` | on | `did:webvh` support. |
| `method-web` | on | `did:web` support. |
| `method-webs` | off | `did:webs` support (pulls the KERI stack). |
| `server-core` | off | Server infrastructure, the client types (`WebVHClient`, `tasks`). Every feature below except the `method-*` ones enables it. |
| `store-fjall` | off | Embedded fjall store. |
| `store-redis` | off | Redis store. |
| `store-dynamodb` | off | AWS DynamoDB store. |
| `store-firestore` | off | Google Cloud Firestore store. |
| `store-cosmosdb` | off | Azure Cosmos DB store (one container, `cosmosdb_container`). |
| `keyring` | off | OS keyring secrets backend (macOS, Windows, Linux Secret Service). |
| `aws-secrets` | off | AWS Secrets Manager. |
| `gcp-secrets` | off | GCP Secret Manager. |
| `azure-secrets` | off | Azure Key Vault. |
| `vault-secrets` | off | HashiCorp Vault KV v2 (Kubernetes, token or AppRole auth). |
| `k8s-secrets` | off | A native Kubernetes `Secret`. |
| `passkey` | off | WebAuthn passkey enrolment and login. |
| `setup-wizard` | off | Interactive `dialoguer` prompts for the binaries' `setup`. |
| `metrics` | off | In-process operational counters, read through the signed `server/metrics` Trust Task (no scrape endpoint; see [docs/metrics.md](../docs/metrics.md)). |
| `test-support` | off | Test-only seams; never in a release build. |

A binary compiles in exactly one `store-*` backend.

> **Server tests need a feature.** The `server` modules compile only with
> `server-core`, and store-backed tests need a backend:
> `cargo test -p did-hosting-common --features store-fjall`. A plain
> `cargo test -p did-hosting-common` silently skips them.

## Usage

```toml
[dependencies]
did-hosting-common = { version = "0.12", features = ["server-core"] }
```

```rust
use did_hosting_common::WebVHClient;

let mut client = WebVHClient::new("https://control.example.com");
client.sign_as(&my_did, &my_secret, &service_did).await?;
let dids = client.list_dids().await?;
```

## Requirements

- Rust: the workspace MSRV is `rust-version` in the root
  [`Cargo.toml`](../Cargo.toml) (2024 edition).

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
