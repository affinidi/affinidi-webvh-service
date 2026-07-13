# Affinidi DID Hosting Common

Shared library used by all DID Hosting service crates. This crate
provides common types, traits, and modules so that services
share a consistent implementation of cross-cutting concerns.

> **IMPORTANT:**
> did-hosting-service crates are provided "as is" without any
> warranties or guarantees, and by using this framework, users
> agree to assume all risks associated with its deployment and
> use including implementing security, and privacy measures in
> their applications. Affinidi assumes no liability for any
> issues arising from the use or modification of the project.

## Modules

### Core Types (`types.rs`)

- `SyncDidRequest` / `SyncDeleteRequest` — DID replication
  payloads used between did-hosting-server and webvh-watcher

### Server Modules (`server/`, behind `server-core` feature)

Shared infrastructure for authenticated services:

- **`config`** — `ServerConfig`, `LogConfig`, `AuthConfig`,
  `SecretsConfig`, `StoreConfig`, `FeaturesConfig`, and
  `apply_env_overrides()` helper
- **`auth`** — DIDComm v2 challenge-response authentication
  with JWT token issuance. Includes `AuthState` trait,
  `JwtKeys`, session management, and auth extractors
- **`acl`** — Access control with `AclEntry`, `Role`
  (Admin/Owner), and CRUD operations on the ACL keyspace
- **`store`** — Storage abstraction over fjall with
  `KeyspaceHandle`, batch operations, and persistence
- **`secret_store`** — Pluggable secrets backend trait with
  implementations for OS keyring, plaintext (dev only),
  AWS Secrets Manager, and GCP Secret Manager
- **`error`** — `AppError` enum with Axum `IntoResponse`
  implementation
- **`passkey`** — WebAuthn passkey enrollment and login
  (behind `passkey` feature). Provides `PasskeyState` trait
  and generic route handlers

### Witness Client (`witness_client.rs`)

HTTP client for communicating with webvh-witness instances.

## Feature Flags

| Feature | Default | Description |
| ------- | ------- | ----------- |
| `server-core` | off | Server infrastructure (auth, ACL, config, secret-store framework, security headers). Enables every other server-side feature below. |
| `metrics` | off | Prometheus metrics emitters (requires `server-core`). |
| `setup-wizard` | off | Interactive `dialoguer` prompts used by binary setup commands (requires `server-core`). |
| `passkey` | off | WebAuthn passkey enrolment + login (requires `server-core`). |
| `store-fjall` | off | Fjall embedded key-value store. |
| `store-redis` | off | Redis store backend. |
| `store-dynamodb` | off | AWS DynamoDB store backend (auto-provisions 12 keyspace-per-table layout). |
| `store-dynamodb-single` | off | AWS DynamoDB store backend using **one externally-provisioned** composite-key (`pk`+`sk`) table. Requires `store.dynamodb_table_name`. No `CreateTable`/`DescribeTable`/`Scan` at runtime. |
| `store-firestore` | off | Google Cloud Firestore store backend. |
| `store-cosmosdb` | off | Azure Cosmos DB (`key_auth`) store backend. |
| `keyring` | off | OS keyring secret backend (`keyring-core` 1.x). Supported targets: macOS, Windows, Linux. |
| `aws-secrets` | off | AWS Secrets Manager secret backend. |
| `gcp-secrets` | off | GCP Secret Manager secret backend. |
| `azure-secrets` | off | Azure Key Vault secret backend. |

> **Storage backends are mutually exclusive.** Only one of `store-fjall`,
> `store-redis`, `store-dynamodb`, `store-dynamodb-single`, `store-firestore`,
> `store-cosmosdb` may be active at a time — the binaries' `build.rs` panics
> at compile time if more than one is selected.

## Usage

Services depend on did-hosting-common with the features they need:

```toml
[dependencies]
did-hosting-common = { path = "../did-hosting-common", features = ["server-core", "store-fjall"] }
```

Services typically re-export shared modules for internal use:

```rust
// In a service's acl.rs, auth.rs, store.rs, etc.
pub use did_hosting_common::server::acl::*;
```

## Requirements

- Rust 1.94.0+ (2024 Edition)

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
