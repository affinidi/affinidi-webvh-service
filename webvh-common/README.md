# Affinidi WebVH Common

Shared library used by all WebVH service crates. This crate
provides common types, traits, and modules so that services
share a consistent implementation of cross-cutting concerns.

> **IMPORTANT:**
> affinidi-webvh-service crates are provided "as is" without any
> warranties or guarantees, and by using this framework, users
> agree to assume all risks associated with its deployment and
> use including implementing security, and privacy measures in
> their applications. Affinidi assumes no liability for any
> issues arising from the use or modification of the project.

## Modules

### Core Types (`types.rs`)

- `SyncDidRequest` / `SyncDeleteRequest` — DID replication
  payloads used between webvh-server and webvh-watcher

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

| Feature | Description |
| ------- | ----------- |
| `server-core` | Server infrastructure (auth, ACL, store, config, secrets) |
| `store-fjall` | Fjall embedded key-value store backend |
| `keyring` | OS keyring secrets backend |
| `aws-secrets` | AWS Secrets Manager backend |
| `gcp-secrets` | GCP Secret Manager backend |
| `passkey` | WebAuthn passkey authentication |

## Usage

Services depend on webvh-common with the features they need:

```toml
[dependencies]
affinidi-webvh-common = { path = "../webvh-common", features = ["server-core", "store-fjall"] }
```

Services typically re-export shared modules for internal use:

```rust
// In a service's acl.rs, auth.rs, store.rs, etc.
pub use affinidi_webvh_common::server::acl::*;
```

## Requirements

- Rust 1.91.0+ (2024 Edition)

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
