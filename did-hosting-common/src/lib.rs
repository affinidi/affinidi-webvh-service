//! Shared library for the DID hosting service: the stable surface every
//! binary (`did-hosting-server`, `-control`, `-witness`, `-watcher`,
//! `-daemon`) and external clients build on.
//!
//! # Stability
//!
//! The wire and data shapes here — request/response types (the private
//! `types` module, re-exported at the root), DID parsing ([`did`], [`scid`]), the
//! [`DidMethod`](method::DidMethod) abstraction, the `DidRecord`
//! ([`did_ops`]) and the generated Trust Task types (`tasks`) — are what
//! the other crates point consumers at. The `server` module is shared
//! service plumbing: public so the binaries can compose it, but unstable.
//!
//! # Feature flags
//!
//! - `method-webvh`, `method-web` (default), `method-webs`,
//!   `method-webplus` — which DID methods [`method::method_by_name`]
//!   compiles in. `method-webs` pulls the KERI stack; `method-webplus` is
//!   a stub.
//! - `server-core` — the service runtime: `server` (config, store, ACL,
//!   auth, Trust Task dispatch, DIDComm/TSP transports, identity,
//!   migrations, stats), the `tasks` types, the `WebVHClient` and
//!   `WitnessClient` HTTP clients and `outbound_client`.
//! - `store-fjall`, `store-redis`, `store-dynamodb`, `store-firestore`,
//!   `store-cosmosdb` — storage backends (each implies `server-core`).
//! - `keyring`, `aws-secrets`, `gcp-secrets`, `azure-secrets`,
//!   `vault-secrets`, `k8s-secrets` — secret-store backends.
//! - `setup-wizard` — interactive setup prompts; `passkey` — WebAuthn
//!   sign-in; `metrics` — operational counters
//!   (read through the `server/metrics` Trust Task).
//! - `test-support`, `cosmosdb-emulator` — test-only seams.

pub mod cli_reference;
#[cfg(feature = "server-core")]
mod client;
pub mod did;
pub mod did_ops;
pub mod didcomm_types;
mod error;
#[cfg(feature = "server-core")]
mod http;
/// The shared outbound HTTP client: finite timeouts, redirects refused.
#[cfg(feature = "server-core")]
pub use http::outbound_client;
pub mod method;
pub mod scid;
mod types;
#[cfg(feature = "server-core")]
mod witness_client;

#[cfg(feature = "server-core")]
pub mod server;

/// The Trust Task types this workspace speaks, generated at build time by
/// `trust-tasks-build` from the versions pinned in `trust-tasks.lock` (beside
/// this crate's `Cargo.toml`). Each version sits at the path `trust_tasks_rs::specs`
/// would give it (`tasks::acl::grant::v0_2`). The framework's own
/// specifications (`trust-task-discovery`, `trust-task-error`) are not here:
/// the `trust-tasks-rs` runtime carries them.
#[cfg(feature = "server-core")]
#[allow(clippy::all, clippy::pedantic, missing_docs, unreachable_pub)]
pub mod tasks {
    include!(concat!(env!("OUT_DIR"), "/trust_tasks_generated.rs"));
    include!(concat!(env!("OUT_DIR"), "/trust_tasks_schema_index.rs"));

    /// The payload schema a document of `type_uri` must satisfy: a pinned
    /// version's from [`schema_for`], else the framework's own specs
    /// (discovery, `trust-task-error`), which the runtime carries and this
    /// workspace does not pin. The one lookup every reply-conformance check
    /// uses, so they cannot drift apart.
    pub fn payload_schema(type_uri: &str) -> Option<&'static str> {
        schema_for(type_uri).or_else(|| ::trust_tasks_rs::schema_index::schema_for(type_uri))
    }
}

#[cfg(feature = "server-core")]
pub use client::{DidSummary, WebVHClient};
pub use error::{Result, WebVHError};
pub use types::*;
#[cfg(feature = "server-core")]
pub use witness_client::WitnessClient;

// Re-export Secret so SDK users don't need affinidi-tdk directly.
pub use affinidi_tdk::secrets_resolver::secrets::Secret;
