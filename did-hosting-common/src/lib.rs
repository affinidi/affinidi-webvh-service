#[cfg(feature = "server-core")]
mod client;
pub mod did;
pub mod did_ops;
pub mod didcomm_types;
mod error;
#[cfg(feature = "server-core")]
mod http;
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
}

#[cfg(feature = "server-core")]
pub use client::{DidSummary, WebVHClient};
pub use error::{Result, WebVHError};
pub use types::*;
#[cfg(feature = "server-core")]
pub use witness_client::WitnessClient;

// Re-export Secret so SDK users don't need affinidi-tdk directly.
pub use affinidi_tdk::secrets_resolver::secrets::Secret;
