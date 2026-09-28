#[cfg(feature = "server-core")]
mod client;
pub mod did;
pub mod did_ops;
pub mod didcomm_types;
mod error;
#[cfg(feature = "server-core")]
mod http;
pub mod method;
mod types;
#[cfg(feature = "server-core")]
mod witness_client;

#[cfg(feature = "server-core")]
pub mod server;

#[cfg(feature = "server-core")]
pub use client::{DidSummary, WebVHClient};
pub use error::{Result, WebVHError};
pub use types::*;
#[cfg(feature = "server-core")]
pub use witness_client::WitnessClient;

// Re-export Secret so SDK users don't need affinidi-tdk directly.
pub use affinidi_tdk::secrets_resolver::secrets::Secret;
