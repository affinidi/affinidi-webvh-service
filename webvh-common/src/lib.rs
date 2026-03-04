mod client;
mod control_client;
pub mod did;
mod error;
mod types;
mod watcher_client;
mod witness_client;

#[cfg(feature = "server-core")]
pub mod server;

pub use client::WebVHClient;
pub use control_client::{
    ControlClient, DidSyncEntry, DidSyncUpdate, RegisterServiceRequest, RegisterServiceResponse,
};
pub use error::{Result, WebVHError};
pub use types::*;
pub use watcher_client::WatcherClient;
pub use witness_client::WitnessClient;

// Re-export Secret so SDK users don't need affinidi-tdk directly.
pub use affinidi_tdk::secrets_resolver::secrets::Secret;
