mod client;
pub mod did;
mod error;
mod types;

pub use client::WebVHClient;
pub use error::{Result, WebVHError};
pub use types::*;

// Re-export Secret so SDK users don't need affinidi-tdk directly.
pub use affinidi_tdk::secrets_resolver::secrets::Secret;
