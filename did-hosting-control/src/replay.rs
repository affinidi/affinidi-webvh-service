//! The anti-replay cache now lives in `did-hosting-common`, because the edge
//! servers gate their signed inbound traffic on it too. Re-exported here so
//! existing `did_hosting_control::replay::ReplayCache` paths keep compiling.

pub use did_hosting_common::server::replay::*;
