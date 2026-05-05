//! WebVH Watcher — read-only DID mirror that receives pushed updates from
//! servers and serves them publicly for redundancy.
//!
//! # Stability
//!
//! Pre-1.0 — the public-module surface is intentionally wide so that
//! `webvh-daemon` can compose this crate as a library. Treat every `pub`
//! module as **unstable**; breaking changes can land in any minor version.
//! Pin internal deps with `major.minor` (`= "0.6"`).

pub mod config;
pub mod error;
pub mod health;
pub mod routes;
pub mod server;
pub mod setup;
pub mod store;
pub mod watcher_ops;
