//! WebVH Watcher — a read-only DID mirror. Its sources (control planes) push
//! signed `webvh/sync/*` Trust Tasks to it over TSP, DIDComm or HTTPS; it
//! verifies every log exactly as an edge does and serves the result publicly
//! for redundancy. It has its own DID, with keys in a VTA context.
//!
//! # Stability
//!
//! Pre-1.0 — the public-module surface is intentionally wide so that
//! `did-hosting-daemon` can compose this crate as a library. Treat every `pub`
//! module as **unstable**; breaking changes can land in any minor version.
//! Pin internal deps with `major.minor` (`= "0.6"`).

pub mod config;
pub mod error;
pub mod health;
pub mod messaging;
pub mod routes;
pub mod secret_store;
pub mod server;
pub mod setup;
pub mod store;
pub mod trust_tasks;
pub mod tsp;
pub mod watcher_ops;
