//! DID Hosting Control Plane — DID lifecycle management, ACL, registry, and UI.
//!
//! # Stability
//!
//! Pre-1.0 — the public-module surface is intentionally wide so that
//! `did-hosting-daemon` can compose this crate as a library. Treat every `pub`
//! module as **unstable**; breaking changes can land in any minor version.
//! Pin internal deps with `major.minor` (`= "0.6"`). The semver-stable
//! shapes consumers should rely on (request/response types, DID shapes,
//! auth primitives) live in `did-hosting-common`.

pub mod acl;
pub mod auth;
pub mod config;
pub mod did_ops;
pub mod error;
#[cfg(feature = "ui")]
pub mod frontend;
pub mod health;
pub mod identity_rotation;
pub mod messaging;
pub mod outbox;
pub mod path_locks;
pub mod pending_challenges;
pub mod purge_sweep;
pub mod rate_limit;
pub mod registry;
pub mod replay;
pub mod routes;
pub mod secret_store;
pub mod server;
pub mod server_push;
pub mod setup;
pub mod setup_recipe;
pub mod store;
pub mod trust_tasks_did;
pub mod trust_tasks_infra;
pub mod tsp;
