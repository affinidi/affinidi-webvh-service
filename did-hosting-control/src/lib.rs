//! DID Hosting Control Plane — DID lifecycle management, ACL, registry, and UI.
//!
//! # Stability
//!
//! Pre-1.0 — the public-module surface is intentionally wide so that
//! `did-hosting-daemon` can compose this crate as a library. Treat every `pub`
//! module as **unstable**; breaking changes can land in any minor version.
//! Pin internal deps to the release's `major.minor`. The semver-stable
//! shapes consumers should rely on (request/response types, DID shapes,
//! auth primitives) live in `did-hosting-common`.

pub mod auth;
pub mod cli;
pub mod config;
pub(crate) mod control_tasks;
pub mod did_ops;
#[cfg(feature = "ui")]
pub mod frontend;
pub mod geoip;
pub mod health;
pub mod identity_rotation;
pub mod messaging;
pub mod oob;
pub mod outbox;
pub mod pending_challenges;
pub mod purge_sweep;
pub mod rate_limit;
pub mod registry;
#[cfg(test)]
mod replication_e2e;
pub mod routes;
pub mod secret_store;
pub mod server;
pub mod server_push;
pub mod setup;
pub mod setup_recipe;
pub mod sign_in_readiness;
pub mod signing;
pub mod stats_admin;
pub mod stats_cli;
pub mod stats_flush;
pub mod stats_migration;
pub mod stats_query;
#[cfg(feature = "test-support")]
pub mod test_support;
pub mod trust_tasks_auth;
pub mod tsp;
pub mod unlisted_signers;
#[cfg(test)]
mod watcher_e2e;
pub(crate) mod webs_self_register;
