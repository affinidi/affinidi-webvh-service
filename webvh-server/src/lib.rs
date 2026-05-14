//! WebVH Server — read-only DID-resolver edge node.
//!
//! # Stability
//!
//! Every module below is `pub` because `webvh-daemon` (and `webvh-server`'s
//! own binary) consume them as if this crate were an internal library.
//! Treat the public surface as **unstable** while the workspace is pre-1.0:
//! breaking changes can land in any minor version. Pin internal deps with a
//! `major.minor` constraint (`= "0.6"`) so a `0.7` cycle that narrows the
//! API doesn't surprise you. The thin, semver-stable consumer-facing
//! surface lives in `affinidi-webvh-common` (DID types, request/response
//! shapes, shared auth primitives).

pub mod acl;
pub mod auth;
pub mod backup;
pub mod bootstrap;
pub mod cache;
pub mod config;
pub mod control_register;
pub mod did_ops;
pub mod error;
pub mod health;
pub mod messaging;
pub mod mnemonic;
pub mod routes;
pub mod secret_store;
pub mod server;
pub mod setup;
pub mod setup_recipe;
pub mod stats;
pub mod store;
pub mod watcher_push;
