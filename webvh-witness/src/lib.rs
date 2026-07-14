//! WebVH Witness — generates and signs cryptographic witness proofs for
//! DID integrity verification.
//!
//! # Stability
//!
//! Pre-1.0 — the public-module surface is intentionally wide so that
//! `did-hosting-daemon` can compose this crate as a library. Treat every `pub`
//! module as **unstable**; breaking changes can land in any minor version.
//! Pin internal deps with `major.minor` (`= "0.6"`).
//!
//! Notably stable: the [`signing::WitnessSigner`] trait is the documented
//! extension point for plugging in remote-signing backends (HSM, KMS,
//! VTA-managed keys). Its signature is async (returns a `BoxFuture`) and
//! intended to remain stable across the 0.6 series.

pub mod acl;
pub mod auth;
pub mod config;
pub mod error;
pub mod health;
pub mod identity_rotation;
pub mod messaging;
pub mod routes;
pub mod secret_store;
pub mod server;
pub mod setup;
pub mod setup_recipe;
pub mod signing;
pub mod store;
pub mod witness_ops;
