//! Re-export of `did_hosting_common::server::path_locks::PathLocks`.
//!
//! The original implementation lived here; it moved into
//! `did-hosting-common` so the trust-tasks dispatch core (which lives
//! in the common crate to be shared with the daemon) can construct
//! one. This module is preserved as a re-export to keep the existing
//! `crate::path_locks::PathLocks` call sites intact — new consumers
//! depend on the common crate directly.

pub use did_hosting_common::server::path_locks::PathLocks;
