//! Shared DID types and pure helper functions used by both did-hosting-server and
//! did-hosting-control.
//!
//! This module contains the data types and validation/extraction functions that
//! are independent of any particular server's `AppState` or business logic:
//!
//! - `record` — the stored data types ([`DidRecord`], [`LogMetadata`], …)
//!   and the store key builders.
//! - `verify` — [`parse_log`], [`validate_did_jsonl`] and every did:webvh
//!   log verifier.
//! - `extract` — read-only extraction of identifiers, names and metadata
//!   from a `did.jsonl`.
//!
//! Every item is re-exported here, so `did_ops::X` paths are unchanged.

mod extract;
mod record;
mod verify;

pub use extract::*;
pub use record::*;
pub use verify::*;

#[cfg(test)]
mod tests;
