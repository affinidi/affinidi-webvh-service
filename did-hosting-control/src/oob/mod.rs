//! Wallet sign-in started by a trigger link: this control plane as the
//! `auth/oob/*` sign-in service (base design sections 7, 10 and 12; contract
//! C1 to C9).
//!
//! The console shows a trigger link as a clickable QR code. The member's
//! wallet claims the request, proves who it is (`identify`, checked against
//! the ACL and the member's `authentication` key), and the member approves a
//! `grant` (checked against `assertionMethod`). The browser, holding the
//! starter key `K_b`, redeems the request by long poll and gets an ordinary
//! console session bound to `K_b` as its session key.
//!
//! - [`types`]: local wire types until the generated bindings exist.
//! - [`store`]: the request store, compare-and-set, and the two clocks.
//! - [`service`]: the state machine and its checks, transport-neutral.
//! - [`http`]: the `POST /api/trust-tasks` binding and the session.

pub mod http;
pub mod service;
pub mod store;
pub mod types;

#[cfg(test)]
mod tests;

pub use http::OobRuntime;
