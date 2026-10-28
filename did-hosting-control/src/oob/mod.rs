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
//! - [`types`]: the generated `did_hosting_common::tasks::auth::oob` wire types.
//! - [`store`]: the request store, compare-and-set, and the two clocks.
//! - [`service`]: the state machine and its checks, transport-neutral.
//! - [`http`]: the family's rows of the `control_tasks` table (bound-key
//!   rows, `ProofRule::BoundKey`): their admission, the state machine's
//!   environment, and the session a `redeem` creates.
//!
//! The family is served through the same `POST /api/trust-tasks` router and
//! gate as every other Trust Task; see [`http`] for what the gate checks for
//! these rows and what the state machine checks after it.

pub mod http;
pub mod service;
pub mod store;
pub mod types;

#[cfg(test)]
mod tests;

pub use http::OobRuntime;
