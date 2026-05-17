//! # `did-hosting-client`
//!
//! Client library for talking to a `did-hosting-server` /
//! `did-hosting-daemon` over REST + DIDComm v2. The daemon's wire
//! contract is the source of truth; this crate ships a thin typed
//! surface that mirrors it.
//!
//! ## Scope
//!
//! Per `docs/did-hosting-client-crate-spec.md`:
//!
//! - **Authentication**: DIDComm v2 JWS challenge-response →
//!   Bearer-token Authorization for subsequent REST calls.
//! - **DID lifecycle**: reserve path / check path / atomic
//!   register-and-publish / publish update / delete.
//! - **Trust-Tasks transport**: every REST call sets the canonical
//!   `Trust-Task:` HTTP header (T8b) so the daemon can exact-match
//!   the operation.
//!
//! Out of scope for v0.1 — admin / observability surface (ACL,
//! stats, time-series, services overview, registry CRUD). Those are
//! exposed by the daemon but the integrator-facing client doesn't
//! ship them until v0.2+.
//!
//! ## Design choices
//!
//! - **No `did-hosting-common` dep.** This is a thin integration
//!   crate; pulling in the daemon-internal types would chain in
//!   fjall, axum, the secret-store backends, etc. The only daemon-
//!   shared crate is `didwebvh-rs` (protocol types).
//! - **HTTPS-only by default.** Loopback (`127.0.0.1`, `::1`,
//!   `localhost`) and explicit "trust this host" overrides exist
//!   for dev — production deployments fail closed.
//! - **Token zeroization.** `TokenData` derives `ZeroizeOnDrop` +
//!   redacts via `Debug`. The library does its part; integrators
//!   are still responsible for not logging the structure.
//! - **No tokio in trait bounds.** `ServerLocks` uses
//!   `tokio::sync::Mutex` for its internal registry but no trait
//!   defined here requires a specific runtime — integrators can
//!   plug `HostingTokenStore` against any executor.
//!
//! ## Stability
//!
//! v0.1 is a **skeleton release** that exports types but no Client
//! yet (T44 lands the crate; T45-T51 land the actual surface). The
//! Trust-Task URL constants in [`trust_tasks`] are the only stable
//! API in v0.1; the rest of the module tree is `#[doc(hidden)]`
//! until T45 fills it in.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod trust_tasks;

/// Crate version string (`CARGO_PKG_VERSION`). Useful for telemetry
/// and for the `User-Agent` header the client will send once T46
/// wires the transport. Pinned here as the single source of truth.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
