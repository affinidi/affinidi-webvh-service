//! Configuration sections shared by every service (`[features]`, `[server]`,
//! `[log]`, `[store]`, `[auth]`, `[secrets]`, `[vta]`, `[replay]`, …), their
//! defaults, validation and environment overrides.
//!
//! One submodule per section; every item is re-exported here, so
//! `config::X` paths are unchanged.

mod auth;
mod env;
mod features;
mod fjall;
mod hosting;
mod identity;
mod log;
mod replay;
mod resolve;
mod secrets;
mod server;
mod store;

pub use auth::*;
pub use env::*;
pub use features::*;
pub use fjall::*;
pub use hosting::*;
pub use identity::*;
pub use log::*;
pub use replay::*;
pub use resolve::*;
pub use secrets::*;
pub use server::*;
pub use store::*;

/// Serde default for a `bool` field that is on unless configured off.
fn default_true() -> bool {
    true
}

/// Serde `skip_serializing_if` for a `bool` field written only when set.
fn is_false(b: &bool) -> bool {
    !*b
}

#[cfg(test)]
// Some of these tests mutate the process environment (`std::env::set_var` is
// `unsafe` in edition 2024), so the module opts out of the workspace ban.
#[allow(unsafe_code)]
#[path = "config_tests.rs"]
mod tests;

#[cfg(test)]
// `std::env::set_var` / `remove_var` are `unsafe` in edition 2024; these tests
// mutate the process environment, so they opt out of the workspace ban.
#[allow(unsafe_code)]
#[path = "fjall_config_tests.rs"]
mod fjall_config_tests;

#[cfg(test)]
// `std::env::set_var` / `remove_var` are `unsafe` in edition 2024; these tests
// mutate the process environment, so they opt out of the workspace ban.
#[allow(unsafe_code)]
#[path = "resolve_cache_tests.rs"]
mod resolve_cache_tests;

#[cfg(test)]
#[path = "trusted_proxies_tests.rs"]
mod trusted_proxies_tests;
