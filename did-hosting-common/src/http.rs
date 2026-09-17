//! Shared outbound HTTP client construction.
//!
//! Every inter-service client (`WatcherClient`, `WitnessClient`,
//! `ControlClient`, `WebVHClient`) talks to a peer over the network, so each
//! must fail fast rather than hang a task forever on a peer that accepts the
//! connection and then never responds, and must not silently follow a 3xx to an
//! unintended host (which would also carry any bearer token along). Building
//! them all through one helper keeps that policy in a single place.

use std::time::Duration;

/// Total per-request timeout (connect + send + receive). A peer that stalls
/// past this fails the request instead of pinning the caller's task.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect timeout — a peer that accepts a socket but never completes the
/// handshake is abandoned quickly.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A `reqwest::Client` with request + connect timeouts and redirects refused.
///
/// Redirects are refused (`Policy::none()`) so a compromised or misconfigured
/// endpoint cannot 3xx-bounce the request — and any `Authorization` header on
/// it — to a host the caller did not choose. The runtime server/control clients
/// already build this way; the shared clients now match.
pub(crate) fn outbound_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        // A builder failure means the TLS backend could not initialise — a
        // fatal environment condition, not a runtime input. Fall back to a
        // default client so these infallible constructors keep their signature.
        .unwrap_or_else(|_| reqwest::Client::new())
}
