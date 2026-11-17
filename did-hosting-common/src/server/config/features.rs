//! `[features]`: which services and transports a node runs, the
//! deployment mode, and the setup-time transport selection.

use crate::server::error::AppError;
use serde::{Deserialize, Serialize};

use super::default_true;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeaturesConfig {
    #[serde(default)]
    pub didcomm: bool,
    /// Trust Spanning Protocol (TSP) transport. When enabled (and a
    /// `mediator_did` is configured), the mediator listener also carries
    /// TSP on its shared socket and the service's DID document advertises
    /// a `TSPTransport` service. Additive with `didcomm` — a node can
    /// speak both; TSP is preferred when a peer advertises both.
    #[serde(default)]
    pub tsp: bool,
    /// Run the HTTP listener: the management UI, `POST /api/trust-tasks`
    /// (the HTTPS binding of the Trust Task dispatch), `/api/health` and,
    /// on a witness or watcher, its public routes. There is no REST API
    /// behind it; every management operation is a Trust Task.
    ///
    /// Read by the control plane, the witness and the watcher. A control
    /// plane needs at least one of `http_listener`, `didcomm` and `tsp`. The
    /// hosting server (edge) always serves HTTP — DID resolution is its
    /// job — and does not read this flag; the daemon derives it from the
    /// services it enables.
    ///
    /// Formerly `rest_api`, which is still accepted (in the file and as
    /// `<PREFIX>_FEATURES_REST_API`). Env: `<PREFIX>_FEATURES_HTTP_LISTENER`.
    #[serde(default, alias = "rest_api")]
    pub http_listener: bool,
    /// Serve agent-name redirects (`GET /@alice` -> 302 to a DID).
    ///
    /// **On by default.** A name only resolves if the signed DID document
    /// already claims it via `alsoKnownAs`, so serving the `/@…` namespace
    /// cannot by itself expose a name the controller has not authorised: with
    /// no names bound, every `/@…` request 404s exactly as it did before.
    /// Meanwhile the write path (bind/park/resume, over Trust Tasks)
    /// and the UI that drives it are *not* gated on this flag — leaving it off
    /// let an owner bind a name that then silently failed to resolve, which is
    /// the worse default.
    ///
    /// Set `agent_names = false` (or `…_FEATURES_AGENT_NAMES=0`) to keep the
    /// `/@…` namespace unserved on a host that wants those paths free for
    /// something else.
    #[serde(default = "default_true")]
    pub agent_names: bool,
    /// Deployment mode: `"standalone"` for individual services, `"daemon"`
    /// for the unified binary (which sets it itself). Controls UI behaviour
    /// (e.g., hiding service topology in daemon mode).
    #[serde(default)]
    pub deployment_mode: DeploymentMode,
}

/// [`FeaturesConfig::deployment_mode`]: whether the service runs on its own
/// or inside `did-hosting-daemon`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    #[default]
    Standalone,
    Daemon,
}

impl DeploymentMode {
    /// The config-file spelling (`"standalone"` / `"daemon"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Daemon => "daemon",
        }
    }
}

impl std::fmt::Display for DeploymentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Hand-written so the in-code default matches what serde fills in for an
/// absent field — a derived `Default` would give `agent_names: false` and an
/// empty `deployment_mode`, so every `..Default::default()` call site (the
/// setup wizards, the recipe writer, tests) would disagree with the same
/// config round-tripped through TOML.
impl Default for FeaturesConfig {
    fn default() -> Self {
        Self {
            didcomm: false,
            tsp: false,
            http_listener: false,
            agent_names: true,
            deployment_mode: DeploymentMode::default(),
        }
    }
}

/// Three-way messaging-transport selection used by setup wizards and
/// recipes. TSP and DIDComm both ride the same mediator socket, so this
/// choice is only meaningful when a `mediator_did` is configured; with no
/// mediator the node is HTTP-only and both flags are false regardless.
///
/// The selection maps directly onto [`FeaturesConfig::didcomm`] /
/// [`FeaturesConfig::tsp`], which in turn drive the listener protocol
/// matrix and (for self-managed DIDs) which service entries the DID
/// document advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSelection {
    Didcomm,
    Tsp,
    Both,
}

impl TransportSelection {
    /// `(didcomm, tsp)` feature flags for this selection.
    pub fn as_flags(self) -> (bool, bool) {
        match self {
            Self::Didcomm => (true, false),
            Self::Tsp => (false, true),
            Self::Both => (true, true),
        }
    }

    /// Inverse of [`Self::as_flags`]: the selection implied by `(didcomm,
    /// tsp)` feature flags. Returns `None` when both are false (no messaging
    /// transport — an HTTP-only node the selection doesn't describe).
    pub fn from_flags(didcomm: bool, tsp: bool) -> Option<Self> {
        match (didcomm, tsp) {
            (true, true) => Some(Self::Both),
            (true, false) => Some(Self::Didcomm),
            (false, true) => Some(Self::Tsp),
            (false, false) => None,
        }
    }

    /// Parse a recipe `transport` string. Recognises `didcomm`, `tsp`, and
    /// `both` (case-insensitive, `+`-joined aliases accepted).
    pub fn parse(s: &str) -> Result<Self, AppError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "didcomm" => Ok(Self::Didcomm),
            "tsp" => Ok(Self::Tsp),
            "both" | "didcomm+tsp" | "tsp+didcomm" => Ok(Self::Both),
            other => Err(AppError::Config(format!(
                "invalid transport '{other}' (expected 'didcomm', 'tsp', or 'both')"
            ))),
        }
    }

    /// Canonical lower-case string, suitable for persisting into a recipe.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Didcomm => "didcomm",
            Self::Tsp => "tsp",
            Self::Both => "both",
        }
    }
}
