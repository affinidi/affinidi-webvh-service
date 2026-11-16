//! The edges a DID change is pushed to, as the registry holds them.

use tracing::{debug, warn};

use crate::registry::{self, ServiceType};

/// The edges a DID change is pushed to, as the registry holds them.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum PushTargets {
    /// Active edges, as (server DID, instance id).
    Active(Vec<(String, String)>),
    /// No edge is registered: always so for a daemon, and for a control plane
    /// until its first edge registers. Nothing is missed.
    NoneRegistered,
    /// Edges are registered but none is active (degraded, unreachable, or
    /// registered without a DID), so this change reaches none of them now.
    NoneActive,
    /// The registry could not be read; the failure is already logged.
    Unknown,
}

/// Most one "registered but none active" warning per this many seconds: it
/// is a property of the registry, not of each DID change.
const NO_ACTIVE_EDGES_WARN_SECS: u64 = 300;

/// Unix second of the last "registered but none active" warning.
static LAST_NO_ACTIVE_EDGES_WARN: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

impl PushTargets {
    fn from_instances(instances: Vec<registry::ServiceInstance>) -> Self {
        let registered: Vec<_> = instances
            .into_iter()
            .filter(|i| i.service_type == ServiceType::Server)
            .collect();
        if registered.is_empty() {
            return Self::NoneRegistered;
        }
        let active: Vec<_> = registered
            .into_iter()
            .filter(|i| i.status == registry::ServiceStatus::Active)
            .filter_map(|i| {
                let did = i.metadata.get("did")?.as_str()?.to_string();
                Some((did, i.instance_id))
            })
            .collect();
        if active.is_empty() {
            Self::NoneActive
        } else {
            Self::Active(active)
        }
    }

    /// Log why a change was not pushed. An empty registry is the normal
    /// state of a daemon, so it is debug; registered edges that are all
    /// down miss this change, so that warns, at most once per
    /// [`NO_ACTIVE_EDGES_WARN_SECS`].
    pub(super) fn log(&self, op: &str, mnemonic: &str) {
        match self {
            Self::NoneRegistered => {
                debug!(mnemonic = %mnemonic, "{op}: no servers registered");
            }
            Self::NoneActive => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let last = LAST_NO_ACTIVE_EDGES_WARN.load(std::sync::atomic::Ordering::Relaxed);
                if now.saturating_sub(last) >= NO_ACTIVE_EDGES_WARN_SECS
                    && LAST_NO_ACTIVE_EDGES_WARN
                        .compare_exchange(
                            last,
                            now,
                            std::sync::atomic::Ordering::Relaxed,
                            std::sync::atomic::Ordering::Relaxed,
                        )
                        .is_ok()
                {
                    warn!(
                        mnemonic = %mnemonic,
                        "{op}: servers are registered but none is active; changes are not \
                         reaching them (repeats are logged at debug for {NO_ACTIVE_EDGES_WARN_SECS} s)"
                    );
                } else {
                    debug!(mnemonic = %mnemonic, "{op}: servers are registered but none is active");
                }
            }
            Self::Active(_) | Self::Unknown => {}
        }
    }
}

/// The registry's push targets for a DID change.
pub(super) async fn push_targets(
    registry_ks: &did_hosting_common::server::store::KeyspaceHandle,
) -> PushTargets {
    match registry::list_instances(registry_ks).await {
        Ok(instances) => PushTargets::from_instances(instances),
        Err(e) => {
            warn!(error = %e, "server push: failed to list instances");
            PushTargets::Unknown
        }
    }
}

#[cfg(test)]
#[path = "targets_tests.rs"]
mod push_target_tests;
