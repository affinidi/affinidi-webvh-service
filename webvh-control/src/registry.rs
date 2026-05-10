//! Service registry — tracks registered backend service instances.

use crate::error::AppError;
use crate::store::KeyspaceHandle;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceType {
    Server,
    Witness,
    Watcher,
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Server => write!(f, "server"),
            Self::Witness => write!(f, "witness"),
            Self::Watcher => write!(f, "watcher"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    Active,
    Degraded,
    Unreachable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInstance {
    pub instance_id: String,
    pub service_type: ServiceType,
    pub label: Option<String>,
    pub url: String,
    pub status: ServiceStatus,
    pub last_health_check: Option<u64>,
    pub registered_at: u64,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

fn instance_key(instance_id: &str) -> String {
    format!("instance:{instance_id}")
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

pub async fn register_instance(
    registry_ks: &KeyspaceHandle,
    instance: &ServiceInstance,
) -> Result<(), AppError> {
    registry_ks
        .insert(instance_key(&instance.instance_id), instance)
        .await
}

pub async fn deregister_instance(
    registry_ks: &KeyspaceHandle,
    instance_id: &str,
) -> Result<(), AppError> {
    registry_ks.remove(instance_key(instance_id)).await
}

pub async fn get_instance(
    registry_ks: &KeyspaceHandle,
    instance_id: &str,
) -> Result<Option<ServiceInstance>, AppError> {
    registry_ks.get(instance_key(instance_id)).await
}

pub async fn list_instances(
    registry_ks: &KeyspaceHandle,
) -> Result<Vec<ServiceInstance>, AppError> {
    let raw = registry_ks.prefix_iter_raw("instance:").await?;
    let mut instances = Vec::with_capacity(raw.len());
    for (_key, value) in raw {
        if let Ok(instance) = serde_json::from_slice::<ServiceInstance>(&value) {
            instances.push(instance);
        }
    }
    Ok(instances)
}

pub async fn list_instances_by_type(
    registry_ks: &KeyspaceHandle,
    service_type: &ServiceType,
) -> Result<Vec<ServiceInstance>, AppError> {
    let all = list_instances(registry_ks).await?;
    Ok(all
        .into_iter()
        .filter(|i| &i.service_type == service_type)
        .collect())
}

/// Update the status and health check timestamp of an instance.
pub async fn update_instance_status(
    registry_ks: &KeyspaceHandle,
    instance_id: &str,
    status: ServiceStatus,
    timestamp: u64,
) -> Result<(), AppError> {
    if let Some(mut instance) = get_instance(registry_ks, instance_id).await? {
        instance.status = status;
        instance.last_health_check = Some(timestamp);
        register_instance(registry_ks, &instance).await?;
    }
    Ok(())
}

/// Determine instance health based on recency of last health-pong.
///
/// Instances that responded within `timeout_secs` are Active; those that
/// haven't responded at all (or within 2× the timeout) are Unreachable.
///
/// Validate a registered service URL against the operator-configured
/// allowlist.
///
/// Returns `Ok(())` when the URL's host is allowlisted (case-insensitive
/// exact match). Returns `Forbidden` when the allowlist is non-empty
/// and the URL does not match, or when the URL fails to parse / has no
/// host. Returns `Ok(())` when the allowlist is empty (operator has
/// opted out of host gating — this is the existing behaviour and is
/// retained for backwards compatibility, though operators should
/// configure an allowlist in any deployment that exposes the proxy
/// route).
///
/// Used by both `routes/registry::register_service` (REST) and
/// `messaging::handle_server_register` (DIDComm) so the gate cannot be
/// bypassed by choosing the right transport. Without parity, an ACL'd
/// Service-role caller can register an arbitrary URL via DIDComm and
/// the proxy at `/api/proxy/server/{instance_id}/{*path}` will then
/// forward an Admin caller's `Authorization` header to that URL — SSRF
/// + token exfil in one step.
pub fn validate_registered_url(url: &str, allowlist: &[String]) -> Result<(), AppError> {
    if allowlist.is_empty() {
        return Ok(());
    }
    let parsed = url::Url::parse(url)
        .map_err(|_| AppError::Forbidden("registered URL is malformed".into()))?;
    let host = match parsed.host_str() {
        Some(h) => h.to_ascii_lowercase(),
        None => {
            return Err(AppError::Forbidden(
                "registered URL has no host component".into(),
            ));
        }
    };
    if allowlist
        .iter()
        .any(|entry| entry.eq_ignore_ascii_case(&host))
    {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "registered URL host is not in the operator-configured allowlist".into(),
        ))
    }
}

/// Freshly registered instances (no pong yet) stay Active for one grace
/// period to allow the first ping/pong roundtrip to complete.
pub fn health_status_from_timestamp(
    instance: &ServiceInstance,
    now: u64,
    timeout_secs: u64,
) -> ServiceStatus {
    match instance.last_health_check {
        Some(ts) if now.saturating_sub(ts) <= timeout_secs => ServiceStatus::Active,
        Some(ts) if now.saturating_sub(ts) <= timeout_secs * 2 => ServiceStatus::Degraded,
        Some(_) => ServiceStatus::Unreachable,
        // No pong received yet — give a grace period from registration time
        None => {
            if now.saturating_sub(instance.registered_at) <= timeout_secs * 2 {
                ServiceStatus::Active
            } else {
                ServiceStatus::Unreachable
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// Empty allowlist preserves the existing "operator opted out" behaviour.
    /// Documented as backwards-compatible — if you operate the proxy you
    /// should configure an allowlist.
    #[test]
    fn empty_allowlist_accepts_anything() {
        assert!(validate_registered_url("http://anywhere.example/", &[]).is_ok());
        assert!(validate_registered_url("http://169.254.169.254/", &[]).is_ok());
    }

    #[test]
    fn host_in_allowlist_accepted() {
        let allow = list(&["server-1.internal", "server-2.internal"]);
        assert!(validate_registered_url("http://server-1.internal:8080/api", &allow).is_ok());
        assert!(validate_registered_url("https://server-2.internal/", &allow).is_ok());
    }

    /// Case-insensitive host comparison — an allowlist of `Server.Example`
    /// matches a URL with host `server.example` and vice versa.
    #[test]
    fn host_match_is_case_insensitive() {
        let allow = list(&["Server.Example"]);
        assert!(validate_registered_url("http://SERVER.EXAMPLE/", &allow).is_ok());
        assert!(validate_registered_url("http://server.example/", &allow).is_ok());
    }

    /// Exact-host match — an entry of `example.com` MUST NOT match
    /// `evil.example.com`. Pinning this prevents a regression to suffix
    /// matching.
    #[test]
    fn suffix_attacker_host_rejected() {
        let allow = list(&["example.com"]);
        assert!(validate_registered_url("http://evil.example.com/", &allow).is_err());
    }

    /// SSRF surface: cloud-metadata, loopback, and RFC1918 hosts are NOT
    /// auto-rejected when not in the allowlist — operators must opt in to
    /// the allowlist to block them. (A future hardening change can add
    /// default-denylist semantics; this test pins the current behaviour
    /// so any change is deliberate.)
    #[test]
    fn metadata_ip_rejected_when_allowlist_excludes_it() {
        let allow = list(&["server-1.internal"]);
        assert!(validate_registered_url("http://169.254.169.254/", &allow).is_err());
        assert!(validate_registered_url("http://127.0.0.1:5432/", &allow).is_err());
        assert!(validate_registered_url("http://192.168.1.10/", &allow).is_err());
    }

    #[test]
    fn malformed_url_rejected() {
        let allow = list(&["example.com"]);
        let err = validate_registered_url("not a url", &allow).unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    #[test]
    fn url_without_host_rejected() {
        let allow = list(&["example.com"]);
        // file:/// has no host
        let err = validate_registered_url("file:///etc/passwd", &allow).unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }
}
