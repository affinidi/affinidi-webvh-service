//! Service registry — tracks registered backend service instances.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use did_hosting_common::server::didcomm_profile::{ObservedTransport, resolve_service_types};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::error::AppError;
use crate::store::KeyspaceHandle;

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

    // ---- Capability declaration (T27) ----
    //
    // Both fields are `#[serde(default)]` so pre-T27 records persisted
    // on disk continue to deserialise. `default_enabled_methods`
    // returns `["webvh"]` — the only method any pre-T27 server could
    // host — which matches the spec's backwards-compat behaviour.
    //
    // The control plane uses these for:
    // - routing inbound DIDs to a server that supports the method
    //   (`enabled_methods`);
    // - choosing which servers receive `domain/assign/1.0` Trust
    //   Tasks (T28) and which the unassignment-purge sweep (T30)
    //   targets (`served_domains`).
    /// DID methods this server's binary supports. New servers send
    /// the exhaustive enabled-at-compile-time list from
    /// [`did_hosting_common::method::enabled_methods`].
    #[serde(default = "default_enabled_methods")]
    pub enabled_methods: Vec<String>,

    /// Domains the server currently hosts. Initially empty after a
    /// fresh register; control-plane updates via `domain/assign/1.0`
    /// (T28). Persisted so the registry survives a control-plane
    /// restart.
    #[serde(default)]
    pub served_domains: Vec<String>,

    /// Server-register protocol version. Distinct from the Trust-Task
    /// URL's version: the URL tracks the *wire* compatibility, this
    /// tracks the *capability-set* compatibility (added in T27 to
    /// detect old daemons that don't speak the assignment protocol).
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,

    // ---- Advertised-service cache ----
    //
    // What this instance's *DID document* says it speaks — as opposed to
    // `enabled_methods`, which is what its *binary* was compiled with.
    // The registry stores only a DID string (in `metadata.did`), so these
    // are resolved from that document and cached here rather than
    // re-resolved on every registry list.
    //
    // Refreshed on register and on each health check. A daemon does not
    // run the health-check loop (see CLAUDE.md — the registry is empty in
    // the self-contained deployment), so in that unusual configuration
    // these refresh only on re-register.
    /// `service[].type` values from the instance's DID document, in
    /// document order. `None` means "not resolved" — no DID recorded, the
    /// DID wouldn't resolve, or a pre-existing record from before this
    /// field existed. The UI hides the badge row. `Some(vec![])` means the
    /// document resolved and advertises no services.
    #[serde(default)]
    pub advertised_services: Option<Vec<String>>,

    /// Epoch seconds of the last successful `advertised_services` resolve.
    /// Lets the UI mark badges stale; `None` alongside a `None`
    /// `advertised_services` means we have never had a successful resolve.
    #[serde(default)]
    pub services_checked_at: Option<u64>,

    /// Whether this instance understands infrastructure **trust tasks**
    /// (`.../server/health/0.1` and friends) as opposed to only the legacy
    /// `MSG_*` DIDComm messages.
    ///
    /// Self-asserted by the server in its registration body. `false` for every
    /// pre-existing record and for any server that doesn't send the flag, which
    /// is exactly the older fleet — so the control plane keeps pinging them the
    /// legacy way and a rolling upgrade never drops a node to `Unreachable`.
    ///
    /// When `true`, the health loop sends the ping as a trust task and lets
    /// `send_trust_task` choose TSP or DIDComm from the server's DID document.
    /// That is the only path by which a TSP-only server is reachable at all.
    #[serde(default)]
    pub trust_task_capable: bool,

    /// When `true`, the control plane may coalesce bulk DID sync updates into
    /// `MSG_SYNC_BATCH` messages for this server instead of one frame per DID —
    /// which is what keeps the server's per-frame TSP reply from bursting past
    /// the mediator's rate limit on a resync. Servers registered before this
    /// existed default to `false` and keep getting one message per DID.
    #[serde(default)]
    pub sync_batch_capable: bool,

    // ---- Observed link transport ----
    //
    // What actually moved, per direction — not what `advertised_services`
    // says the peer *could* speak. The two disagree whenever a TSP send
    // falls back to DIDComm, or a server registered before its document
    // advertised a transport. Reporting the advertised value as the one in
    // use would quietly lie to the operator, which is the whole reason
    // these are recorded rather than inferred.
    /// Transport the last inbound message from this instance arrived on
    /// (registration, health pong). `None` until one arrives.
    #[serde(default)]
    pub last_inbound_transport: Option<ObservedTransport>,
    /// Epoch seconds of that inbound message.
    #[serde(default)]
    pub last_inbound_at: Option<u64>,

    /// Transport the last **health ping** to this instance actually went out
    /// on. Scoped to the ping deliberately: it is the only outbound path that
    /// runs on a timer, so it is the one whose observation stays fresh. The
    /// outbox's sync/domain pushes also pick a transport per DID document, but
    /// they fire only on mutations and would leave this stale for hours.
    #[serde(default)]
    pub last_outbound_transport: Option<ObservedTransport>,
    /// Epoch seconds of that outbound ping.
    #[serde(default)]
    pub last_outbound_at: Option<u64>,
}

fn default_enabled_methods() -> Vec<String> {
    vec!["webvh".to_string()]
}

fn default_protocol_version() -> String {
    "1.0".to_string()
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

impl ServiceInstance {
    /// The instance's DID, as recorded under `metadata.did` by the
    /// DIDComm registration path. `None` for REST-registered instances,
    /// which carry no DID and therefore can never have badges.
    pub fn did(&self) -> Option<&str> {
        self.metadata.get("did").and_then(|v| v.as_str())
    }
}

/// Resolve an instance's DID document and cache the services it advertises.
///
/// Called on registration and from the periodic health check, so badges
/// track a server that adds or drops a transport. A no-op for instances
/// with no `metadata.did` (the REST registration path records none), and a
/// no-op when no DID resolver is configured — rather than let
/// `resolve_service_types` build a throwaway `DIDCacheClient` per instance
/// per health tick.
///
/// **A failed resolve leaves the previous cache in place.** A transient
/// network blip should not blank a server's badges in the UI; instead
/// `services_checked_at` stops advancing, which is what lets the UI mark
/// the badges stale. Only a *successful* resolve overwrites, so a server
/// that genuinely drops a service still converges once it's reachable.
pub async fn refresh_advertised_services(
    registry_ks: &KeyspaceHandle,
    instance_id: &str,
    did_resolver: Option<&DIDCacheClient>,
    now: u64,
) -> Result<(), AppError> {
    let Some(resolver) = did_resolver else {
        return Ok(());
    };
    let Some(mut instance) = get_instance(registry_ks, instance_id).await? else {
        return Ok(());
    };
    let Some(did) = instance.did().map(str::to_string) else {
        return Ok(());
    };

    let Some(services) = resolve_service_types(&did, Some(resolver)).await else {
        debug!(
            instance_id = %instance_id,
            did = %did,
            "advertised-service refresh failed to resolve; keeping previous cache"
        );
        return Ok(());
    };

    debug!(
        instance_id = %instance_id,
        did = %did,
        services = ?services,
        "advertised services refreshed"
    );
    instance.advertised_services = Some(services);
    instance.services_checked_at = Some(now);
    register_instance(registry_ks, &instance).await
}

/// Record the transport an inbound message from `sender_did` arrived on.
///
/// Looked up by DID rather than instance id, because the caller — a trust-task
/// or DIDComm handler — knows only the transport-authenticated sender. A DID
/// that maps to no registered instance is ignored: plenty of peers talk to the
/// control plane without being servers.
///
/// Best-effort by design. This is observability; a failed write must never fail
/// a registration or a health pong.
pub async fn record_inbound_transport(
    registry_ks: &KeyspaceHandle,
    sender_did: &str,
    transport: ObservedTransport,
    now: u64,
) {
    let Ok(instances) = list_instances(registry_ks).await else {
        return;
    };
    let Some(mut inst) = instances.into_iter().find(|i| i.did() == Some(sender_did)) else {
        return;
    };
    inst.last_inbound_transport = Some(transport);
    inst.last_inbound_at = Some(now);
    if let Err(e) = register_instance(registry_ks, &inst).await {
        debug!(did = sender_did, error = %e, "failed to record inbound transport");
    }
}

/// Record the transport an outbound health ping to `instance_id` went out on.
///
/// Takes the transport that *actually carried* the message — after any
/// TSP→DIDComm fallback — not the one the DID document advertised.
pub async fn record_outbound_transport(
    registry_ks: &KeyspaceHandle,
    instance_id: &str,
    transport: ObservedTransport,
    now: u64,
) {
    let Ok(Some(mut inst)) = get_instance(registry_ks, instance_id).await else {
        return;
    };
    inst.last_outbound_transport = Some(transport);
    inst.last_outbound_at = Some(now);
    if let Err(e) = register_instance(registry_ks, &inst).await {
        debug!(instance_id, error = %e, "failed to record outbound transport");
    }
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

    /// T27 backwards-compat: a pre-T27 `ServiceInstance` (no capability
    /// fields in the persisted JSON) deserialises with `enabled_methods
    /// = ["webvh"]`, `served_domains = []`, `protocol_version = "1.0"`.
    /// Catching this here matters because the persisted records are
    /// stored as JSON and any deployment upgrading from v0.7 will have
    /// pre-T27 records on disk.
    #[test]
    fn pre_t27_record_deserialises_with_compat_defaults() {
        let json = r#"{
            "instanceId": "did_example_old",
            "serviceType": "server",
            "label": null,
            "url": "http://old.example.com",
            "status": "active",
            "lastHealthCheck": null,
            "registeredAt": 1,
            "metadata": { "did": "did:example:old" }
        }"#;
        let instance: ServiceInstance = serde_json::from_str(json).unwrap();
        assert_eq!(instance.enabled_methods, vec!["webvh".to_string()]);
        assert!(instance.served_domains.is_empty());
        assert_eq!(instance.protocol_version, "1.0");
    }

    /// New T27 records round-trip exactly.
    #[test]
    fn t27_record_round_trips() {
        let original = ServiceInstance {
            instance_id: "x".into(),
            service_type: ServiceType::Server,
            label: None,
            url: "http://new.example.com".into(),
            status: ServiceStatus::Active,
            last_health_check: None,
            registered_at: 0,
            metadata: serde_json::Value::Null,
            enabled_methods: vec!["webvh".into(), "web".into()],
            served_domains: vec!["a.example".into()],
            protocol_version: "1.1".into(),
            advertised_services: Some(vec!["WebVHHosting".into(), "TSPTransport".into()]),
            services_checked_at: Some(1234),
            trust_task_capable: true,
            sync_batch_capable: true,
            last_inbound_transport: Some(ObservedTransport::Tsp),
            last_inbound_at: Some(1111),
            last_outbound_transport: Some(ObservedTransport::Didcomm),
            last_outbound_at: Some(2222),
        };
        let bytes = serde_json::to_vec(&original).unwrap();
        let parsed: ServiceInstance = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.enabled_methods, original.enabled_methods);
        assert_eq!(parsed.served_domains, original.served_domains);
        assert_eq!(parsed.advertised_services, original.advertised_services);
        assert_eq!(parsed.services_checked_at, original.services_checked_at);
        assert_eq!(
            parsed.last_inbound_transport,
            original.last_inbound_transport
        );
        assert_eq!(
            parsed.last_outbound_transport,
            original.last_outbound_transport
        );
        assert_eq!(parsed.protocol_version, original.protocol_version);
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
