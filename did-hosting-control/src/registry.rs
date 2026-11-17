//! Service registry — tracks registered backend service instances.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use did_hosting_common::server::didcomm_profile::{ObservedTransport, resolve_service_types};
use serde::{Deserialize, Serialize};
use tracing::debug;

use did_hosting_common::server::error::AppError;
use did_hosting_common::server::store::KeyspaceHandle;

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

    // ---- Capability declaration ----
    //
    // Both fields are `#[serde(default)]` so records persisted before
    // servers declared capabilities continue to deserialise.
    // `default_enabled_methods` returns `["webvh"]` — the only method
    // such a server could host — which matches the spec's
    // backwards-compat behaviour.
    //
    // The control plane uses these for:
    // - routing inbound DIDs to a server that supports the method
    //   (`enabled_methods`);
    // - choosing which servers receive `replica/domain/assign` Trust
    //   Tasks and which the unassignment-purge sweep targets
    //   (`served_domains`).
    /// DID methods this server's binary supports. New servers send
    /// the exhaustive enabled-at-compile-time list from
    /// [`did_hosting_common::method::enabled_methods`].
    #[serde(default = "default_enabled_methods")]
    pub enabled_methods: Vec<String>,

    /// Domains the server currently hosts. Initially empty after a
    /// fresh register; control-plane updates via `replica/domain/assign`.
    /// Persisted so the registry survives a control-plane
    /// restart.
    #[serde(default)]
    pub served_domains: Vec<String>,

    /// Server-register protocol version. Distinct from the Trust-Task
    /// URL's version: the URL tracks the *wire* compatibility, this
    /// tracks the *capability-set* compatibility (added with the
    /// capability declaration, to detect old daemons that don't speak the
    /// assignment protocol).
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

    // ---- Replication lag ----
    /// Epoch seconds of the last signed acknowledgement (or final refusal)
    /// this server sent for a queued directive — the last time the outbox
    /// moved for it.
    #[serde(default)]
    pub last_ack_at: Option<u64>,
    /// Epoch seconds of the last reconcile this server started against the
    /// full `did/list` — its staleness-bound backstop.
    #[serde(default)]
    pub last_reconcile_at: Option<u64>,
}

/// Record an edge's acknowledgement at `now` (best effort: a failure only
/// leaves the lag metric older than it is).
pub async fn record_ack(registry_ks: &KeyspaceHandle, did: &str, now: u64) {
    best_effort(
        did,
        update_instance_for_did(registry_ks, did, |i| {
            i.last_ack_at = Some(now);
            true
        })
        .await,
    );
}

/// Record the start of an edge's reconcile at `now` (best effort).
pub async fn record_reconcile(registry_ks: &KeyspaceHandle, did: &str, now: u64) {
    best_effort(
        did,
        update_instance_for_did(registry_ks, did, |i| {
            i.last_reconcile_at = Some(now);
            true
        })
        .await,
    );
}

fn best_effort<T>(did: &str, result: Result<T, AppError>) {
    if let Err(e) = result {
        tracing::warn!(did, error = %e, "failed to record replication progress");
    }
}

// ---------------------------------------------------------------------------
// Serialised mutation
// ---------------------------------------------------------------------------

/// One lock per instance id. Every write to an instance record — a
/// registration, a status sweep, a pong, an ack, a badge refresh — reads and
/// writes it under this lock, so concurrent writers (the health loop and the
/// inbound handlers) cannot lose each other's fields.
static INSTANCE_LOCKS: std::sync::LazyLock<did_hosting_common::server::path_locks::PathLocks> =
    std::sync::LazyLock::new(did_hosting_common::server::path_locks::PathLocks::new);

/// Read the record under `instance_id`, let `change` produce what to store,
/// and store it — under the instance's lock. `change` returns `None` to leave
/// the record as it is (and `Some` of the same record to rewrite it). Returns
/// what is stored afterwards.
pub async fn upsert_instance(
    registry_ks: &KeyspaceHandle,
    instance_id: &str,
    change: impl FnOnce(Option<ServiceInstance>) -> Option<ServiceInstance>,
) -> Result<Option<ServiceInstance>, AppError> {
    let _guard = INSTANCE_LOCKS.guard(instance_id).await;
    let current = get_instance(registry_ks, instance_id).await?;
    match change(current.clone()) {
        Some(next) => {
            registry_ks.insert(instance_key(instance_id), &next).await?;
            Ok(Some(next))
        }
        None => Ok(current),
    }
}

/// Change an existing instance in place, under its lock. `change` returns
/// whether it changed anything (nothing is written otherwise). Returns the
/// instance as stored, or `None` when there is none.
pub async fn update_instance(
    registry_ks: &KeyspaceHandle,
    instance_id: &str,
    change: impl FnOnce(&mut ServiceInstance) -> bool,
) -> Result<Option<ServiceInstance>, AppError> {
    upsert_instance(registry_ks, instance_id, |current| {
        let mut instance = current?;
        change(&mut instance).then_some(instance)
    })
    .await
}

/// [`update_instance`] for the instance `did` registered — only if the
/// record under its id is that DID's ([`get_instance_for_did`]).
pub async fn update_instance_for_did(
    registry_ks: &KeyspaceHandle,
    did: &str,
    change: impl FnOnce(&mut ServiceInstance) -> bool,
) -> Result<Option<ServiceInstance>, AppError> {
    update_instance(registry_ks, &instance_id_for(did), |instance| {
        instance.did() == Some(did) && change(instance)
    })
    .await
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

/// Store `instance` whole, replacing any record under its id (under the
/// instance's lock). A writer that builds on the stored record uses
/// [`upsert_instance`] or [`update_instance`] instead.
pub async fn register_instance(
    registry_ks: &KeyspaceHandle,
    instance: &ServiceInstance,
) -> Result<(), AppError> {
    upsert_instance(registry_ks, &instance.instance_id, |_| {
        Some(instance.clone())
    })
    .await
    .map(|_| ())
}

pub async fn deregister_instance(
    registry_ks: &KeyspaceHandle,
    instance_id: &str,
) -> Result<(), AppError> {
    let _guard = INSTANCE_LOCKS.guard(instance_id).await;
    registry_ks.remove(instance_key(instance_id)).await
}

pub async fn get_instance(
    registry_ks: &KeyspaceHandle,
    instance_id: &str,
) -> Result<Option<ServiceInstance>, AppError> {
    registry_ks.get(instance_key(instance_id)).await
}

/// The registry id a server registering as `did` is kept under.
///
/// Not one-to-one: `did:web:h:a_b` and `did:web:h:a:b` share an id. Look a
/// server up by its DID with [`get_instance_for_did`], which checks the
/// record is that DID's.
pub fn instance_id_for(did: &str) -> String {
    did_hosting_common::server::trust_tasks::infra::instance_id_for(did)
}

/// The instance `did` registered: the record under [`instance_id_for`],
/// only if it was registered by `did` (`metadata.did`). Another DID whose id
/// collides gets `None`, so it can neither update nor be mistaken for it.
pub async fn get_instance_for_did(
    registry_ks: &KeyspaceHandle,
    did: &str,
) -> Result<Option<ServiceInstance>, AppError> {
    Ok(get_instance(registry_ks, &instance_id_for(did))
        .await?
        .filter(|instance| instance.did() == Some(did)))
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

impl ServiceInstance {
    /// The instance's DID, as recorded under `metadata.did` by the
    /// `server/register` and `registry/admin-register` tasks. `None` for
    /// config-seeded `[[registry.instances]]` entries, which carry no DID
    /// and therefore can never have badges.
    pub fn did(&self) -> Option<&str> {
        self.metadata.get("did").and_then(|v| v.as_str())
    }
}

/// Resolve an instance's DID document and cache the services it advertises.
///
/// Called on registration and from the periodic health check, so badges
/// track a server that adds or drops a transport. A no-op for instances
/// with no `metadata.did` (config-seeded instances record none), and a
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
    let Some(instance) = get_instance(registry_ks, instance_id).await? else {
        return Ok(());
    };
    let Some(did) = instance.did().map(str::to_string) else {
        return Ok(());
    };

    // Resolved outside the instance's lock: it can take a network round trip.
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
    // Written only if the record is still the same DID's.
    update_instance(registry_ks, instance_id, |instance| {
        if instance.did() != Some(did.as_str()) {
            return false;
        }
        instance.advertised_services = Some(services);
        instance.services_checked_at = Some(now);
        true
    })
    .await
    .map(|_| ())
}

/// Record the transport an inbound message from `sender_did` arrived on.
///
/// Looked up by the id derived from the DID ([`update_instance_for_did`]),
/// because the caller — a trust-task or DIDComm handler — knows only the
/// transport-authenticated sender. A DID that maps to no registered instance
/// is ignored: plenty of peers talk to the control plane without being
/// servers.
///
/// Best-effort by design. This is observability; a failed write must never fail
/// a registration or a health pong.
pub async fn record_inbound_transport(
    registry_ks: &KeyspaceHandle,
    sender_did: &str,
    transport: ObservedTransport,
    now: u64,
) {
    if let Err(e) = update_instance_for_did(registry_ks, sender_did, |inst| {
        inst.last_inbound_transport = Some(transport);
        inst.last_inbound_at = Some(now);
        true
    })
    .await
    {
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
    if let Err(e) = update_instance(registry_ks, instance_id, |inst| {
        inst.last_outbound_transport = Some(transport);
        inst.last_outbound_at = Some(now);
        true
    })
    .await
    {
        debug!(instance_id, error = %e, "failed to record outbound transport");
    }
}

/// Re-derive an instance's status from its last successful health check
/// ([`health_status_from_timestamp`]), under the instance's lock and from the
/// record as it is now, so a pong that landed meanwhile is not undone.
/// Returns the `(old, new)` status when it changed.
///
/// Never touches `last_health_check`: only a successful check — a health
/// pong (`messaging::do_health_pong`) — records one. Stamping it here, as this
/// once did on every change, made the next sweep read a degraded instance as
/// freshly checked and flip it back to `Active` with no pong at all.
pub async fn reevaluate_status(
    registry_ks: &KeyspaceHandle,
    instance_id: &str,
    now: u64,
    timeout_secs: u64,
) -> Result<Option<(ServiceStatus, ServiceStatus)>, AppError> {
    let mut changed = None;
    update_instance(registry_ks, instance_id, |current| {
        let status = health_status_from_timestamp(current, now, timeout_secs);
        if status == current.status {
            return false;
        }
        changed = Some((current.status.clone(), status.clone()));
        current.status = status;
        true
    })
    .await?;
    Ok(changed)
}

/// The id a `[[registry.instances]]` entry is seeded under: stable across
/// restarts (a hash of its type and URL), so seeding is an upsert rather than
/// a new record per boot.
pub fn seeded_instance_id(service_type: &ServiceType, url: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::new()
        .chain_update(service_type.to_string().as_bytes())
        .chain_update([0u8])
        .chain_update(url.trim_end_matches('/').as_bytes())
        .finalize();
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("seed-{hex}")
}

/// Validate a registered service URL against the operator-configured
/// allowlist (`registry.url_allowlist`).
///
/// Returns `Forbidden` when the URL fails to parse or has no host, or when
/// its host is a non-routable / internal IP literal (loopback, RFC1918,
/// link-local, CGNAT, …) that the allowlist does not name explicitly — this
/// applies even when the allowlist is empty. With an empty allowlist any
/// other host is accepted; with a non-empty one, only a listed host
/// (case-insensitive exact match) is.
///
/// Used by every registration path — an administrator's
/// `registry/admin-register` and a server's `server/register`
/// (`messaging::do_server_register`) — so the gate cannot be bypassed by
/// choosing a different task or transport.
pub fn validate_registered_url(url: &str, allowlist: &[String]) -> Result<(), AppError> {
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

    // Default-deny dangerous address classes for a *literal* host, applied
    // UNCONDITIONALLY — including when the allowlist is empty (SEC-4045 W6),
    // so a Service-role DID cannot record a metadata / RFC1918 / loopback /
    // CGNAT / link-local host in the registry. `is_globally_routable` covers
    // loopback, RFC1918, link-local (incl. 169.254.169.254), CGNAT
    // (100.64/10 — Alibaba/Oracle metadata), ULA, unspecified, and IPv4-mapped
    // IPv6 forms. A non-literal (DNS) host is not classified here.
    //
    // An operator who *explicitly* allowlists an internal host below has opted
    // in and is trusted; this default-deny only bites the unconfigured default.
    if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && !affinidi_net_guard::is_globally_routable(ip)
        && !allowlist
            .iter()
            .any(|entry| entry.eq_ignore_ascii_case(&host))
    {
        return Err(AppError::Forbidden(
            "registered URL host is a non-routable / internal address; allowlist it explicitly to permit it".into(),
        ));
    }

    if allowlist.is_empty() {
        // No host allowlist configured: the address-class default-deny above is
        // the whole gate.
        return Ok(());
    }
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

/// Determine instance health based on recency of the last health pong.
///
/// Instances that responded within `timeout_secs` are Active, within 2× the
/// timeout Degraded, and beyond that Unreachable.
///
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

    /// Backwards-compat: a `ServiceInstance` persisted before the capability
    /// declaration (no capability fields in the JSON) deserialises with
    /// `enabled_methods = ["webvh"]`, `served_domains = []`,
    /// `protocol_version = "1.0"`. Catching this here matters because the
    /// persisted records are stored as JSON and an upgraded deployment may
    /// still have such records on disk.
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

    /// Records with the capability declaration round-trip exactly.
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
            sync_batch_capable: true,
            last_inbound_transport: Some(ObservedTransport::Tsp),
            last_inbound_at: Some(1111),
            last_outbound_transport: Some(ObservedTransport::Didcomm),
            last_outbound_at: Some(2222),
            last_ack_at: None,
            last_reconcile_at: None,
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

    /// Empty allowlist no longer means "accept anything" (SEC-4045 W6). A
    /// public host (DNS name or globally-routable literal) is still accepted —
    /// the operator opted out of host *allowlisting* — but a non-routable /
    /// metadata literal is refused by the address-class default-deny, so a
    /// default config cannot record an internal target.
    #[test]
    fn empty_allowlist_accepts_public_but_blocks_internal_literals() {
        assert!(validate_registered_url("http://anywhere.example/", &[]).is_ok());
        assert!(validate_registered_url("https://1.2.3.4/", &[]).is_ok());
        assert!(validate_registered_url("http://169.254.169.254/", &[]).is_err());
        assert!(validate_registered_url("http://127.0.0.1:5432/", &[]).is_err());
        assert!(validate_registered_url("http://192.168.1.10/", &[]).is_err());
        // CGNAT range — Alibaba/Oracle metadata.
        assert!(validate_registered_url("http://100.100.100.200/", &[]).is_err());
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

    /// SSRF surface: cloud-metadata, loopback, and RFC1918 literal hosts are
    /// rejected when not explicitly allowlisted — both by the allowlist
    /// mismatch and, since SEC-4045 W6, by the unconditional address-class
    /// default-deny.
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
