//! `did-management/server/{info,config,metrics}`, `stats/*` and
//! `identity/*`: what the service says about itself.

use serde_json::{Value, json};
use tracing::warn;
use trust_tasks_rs::specs::did_management::{
    identity::{list as identity_list, retire as identity_retire},
    server::{config, info, metrics},
    stats::{get as stats_get, timeseries},
};

use did_hosting_common::server::pending_purge::parse_grace_string;

use super::{Cx, TaskError, at, typed};
use crate::did_ops;
use crate::error::AppError;
use crate::server::AppState;

/// `server/info/0.1`: the one public read. Accepted with no proof; answers
/// only what the service already publishes, and the reply — signed by the DID
/// it names as `serviceDid` — is what lets a client check it is talking to
/// the service that DID belongs to.
pub(crate) async fn info(
    cx: &Cx<'_>,
    _p: info::v0_1::Payload,
) -> Result<info::v0_1::Response, TaskError> {
    let state = cx.state;
    let service_did = state
        .config
        .server_did
        .clone()
        .ok_or_else(|| AppError::Config("server_did not configured".into()))?;
    let mut body = serde_json::Map::new();
    body.insert("serviceDid".into(), json!(service_did));
    body.insert(
        "agentNames".into(),
        json!(state.config.features.agent_names),
    );
    body.insert(
        "serviceNames".into(),
        json!(super::queries::server_agent_names(state).await),
    );
    if let Ok(grace) = parse_grace_string(&state.config.hosting.disable_purge_grace) {
        body.insert("domainPurgeGraceSeconds".into(), json!(grace));
    }
    typed(Value::Object(body), "server/info response")
}

/// `server/config/0.1`: the effective configuration, never a secret. Admin.
pub(crate) async fn config(
    cx: &Cx<'_>,
    _p: config::v0_1::Payload,
) -> Result<config::v0_1::Response, TaskError> {
    cx.admin().await?;
    let state = cx.state;
    let c = &state.config;
    let mut body = serde_json::Map::new();
    body.insert(
        "serviceDid".into(),
        json!(c.server_did.clone().unwrap_or_default()),
    );
    body.insert("softwareVersion".into(), json!(env!("CARGO_PKG_VERSION")));
    body.insert(
        "deploymentMode".into(),
        json!(if c.features.deployment_mode.is_empty() {
            "control".to_string()
        } else {
            c.features.deployment_mode.clone()
        }),
    );
    if let Some(url) = c.public_url.as_deref().and_then(without_credentials) {
        body.insert("publicUrl".into(), json!(url));
    }
    if let Some(url) = c.did_hosting_url.as_deref().and_then(without_credentials) {
        body.insert("didHostingUrl".into(), json!(url));
    }
    if let Some(mediator) = &c.mediator_did {
        body.insert("mediatorDid".into(), json!(mediator));
    }
    body.insert(
        "transports".into(),
        json!({ "tsp": c.features.tsp, "didcomm": c.features.didcomm }),
    );
    if let Some(services) = super::queries::control_advertised_services(state).await {
        body.insert("advertisedServices".into(), json!(services));
    }
    body.insert(
        "enabledMethods".into(),
        json!(did_hosting_common::method::enabled_methods()),
    );
    body.insert("agentNames".into(), json!(c.features.agent_names));
    body.insert(
        "listenAddress".into(),
        json!(format!("{}:{}", c.server.host, c.server.port)),
    );
    let mut vta = serde_json::Map::new();
    if let Some(did) = &c.vta.did {
        vta.insert("did".into(), json!(did));
    }
    if let Some(url) = c.vta.url.as_deref().and_then(without_credentials) {
        vta.insert("url".into(), json!(url));
    }
    if !vta.is_empty() {
        body.insert("vta".into(), Value::Object(vta));
    }
    body.insert(
        "registry".into(),
        json!({
            "healthCheckIntervalSeconds": c.registry.health_check_interval.max(1),
            "configuredInstances": c.registry.instances.len(),
        }),
    );
    body.insert(
        "sessions".into(),
        json!({
            "accessTokenSeconds": c.auth.access_token_expiry.max(1),
            "refreshTokenSeconds": c.auth.refresh_token_expiry.max(1),
            "adminIdleTimeoutSeconds": c.auth.admin_idle_timeout.max(1),
            "passkeyEnrollmentSeconds": c.auth.passkey_enrollment_ttl.max(1),
        }),
    );
    body.insert(
        "storage".into(),
        json!({ "dataDir": c.store.data_dir.display().to_string() }),
    );
    body.insert(
        "logging".into(),
        json!({
            "level": c.log.level,
            "format": format!("{:?}", c.log.format).to_lowercase(),
        }),
    );
    typed(Value::Object(body), "server/config response")
}

/// A URL with any userinfo removed, or `None` when it does not parse — the
/// configuration read never carries a credential.
fn without_credentials(url: &str) -> Option<String> {
    let mut parsed = url::Url::parse(url).ok()?;
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    Some(parsed.to_string())
}

/// `server/metrics/0.1`: the service's own counters, authenticated. Admin.
pub(crate) async fn metrics(
    cx: &Cx<'_>,
    _p: metrics::v0_1::Payload,
) -> Result<metrics::v0_1::Response, TaskError> {
    cx.admin().await?;
    #[cfg(feature = "metrics")]
    let counters: Vec<Value> = did_hosting_common::server::metrics::counters()
        .into_iter()
        .map(|(name, value)| json!({ "name": name, "value": value }))
        .collect();
    #[cfg(not(feature = "metrics"))]
    let counters: Vec<Value> = Vec::new();
    let gauges = replication_gauges(cx.state).await?;
    typed(
        json!({
            "snapshot": {
                "takenAt": chrono::Utc::now(),
                "counters": counters,
                "gauges": gauges,
                "histograms": [],
            }
        }),
        "server/metrics response",
    )
}

/// Per-edge replication lag, labelled `{edge: <server DID>}`, for every hosting
/// server in the registry:
///
/// - `did_hosting_replication_pending` — directives queued for it, unacknowledged;
/// - `did_hosting_replication_lag_seconds` — age of the oldest of them (0 when
///   none is waiting): how far behind the control plane it is;
/// - `did_hosting_replication_last_ack_age_seconds` — since its last signed
///   acknowledgement, when it has sent one;
/// - `did_hosting_replication_last_reconcile_age_seconds` — since it last
///   started a reconcile against `did/list`, when it has. An edge past its own
///   staleness bound here is reporting itself degraded.
pub(crate) async fn replication_gauges(state: &AppState) -> Result<Vec<Value>, TaskError> {
    let now = did_hosting_common::server::auth::session::now_epoch();
    let mut gauges = Vec::new();
    for instance in crate::registry::list_instances(&state.registry_ks).await? {
        if instance.service_type != crate::registry::ServiceType::Server {
            continue;
        }
        let Some(edge) = instance.metadata.get("did").and_then(Value::as_str) else {
            continue;
        };
        let pending = crate::outbox::list_pending_for_target(&state.store, edge).await?;
        let lag = pending
            .iter()
            .map(|(_, e)| now.saturating_sub(e.enqueued_at))
            .max()
            .unwrap_or(0);
        let gauge = |name: &str, value: u64| json!({ "name": name, "value": value, "labels": { "edge": edge } });
        gauges.push(gauge(
            "did_hosting_replication_pending",
            pending.len() as u64,
        ));
        gauges.push(gauge("did_hosting_replication_lag_seconds", lag));
        if let Some(at) = instance.last_ack_at {
            gauges.push(gauge(
                "did_hosting_replication_last_ack_age_seconds",
                now.saturating_sub(at),
            ));
        }
        if let Some(at) = instance.last_reconcile_at {
            gauges.push(gauge(
                "did_hosting_replication_last_reconcile_age_seconds",
                now.saturating_sub(at),
            ));
        }
    }
    Ok(gauges)
}

/// `stats/get/0.1`: one slot's counters (owner or admin — a slot the caller
/// may not read answers exactly as a missing one), or, with no `mnemonic`, the
/// server-wide aggregate (admin).
pub(crate) async fn stats_get(
    cx: &Cx<'_>,
    p: stats_get::v0_1::Payload,
) -> Result<stats_get::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let state = cx.state;
    let Some(mnemonic) = p.mnemonic.as_deref() else {
        let auth = cx.admin().await?;
        let _ = auth;
        let agg = state.stats_collector.get_aggregate();
        let mut body = serde_json::Map::new();
        body.insert("totalDids".into(), json!(agg.total_dids));
        body.insert("totalResolves".into(), json!(agg.total_resolves));
        body.insert("totalUpdates".into(), json!(agg.total_updates));
        if let Some(t) = agg.last_resolved_at {
            body.insert("lastResolvedAt".into(), json!(at(t)));
        }
        if let Some(t) = agg.last_updated_at {
            body.insert("lastUpdatedAt".into(), json!(at(t)));
        }
        return typed(Value::Object(body), "stats/get response");
    };
    let not_found = || {
        TaskError::Declared(
            stats_get::v0_1::error_codes::NOT_FOUND,
            "no such slot".into(),
        )
    };
    let (record, _) = did_ops::get_did_info(&auth, state, mnemonic)
        .await
        .map_err(|e| match e {
            AppError::NotFound(_) | AppError::Forbidden(_) => not_found(),
            other => other.into(),
        })?;
    did_ops::ensure_slot_domain_matches(&record, p.domain.as_deref().map(|d| d.as_str()))?;
    let stats: did_hosting_common::DidStats = state
        .stats_ks
        .get(format!("stats:{mnemonic}"))
        .await?
        .unwrap_or_default();
    let mut body = serde_json::Map::new();
    body.insert("mnemonic".into(), json!(mnemonic.as_str()));
    body.insert("totalResolves".into(), json!(stats.total_resolves));
    body.insert("totalUpdates".into(), json!(stats.total_updates));
    if let Some(t) = stats.last_resolved_at {
        body.insert("lastResolvedAt".into(), json!(at(t)));
    }
    if let Some(t) = stats.last_updated_at {
        body.insert("lastUpdatedAt".into(), json!(at(t)));
    }
    typed(Value::Object(body), "stats/get response")
}

/// `stats/timeseries/0.1`: a slot's series (owner or admin), a domain's
/// (admin, or a caller whose domain scope holds it — a domain outside it
/// answers exactly as an unknown one), or the server-wide series (admin).
pub(crate) async fn timeseries(
    cx: &Cx<'_>,
    p: timeseries::v0_1::Payload,
) -> Result<timeseries::v0_1::Response, TaskError> {
    use crate::acl::Role;
    use timeseries::v0_1::{PayloadRange, error_codes};

    let auth = cx.auth().await?;
    let state = cx.state;
    let (range, range_name, bucket_seconds) = match p.range {
        PayloadRange::LastHour => ("1h", "lastHour", 300u64),
        PayloadRange::LastWeek => ("7d", "lastWeek", 3600),
        PayloadRange::Last30Days => ("30d", "last30Days", 14400),
        _ => ("24h", "lastDay", 900),
    };
    let points = match (p.mnemonic.as_deref(), p.domain.as_deref()) {
        (Some(mnemonic), domain) => {
            let (record, _) = did_ops::get_did_info(&auth, state, mnemonic)
                .await
                .map_err(|e| match e {
                    AppError::NotFound(_) | AppError::Forbidden(_) => {
                        TaskError::Declared(error_codes::NOT_FOUND, "no such slot".into())
                    }
                    other => other.into(),
                })?;
            did_ops::ensure_slot_domain_matches(&record, domain.map(|d| d.as_str()))?;
            super::queries::query_timeseries(&state.timeseries_ks, mnemonic, range).await?
        }
        (None, Some(domain)) => {
            let unknown = || {
                TaskError::Declared(
                    error_codes::UNKNOWN_DOMAIN,
                    format!("`{}` is not a hosting domain", domain.as_str()),
                )
            };
            let canonical = did_hosting_common::server::domain::normalize_domain_name(domain)
                .map_err(|_| unknown())?;
            if did_hosting_common::server::domain::get_domain(&state.store, &canonical)
                .await?
                .is_none()
            {
                return Err(unknown());
            }
            if auth.role != Role::Admin {
                let scope =
                    match did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, &auth.did)
                        .await?
                    {
                        Some(e) => e.domains,
                        None => did_hosting_common::server::domain::DomainScope::All,
                    };
                if !scope.allows(&canonical) {
                    return Err(unknown());
                }
            }
            super::queries::query_timeseries_by_domain(state, &canonical, range).await?
        }
        (None, None) => {
            cx.admin().await?;
            super::queries::query_timeseries(&state.timeseries_ks, "_all", range).await?
        }
    };
    let points: Vec<Value> = points
        .iter()
        .map(|pt| json!({ "at": at(pt.timestamp), "resolves": pt.resolves, "updates": pt.updates }))
        .collect();
    typed(
        json!({ "range": range_name, "bucketSeconds": bucket_seconds, "points": points }),
        "stats/timeseries response",
    )
}

/// `identity/list/0.1`: every generation the running process honours, newest
/// first, never key material. Admin.
pub(crate) async fn identity_list(
    cx: &Cx<'_>,
    _p: identity_list::v0_1::Payload,
) -> Result<identity_list::v0_1::Response, TaskError> {
    cx.admin().await?;
    let state = cx.state;
    let generations: Vec<Value> = match state.identity.as_ref() {
        None => Vec::new(),
        Some(identity) => {
            let generations = identity.generations();
            let current = generations.first().map(|g| g.id);
            // A generation with no key-agreement key is a signing-only
            // identity (tools and tests), not a rotating messaging identity.
            generations
                .iter()
                .filter(|g| !g.ka_kid.is_empty() && !g.signing_kid.is_empty())
                .map(|g| {
                    let mut out = serde_json::Map::new();
                    out.insert("generationId".into(), json!(g.id));
                    out.insert("did".into(), json!(g.did));
                    out.insert("current".into(), json!(Some(g.id) == current));
                    out.insert("signingKeyId".into(), json!(g.signing_kid));
                    out.insert("keyAgreementKeyId".into(), json!(g.ka_kid));
                    if let Some(m) = &g.mediator_did {
                        out.insert("mediatorDid".into(), json!(m));
                    }
                    out.insert(
                        "transports".into(),
                        json!({ "tsp": g.protocols.tsp, "didcomm": g.protocols.didcomm }),
                    );
                    out.insert("createdAt".into(), json!(at(g.created_at)));
                    if Some(g.id) != current {
                        if let Some(t) = g.retired_at {
                            out.insert("retiredAt".into(), json!(at(t)));
                        }
                        if let Some(t) = g.expires_at {
                            out.insert("expiresAt".into(), json!(at(t)));
                        }
                    }
                    Value::Object(out)
                })
                .collect()
        }
    };
    typed(
        json!({
            "generations": generations,
            "rotationGraceSeconds": state.config.identity.rotation_grace_secs(),
        }),
        "identity/list response",
    )
}

/// `identity/retire/0.1`: the kill switch — drop a superseded generation's
/// keys now. Admin, and never the service itself: a document the service
/// signed is not an administrator's decision.
pub(crate) async fn identity_retire(
    cx: &Cx<'_>,
    p: identity_retire::v0_1::Payload,
) -> Result<identity_retire::v0_1::Response, TaskError> {
    use identity_retire::v0_1::error_codes;

    let auth = cx.admin().await?;
    let state = cx.state;
    let own = state
        .identity
        .as_ref()
        .is_some_and(|identity| identity.generations().iter().any(|g| g.did == auth.did))
        || state.config.server_did.as_deref() == Some(auth.did.as_str());
    if own {
        return Err(TaskError::Standard(
            trust_tasks_rs::StandardCode::PermissionDenied,
            "the service is never its own administrator".into(),
        ));
    }
    let identity = state.identity.as_ref().ok_or_else(|| {
        TaskError::Declared(error_codes::NOT_FOUND, "no rotating identity".into())
    })?;
    let generations = identity.generations();
    match generations.iter().position(|g| g.id == p.generation_id) {
        None => {
            return Err(TaskError::Declared(
                error_codes::NOT_FOUND,
                format!("no generation {}", p.generation_id),
            ));
        }
        Some(0) => {
            return Err(TaskError::Declared(
                error_codes::CURRENT,
                "the current generation cannot be retired; rotate first".into(),
            ));
        }
        Some(_) => {}
    }
    crate::identity_rotation::retire_generation_now(state, p.generation_id).await?;
    warn!(caller = %auth.did, generation_id = p.generation_id, "identity generation retired by an administrator");
    typed(
        json!({ "generationId": p.generation_id, "droppedAt": chrono::Utc::now() }),
        "identity/retire response",
    )
}
