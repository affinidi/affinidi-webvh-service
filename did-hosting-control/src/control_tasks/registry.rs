//! `did-management/registry/*`: the control plane's fleet of registered
//! service instances. Every task here is an administrator's.

use serde_json::{Value, json};
use tracing::info;
use trust_tasks_rs::specs::did_management::registry::{
    admin_register, check, deregister, get, list, purge_domain,
};

use did_hosting_common::server::didcomm_profile::ObservedTransport;
use did_hosting_common::server::domain::normalize_domain_name;

use super::{Cx, TaskError, at, typed};
use crate::registry::{self, ServiceInstance, ServiceStatus, ServiceType};

/// The DID a registered instance is addressed by.
fn instance_did(instance: &ServiceInstance) -> Option<&str> {
    instance
        .metadata
        .get("did")
        .and_then(|v| v.as_str())
        .filter(|d| !d.is_empty())
}

fn transport(t: ObservedTransport) -> &'static str {
    match t {
        ObservedTransport::Tsp => "tsp",
        ObservedTransport::Didcomm => "didcomm",
        ObservedTransport::Https => "https",
    }
}

/// A registry entry in the shared `ServiceInstance` 0.2 wire shape, or `None`
/// for an entry with no DID to name it by (the schema requires one; such an
/// entry predates DID-addressed registration and cannot be acted on).
pub(crate) fn spec_instance(instance: &ServiceInstance) -> Option<Value> {
    let did = instance_did(instance)?;
    let mut out = serde_json::Map::new();
    out.insert("instanceId".into(), json!(instance.instance_id));
    out.insert("did".into(), json!(did));
    out.insert(
        "serviceType".into(),
        json!(instance.service_type.to_string()),
    );
    if let Some(label) = &instance.label {
        out.insert("label".into(), json!(label));
    }
    if !instance.url.is_empty() {
        out.insert("publicUrl".into(), json!(instance.url));
    }
    out.insert(
        "status".into(),
        json!(match instance.status {
            ServiceStatus::Active => "active",
            ServiceStatus::Degraded => "degraded",
            ServiceStatus::Unreachable => "unreachable",
        }),
    );
    out.insert("servedDomains".into(), json!(instance.served_domains));
    if !instance.enabled_methods.is_empty() {
        out.insert("enabledMethods".into(), json!(instance.enabled_methods));
    }
    if let Some(services) = &instance.advertised_services {
        out.insert("advertisedServices".into(), json!(services));
        if let Some(checked) = instance.services_checked_at {
            out.insert("servicesCheckedAt".into(), json!(at(checked)));
        }
    }
    if let (Some(t), Some(when)) = (instance.last_inbound_transport, instance.last_inbound_at) {
        out.insert(
            "lastInbound".into(),
            json!({ "transport": transport(t), "at": at(when) }),
        );
    }
    if let (Some(t), Some(when)) = (instance.last_outbound_transport, instance.last_outbound_at) {
        out.insert(
            "lastOutbound".into(),
            json!({ "transport": transport(t), "at": at(when) }),
        );
    }
    if let Some(checked) = instance.last_health_check {
        out.insert("lastHealthCheck".into(), json!(at(checked)));
    }
    out.insert("registeredAt".into(), json!(at(instance.registered_at)));
    Some(Value::Object(out))
}

/// `registry/list/0.1`: every entry matching the filters, by `instanceId`.
pub(crate) async fn list(
    cx: &Cx<'_>,
    p: list::v0_1::Payload,
) -> Result<list::v0_1::Response, TaskError> {
    cx.admin().await?;
    let mut instances = registry::list_instances(&cx.state.registry_ks).await?;
    instances.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
    let want_type = p.service_type.map(|t| t.to_string());
    let want_status = p.status.map(|s| s.to_string());
    let instances: Vec<Value> = instances
        .iter()
        .filter(|i| {
            want_type
                .as_deref()
                .is_none_or(|t| i.service_type.to_string() == t)
        })
        .filter_map(spec_instance)
        .filter(|i| {
            want_status
                .as_deref()
                .is_none_or(|s| i["status"].as_str() == Some(s))
        })
        .collect();
    typed(json!({ "instances": instances }), "registry list response")
}

/// The entry for `instance_id` in its wire shape, or `code`.
async fn wire_instance(
    cx: &Cx<'_>,
    instance_id: &str,
    code: trust_tasks_rs::DeclaredErrorCode,
) -> Result<Value, TaskError> {
    registry::get_instance(&cx.state.registry_ks, instance_id)
        .await?
        .as_ref()
        .and_then(spec_instance)
        .ok_or_else(|| TaskError::Declared(code, format!("no instance `{instance_id}`")))
}

/// `registry/get/0.1`.
pub(crate) async fn get(
    cx: &Cx<'_>,
    p: get::v0_1::Payload,
) -> Result<get::v0_1::Response, TaskError> {
    cx.admin().await?;
    let instance = wire_instance(cx, &p.instance_id, get::v0_1::error_codes::NOT_FOUND).await?;
    typed(json!({ "instance": instance }), "registry get response")
}

/// `registry/check/0.1`: recompute the verdict and re-resolve the advertised
/// services — a failed resolution keeps the previous observation and does not
/// fail the task — then answer the entry as stored.
pub(crate) async fn check(
    cx: &Cx<'_>,
    p: check::v0_1::Payload,
) -> Result<check::v0_1::Response, TaskError> {
    cx.admin().await?;
    let state = cx.state;
    let code = check::v0_1::error_codes::NOT_FOUND;
    let instance = registry::get_instance(&state.registry_ks, &p.instance_id)
        .await?
        .ok_or_else(|| {
            TaskError::Declared(code, format!("no instance `{}`", p.instance_id.as_str()))
        })?;
    let now = crate::auth::session::now_epoch();
    let interval = state.config.registry.health_check_interval.max(10);
    let status = registry::health_status_from_timestamp(&instance, now, interval);
    registry::update_instance_status(&state.registry_ks, &p.instance_id, status, now).await?;
    if let Err(e) = registry::refresh_advertised_services(
        &state.registry_ks,
        &p.instance_id,
        state.did_resolver.as_ref(),
        now,
    )
    .await
    {
        tracing::warn!(instance_id = %p.instance_id.as_str(), error = %e, "registry check: services not re-resolved");
    }
    let instance = wire_instance(cx, &p.instance_id, code).await?;
    typed(json!({ "instance": instance }), "registry check response")
}

/// `registry/admin-register/0.1`: add a hosting server to the registry by
/// hand. An existing `instanceId` is refused, never overwritten.
pub(crate) async fn admin_register(
    cx: &Cx<'_>,
    p: admin_register::v0_1::Payload,
) -> Result<admin_register::v0_1::Response, TaskError> {
    let auth = cx.admin().await?;
    let state = cx.state;
    if registry::get_instance(&state.registry_ks, &p.instance_id)
        .await?
        .is_some()
    {
        return Err(TaskError::Declared(
            admin_register::v0_1::error_codes::INSTANCE_EXISTS,
            format!(
                "instance `{}` is already registered",
                p.instance_id.as_str()
            ),
        ));
    }
    registry::validate_registered_url(&p.public_url, &state.config.registry.url_allowlist)?;
    let served_domains = p
        .served_domains
        .iter()
        .map(|d| normalize_domain_name(d))
        .collect::<Result<Vec<_>, _>>()?;
    let now = crate::auth::session::now_epoch();
    let instance = ServiceInstance {
        instance_id: p.instance_id.to_string(),
        service_type: ServiceType::Server,
        label: p.label.as_ref().map(|l| l.to_string()),
        url: p.public_url.clone(),
        status: ServiceStatus::Active,
        last_health_check: None,
        registered_at: now,
        metadata: json!({ "did": p.did.as_str() }),
        enabled_methods: vec!["webvh".to_string()],
        served_domains,
        protocol_version: "1.0".to_string(),
        advertised_services: None,
        services_checked_at: None,
        trust_task_capable: true,
        sync_batch_capable: false,
        last_inbound_transport: None,
        last_inbound_at: None,
        last_outbound_transport: None,
        last_outbound_at: None,
    };
    registry::register_instance(&state.registry_ks, &instance).await?;
    info!(caller = %auth.did, instance_id = %instance.instance_id, "instance registered by an administrator");
    let mut entry = serde_json::Map::new();
    entry.insert("instanceId".into(), json!(instance.instance_id));
    entry.insert("did".into(), json!(p.did.as_str()));
    if let Some(label) = &instance.label {
        entry.insert("label".into(), json!(label));
    }
    entry.insert("publicUrl".into(), json!(instance.url));
    entry.insert("servedDomains".into(), json!(instance.served_domains));
    typed(
        json!({ "entry": Value::Object(entry) }),
        "registry admin-register response",
    )
}

/// `registry/deregister/0.1`.
pub(crate) async fn deregister(
    cx: &Cx<'_>,
    p: deregister::v0_1::Payload,
) -> Result<deregister::v0_1::Response, TaskError> {
    let auth = cx.admin().await?;
    let state = cx.state;
    if registry::get_instance(&state.registry_ks, &p.instance_id)
        .await?
        .is_none()
    {
        return Err(TaskError::Declared(
            deregister::v0_1::error_codes::NOT_FOUND,
            format!("no instance `{}`", p.instance_id.as_str()),
        ));
    }
    registry::deregister_instance(&state.registry_ks, &p.instance_id).await?;
    info!(caller = %auth.did, instance_id = %p.instance_id.as_str(), "instance deregistered");
    typed(
        json!({ "instanceId": p.instance_id.as_str(), "removedAt": chrono::Utc::now() }),
        "registry deregister response",
    )
}

/// `registry/purge-domain/0.1`: queue a purge of a domain's content on one
/// server, now. Refused while the registry still records the domain as
/// assigned to that server — a purge must follow an unassignment, never race
/// one — and queued in the durable outbox, signed at send time.
pub(crate) async fn purge_domain(
    cx: &Cx<'_>,
    p: purge_domain::v0_1::Payload,
) -> Result<purge_domain::v0_1::Response, TaskError> {
    use purge_domain::v0_1::error_codes as codes;

    let auth = cx.admin().await?;
    let state = cx.state;
    let instance = registry::get_instance(&state.registry_ks, &p.instance_id)
        .await?
        .ok_or_else(|| {
            TaskError::Declared(
                codes::NOT_FOUND,
                format!("no instance `{}`", p.instance_id.as_str()),
            )
        })?;
    if instance.service_type != ServiceType::Server {
        return Err(TaskError::Declared(
            codes::NOT_A_SERVER,
            format!(
                "instance `{}` is not a hosting server",
                p.instance_id.as_str()
            ),
        ));
    }
    let domain = normalize_domain_name(&p.domain).map_err(|_| {
        TaskError::Declared(codes::UNKNOWN_DOMAIN, "not a valid domain name".into())
    })?;
    let known = did_hosting_common::server::domain::get_domain(&state.store, &domain)
        .await?
        .is_some();
    if !known {
        return Err(TaskError::Declared(
            codes::UNKNOWN_DOMAIN,
            format!("`{domain}` is not a hosting domain"),
        ));
    }
    if instance.served_domains.contains(&domain) {
        return Err(TaskError::Declared(
            codes::STILL_ASSIGNED,
            format!("`{domain}` is still assigned to this instance; unassign it first"),
        ));
    }
    let target = instance_did(&instance).ok_or_else(|| {
        TaskError::Declared(
            codes::NOT_FOUND,
            "the instance has no DID to address".into(),
        )
    })?;
    crate::server_push::send_domain_purge(state, target, &domain).await?;
    info!(caller = %auth.did, instance_id = %p.instance_id.as_str(), %domain, "domain purge queued for server");
    typed(
        json!({ "domain": domain, "instanceId": p.instance_id.as_str(), "status": "queued" }),
        "registry purge-domain response",
    )
}
