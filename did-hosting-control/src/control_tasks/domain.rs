//! `did-management/me/domains` and the `domain/*` family.

use serde_json::{Value, json};
use tracing::{info, warn};
use trust_tasks_rs::specs::did_management::{
    domain::{assign, create, list, purge, set_default, set_state, unassign, update},
    me::domains as me_domains_spec,
};

use did_hosting_common::server::auth::session::now_epoch;
use did_hosting_common::server::domain::{
    self as store, DomainEntry, DomainStatus, DomainUrlScheme, normalize_domain_name,
};
use did_hosting_common::server::pending_purge;
use did_hosting_common::server::trust_tasks::ext::WEBVH_EXT_KEY;
use trust_tasks_rs::DeclaredErrorCode;

use super::{Cx, TaskError, at, typed};
use crate::error::AppError;
use crate::server::AppState;

/// A stored domain in the shared `DomainEntry` wire shape.
///
/// The schema carries the lifecycle (`name`, `label`, `status`,
/// `defaultDomain`, `createdAt`, `disabledAt`, `purgeAt`); this host's own
/// settings for the domain — URL scheme, branding, witness and watcher lists,
/// quota, the `.well-known` switch — travel under the host's extension
/// namespace, where the schema allows them, rather than as members it does not.
pub(crate) fn spec_domain_entry(entry: &DomainEntry) -> Value {
    let mut out = serde_json::Map::new();
    out.insert("name".into(), json!(entry.name));
    if let Some(label) = &entry.label {
        out.insert("label".into(), json!(label));
    }
    out.insert(
        "status".into(),
        json!(match entry.status {
            DomainStatus::Active => "active",
            DomainStatus::Disabled => "disabled",
        }),
    );
    out.insert("defaultDomain".into(), json!(entry.default_domain));
    out.insert("createdAt".into(), json!(at(entry.created_at)));
    if entry.status == DomainStatus::Disabled {
        if let Some(disabled_at) = entry.disabled_at {
            out.insert("disabledAt".into(), json!(at(disabled_at)));
        }
        if let Some(purge_at) = entry.purge_at {
            out.insert("purgeAt".into(), json!(at(purge_at)));
        }
    }
    let mut host = serde_json::Map::new();
    host.insert("scheme".into(), json!(entry.scheme));
    host.insert("wellKnownEnabled".into(), json!(entry.well_known_enabled));
    if let Some(branding) = &entry.branding {
        host.insert("branding".into(), json!(branding));
    }
    if let Some(witnesses) = &entry.witnesses {
        host.insert("witnesses".into(), json!(witnesses));
    }
    if let Some(watchers) = &entry.watchers {
        host.insert("watchers".into(), json!(watchers));
    }
    if let Some(quota) = &entry.quota {
        host.insert("quota".into(), json!(quota));
    }
    out.insert("ext".into(), json!({ WEBVH_EXT_KEY: host }));
    Value::Object(out)
}

/// `me/domains/0.1`: the domains the caller may host DIDs under.
pub(crate) async fn me_domains(
    cx: &Cx<'_>,
    _p: me_domains_spec::v0_1::Payload,
) -> Result<me_domains_spec::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let resp = crate::routes::domain::fetch_me_domains_for_caller(&auth, cx.state).await?;
    let domains: Vec<Value> = resp.domains.iter().map(spec_domain_entry).collect();
    let mut body = serde_json::Map::new();
    body.insert("domains".into(), json!(domains));
    if let Some(default) = resp.default {
        body.insert("default".into(), json!(default));
    }
    typed(Value::Object(body), "me/domains response")
}

/// A domain name in canonical form, or the task's `unknownDomain`.
fn canonical(name: &str, unknown: DeclaredErrorCode) -> Result<String, TaskError> {
    normalize_domain_name(name)
        .map_err(|_| TaskError::Declared(unknown, format!("`{name}` is not a valid domain name")))
}

/// The stored entry for `name`, or the task's `unknownDomain`.
async fn existing(
    state: &AppState,
    name: &str,
    unknown: DeclaredErrorCode,
) -> Result<DomainEntry, TaskError> {
    store::get_domain(&state.store, name)
        .await?
        .ok_or_else(|| TaskError::Declared(unknown, format!("`{name}` is not a hosting domain")))
}

fn entry_response<T: serde::de::DeserializeOwned>(
    entry: &DomainEntry,
    what: &str,
) -> Result<T, TaskError> {
    typed(json!({ "entry": spec_domain_entry(entry) }), what)
}

/// `domain/list/0.1`: every domain, optionally in one state. Admin.
pub(crate) async fn list(
    cx: &Cx<'_>,
    p: list::v0_1::Payload,
) -> Result<list::v0_1::Response, TaskError> {
    cx.admin().await?;
    let mut domains = store::list_domains(&cx.state.store).await?;
    if let Some(status) = p.status {
        let want = match status {
            list::v0_1::PayloadStatus::Active => DomainStatus::Active,
            _ => DomainStatus::Disabled,
        };
        domains.retain(|d| d.status == want);
    }
    domains.sort_by(|a, b| a.name.cmp(&b.name));
    let mut body = serde_json::Map::new();
    body.insert(
        "domains".into(),
        json!(domains.iter().map(spec_domain_entry).collect::<Vec<_>>()),
    );
    if let Some(default) = store::get_default_domain(&cx.state.store).await? {
        body.insert("default".into(), json!(default));
    }
    typed(Value::Object(body), "domain list response")
}

/// `domain/create/0.1`. Admin.
pub(crate) async fn create(
    cx: &Cx<'_>,
    p: create::v0_1::Payload,
) -> Result<create::v0_1::Response, TaskError> {
    let auth = cx.admin().await?;
    let state = cx.state;
    let name = normalize_domain_name(&p.name).map_err(|e| {
        TaskError::Declared(create::v0_1::error_codes::INVALID_NAME, e.user_message())
    })?;
    let entry = DomainEntry {
        name: name.clone(),
        label: p.label.as_ref().map(|l| l.to_string()),
        scheme: DomainUrlScheme::Https,
        status: DomainStatus::Active,
        created_at: now_epoch(),
        default_domain: false,
        branding: None,
        witnesses: None,
        watchers: None,
        quota: None,
        well_known_enabled: false,
        disabled_at: None,
        purge_at: None,
    };
    store::create_domain(&state.store, &entry)
        .await
        .map_err(|e| match e {
            AppError::Conflict(message) => {
                TaskError::Declared(create::v0_1::error_codes::DOMAIN_EXISTS, message)
            }
            other => other.into(),
        })?;
    if p.set_as_default {
        store::set_default_domain(&state.store, &name).await?;
    }
    let stored = existing(state, &name, create::v0_1::error_codes::INVALID_NAME).await?;
    let (sent, failed) = crate::server_push::fanout_domain_upsert(state, &stored).await;
    info!(caller = %auth.did, domain = %name, set_as_default = p.set_as_default, fanout_sent = sent, fanout_failed = failed, "domain created");
    entry_response(&stored, "domain create response")
}

/// `domain/update/0.1`: the domain's label. Admin.
pub(crate) async fn update(
    cx: &Cx<'_>,
    p: update::v0_1::Payload,
) -> Result<update::v0_1::Response, TaskError> {
    let auth = cx.admin().await?;
    let state = cx.state;
    let unknown = update::v0_1::error_codes::UNKNOWN_DOMAIN;
    let name = canonical(&p.name, unknown)?;
    let mut entry = existing(state, &name, unknown).await?;
    if let Some(label) = p.label.as_ref() {
        entry.label = Some(label.to_string());
    }
    store::update_domain(&state.store, &name, &entry).await?;
    let (sent, failed) = crate::server_push::fanout_domain_upsert(state, &entry).await;
    info!(caller = %auth.did, domain = %name, fanout_sent = sent, fanout_failed = failed, "domain updated");
    entry_response(&entry, "domain update response")
}

/// `domain/set-state/0.1`: disable (scheduling the purge after the grace
/// period) or re-enable a domain. Admin.
pub(crate) async fn set_state(
    cx: &Cx<'_>,
    p: set_state::v0_1::Payload,
) -> Result<set_state::v0_1::Response, TaskError> {
    let auth = cx.admin().await?;
    let state = cx.state;
    let unknown = set_state::v0_1::error_codes::UNKNOWN_DOMAIN;
    let name = canonical(&p.name, unknown)?;
    existing(state, &name, unknown).await?;
    match p.state {
        set_state::v0_1::PayloadState::Active => store::enable_domain(&state.store, &name).await?,
        set_state::v0_1::PayloadState::Disabled => {
            let grace_seconds =
                pending_purge::parse_grace_string(&state.config.hosting.disable_purge_grace)
                    .map_err(|e| {
                        AppError::Internal(format!(
                            "config [hosting] disable_purge_grace is invalid: {e}"
                        ))
                    })?;
            store::disable_domain(&state.store, &name, now_epoch(), grace_seconds, &auth.did)
                .await
                .map_err(|e| match e {
                    AppError::Conflict(message) => {
                        TaskError::Declared(set_state::v0_1::error_codes::IS_DEFAULT, message)
                    }
                    other => other.into(),
                })?;
        }
        _ => return Err(AppError::Validation("unsupported domain state".into()).into()),
    }
    let entry = existing(state, &name, unknown).await?;
    let (sent, failed) = crate::server_push::fanout_domain_upsert(state, &entry).await;
    info!(caller = %auth.did, domain = %name, status = ?entry.status, fanout_sent = sent, fanout_failed = failed, "domain state set");
    entry_response(&entry, "domain set-state response")
}

/// `domain/set-default/0.1`. Admin.
pub(crate) async fn set_default(
    cx: &Cx<'_>,
    p: set_default::v0_1::Payload,
) -> Result<set_default::v0_1::Response, TaskError> {
    let auth = cx.admin().await?;
    let state = cx.state;
    let unknown = set_default::v0_1::error_codes::UNKNOWN_DOMAIN;
    let name = canonical(&p.name, unknown)?;
    existing(state, &name, unknown).await?;
    let previous = store::get_default_domain(&state.store).await?;
    store::set_default_domain(&state.store, &name)
        .await
        .map_err(|e| match e {
            AppError::Conflict(message) => {
                TaskError::Declared(set_default::v0_1::error_codes::DOMAIN_DISABLED, message)
            }
            other => other.into(),
        })?;
    let entry = existing(state, &name, unknown).await?;
    let (sent, failed) = crate::server_push::fanout_domain_upsert(state, &entry).await;
    info!(caller = %auth.did, domain = %name, fanout_sent = sent, fanout_failed = failed, "domain set as default");
    let mut body = serde_json::Map::new();
    body.insert("entry".into(), spec_domain_entry(&entry));
    if let Some(previous) = previous.filter(|p| *p != name) {
        body.insert("previousDefault".into(), json!(previous));
    }
    typed(Value::Object(body), "domain set-default response")
}

/// `domain/purge/0.1`: delete a disabled domain now, overriding the grace
/// period, optionally queueing a purge on every server that hosts it.
/// Destructive and irreversible, so — as on every other surface — it needs
/// an administrator in a stepped-up (`aal2`) session.
pub(crate) async fn purge(
    cx: &Cx<'_>,
    p: purge::v0_1::Payload,
) -> Result<purge::v0_1::Response, TaskError> {
    let auth = cx.admin().await?;
    if auth.acr != "aal2" {
        return Err(AppError::StepUpRequired(
            "purging a domain requires a stepped-up (aal2) session".into(),
        )
        .into());
    }
    let state = cx.state;
    let unknown = purge::v0_1::error_codes::UNKNOWN_DOMAIN;
    let name = canonical(&p.name, unknown)?;
    let entry = existing(state, &name, unknown).await?;
    if entry.status == DomainStatus::Active {
        return Err(TaskError::Declared(
            purge::v0_1::error_codes::NOT_DISABLED,
            format!("`{name}` is active; disable it first"),
        ));
    }
    if store::get_default_domain(&state.store).await?.as_deref() == Some(name.as_str()) {
        return Err(TaskError::Declared(
            purge::v0_1::error_codes::IS_DEFAULT,
            format!("`{name}` is the default domain"),
        ));
    }
    let mut fanout = Vec::new();
    if p.purge_servers {
        for inst in crate::registry::list_instances(&state.registry_ks).await? {
            if !inst.served_domains.iter().any(|d| d == &name) {
                continue;
            }
            let status = match inst.metadata.get("did").and_then(|v| v.as_str()) {
                Some(target) => {
                    match crate::server_push::send_domain_purge(state, target, &name).await {
                        Ok(()) => "queued",
                        Err(e) => {
                            warn!(instance_id = %inst.instance_id, error = %e, "purge fanout: could not queue");
                            "failed"
                        }
                    }
                }
                None => "failed",
            };
            fanout.push(json!({ "instanceId": inst.instance_id, "status": status }));
        }
    }
    store::delete_domain_record(&state.store, &name).await?;
    let _ = pending_purge::cancel(&state.store, &name).await;
    info!(caller = %auth.did, acr = %auth.acr, domain = %name, servers = fanout.len(), "domain purged (admin override of grace window)");
    typed(
        json!({ "name": name, "purgedAt": chrono::Utc::now(), "fanout": fanout }),
        "domain purge response",
    )
}

/// Queue a domain directive for one registered server.
async fn queue_for_instance(
    cx: &Cx<'_>,
    instance_id: &str,
    domain: &str,
    unknown_domain: DeclaredErrorCode,
    unknown_instance: DeclaredErrorCode,
    send: impl AsyncFnOnce(&AppState, &str, &str) -> Result<(), String>,
) -> Result<Value, TaskError> {
    let state = cx.state;
    let name = canonical(domain, unknown_domain)?;
    existing(state, &name, unknown_domain).await?;
    let instance = crate::registry::get_instance(&state.registry_ks, instance_id)
        .await?
        .ok_or_else(|| {
            TaskError::Declared(unknown_instance, format!("no instance `{instance_id}`"))
        })?;
    let target = instance
        .metadata
        .get("did")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            TaskError::Declared(
                unknown_instance,
                format!("instance `{instance_id}` has no DID to address"),
            )
        })?;
    send(state, target, &name)
        .await
        .map_err(|e| AppError::Internal(format!("could not queue the directive: {e}")))?;
    Ok(json!({ "domain": name, "instanceId": instance_id, "status": "queued" }))
}

/// `domain/assign/0.1`: tell one server to host a domain. Admin.
pub(crate) async fn assign(
    cx: &Cx<'_>,
    p: assign::v0_1::Payload,
) -> Result<assign::v0_1::Response, TaskError> {
    let auth = cx.admin().await?;
    let body = queue_for_instance(
        cx,
        &p.instance_id,
        &p.domain,
        assign::v0_1::error_codes::UNKNOWN_DOMAIN,
        assign::v0_1::error_codes::UNKNOWN_INSTANCE,
        async |state, target, name| {
            crate::server_push::send_domain_assign(state, target, name)
                .await
                .map_err(|e| e.to_string())
        },
    )
    .await?;
    info!(caller = %auth.did, instance_id = %p.instance_id.as_str(), domain = %p.domain.as_str(), "domain assignment queued");
    typed(body, "domain assign response")
}

/// `domain/unassign/0.1`: tell one server to stop hosting a domain. Admin.
pub(crate) async fn unassign(
    cx: &Cx<'_>,
    p: unassign::v0_1::Payload,
) -> Result<unassign::v0_1::Response, TaskError> {
    let auth = cx.admin().await?;
    let body = queue_for_instance(
        cx,
        &p.instance_id,
        &p.domain,
        unassign::v0_1::error_codes::UNKNOWN_DOMAIN,
        unassign::v0_1::error_codes::UNKNOWN_INSTANCE,
        async |state, target, name| {
            crate::server_push::send_domain_unassign(state, target, name)
                .await
                .map_err(|e| e.to_string())
        },
    )
    .await?;
    info!(caller = %auth.did, instance_id = %p.instance_id.as_str(), domain = %p.domain.as_str(), "domain unassignment queued");
    typed(body, "domain unassign response")
}
