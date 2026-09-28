//! `did-management/did/*` and `webvh/witness/publish`.

use did_hosting_common::server::auth::session::now_epoch;
use serde_json::json;
use tracing::info;
use trust_tasks_rs::specs::{
    did_management::did::{
        change_owner, check_name, delete, info, list, log, register, rollback, set_state,
    },
    webvh::witness::publish as witness_publish,
};

use did_hosting_common::did_ops::did_key;

use super::{Cx, TaskError, spec_record, typed};
use crate::did_ops;
use crate::error::AppError;
use crate::server::AppState;
use crate::server_push;

/// `did/check-name/0.1`: an availability probe, or (`reserve: true`) an atomic
/// claim of a slot — auto-assigned when `path` is absent.
pub(crate) async fn check_name(
    cx: &Cx<'_>,
    p: check_name::v0_1::Payload,
) -> Result<check_name::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let state = cx.state;
    let path = p.path.as_deref().map(String::as_str);

    // Probe mode is read-only and must name a path; a path-less request only
    // means something as an auto-assign reservation.
    if !p.reserve {
        let path = path.ok_or_else(|| {
            AppError::Validation(
                "[path] check-name without `reserve: true` requires a `path` to probe".into(),
            )
        })?;
        let probe = did_ops::check_name(state, path).await?;
        return typed(
            json!({ "available": probe.available, "reserved": false }),
            "check-name response",
        );
    }

    // Domain: explicit on the wire → caller's ACL default → system default.
    // An explicit domain that does not resolve is refused rather than dropped.
    let acl_scope =
        match did_hosting_common::server::acl::get_acl_entry(&state.acl_ks, &auth.did).await? {
            Some(e) => e.domains,
            None => did_hosting_common::server::domain::DomainScope::All,
        };
    let system_default = did_hosting_common::server::domain::get_default_domain(&state.store)
        .await
        .ok()
        .flatten();
    let resolved_domain = match did_hosting_common::server::domain::resolve_request_domain(
        p.domain.as_deref(),
        &acl_scope,
        system_default.as_deref(),
    ) {
        Ok(d) => Some(d),
        Err(e) if p.domain.is_some() => {
            return Err(
                AppError::Validation(format!("did-management:unknown_domain — {e}")).into(),
            );
        }
        Err(_) => None,
    };

    // A named path that is already taken is not an error: the spec answers
    // `available: false, reserved: false` and changes nothing.
    match did_ops::create_did(&auth, state, path, false, resolved_domain.as_deref()).await {
        Ok(result) => {
            let record: did_hosting_common::did_ops::DidRecord = state
                .dids_ks
                .get(did_key(&result.mnemonic))
                .await?
                .ok_or_else(|| AppError::Internal("record missing after reservation".into()))?;
            let record: check_name::v0_1::DidRecord = spec_record(state, &record)?;
            typed(
                json!({ "available": true, "reserved": true, "record": record }),
                "check-name response",
            )
        }
        Err(AppError::Conflict(_)) => typed(
            json!({ "available": false, "reserved": false }),
            "check-name response",
        ),
        Err(e) => Err(e.into()),
    }
}

/// `did/register/0.1`: claim a slot and publish its first (or next) signed log
/// in one step.
pub(crate) async fn register(
    cx: &Cx<'_>,
    p: register::v0_1::Payload,
) -> Result<register::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let state = cx.state;
    // The typed payload is the schema's; `DidRegisterRequest::resolve` is the
    // one place the method is derived from and cross-checked against the data.
    let req: did_hosting_common::DidRegisterRequest = serde_json::from_value(json!({
        "path": p.path.as_str(),
        "method": serde_json::to_value(&p.method)?,
        "didData": serde_json::to_value(&p.did_data)?,
        "force": p.force,
    }))
    .map_err(|e| AppError::Validation(format!("invalid register payload: {e}")))?;
    let (method, payload) = req.resolve().map_err(AppError::Validation)?;
    if method != "webvh" {
        return Err(AppError::Validation(format!(
            "this host registers webvh only over this task; received method = '{method}'"
        ))
        .into());
    }
    let did_log = std::str::from_utf8(&payload).map_err(|e| {
        AppError::Validation(format!("[log] webvh didData is not valid UTF-8: {e}"))
    })?;

    let result = did_ops::register_did_atomic(
        &auth,
        state,
        p.path.as_str(),
        did_log,
        p.force,
        p.domain.as_deref(),
    )
    .await?;
    server_push::notify_servers_did(state, result.mnemonic.clone());

    let record = stored(cx, &result.mnemonic).await?;
    typed(
        json!({ "record": spec_record::<register::v0_1::DidRecord>(state, &record)? }),
        "register response",
    )
}

/// `did/info/0.1`.
pub(crate) async fn info(
    cx: &Cx<'_>,
    p: info::v0_1::Payload,
) -> Result<info::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let state = cx.state;
    let (record, log_metadata) = did_ops::get_did_info(&auth, state, &p.mnemonic).await?;
    did_ops::ensure_slot_domain_matches(&record, p.domain.as_deref())?;

    let mut body = serde_json::Map::new();
    body.insert(
        "record".into(),
        serde_json::to_value(spec_record::<info::v0_1::DidRecord>(state, &record)?)?,
    );
    if let Some(meta) = log_metadata {
        let mut summary = serde_json::Map::new();
        if let Some(id) = meta.latest_version_id {
            summary.insert("latestVersionId".into(), json!(id));
        }
        if let Some(time) = meta
            .latest_version_time
            .as_deref()
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        {
            summary.insert(
                "latestVersionTime".into(),
                json!(
                    time.with_timezone(&chrono::Utc)
                        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                ),
            );
        }
        body.insert("logSummary".into(), serde_json::Value::Object(summary));
    }
    typed(serde_json::Value::Object(body), "info response")
}

/// `did/list/0.1`: `{records, total}`, paged. A non-admin may name only
/// themselves as `owner`; naming anyone else is refused, not ignored.
pub(crate) async fn list(
    cx: &Cx<'_>,
    p: list::v0_1::Payload,
) -> Result<list::v0_1::Response, TaskError> {
    use crate::acl::Role;

    let auth = cx.auth().await?;
    let state = cx.state;
    if auth.role != Role::Admin
        && let Some(owner) = p.owner.as_deref()
        && owner != auth.did
    {
        return Err(TaskError::Declared(
            list::v0_1::error_codes::FORBIDDEN,
            "only an administrator may list another owner's slots".into(),
        ));
    }
    let domain = match p.domain.as_deref() {
        Some(d) => {
            let canonical = did_hosting_common::server::domain::normalize_domain_name(d)
                .map_err(|_| unknown_domain(d))?;
            if did_hosting_common::server::domain::get_domain(&state.store, &canonical)
                .await?
                .is_none()
            {
                return Err(unknown_domain(d));
            }
            Some(canonical)
        }
        None => None,
    };

    // A registered hosting server reconciling against the listing: it is sent
    // every slot anyway, and the listing is how it catches what it missed
    // (the replication staleness bound). Only a server-type registry entry
    // under the caller's own DID qualifies — a witness or watcher with the
    // Service role does not.
    let replica = auth.role == Role::Service && is_hosting_server(state, &auth.did).await;
    if replica && p.owner.is_none() && p.offset.unwrap_or(0) == 0 {
        crate::registry::record_reconcile(&state.registry_ks, &auth.did, now_epoch()).await;
    }
    let (records, total) = did_ops::list_dids_page(
        &auth,
        replica,
        state,
        p.owner.as_deref(),
        domain.as_deref(),
        p.limit.map(|l| l.get() as usize),
        p.offset.map(|o| o as usize),
    )
    .await?;
    let records = records
        .iter()
        .map(|(record, total_resolves)| {
            let mut value =
                serde_json::to_value(spec_record::<list::v0_1::DidRecord>(state, record)?)?;
            value["totalResolves"] = json!(total_resolves);
            Ok(value)
        })
        .collect::<Result<Vec<_>, TaskError>>()?;
    typed(
        json!({ "records": records, "total": total }),
        "list response",
    )
}

/// Whether `did` is registered here as a hosting server (an edge).
async fn is_hosting_server(state: &AppState, did: &str) -> bool {
    matches!(
        crate::registry::get_instance(&state.registry_ks, &did.replace(':', "_")).await,
        Ok(Some(instance)) if instance.service_type == crate::registry::ServiceType::Server
            && instance.metadata.get("did").and_then(|d| d.as_str()) == Some(did)
    )
}

fn unknown_domain(domain: &str) -> TaskError {
    TaskError::Declared(
        list::v0_1::error_codes::UNKNOWN_DOMAIN,
        format!("`{domain}` is not a hosting domain on this service"),
    )
}

/// `did/delete/0.1`: answers with the record as it stood.
pub(crate) async fn delete(
    cx: &Cx<'_>,
    p: delete::v0_1::Payload,
) -> Result<delete::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let state = cx.state;
    let (record, _) = did_ops::get_did_info(&auth, state, &p.mnemonic).await?;
    did_ops::delete_did(&auth, state, &p.mnemonic, p.domain.as_deref()).await?;
    server_push::notify_servers_delete(state, p.mnemonic.to_string());
    typed(
        json!({ "record": spec_record::<delete::v0_1::DidRecord>(state, &record)? }),
        "delete response",
    )
}

/// `did/change-owner/0.1`.
pub(crate) async fn change_owner(
    cx: &Cx<'_>,
    p: change_owner::v0_1::Payload,
) -> Result<change_owner::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let state = cx.state;
    let (current, _) = did_ops::get_did_info(&auth, state, &p.mnemonic).await?;
    did_ops::ensure_slot_domain_matches(&current, p.domain.as_deref())?;
    let record = did_ops::change_did_owner(&auth, state, &p.mnemonic, &p.new_owner).await?;
    typed(
        json!({ "record": spec_record::<change_owner::v0_1::DidRecord>(state, &record)? }),
        "change-owner response",
    )
}

/// `webvh/witness/publish/0.1`.
pub(crate) async fn witness_publish(
    cx: &Cx<'_>,
    p: witness_publish::v0_1::Payload,
) -> Result<witness_publish::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let state = cx.state;
    let witness = serde_json::to_string(&p.witness)?;
    did_ops::upload_witness(&auth, state, &p.mnemonic, &witness).await?;
    let base_url = state
        .config
        .did_hosting_url
        .as_deref()
        .or(state.config.public_url.as_deref())
        .unwrap_or("http://localhost");
    let witness_url = format!(
        "{}/{}/did-witness.json",
        base_url.trim_end_matches('/'),
        p.mnemonic.as_str()
    );
    server_push::notify_servers_did(state, p.mnemonic.to_string());
    info!(did = %auth.did, mnemonic = %p.mnemonic.as_str(), "witness proofs published");
    typed(
        json!({ "mnemonic": p.mnemonic.as_str(), "witnessUrl": witness_url }),
        "witness publish response",
    )
}

/// The stored record for `mnemonic`, which the caller has just written.
async fn stored(
    cx: &Cx<'_>,
    mnemonic: &str,
) -> Result<did_hosting_common::did_ops::DidRecord, TaskError> {
    Ok(cx
        .state
        .dids_ks
        .get(did_key(mnemonic))
        .await?
        .ok_or_else(|| AppError::Internal(format!("record `{mnemonic}` missing after write")))?)
}

/// `did/set-state/0.1`: `suspended` stops the slot resolving on every edge,
/// `active` resumes it. The state travels to edges with the slot's content.
pub(crate) async fn set_state(
    cx: &Cx<'_>,
    p: set_state::v0_1::Payload,
) -> Result<set_state::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let state = cx.state;
    let (current, _) = did_ops::get_did_info(&auth, state, &p.mnemonic).await?;
    did_ops::ensure_slot_domain_matches(&current, p.domain.as_deref())?;
    let disabled = match p.state {
        set_state::v0_1::PayloadState::Active => false,
        set_state::v0_1::PayloadState::Suspended => true,
        _ => return Err(AppError::Validation("unsupported DID state".into()).into()),
    };
    did_ops::set_did_disabled(&auth, state, &p.mnemonic, disabled).await?;
    server_push::notify_servers_did(state, p.mnemonic.to_string());
    let record = stored(cx, &p.mnemonic).await?;
    typed(
        json!({ "record": spec_record::<set_state::v0_1::DidRecord>(state, &record)? }),
        "set-state response",
    )
}

/// `did/rollback/0.1`: discard every entry after `targetVersion`.
pub(crate) async fn rollback(
    cx: &Cx<'_>,
    p: rollback::v0_1::Payload,
) -> Result<rollback::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let state = cx.state;
    let (current, _) = did_ops::get_did_info(&auth, state, &p.mnemonic).await?;
    did_ops::ensure_slot_domain_matches(&current, p.domain.as_deref())?;
    let (record, _, removed) =
        did_ops::rollback_did_to(&auth, state, &p.mnemonic, Some(p.target_version.get()))
            .await
            .map_err(|e| match e {
                AppError::Validation(message) if message.starts_with("invalid target version") => {
                    TaskError::Declared(
                        rollback::v0_1::error_codes::INVALID_TARGET_VERSION,
                        message,
                    )
                }
                other => other.into(),
            })?;
    if removed > 0 {
        server_push::notify_servers_did(state, p.mnemonic.to_string());
    }
    typed(
        json!({
            "record": spec_record::<rollback::v0_1::DidRecord>(state, &record)?,
            "removedVersions": removed,
        }),
        "rollback response",
    )
}

/// `did/log/0.1`: the slot's history, oldest first — and, with `raw`, the
/// stored artifacts verbatim. A slot that does not exist, one the caller may
/// not read, and one with no published content are answered alike.
pub(crate) async fn log(
    cx: &Cx<'_>,
    p: log::v0_1::Payload,
) -> Result<log::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let state = cx.state;
    let not_found = || {
        TaskError::Declared(
            log::v0_1::error_codes::NOT_FOUND,
            "no such slot with published content".into(),
        )
    };
    let (record, _) = did_ops::get_did_info(&auth, state, &p.mnemonic)
        .await
        .map_err(|e| match e {
            AppError::NotFound(_) | AppError::Forbidden(_) => not_found(),
            other => other.into(),
        })?;
    did_ops::ensure_slot_domain_matches(&record, p.domain.as_deref().map(|d| d.as_str()))?;
    let content = match did_ops::get_raw_log(&auth, state, &p.mnemonic).await {
        Ok(content) => content,
        Err(AppError::NotFound(_)) => return Err(not_found()),
        Err(e) => return Err(e.into()),
    };
    let entries: Vec<serde_json::Value> = did_hosting_common::did_ops::parse_log_entries(&content)
        .into_iter()
        .map(|e| {
            let mut entry = serde_json::Map::new();
            if let Some(id) = e.version_id {
                entry.insert("versionId".into(), json!(id));
            }
            if let Some(time) = e.version_time {
                entry.insert("versionTime".into(), json!(time));
            }
            entry.insert(
                "state".into(),
                e.state
                    .filter(|s| s.is_object())
                    .unwrap_or_else(|| json!({})),
            );
            if let Some(parameters) = e.parameters.filter(|p| p.is_object()) {
                entry.insert("parameters".into(), parameters);
            }
            serde_json::Value::Object(entry)
        })
        .collect();
    let method = if record.method.is_empty() {
        "webvh".to_string()
    } else {
        record.method.clone()
    };
    let mut body = serde_json::Map::new();
    body.insert("mnemonic".into(), json!(p.mnemonic.as_str()));
    body.insert("method".into(), json!(method));
    body.insert("entries".into(), json!(entries));
    if p.raw.unwrap_or(false) {
        body.insert("logContent".into(), json!(content));
        if let Some(witness) = state
            .dids_ks
            .get_raw(did_hosting_common::did_ops::content_witness_key(
                &p.mnemonic,
            ))
            .await?
            .and_then(|w| String::from_utf8(w).ok())
            .filter(|w| !w.is_empty())
        {
            body.insert("witnessContent".into(), json!(witness));
        }
    }
    typed(serde_json::Value::Object(body), "log response")
}
