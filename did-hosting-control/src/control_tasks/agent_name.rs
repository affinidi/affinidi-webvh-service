//! `did-management/agent-name/*`.

use serde_json::json;
use tracing::info;
use trust_tasks_rs::specs::did_management::agent_name::{check, list, remove, update};

use super::{Cx, TaskError, at, spec_record, typed};
use crate::did_ops;
use crate::error::AppError;
use crate::server_push;

/// The signed `did.jsonl` a mutating verb carries. The host keeps webvh logs,
/// which are text; an object-form `didData` names no log this host can store.
fn did_log(did_data: &serde_json::Value) -> Result<String, TaskError> {
    match did_data {
        serde_json::Value::String(s) => Ok(s.clone()),
        _ => Err(AppError::Validation(
            "[log] didData must be the slot's signed did.jsonl, as a string".into(),
        )
        .into()),
    }
}

/// `agent-name/update/0.1`: `active` binds, refreshes or resumes a name;
/// `parked` stops it resolving and keeps the reservation.
pub(crate) async fn update(
    cx: &Cx<'_>,
    p: update::v0_1::Payload,
) -> Result<update::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let state = cx.state;
    let log = did_log(&serde_json::to_value(&p.did_data)?)?;
    let desired = match p.state {
        update::v0_1::PayloadState::Active => did_ops::AgentNameState::Active,
        update::v0_1::PayloadState::Parked => did_ops::AgentNameState::Parked,
        // `#[non_exhaustive]`: a state a later schema adds is not one this
        // host knows how to apply.
        _ => {
            return Err(AppError::Validation("unsupported agent-name state".into()).into());
        }
    };
    let record = did_ops::update_agent_name(
        &auth,
        state,
        &p.mnemonic,
        &p.name,
        &log,
        p.domain.as_deref(),
        desired,
    )
    .await?;
    // Every update publishes a new version, so the edges need it.
    server_push::notify_servers_did(state, p.mnemonic.to_string());
    info!(did = %auth.did, mnemonic = %p.mnemonic.as_str(), name = %p.name.as_str(), state = ?desired, "agent name updated");
    typed(
        json!({ "record": spec_record::<update::v0_1::DidRecord>(state, &record)? }),
        "agent-name update response",
    )
}

/// `agent-name/remove/0.1`: release a name.
pub(crate) async fn remove(
    cx: &Cx<'_>,
    p: remove::v0_1::Payload,
) -> Result<remove::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let state = cx.state;
    let log = did_log(&serde_json::to_value(&p.did_data)?)?;
    let record = did_ops::remove_agent_name(
        &auth,
        state,
        &p.mnemonic,
        &p.name,
        &log,
        p.domain.as_deref(),
    )
    .await?;
    server_push::notify_servers_did(state, p.mnemonic.to_string());
    info!(did = %auth.did, mnemonic = %p.mnemonic.as_str(), name = %p.name.as_str(), "agent name removed");
    typed(
        json!({ "record": spec_record::<remove::v0_1::DidRecord>(state, &record)? }),
        "agent-name remove response",
    )
}

/// `agent-name/list/0.1`: every name in the slot's registry, parked included —
/// the registry, not the DID document, is the only place a parked name shows.
pub(crate) async fn list(
    cx: &Cx<'_>,
    p: list::v0_1::Payload,
) -> Result<list::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let (domain, names) =
        did_ops::list_agent_names(&auth, cx.state, &p.mnemonic, p.domain.as_deref()).await?;
    let entries: Vec<_> = names
        .iter()
        .map(|e| {
            json!({
                "name": e.name,
                "enabled": e.enabled,
                "createdAt": at(e.created_at),
            })
        })
        .collect();
    let mut body = serde_json::Map::new();
    body.insert("mnemonic".into(), json!(p.mnemonic.as_str()));
    if !domain.is_empty() {
        body.insert("domain".into(), json!(domain));
    }
    body.insert("agentNames".into(), json!(entries));
    typed(serde_json::Value::Object(body), "agent-name list response")
}

/// `agent-name/check/0.1`: is a name free on a domain?
pub(crate) async fn check(
    cx: &Cx<'_>,
    p: check::v0_1::Payload,
) -> Result<check::v0_1::Response, TaskError> {
    let auth = cx.auth().await?;
    let state = cx.state;
    let domain =
        crate::routes::did_manage::resolve_agent_name_domain(&auth, state, p.domain.as_deref())
            .await
            .map_err(|e| {
                TaskError::Declared(
                    check::v0_1::error_codes::UNKNOWN_DOMAIN,
                    AppErrorMessage(e).to_string(),
                )
            })?;
    // The only validation this probe does is the name's grammar.
    let result = did_ops::check_agent_name(state, &domain, &p.name)
        .await
        .map_err(|e| match e {
            AppError::Validation(message) => {
                TaskError::Declared(check::v0_1::error_codes::INVALID_NAME, message)
            }
            other => other.into(),
        })?;
    typed(serde_json::to_value(result)?, "agent-name check response")
}

/// A shared-engine failure's caller-safe message.
struct AppErrorMessage(AppError);

impl std::fmt::Display for AppErrorMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.user_message())
    }
}
