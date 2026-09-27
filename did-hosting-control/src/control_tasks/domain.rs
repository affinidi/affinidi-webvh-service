//! `did-management/me/domains` and (next) the `domain/*` family.

use serde_json::{Value, json};
use trust_tasks_rs::specs::did_management::me::domains as me_domains_spec;

use did_hosting_common::server::domain::{DomainEntry, DomainStatus};
use did_hosting_common::server::trust_tasks::ext::WEBVH_EXT_KEY;

use super::{Cx, TaskError, at, typed};

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
