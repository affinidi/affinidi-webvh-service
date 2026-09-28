//! A [`DomainEntry`] in the shared `DomainEntry` wire shape the
//! `did-management/*` specifications carry.
//!
//! The schema carries the lifecycle (`name`, `label`, `status`,
//! `defaultDomain`, `createdAt`, `disabledAt`, `purgeAt`). This host's own
//! settings for the domain — URL scheme, branding, witness and watcher lists,
//! quota, the `.well-known` switch — travel under the host's extension
//! namespace ([`WEBVH_EXT_KEY`]), where the schema allows them, rather than as
//! members it does not.
//!
//! [`to_spec`] is what the control plane sends (in `domain/*` answers and in
//! `replica/domain/upsert`); [`from_spec`] is how a replica reads the entry
//! back into its own store.

use serde_json::{Value, json};

use super::{DomainEntry, DomainStatus, DomainUrlScheme};
use crate::server::trust_tasks::ext::WEBVH_EXT_KEY;

fn at(secs: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0).unwrap_or_default()
}

fn secs(value: &Value, member: &str) -> Result<Option<u64>, String> {
    match value.get(member) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let text = v
                .as_str()
                .ok_or_else(|| format!("`{member}` is not a date-time"))?;
            let t = chrono::DateTime::parse_from_rfc3339(text)
                .map_err(|e| format!("`{member}` is not a date-time: {e}"))?;
            Ok(Some(t.timestamp().max(0) as u64))
        }
    }
}

/// One of this host's settings from the entry's extension, if present.
fn host_setting<T: serde::de::DeserializeOwned>(
    host: &Value,
    member: &str,
) -> Result<Option<T>, String> {
    match host.get(member) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => serde_json::from_value(v.clone())
            .map(Some)
            .map_err(|e| format!("`ext.{WEBVH_EXT_KEY}.{member}` is malformed: {e}")),
    }
}

/// `entry` in the shared wire shape.
pub fn to_spec(entry: &DomainEntry) -> Value {
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

/// Read an entry in the shared wire shape back into a [`DomainEntry`].
///
/// The caller has already read `value` through the task's generated type, so
/// its members are the schema's; this only maps them. Host settings absent
/// from the extension take the same defaults a new domain gets.
pub fn from_spec(value: &Value) -> Result<DomainEntry, String> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .ok_or("`name` is missing")?
        .to_string();
    let status = match value.get("status").and_then(Value::as_str) {
        Some("active") => DomainStatus::Active,
        Some("disabled") => DomainStatus::Disabled,
        other => return Err(format!("`status` {other:?} is not active or disabled")),
    };
    let created_at = secs(value, "createdAt")?.ok_or("`createdAt` is missing")?;
    let host = value
        .get("ext")
        .and_then(|e| e.get(WEBVH_EXT_KEY))
        .cloned()
        .unwrap_or(Value::Null);
    let scheme: Option<DomainUrlScheme> = host_setting(&host, "scheme")?;
    let well_known_enabled: Option<bool> = host_setting(&host, "wellKnownEnabled")?;
    Ok(DomainEntry {
        name,
        label: value.get("label").and_then(Value::as_str).map(String::from),
        scheme: scheme.unwrap_or(DomainUrlScheme::Https),
        status,
        created_at,
        default_domain: value
            .get("defaultDomain")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        branding: host_setting(&host, "branding")?,
        witnesses: host_setting(&host, "witnesses")?,
        watchers: host_setting(&host, "watchers")?,
        quota: host_setting(&host, "quota")?,
        well_known_enabled: well_known_enabled.unwrap_or(false),
        disabled_at: secs(value, "disabledAt")?,
        purge_at: secs(value, "purgeAt")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::domain::DomainBranding;

    fn entry(status: DomainStatus) -> DomainEntry {
        DomainEntry {
            name: "did.example.com".into(),
            label: Some("Example".into()),
            scheme: DomainUrlScheme::Http,
            status,
            created_at: 1_700_000_000,
            default_domain: true,
            branding: Some(DomainBranding {
                display_name: Some("Example".into()),
                logo_url: None,
                tos_url: None,
                contact_email: None,
            }),
            witnesses: Some(vec!["did:key:z6Mkw".into()]),
            watchers: None,
            quota: None,
            well_known_enabled: true,
            disabled_at: (status == DomainStatus::Disabled).then_some(1_700_000_100),
            purge_at: (status == DomainStatus::Disabled).then_some(1_700_000_200),
        }
    }

    /// What the control plane sends is what a replica stores.
    #[test]
    fn round_trips() {
        for status in [DomainStatus::Active, DomainStatus::Disabled] {
            let original = entry(status);
            assert_eq!(from_spec(&to_spec(&original)).unwrap(), original);
        }
    }

    /// The wire shape is the one `replica/domain/upsert` declares.
    #[test]
    fn fits_the_replica_upsert_schema() {
        use trust_tasks_rs::specs::did_management::replica::domain::upsert::v0_1 as upsert;
        for status in [DomainStatus::Active, DomainStatus::Disabled] {
            let payload = json!({ "entry": to_spec(&entry(status)) });
            serde_json::from_value::<upsert::Payload>(payload).expect("fits the schema");
        }
    }
}
