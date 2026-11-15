//! The wire shapes of the two infrastructure tasks an edge and its control
//! plane exchange on a timer: `did-management/server/stats-sync/0.1` and
//! `did-management/server/health/0.1`, as `trust-tasks.lock` pins them.
//!
//! Both ends build and read these documents here, so they cannot drift apart
//! (#449). Every body this module writes is read back through the generated
//! type before it leaves, so it leaves only in the shape its schema allows.
//!
//! ## What the specifications do not carry
//!
//! The pinned specifications are closed but for their `ext` slot (SPEC.md
//! §4.5.1). What this service needs beyond them travels there, under the
//! namespace it owns ([`WEBVH_EXT_KEY`]); a peer that does not implement
//! webvh ignores it, and this service reads it typed and closed:
//!
//! ```json
//! // stats-sync request
//! "ext": { "vnd.affinidi.webvh": {
//!   "seq": 7,
//!   "lastSeen": [{ "mnemonic": "alice", "lastResolvedAt": 1767225600 }]
//! } }
//! // stats-sync response, when nothing was counted for a stale `seq`
//! "ext": { "vnd.affinidi.webvh": { "skipped": "stale_seq" } }
//! // health response
//! "ext": { "vnd.affinidi.webvh": { "version": "0.9.0", "didCount": 12 } }
//! ```
//!
//! `seq` orders one edge process's syncs; a sync without it is not ordered
//! (its document id is still replay-checked like any other). `lastSeen`
//! dates an entry's latest events, which is where the control plane files
//! them in its time series. The stats-sync `buckets` member is refused rather
//! than ignored (R3.6): the control plane derives its buckets from `lastSeen`
//! and would otherwise drop what a peer sent there.
//!
//! ## The shape before #449 (one release)
//!
//! Before 0.12 both ends spoke a shape of their own on these Type URIs
//! ([`crate::StatsSyncRequest`], [`crate::HealthPong`]). A control plane still
//! *reads* it — [`read_stats_sync`] and [`read_health_reply`] take either
//! shape — so an edge that has not been upgraded keeps reporting. It never
//! writes it: upgrade the control plane first, then its edges. The legacy
//! read goes in 0.13.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use super::ext::WEBVH_EXT_KEY;
use crate::tasks::did_management::server::{
    health::v0_1 as health, stats_sync::v0_1 as stats_sync,
};
use crate::types::{DidStatsDelta, HealthPong as LegacyHealthPong, StatsSyncRequest};

/// The registry id of the instance `did` registers as: the `instanceId` an
/// edge names itself by in `server/register`, `server/stats-sync` and
/// `server/health`, and the control plane files it under.
pub fn instance_id_for(did: &str) -> String {
    did.replace(':', "_")
}

/// `vnd.affinidi.webvh` in a stats-sync request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatsSyncExt {
    /// Monotonic per-process sequence number; `0` after a restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// When each entry's latest events happened.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub last_seen: Vec<StatsSyncLastSeen>,
}

/// When one `perMnemonic` entry's latest resolve and update happened (epoch
/// seconds).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatsSyncLastSeen {
    pub mnemonic: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resolved_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_updated_at: Option<u64>,
}

/// `vnd.affinidi.webvh` in a stats-sync response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatsSyncAckExt {
    /// Why nothing was counted (`stale_seq`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

/// `vnd.affinidi.webvh` in a health response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HealthExt {
    /// The edge's package version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// How many DIDs the edge holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_count: Option<u64>,
}

/// `{"vnd.affinidi.webvh": ext}`, or nothing when `ext` says nothing.
fn ext_member<T: Serialize>(ext: &T) -> Option<Value> {
    let value = serde_json::to_value(ext).expect("an ext namespace serialises");
    match &value {
        Value::Object(map) if map.is_empty() => None,
        _ => Some(json!({ WEBVH_EXT_KEY: value })),
    }
}

/// Our namespace in `body`'s `ext`, typed; the default when absent. Other
/// namespaces are not ours to read and are ignored (SPEC.md §4.5.1).
fn read_ext<T: DeserializeOwned + Default>(body: &Value) -> Result<T, String> {
    match body.get("ext").and_then(|ext| ext.get(WEBVH_EXT_KEY)) {
        None => Ok(T::default()),
        Some(ns) => {
            serde_json::from_value(ns.clone()).map_err(|e| format!("`ext.{WEBVH_EXT_KEY}`: {e}"))
        }
    }
}

/// Read `body` back through the generated type `P`: what leaves is only ever
/// what the pinned schema allows.
fn conformant<P: DeserializeOwned>(body: Value, what: &str) -> Result<Value, String> {
    match serde_json::from_value::<P>(body.clone()) {
        Ok(_) => Ok(body),
        Err(e) => Err(format!("not a {what} its pinned schema allows: {e}")),
    }
}

// ---------------------------------------------------------------------------
// server/stats-sync/0.1
// ---------------------------------------------------------------------------

/// The `server/stats-sync/0.1` payload an edge sends: its `instanceId`, a
/// `perMnemonic` entry per delta, and `seq` and the latest-event times in
/// [`StatsSyncExt`].
pub fn stats_sync_body(
    instance_id: &str,
    seq: u64,
    deltas: &[DidStatsDelta],
) -> Result<Value, String> {
    let per_mnemonic: Vec<Value> = deltas
        .iter()
        .map(|d| {
            json!({
                "mnemonic": d.mnemonic,
                "resolves": d.resolve_delta,
                "updates": d.update_delta,
            })
        })
        .collect();
    let ext = StatsSyncExt {
        seq: Some(seq),
        last_seen: deltas
            .iter()
            .filter(|d| d.last_resolved_at.is_some() || d.last_updated_at.is_some())
            .map(|d| StatsSyncLastSeen {
                mnemonic: d.mnemonic.clone(),
                last_resolved_at: d.last_resolved_at,
                last_updated_at: d.last_updated_at,
            })
            .collect(),
    };
    let mut body = json!({ "instanceId": instance_id, "perMnemonic": per_mnemonic });
    if let Some(ext) = ext_member(&ext) {
        body["ext"] = ext;
    }
    conformant::<stats_sync::Payload>(body, "stats-sync payload")
}

/// A stats sync as the control plane reads it, whichever shape it came in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatsSync {
    /// Who the sender says it is: the conformant shape's `instanceId`, or the
    /// legacy shape's `server_did` ([`StatsSyncIdentity`]).
    pub identity: StatsSyncIdentity,
    /// The ordering number, when the sender gave one.
    pub seq: Option<u64>,
    /// One per `perMnemonic` entry, in order.
    pub deltas: Vec<DidStatsDelta>,
}

/// How a stats sync names its sender.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum StatsSyncIdentity {
    /// `instanceId`: must be [`instance_id_for`] the signer.
    InstanceId(String),
    /// The legacy `server_did`: must be the signer.
    ServerDid(String),
    /// A legacy body naming nobody: the signer.
    #[default]
    Signer,
}

impl StatsSyncIdentity {
    /// Whether this names `signer`; `Err` carries what it named instead.
    pub fn check(&self, signer: &str) -> Result<(), String> {
        match self {
            Self::InstanceId(id) if *id == instance_id_for(signer) => Ok(()),
            Self::ServerDid(did) if did == signer => Ok(()),
            Self::Signer => Ok(()),
            Self::InstanceId(other) | Self::ServerDid(other) => Err(other.clone()),
        }
    }
}

/// Read a `server/stats-sync/0.1` payload, in the pinned shape or (for one
/// release) the legacy one. Both are closed; `Err` says why it was refused.
pub fn read_stats_sync(body: &Value) -> Result<StatsSync, String> {
    // The legacy shape has none of the pinned members; a body with any of
    // them is held to the pinned schema.
    let pinned = ["instanceId", "perMnemonic", "buckets", "ext"]
        .iter()
        .any(|m| body.get(m).is_some());
    if !pinned {
        let legacy: StatsSyncRequest =
            serde_json::from_value(body.clone()).map_err(|e| e.to_string())?;
        return Ok(StatsSync {
            identity: legacy
                .server_did
                .map_or(StatsSyncIdentity::Signer, StatsSyncIdentity::ServerDid),
            seq: Some(legacy.seq),
            deltas: legacy
                .did_deltas
                .into_iter()
                .map(|d| DidStatsDelta {
                    mnemonic: d.mnemonic,
                    resolve_delta: d.resolve_delta,
                    update_delta: d.update_delta,
                    last_resolved_at: d.last_resolved_at,
                    last_updated_at: d.last_updated_at,
                })
                .collect(),
        });
    }

    let payload: stats_sync::Payload =
        serde_json::from_value(body.clone()).map_err(|e| e.to_string())?;
    if !payload.buckets.is_empty() {
        return Err("`buckets` is not read by this service: date entries in \
                    `ext.vnd.affinidi.webvh.lastSeen` instead"
            .into());
    }
    let ext: StatsSyncExt = read_ext(body)?;
    let mut last_seen = std::collections::HashMap::with_capacity(ext.last_seen.len());
    for seen in ext.last_seen {
        if !payload
            .per_mnemonic
            .iter()
            .any(|e| *e.mnemonic == seen.mnemonic)
        {
            return Err(format!(
                "`lastSeen` dates `{}`, which `perMnemonic` does not count",
                seen.mnemonic.chars().take(64).collect::<String>()
            ));
        }
        if last_seen.insert(seen.mnemonic.clone(), seen).is_some() {
            return Err("`lastSeen` dates one mnemonic twice".into());
        }
    }
    Ok(StatsSync {
        identity: StatsSyncIdentity::InstanceId(payload.instance_id.to_string()),
        seq: ext.seq,
        deltas: payload
            .per_mnemonic
            .into_iter()
            .map(|entry| {
                let mnemonic = entry.mnemonic.to_string();
                let seen = last_seen.get(&mnemonic);
                DidStatsDelta {
                    resolve_delta: entry.resolves,
                    update_delta: entry.updates,
                    last_resolved_at: seen.and_then(|s| s.last_resolved_at),
                    last_updated_at: seen.and_then(|s| s.last_updated_at),
                    mnemonic,
                }
            })
            .collect(),
    })
}

/// The `server/stats-sync/0.1#response` a control plane answers with:
/// `accepted` entries counted, and why nothing was when a stale `seq`
/// skipped the sync.
pub fn stats_sync_ack(
    instance_id: &str,
    accepted: u64,
    skipped: Option<&str>,
) -> Result<Value, String> {
    let mut body = json!({ "instanceId": instance_id, "accepted": accepted });
    if let Some(ext) = ext_member(&StatsSyncAckExt {
        skipped: skipped.map(str::to_string),
    }) {
        body["ext"] = ext;
    }
    conformant::<stats_sync::Response>(body, "stats-sync response")
}

// ---------------------------------------------------------------------------
// server/health/0.1
// ---------------------------------------------------------------------------

/// The `server/health/0.1` payload a control plane pings `instance_id` with.
pub fn health_ping_body(instance_id: &str) -> Result<Value, String> {
    conformant::<health::Payload>(json!({ "instanceId": instance_id }), "health ping")
}

/// Read a health ping: the `instanceId` it probes, or `None` for the legacy
/// empty ping (one release).
pub fn read_health_ping(body: &Value) -> Result<Option<String>, String> {
    if body.as_object().is_some_and(serde_json::Map::is_empty) {
        return Ok(None);
    }
    let payload: health::Payload =
        serde_json::from_value(body.clone()).map_err(|e| e.to_string())?;
    Ok(Some(payload.instance_id.to_string()))
}

/// The `server/health/0.1#response` an edge answers with: healthy as of
/// `observed_at`, with its version and DID count in [`HealthExt`].
pub fn health_pong_body(
    instance_id: &str,
    observed_at: chrono::DateTime<chrono::Utc>,
    version: &str,
    did_count: u64,
) -> Result<Value, String> {
    let mut body = json!({
        "instanceId": instance_id,
        "ok": true,
        "observedAt": chrono::SubsecRound::trunc_subsecs(observed_at, 0),
    });
    if let Some(ext) = ext_member(&HealthExt {
        version: Some(version.to_string()),
        did_count: Some(did_count),
    }) {
        body["ext"] = ext;
    }
    conformant::<health::Response>(body, "health response")
}

/// A health response as the control plane reads it, whichever shape it came
/// in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReply {
    /// The instance answering; `None` from a legacy pong, which names none.
    pub instance_id: Option<String>,
    /// Whether the edge reports itself healthy.
    pub ok: bool,
    pub version: Option<String>,
    pub did_count: Option<u64>,
}

/// Read a `server/health/0.1#response`, in the pinned shape or (for one
/// release) the legacy one. Both are closed.
pub fn read_health_reply(body: &Value) -> Result<HealthReply, String> {
    if body.get("instanceId").is_none() && body.get("status").is_some() {
        let legacy: LegacyHealthPong =
            serde_json::from_value(body.clone()).map_err(|e| e.to_string())?;
        return Ok(HealthReply {
            instance_id: None,
            ok: legacy.status == "ok",
            version: legacy.version,
            did_count: legacy.did_count,
        });
    }
    let response: health::Response =
        serde_json::from_value(body.clone()).map_err(|e| e.to_string())?;
    let ext: HealthExt = read_ext(body)?;
    Ok(HealthReply {
        instance_id: Some(response.instance_id),
        ok: response.ok,
        version: ext.version,
        did_count: ext.did_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EDGE: &str = "did:webvh:QmS:edge.example";

    fn delta(mnemonic: &str, r: u64, last: Option<u64>) -> DidStatsDelta {
        DidStatsDelta {
            mnemonic: mnemonic.into(),
            resolve_delta: r,
            update_delta: 0,
            last_resolved_at: last,
            last_updated_at: None,
        }
    }

    /// What an edge writes is the pinned shape, and reads back to what it
    /// was built from.
    #[test]
    fn a_stats_sync_round_trips_in_the_pinned_shape() {
        let deltas = vec![delta("alice", 3, Some(100)), delta("bob", 1, None)];
        let body = stats_sync_body(&instance_id_for(EDGE), 7, &deltas).unwrap();
        assert_eq!(
            body,
            json!({
                "instanceId": "did_webvh_QmS_edge.example",
                "perMnemonic": [
                    { "mnemonic": "alice", "resolves": 3, "updates": 0 },
                    { "mnemonic": "bob", "resolves": 1, "updates": 0 },
                ],
                "ext": { "vnd.affinidi.webvh": {
                    "seq": 7,
                    "lastSeen": [{ "mnemonic": "alice", "lastResolvedAt": 100 }],
                } },
            })
        );
        let read = read_stats_sync(&body).unwrap();
        assert_eq!(read.seq, Some(7));
        assert_eq!(read.deltas.len(), 2);
        assert_eq!(read.deltas[0].last_resolved_at, Some(100));
        assert_eq!(read.deltas[1].last_resolved_at, None);
        assert!(read.identity.check(EDGE).is_ok());
        assert!(read.identity.check("did:example:other").is_err());
    }

    /// A conforming peer that sends no `ext` is read, unordered.
    #[test]
    fn a_stats_sync_without_ext_is_read_unordered() {
        let body = json!({ "instanceId": "x", "perMnemonic": [] });
        let read = read_stats_sync(&body).unwrap();
        assert_eq!(read.seq, None);
        assert_eq!(read.identity, StatsSyncIdentity::InstanceId("x".into()));
    }

    /// The pinned shape is closed, `buckets` is refused rather than dropped,
    /// and `lastSeen` dates only what is counted.
    #[test]
    fn a_stats_sync_is_refused_rather_than_partly_read() {
        for body in [
            json!({ "instanceId": "x", "perMnemonic": [], "extra": 1 }),
            json!({ "instanceId": "x", "perMnemonic": [],
                    "buckets": [{ "mnemonic": "a", "epoch": 0, "r": 1, "u": 0 }] }),
            json!({ "instanceId": "x", "perMnemonic": [],
                    "ext": { "vnd.affinidi.webvh": { "lastSeen": [{ "mnemonic": "a" }] } } }),
            json!({ "instanceId": "x",
                    "perMnemonic": [{ "mnemonic": "a", "resolves": 1, "updates": 0 }],
                    "ext": { "vnd.affinidi.webvh": { "lastSeen": [
                        { "mnemonic": "a" }, { "mnemonic": "a" }] } } }),
            json!({ "instanceId": "x", "perMnemonic": [],
                    "ext": { "vnd.affinidi.webvh": { "credit": "all" } } }),
            json!({ "server_did": EDGE, "seq": 1, "did_deltas": [], "instanceId": "x" }),
        ] {
            assert!(read_stats_sync(&body).is_err(), "{body}");
        }
        // Another vendor's namespace is not ours to read.
        let other = json!({ "instanceId": "x", "perMnemonic": [],
                            "ext": { "org.example.other": { "anything": true } } });
        assert!(read_stats_sync(&other).is_ok());
    }

    /// The shape before #449 is still read, for one release.
    #[test]
    fn the_legacy_stats_sync_is_still_read() {
        let body = json!({
            "server_did": EDGE,
            "seq": 4,
            "did_deltas": [{ "mnemonic": "alice", "resolve_delta": 2, "update_delta": 1,
                             "last_resolved_at": 9 }],
        });
        let read = read_stats_sync(&body).unwrap();
        assert_eq!(read.identity, StatsSyncIdentity::ServerDid(EDGE.into()));
        assert_eq!(read.seq, Some(4));
        assert_eq!(read.deltas[0].resolve_delta, 2);
        assert_eq!(read.deltas[0].last_resolved_at, Some(9));
        assert!(read_stats_sync(&json!({ "seq": 1, "credit": 1 })).is_err());
    }

    #[test]
    fn a_stats_ack_is_the_pinned_response() {
        assert_eq!(
            stats_sync_ack("x", 3, None).unwrap(),
            json!({ "instanceId": "x", "accepted": 3 })
        );
        assert_eq!(
            stats_sync_ack("x", 0, Some("stale_seq")).unwrap(),
            json!({ "instanceId": "x", "accepted": 0,
                    "ext": { "vnd.affinidi.webvh": { "skipped": "stale_seq" } } })
        );
    }

    /// Ping and pong round-trip in the pinned shape; the legacy forms are
    /// still read.
    #[test]
    fn health_round_trips_and_reads_the_legacy_forms() {
        let id = instance_id_for(EDGE);
        assert_eq!(
            read_health_ping(&health_ping_body(&id).unwrap()).unwrap(),
            Some(id.clone())
        );
        assert_eq!(read_health_ping(&json!({})).unwrap(), None);
        assert!(read_health_ping(&json!({ "instanceId": "x", "extra": 1 })).is_err());

        let observed = chrono::DateTime::from_timestamp(1_767_225_600, 0).unwrap();
        let pong = health_pong_body(&id, observed, "1.2.3", 5).unwrap();
        assert_eq!(
            pong,
            json!({
                "instanceId": id,
                "ok": true,
                "observedAt": "2026-01-01T00:00:00Z",
                "ext": { "vnd.affinidi.webvh": { "version": "1.2.3", "didCount": 5 } },
            })
        );
        let read = read_health_reply(&pong).unwrap();
        assert_eq!(
            read,
            HealthReply {
                instance_id: Some(id),
                ok: true,
                version: Some("1.2.3".into()),
                did_count: Some(5),
            }
        );

        let legacy = read_health_reply(&json!({ "status": "ok", "version": "0.8.0" })).unwrap();
        assert!(legacy.ok);
        assert_eq!(legacy.instance_id, None);
        assert!(
            !read_health_reply(&json!({ "status": "starting" }))
                .unwrap()
                .ok
        );
        assert!(read_health_reply(&json!({ "status": "ok", "extra": 1 })).is_err());
        assert!(
            read_health_reply(&json!({ "instanceId": "x", "ok": true })).is_err(),
            "observedAt is required"
        );
    }
}
