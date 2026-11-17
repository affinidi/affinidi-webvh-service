//! The control plane's inbound Trust Task dispatch, for every transport.
//!
//! - `gate`: the transport-agnostic gate every inbound document passes
//!   (`dispatch_trust_task_doc`) — admission, the ACL pre-filter, proof
//!   verification, the replay check and routing to a `control_tasks` row, the
//!   auth family or the infrastructure family.
//! - `reply`: what a routed document produced, and sealing the reply.
//! - [`infra`]: the infrastructure family edges send (`server/register`,
//!   `server/stats-sync`, health pongs, sync and domain acks).
//! - `didcomm`: the DIDComm listener's router and envelope handler; TSP and
//!   HTTPS reach the gate from `crate::tsp` and `crate::routes::trust_tasks`.
//!
//! Outbound pushes to edges are `crate::server_push`'s.

use affinidi_messaging_didcomm::Message;
use affinidi_messaging_didcomm_service::{
    DIDCommResponse, DIDCommServiceError, Extension, HandlerContext, MESSAGE_PICKUP_STATUS_TYPE,
    MessagePolicy, MiddlewareResult, Next, Router, TRUST_PING_TYPE, handler_fn, ignore_handler,
    middleware_fn, trust_ping_handler,
};
use did_hosting_common::didcomm_types::*;
use did_hosting_common::server::problem_report::log_problem_report;
use did_hosting_common::server::trust_tasks::ProofRule;
use serde_json::{Value, json};
use tracing::{debug, error, info, warn};

use crate::server::AppState;
use crate::server_push;
use did_hosting_common::server::acl::check_acl;

mod didcomm;
mod gate;
pub mod infra;
mod reply;

pub use self::didcomm::*;
pub(crate) use self::gate::*;
pub(crate) use self::infra::{acks::*, health::*, register::*, stats_sync::*};
pub(crate) use self::reply::*;

// ---------------------------------------------------------------------------
// DID operation dispatch
// ---------------------------------------------------------------------------

/// Project a stored [`DidRecord`] into the canonical `DidRecord` wire
/// shape used by the `did-management/did/*` Trust Task family
/// (camelCase keys, RFC3339 timestamps).
///
/// `did_url` is the resolvable location of the DID log document; it is
/// stable from the initial reservation (`versionCount: 0`) and lets the
/// owner know where to publish and where resolvers will fetch. `didId`
/// is only meaningful once a log entry exists, so it is emitted solely
/// when `versionCount > 0`.
pub(crate) fn spec_did_record_json(
    record: &did_hosting_common::did_ops::DidRecord,
    did_url: &str,
) -> Value {
    let rfc3339 = |secs: u64| {
        chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
            .unwrap_or_default()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    };
    let mut rec = serde_json::Map::new();
    rec.insert("mnemonic".into(), json!(record.mnemonic));
    rec.insert("owner".into(), json!(record.owner));
    rec.insert("createdAt".into(), json!(rfc3339(record.created_at)));
    rec.insert("updatedAt".into(), json!(rfc3339(record.updated_at)));
    rec.insert("versionCount".into(), json!(record.version_count));
    rec.insert("method".into(), json!(record.method));
    rec.insert("disabled".into(), json!(record.disabled));
    rec.insert("didUrl".into(), json!(did_url));
    if !record.domain.is_empty() {
        rec.insert("domain".into(), json!(record.domain));
    }
    if let Some(did_id) = record.did_id.as_ref().filter(|_| record.version_count > 0) {
        rec.insert("didId".into(), json!(did_id));
    }
    // The agent-name registry, so the four `agent-name/*` verbs are
    // self-describing: without it a client has to follow every `set` or
    // `disable` with a `did-management/did/info` Trust Task just to learn
    // what its own call did. A *parked* name is invisible in the DID document
    // by design, so the response is the only place the caller can see it.
    //
    // Emitted only when non-empty, matching `domain`/`didId` above: a DID with
    // no names produces a byte-identical response to before, which keeps this
    // additive for the `did-management/did/*` family that shares this shape.
    //
    // The shared `DidRecord` schema is closed, so the names travel under this
    // host's extension namespace rather than as a member it does not define.
    if !record.agent_names.is_empty() {
        rec.insert(
            "ext".into(),
            json!({
                did_hosting_common::server::trust_tasks::ext::WEBVH_EXT_KEY: {
                    "agentNames": record.agent_names,
                }
            }),
        );
    }
    Value::Object(rec)
}

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod tests;
