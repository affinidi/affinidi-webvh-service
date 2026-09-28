//! Shared DIDComm message type constants for the WebVH protocol.
//!
//! Used by the control plane (VTA provisioning + sync push) and server
//! (sync reception only) to ensure consistent protocol URIs.
//!
//! ## Phase 3 end-state — canonical spec URIs only
//!
//! Every `MSG_*` constant in this module now points at the canonical
//! Trust-Task spec URI under
//! `https://trusttasks.org/spec/{did-management,webvh,auth}/...`
//! per dtgwg-trust-tasks-tf. The legacy `affinidi.com/webvh/1.0/*`
//! URIs and the bidirectional `v1_aliases` translation table were
//! removed in this release — did-hosting accepts spec URIs only.
//!
//! Names retained for source-stability (the dispatcher's `match`
//! arms reference them by identifier), but the value of e.g.
//! `MSG_DID_REQUEST` is now the canonical `spec/did-management/did/
//! check-name/0.1` URI, and `MSG_DID_OFFER` is the matching
//! `…#response` form. The historical pair-URL convention (request +
//! `*-confirm` / `*-offer` / `*-ack` response) collapses to the
//! framework `<type>#response` convention (SPEC §4.4.1).
//!
//! Control plane → hosting server domain replication uses the
//! `did-management/replica/domain/*` specifications (`MSG_REPLICA_DOMAIN_*`).

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

pub const MSG_AUTHENTICATE: &str = "https://trusttasks.org/spec/auth/authenticate/0.1";
pub const MSG_AUTH_RESPONSE: &str = "https://trusttasks.org/spec/auth/authenticate/0.1#response";

// ---------------------------------------------------------------------------
// DID management (VTA provisioning protocol)
// ---------------------------------------------------------------------------

pub const MSG_DID_REQUEST: &str = "https://trusttasks.org/spec/did-management/did/check-name/0.1";
pub const MSG_DID_OFFER: &str =
    "https://trusttasks.org/spec/did-management/did/check-name/0.1#response";
/// Atomic claim-and-publish in a single call — and, since the retirement
/// of `did-management/did/publish/0.1` (spec supersededBy: `did/register`),
/// the ONLY publish surface: a register against a slot the caller already
/// owns (including a reserved-but-empty one from `MSG_DID_REQUEST` with
/// `reserve: true`) is accepted as an owner update, which is exactly the
/// operation the retired publish task carried. One-shot register also
/// avoids the window where a reserved slot is allocated but empty, so
/// existing resolvers never see a 404 between the two calls.
pub const MSG_DID_REGISTER: &str = "https://trusttasks.org/spec/did-management/did/register/0.1";
pub const MSG_DID_REGISTER_CONFIRM: &str =
    "https://trusttasks.org/spec/did-management/did/register/0.1#response";
pub const MSG_WITNESS_PUBLISH: &str = "https://trusttasks.org/spec/webvh/witness/publish/0.1";
pub const MSG_WITNESS_CONFIRM: &str =
    "https://trusttasks.org/spec/webvh/witness/publish/0.1#response";
pub const MSG_INFO_REQUEST: &str = "https://trusttasks.org/spec/did-management/did/info/0.1";
pub const MSG_INFO: &str = "https://trusttasks.org/spec/did-management/did/info/0.1#response";
pub const MSG_LIST_REQUEST: &str = "https://trusttasks.org/spec/did-management/did/list/0.1";
pub const MSG_LIST: &str = "https://trusttasks.org/spec/did-management/did/list/0.1#response";
pub const MSG_DELETE: &str = "https://trusttasks.org/spec/did-management/did/delete/0.1";
pub const MSG_DELETE_CONFIRM: &str =
    "https://trusttasks.org/spec/did-management/did/delete/0.1#response";
pub const MSG_DID_CHANGE_OWNER: &str =
    "https://trusttasks.org/spec/did-management/did/change-owner/0.1";
pub const MSG_DID_CHANGE_OWNER_CONFIRM: &str =
    "https://trusttasks.org/spec/did-management/did/change-owner/0.1#response";
pub const MSG_PROBLEM_REPORT: &str =
    "https://trusttasks.org/spec/did-management/did/problem-report/0.1";

/// Dispatcher key for the `me/domains` op — the caller-scoped view of
/// hosting domains. Net-new in DIDComm form (REST has had
/// `GET /api/me/domains` since the multi-domain release); this op
/// never had an `affinidi.com/webvh/1.0/...` legacy URI to migrate
/// from.
pub const MSG_ME_DOMAINS: &str = "https://trusttasks.org/spec/did-management/me/domains/0.1";

// ---------------------------------------------------------------------------
// Agent names (`domain/@name` bound to a hosted DID)
// ---------------------------------------------------------------------------
//
// Net-new in DIDComm form: the verbs shipped REST-only, so a VTA that
// speaks DIDComm/TSP could provision a DID but could not name it. Each verb
// dispatches to the same `did_ops::*_agent_name` function on every transport,
// so they cannot drift. The dispatcher matches on `MSG_*`, and every other
// DIDComm verb declares its request/response pair here.

/// Declarative binding-state update (`state: "active" | "parked"`), the
/// canonical replacement for the retired set / enable / disable verb trio
/// (spec supersededBy: `did-management/agent-name/update`). `active` binds
/// a free name, refreshes an existing binding, or resumes a parked one;
/// `parked` stops the name resolving while keeping its reservation.
pub const MSG_AGENT_NAME_UPDATE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/update/0.1";
pub const MSG_AGENT_NAME_UPDATE_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/update/0.1#response";
pub const MSG_AGENT_NAME_REMOVE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/remove/0.1";
pub const MSG_AGENT_NAME_REMOVE_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/remove/0.1#response";
pub const MSG_AGENT_NAME_LIST: &str =
    "https://trusttasks.org/spec/did-management/agent-name/list/0.1";
pub const MSG_AGENT_NAME_LIST_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/list/0.1#response";
pub const MSG_AGENT_NAME_CHECK: &str =
    "https://trusttasks.org/spec/did-management/agent-name/check/0.1";
pub const MSG_AGENT_NAME_CHECK_RESPONSE: &str =
    "https://trusttasks.org/spec/did-management/agent-name/check/0.1#response";

// ---------------------------------------------------------------------------
// Server registration (server → control plane)
// ---------------------------------------------------------------------------

pub const MSG_SERVER_REGISTER: &str =
    "https://trusttasks.org/spec/did-management/server/register/0.1";
pub const MSG_SERVER_REGISTER_ACK: &str =
    "https://trusttasks.org/spec/did-management/server/register/0.1#response";

// ---------------------------------------------------------------------------
// Health (control plane → server → control plane)
// ---------------------------------------------------------------------------

pub const MSG_HEALTH_PING: &str = "https://trusttasks.org/spec/did-management/server/health/0.1";
pub const MSG_HEALTH_PONG: &str =
    "https://trusttasks.org/spec/did-management/server/health/0.1#response";

// ---------------------------------------------------------------------------
// Sync (control plane ↔ server)
// ---------------------------------------------------------------------------

/// `webvh/sync/update/0.2`: camelCase exactly as schema'd, proof REQUIRED, and
/// the slot's `disabled` state travels with its content. 0.1 is not sent or
/// accepted: its implementations put snake_case members on the wire that its
/// own schema never allowed.
pub const MSG_SYNC_UPDATE: &str = "https://trusttasks.org/spec/webvh/sync/update/0.2";
pub const MSG_SYNC_UPDATE_ACK: &str = "https://trusttasks.org/spec/webvh/sync/update/0.2#response";
pub const MSG_SYNC_DELETE: &str = "https://trusttasks.org/spec/webvh/sync/delete/0.2";
pub const MSG_SYNC_DELETE_ACK: &str = "https://trusttasks.org/spec/webvh/sync/delete/0.2#response";

/// A batch of DID sync updates in a single message — `body.updates` is an array
/// of the same shape [`MSG_SYNC_UPDATE`] carries. Collapses a bulk resync into
/// far fewer transport frames, so the recipient's per-frame TSP reply doesn't
/// burst past the mediator's rate limit. Only sent to servers that advertised
/// `sync_batch` at registration; others still get one `MSG_SYNC_UPDATE` per DID.
pub const MSG_SYNC_BATCH: &str = "https://trusttasks.org/spec/webvh/sync/batch/0.1";
pub const MSG_SYNC_BATCH_ACK: &str = "https://trusttasks.org/spec/webvh/sync/batch/0.1#response";

// ---------------------------------------------------------------------------
// Stats (server → control plane)
// ---------------------------------------------------------------------------

pub const MSG_STATS_SYNC: &str = "https://trusttasks.org/spec/did-management/server/stats-sync/0.1";
pub const MSG_STATS_ACK: &str =
    "https://trusttasks.org/spec/did-management/server/stats-sync/0.1#response";

// ---------------------------------------------------------------------------
// Domain replication (control plane → hosting server)
// ---------------------------------------------------------------------------
//
// The control plane is the source of record for its hosting domains and for
// which server hosts which. It replicates both with the
// `did-management/replica/domain/*` directives, which only the server's one
// configured control plane may send. They are not the administrator-facing
// `did-management/domain/*` tasks, which an administrator sends the control
// plane; those are served by `did-hosting-control` from their generated types.
//
// Every directive is idempotent, travels through the control plane's durable
// outbox, and is settled by the server's signed `#response` (or a signed,
// non-retryable refusal).

/// `replica/domain/assign/0.1`: the server records the assignment on its own
/// clock and cancels any purge it had scheduled for the domain.
pub const MSG_REPLICA_DOMAIN_ASSIGN: &str =
    "https://trusttasks.org/spec/did-management/replica/domain/assign/0.1";
pub const MSG_REPLICA_DOMAIN_ASSIGN_ACK: &str =
    "https://trusttasks.org/spec/did-management/replica/domain/assign/0.1#response";

/// `replica/domain/unassign/0.1`: the server stops accepting content for the
/// domain and schedules its deletion after its grace period (`purgeAt`).
pub const MSG_REPLICA_DOMAIN_UNASSIGN: &str =
    "https://trusttasks.org/spec/did-management/replica/domain/unassign/0.1";
pub const MSG_REPLICA_DOMAIN_UNASSIGN_ACK: &str =
    "https://trusttasks.org/spec/did-management/replica/domain/unassign/0.1#response";

/// `replica/domain/upsert/0.1`: the server's copy of a domain record becomes
/// the carried `entry`, whole. `status: disabled` schedules the purge at
/// `entry.purgeAt`; `status: active` cancels any scheduled purge.
pub const MSG_REPLICA_DOMAIN_UPSERT: &str =
    "https://trusttasks.org/spec/did-management/replica/domain/upsert/0.1";
pub const MSG_REPLICA_DOMAIN_UPSERT_ACK: &str =
    "https://trusttasks.org/spec/did-management/replica/domain/upsert/0.1#response";

/// `replica/domain/purge/0.1`: delete the domain's content now. Refused with
/// `stalePurge` when the server holds an assignment of the domain made after
/// the directive's `issuedAt`.
pub const MSG_REPLICA_DOMAIN_PURGE: &str =
    "https://trusttasks.org/spec/did-management/replica/domain/purge/0.1";
pub const MSG_REPLICA_DOMAIN_PURGE_ACK: &str =
    "https://trusttasks.org/spec/did-management/replica/domain/purge/0.1#response";

#[cfg(all(test, feature = "server-core"))]
mod tests {
    use super::*;
    use trust_tasks_rs::Payload;
    use trust_tasks_rs::specs::did_management::replica::domain::{assign, purge, unassign, upsert};

    /// The replica constants are the generated specifications' Type URIs, so a
    /// directive the control plane sends is one the server's typed handler reads.
    #[test]
    fn replica_constants_are_the_generated_type_uris() {
        for (constant, generated) in [
            (MSG_REPLICA_DOMAIN_ASSIGN, assign::v0_1::Payload::TYPE_URI),
            (
                MSG_REPLICA_DOMAIN_ASSIGN_ACK,
                assign::v0_1::Response::TYPE_URI,
            ),
            (
                MSG_REPLICA_DOMAIN_UNASSIGN,
                unassign::v0_1::Payload::TYPE_URI,
            ),
            (
                MSG_REPLICA_DOMAIN_UNASSIGN_ACK,
                unassign::v0_1::Response::TYPE_URI,
            ),
            (MSG_REPLICA_DOMAIN_UPSERT, upsert::v0_1::Payload::TYPE_URI),
            (
                MSG_REPLICA_DOMAIN_UPSERT_ACK,
                upsert::v0_1::Response::TYPE_URI,
            ),
            (MSG_REPLICA_DOMAIN_PURGE, purge::v0_1::Payload::TYPE_URI),
            (
                MSG_REPLICA_DOMAIN_PURGE_ACK,
                purge::v0_1::Response::TYPE_URI,
            ),
        ] {
            assert_eq!(constant, generated);
        }
    }
}
