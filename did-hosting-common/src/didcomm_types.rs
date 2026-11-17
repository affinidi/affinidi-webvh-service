//! Type URIs of the control-plane ↔ edge (and watcher) Trust Tasks.
//!
//! These name the infrastructure tasks the services of this workspace send
//! each other — registration, health, stats, DID sync and domain replication
//! — and are matched on by both ends' dispatchers, which is why they are
//! plain `&str` constants usable in a `match` pattern, available without the
//! `server-core` feature that generates the task types.
//!
//! Each one is the Type URI of the version `trust-tasks.lock` pins, `_ACK` /
//! `_PONG` being the `#response` form of its request; a test holds every
//! constant to its generated `Payload::TYPE_URI` / `Response::TYPE_URI`, so a
//! version bump cannot leave one behind. Every other task (DID management,
//! agent names, auth, ACL) is named by its generated type directly — there is
//! no constant for it here.

// ---------------------------------------------------------------------------
// Server registration (server → control plane)
// ---------------------------------------------------------------------------

/// `did-management/server/register/0.2`. Its payload is closed, so this
/// service's own registration hints (the delta-sync report, capability flags)
/// travel under `ext` in the [`REGISTER_EXT_NAMESPACE`] namespace.
pub const MSG_SERVER_REGISTER: &str =
    "https://trusttasks.org/spec/did-management/server/register/0.2";
pub const MSG_SERVER_REGISTER_ACK: &str =
    "https://trusttasks.org/spec/did-management/server/register/0.2#response";
/// The `ext` namespace (SPEC §4.5.1) a server's register payload carries this
/// service's hints under: `sync_batch` and `preloaded_dids`. A control plane that does not know a hint ignores it.
pub const REGISTER_EXT_NAMESPACE: &str = "com.affinidi.did-hosting";

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
    use crate::tasks::did_management::replica::domain::{assign, purge, unassign, upsert};
    use crate::tasks::did_management::server::{health, register, stats_sync};
    use crate::tasks::webvh::sync::{batch, delete, update};
    use trust_tasks_rs::Payload;

    /// Every constant here is the Type URI of the version `trust-tasks.lock`
    /// pins, so bumping a task with `trust-tasks add` fails this test until
    /// the constant (and every dispatcher arm keyed on it) moves with it.
    #[test]
    fn every_constant_is_its_generated_type_uri() {
        for (constant, generated) in [
            (MSG_HEALTH_PING, health::v0_1::Payload::TYPE_URI),
            (MSG_HEALTH_PONG, health::v0_1::Response::TYPE_URI),
            (MSG_STATS_SYNC, stats_sync::v0_1::Payload::TYPE_URI),
            (MSG_STATS_ACK, stats_sync::v0_1::Response::TYPE_URI),
            (MSG_SYNC_UPDATE, update::v0_2::Payload::TYPE_URI),
            (MSG_SYNC_UPDATE_ACK, update::v0_2::Response::TYPE_URI),
            (MSG_SYNC_DELETE, delete::v0_2::Payload::TYPE_URI),
            (MSG_SYNC_DELETE_ACK, delete::v0_2::Response::TYPE_URI),
            (MSG_SYNC_BATCH, batch::v0_1::Payload::TYPE_URI),
            (MSG_SYNC_BATCH_ACK, batch::v0_1::Response::TYPE_URI),
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
            (MSG_SERVER_REGISTER, register::v0_2::Payload::TYPE_URI),
            (MSG_SERVER_REGISTER_ACK, register::v0_2::Response::TYPE_URI),
        ] {
            assert_eq!(constant, generated);
        }
    }
}
