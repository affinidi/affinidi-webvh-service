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
//! `MSG_DOMAIN_UPSERT` + `MSG_DOMAIN_UPSERT_ACK` stay on the legacy
//! `affinidi.com/...` namespace because they're control-plane
//! → server internal traffic with no Trust-Task spec covering them.
//! All other constants are canonical.

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
pub const MSG_DID_PUBLISH: &str = "https://trusttasks.org/spec/did-management/did/publish/0.1";
pub const MSG_DID_CONFIRM: &str =
    "https://trusttasks.org/spec/did-management/did/publish/0.1#response";
/// Atomic claim-and-publish in a single call. Use when the caller already has
/// a complete `did.jsonl` for a known path and needs slot allocation +
/// content upload to land in one transaction (e.g. registering an existing
/// serverless DID with this server). The two-step
/// `MSG_DID_REQUEST` + `MSG_DID_PUBLISH` flow has a window where the slot
/// is allocated but empty; this flow has no such gap, so existing
/// resolvers never see a 404 between the two calls.
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

pub const MSG_SYNC_UPDATE: &str = "https://trusttasks.org/spec/webvh/sync/update/0.1";
pub const MSG_SYNC_UPDATE_ACK: &str = "https://trusttasks.org/spec/webvh/sync/update/0.1#response";
pub const MSG_SYNC_DELETE: &str = "https://trusttasks.org/spec/webvh/sync/delete/0.1";
pub const MSG_SYNC_DELETE_ACK: &str = "https://trusttasks.org/spec/webvh/sync/delete/0.1#response";

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
// Domain assignment (control plane → server, T28)
// ---------------------------------------------------------------------------
//
// The control plane is the source of truth for which domains a server
// hosts. It pushes `MSG_DOMAIN_ASSIGN` to claim a domain on a
// registered server and `MSG_DOMAIN_UNASSIGN` to release it. Both are
// idempotent — re-assigning an already-assigned domain or
// unassigning an already-unassigned one is a no-op (no audit-log
// noise). The unassign side queues a `pending_purges` entry; the
// actual content purge runs in the background sweep (T30) after the
// configured grace period.

pub const MSG_DOMAIN_ASSIGN: &str = "https://trusttasks.org/spec/did-management/domain/assign/0.1";
pub const MSG_DOMAIN_ASSIGN_ACK: &str =
    "https://trusttasks.org/spec/did-management/domain/assign/0.1#response";
pub const MSG_DOMAIN_UNASSIGN: &str =
    "https://trusttasks.org/spec/did-management/domain/unassign/0.1";
pub const MSG_DOMAIN_UNASSIGN_ACK: &str =
    "https://trusttasks.org/spec/did-management/domain/unassign/0.1#response";

/// Replicate a `DomainEntry` from the control plane to a server.
/// Covers create / update / disable / enable in one message — the
/// server reacts to the `status` + `disabled_at` / `purge_at` fields:
///
/// - `status: "active"` (timestamps unset) → ensure local entry is
///   Active, cancel any pending purge.
/// - `status: "disabled"` (timestamps set) → ensure local entry is
///   Disabled, schedule a `disable-grace` pending_purge using the
///   carried timestamps so the server's sweeper deletes the entry +
///   hosted DIDs when grace expires.
///
/// Idempotent — re-sending the same entry is a no-op on the server.
/// Servers that don't yet `assigned` the domain still apply the
/// upsert so the entry is ready when they later receive a
/// `domain/assign`.
pub const MSG_DOMAIN_UPSERT: &str = "https://affinidi.com/webvh/1.0/domain/upsert";
pub const MSG_DOMAIN_UPSERT_ACK: &str = "https://affinidi.com/webvh/1.0/domain/upsert-ack";

/// Admin "Purge now" Trust Task (T30). Bypasses the grace period
/// scheduled by an unassignment and deletes every DID on the named
/// domain immediately. The receiving server audit-logs the reason as
/// `admin-immediate` so a compliance audit can distinguish a normal
/// grace-expired purge from an admin-triggered one.
pub const MSG_DOMAIN_PURGE: &str = "https://trusttasks.org/spec/did-management/domain/purge/0.1";
pub const MSG_DOMAIN_PURGE_ACK: &str =
    "https://trusttasks.org/spec/did-management/domain/purge/0.1#response";
