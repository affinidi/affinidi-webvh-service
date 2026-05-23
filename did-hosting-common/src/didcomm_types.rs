//! Shared DIDComm message type constants for the WebVH protocol.
//!
//! Used by the control plane (VTA provisioning + sync push) and server
//! (sync reception only) to ensure consistent protocol URIs.

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

pub const MSG_AUTHENTICATE: &str = "https://affinidi.com/webvh/1.0/authenticate";
pub const MSG_AUTH_RESPONSE: &str = "https://affinidi.com/webvh/1.0/authenticate-response";

// ---------------------------------------------------------------------------
// DID management (VTA provisioning protocol)
// ---------------------------------------------------------------------------

pub const MSG_DID_REQUEST: &str = "https://affinidi.com/webvh/1.0/did/request";
pub const MSG_DID_OFFER: &str = "https://affinidi.com/webvh/1.0/did/offer";
pub const MSG_DID_PUBLISH: &str = "https://affinidi.com/webvh/1.0/did/publish";
pub const MSG_DID_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/confirm";
/// Atomic claim-and-publish in a single call. Use when the caller already has
/// a complete `did.jsonl` for a known path and needs slot allocation +
/// content upload to land in one transaction (e.g. registering an existing
/// serverless DID with this server). The two-step
/// `MSG_DID_REQUEST` + `MSG_DID_PUBLISH` flow has a window where the slot
/// is allocated but empty; this flow has no such gap, so existing
/// resolvers never see a 404 between the two calls.
pub const MSG_DID_REGISTER: &str = "https://affinidi.com/webvh/1.0/did/register";
pub const MSG_DID_REGISTER_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/register-confirm";
pub const MSG_WITNESS_PUBLISH: &str = "https://affinidi.com/webvh/1.0/did/witness-publish";
pub const MSG_WITNESS_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/witness-confirm";
pub const MSG_INFO_REQUEST: &str = "https://affinidi.com/webvh/1.0/did/info-request";
pub const MSG_INFO: &str = "https://affinidi.com/webvh/1.0/did/info";
pub const MSG_LIST_REQUEST: &str = "https://affinidi.com/webvh/1.0/did/list-request";
pub const MSG_LIST: &str = "https://affinidi.com/webvh/1.0/did/list";
pub const MSG_DELETE: &str = "https://affinidi.com/webvh/1.0/did/delete";
pub const MSG_DELETE_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/delete-confirm";
pub const MSG_DID_CHANGE_OWNER: &str = "https://affinidi.com/webvh/1.0/did/change-owner";
pub const MSG_DID_CHANGE_OWNER_CONFIRM: &str =
    "https://affinidi.com/webvh/1.0/did/change-owner-confirm";
pub const MSG_PROBLEM_REPORT: &str = "https://affinidi.com/webvh/1.0/did/problem-report";

// ---------------------------------------------------------------------------
// Server registration (server → control plane)
// ---------------------------------------------------------------------------

pub const MSG_SERVER_REGISTER: &str = "https://affinidi.com/webvh/1.0/server/register";
pub const MSG_SERVER_REGISTER_ACK: &str = "https://affinidi.com/webvh/1.0/server/register-ack";

// ---------------------------------------------------------------------------
// Health (control plane → server → control plane)
// ---------------------------------------------------------------------------

pub const MSG_HEALTH_PING: &str = "https://affinidi.com/webvh/1.0/server/health-ping";
pub const MSG_HEALTH_PONG: &str = "https://affinidi.com/webvh/1.0/server/health-pong";

// ---------------------------------------------------------------------------
// Sync (control plane ↔ server)
// ---------------------------------------------------------------------------

pub const MSG_SYNC_UPDATE: &str = "https://affinidi.com/webvh/1.0/did/sync-update";
pub const MSG_SYNC_UPDATE_ACK: &str = "https://affinidi.com/webvh/1.0/did/sync-update-ack";
pub const MSG_SYNC_DELETE: &str = "https://affinidi.com/webvh/1.0/did/sync-delete";
pub const MSG_SYNC_DELETE_ACK: &str = "https://affinidi.com/webvh/1.0/did/sync-delete-ack";

// ---------------------------------------------------------------------------
// Stats (server → control plane)
// ---------------------------------------------------------------------------

pub const MSG_STATS_SYNC: &str = "https://affinidi.com/webvh/1.0/server/stats-sync";
pub const MSG_STATS_ACK: &str = "https://affinidi.com/webvh/1.0/server/stats-ack";

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

pub const MSG_DOMAIN_ASSIGN: &str = "https://affinidi.com/webvh/1.0/domain/assign";
pub const MSG_DOMAIN_ASSIGN_ACK: &str = "https://affinidi.com/webvh/1.0/domain/assign-ack";
pub const MSG_DOMAIN_UNASSIGN: &str = "https://affinidi.com/webvh/1.0/domain/unassign";
pub const MSG_DOMAIN_UNASSIGN_ACK: &str = "https://affinidi.com/webvh/1.0/domain/unassign-ack";

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
pub const MSG_DOMAIN_PURGE: &str = "https://affinidi.com/webvh/1.0/domain/purge";
pub const MSG_DOMAIN_PURGE_ACK: &str = "https://affinidi.com/webvh/1.0/domain/purge-ack";
