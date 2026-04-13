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
pub const MSG_WITNESS_PUBLISH: &str = "https://affinidi.com/webvh/1.0/did/witness-publish";
pub const MSG_WITNESS_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/witness-confirm";
pub const MSG_INFO_REQUEST: &str = "https://affinidi.com/webvh/1.0/did/info-request";
pub const MSG_INFO: &str = "https://affinidi.com/webvh/1.0/did/info";
pub const MSG_LIST_REQUEST: &str = "https://affinidi.com/webvh/1.0/did/list-request";
pub const MSG_LIST: &str = "https://affinidi.com/webvh/1.0/did/list";
pub const MSG_DELETE: &str = "https://affinidi.com/webvh/1.0/did/delete";
pub const MSG_DELETE_CONFIRM: &str = "https://affinidi.com/webvh/1.0/did/delete-confirm";
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
