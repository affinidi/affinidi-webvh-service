//! Local wire types for the `auth/oob/*` Trust Task family (base design
//! section 10, plus contract C5 and C9).
//!
//! `trust-tasks-rs` 0.25 has no `auth/oob/*` bindings yet, so the shapes live
//! here, matching the schemas on `dtgwg-trust-tasks-tf` branch `feat/auth-oob`
//! (`trust_tasks_rs::specs::auth::oob::*::v0_1` once published) and contract
//! C9: deadlines and `notAfter` are integer epoch seconds only.

// TODO: replace with generated trust-tasks types
use serde::{Deserialize, Serialize};

// TODO: replace with generated trust-tasks types
pub const OOB_TYPE_PREFIX: &str = "https://trusttasks.org/spec/auth/oob/";

// TODO: replace with generated trust-tasks types
pub const TYPE_REQUEST: &str = "https://trusttasks.org/spec/auth/oob/request/0.1";
// TODO: replace with generated trust-tasks types
pub const TYPE_CLAIM: &str = "https://trusttasks.org/spec/auth/oob/claim/0.1";
// TODO: replace with generated trust-tasks types
pub const TYPE_PROVE: &str = "https://trusttasks.org/spec/auth/oob/prove/0.1";
// TODO: replace with generated trust-tasks types
pub const TYPE_IDENTIFY: &str = "https://trusttasks.org/spec/auth/oob/identify/0.1";
// TODO: replace with generated trust-tasks types
pub const TYPE_RESPOND: &str = "https://trusttasks.org/spec/auth/oob/respond/0.1";
// TODO: replace with generated trust-tasks types
pub const TYPE_GRANT: &str = "https://trusttasks.org/spec/auth/oob/grant/0.1";
// TODO: replace with generated trust-tasks types
pub const TYPE_REDEEM: &str = "https://trusttasks.org/spec/auth/oob/redeem/0.1";
// TODO: replace with generated trust-tasks types
pub const TYPE_CANCEL: &str = "https://trusttasks.org/spec/auth/oob/cancel/0.1";

/// Whether `type_uri` names a member of the `auth/oob/*` family.
pub fn is_oob_type(type_uri: &str) -> bool {
    type_uri.starts_with(OOB_TYPE_PREFIX)
}

// TODO: replace with generated trust-tasks types
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestPayload {
    pub purpose: String,
    pub mode: String,
    #[serde(default)]
    pub ext: Option<serde_json::Value>,
}

// TODO: replace with generated trust-tasks types
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RequestResponse {
    pub request_id: String,
    /// Epoch seconds (C9). The starter uses it as the link's `_exp`.
    pub claim_deadline: u64,
}

// TODO: replace with generated trust-tasks types
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestIdPayload {
    pub request_id: String,
    #[serde(default)]
    pub ext: Option<serde_json::Value>,
}

// TODO: replace with generated trust-tasks types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceRef {
    pub did: String,
    pub name: String,
}

/// Step 1: the claim response. Nothing about the starter.
// TODO: replace with generated trust-tasks types
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Step1Response {
    pub request_id: String,
    pub service: ServiceRef,
    pub origin: String,
    pub purpose: String,
    /// Epoch seconds (C9).
    pub decision_deadline: u64,
}

// TODO: replace with generated trust-tasks types
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Requester {
    pub location: String,
    pub browser: String,
    pub os: String,
    /// RFC 3339, as the reference starter writes it (C9 does not cover it).
    pub created_at: String,
    /// `true`, `false` or `"unknown"`.
    pub same_network: serde_json::Value,
}

/// Step 2: the prove response.
// TODO: replace with generated trust-tasks types
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Step2Response {
    #[serde(flatten)]
    pub step1: Step1Response,
    pub session_key: String,
    pub requester: Requester,
    pub identified_as: String,
}

/// `auth/oob/identify` payload. `additionalProperties: false`, no `ext`.
// TODO: replace with generated trust-tasks types
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentifyPayload {
    pub request_id: String,
    pub approver_key: String,
    pub entered_number: String,
}

/// `auth/oob/grant` payload. Closed: no `ext`.
// TODO: replace with generated trust-tasks types
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantPayload {
    pub request_id: String,
    pub decision: String,
    pub session_key: String,
    pub approver_key: String,
    pub origin: String,
    pub context_digest: String,
    /// Integer epoch seconds only (C9).
    pub not_after: u64,
}

/// The successful `redeem` body (C9): never tokens.
// TODO: replace with generated trust-tasks types
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RedeemResponse {
    pub subject: String,
    /// Required by the schema, 1 to 128 characters.
    pub display_name: String,
    /// Epoch seconds (C9).
    pub not_after: u64,
    pub amr: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<serde_json::Value>,
}

/// Request states (base design 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OobState {
    Pending,
    Claimed,
    Identified,
    Approved,
    Consumed,
    Declined,
    Cancelled,
    Expired,
}

impl OobState {
    pub fn as_str(self) -> &'static str {
        match self {
            OobState::Pending => "pending",
            OobState::Claimed => "claimed",
            OobState::Identified => "identified",
            OobState::Approved => "approved",
            OobState::Consumed => "consumed",
            OobState::Declined => "declined",
            OobState::Cancelled => "cancelled",
            OobState::Expired => "expired",
        }
    }

    /// `declined`, `cancelled`, `expired` and `consumed` never change again.
    pub fn is_final(self) -> bool {
        matches!(
            self,
            OobState::Consumed | OobState::Declined | OobState::Cancelled | OobState::Expired
        )
    }

    /// The states the decision window covers.
    pub fn in_decision_window(self) -> bool {
        matches!(
            self,
            OobState::Claimed | OobState::Identified | OobState::Approved
        )
    }
}

/// Machine-readable error codes used across the family (base design 10).
// TODO: replace with generated trust-tasks types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OobErrorCode {
    PurposeUnsupported,
    ModeUnsupported,
    KeyUnsupported,
    RateLimited,
    RequestNotFound,
    RequestExpired,
    AlreadyClaimed,
    NotClaimant,
    NumberMismatch,
    NotAuthorized,
    AlreadyDecided,
    ContextMismatch,
    Pending,
    Declined,
    NotStarter,
    MalformedRequest,
}

impl OobErrorCode {
    /// The wire code: `auth/oob:*` for the shared family, `auth/oob/<task>:*`
    /// for one task (C9), and the framework's own `malformedRequest`.
    pub fn as_str(self) -> &'static str {
        match self {
            OobErrorCode::PurposeUnsupported => "auth/oob/request:purposeUnsupported",
            OobErrorCode::ModeUnsupported => "auth/oob/request:modeUnsupported",
            OobErrorCode::KeyUnsupported => "auth/oob:keyUnsupported",
            OobErrorCode::RateLimited => "auth/oob:rateLimited",
            OobErrorCode::RequestNotFound => "auth/oob:requestNotFound",
            OobErrorCode::RequestExpired => "auth/oob:requestExpired",
            OobErrorCode::AlreadyClaimed => "auth/oob/claim:alreadyClaimed",
            OobErrorCode::NotClaimant => "auth/oob:notClaimant",
            OobErrorCode::NumberMismatch => "auth/oob/prove:numberMismatch",
            OobErrorCode::NotAuthorized => "auth/oob:notAuthorized",
            OobErrorCode::AlreadyDecided => "auth/oob:alreadyDecided",
            OobErrorCode::ContextMismatch => "auth/oob/respond:contextMismatch",
            OobErrorCode::Pending => "auth/oob/redeem:pending",
            OobErrorCode::Declined => "auth/oob/redeem:declined",
            OobErrorCode::NotStarter => "auth/oob:notStarter",
            OobErrorCode::MalformedRequest => "malformedRequest",
        }
    }

    /// The HTTP status, as the reference service suggests.
    pub fn http_status(self) -> u16 {
        match self {
            OobErrorCode::RateLimited => 429,
            OobErrorCode::RequestNotFound => 404,
            OobErrorCode::NotAuthorized | OobErrorCode::NotClaimant | OobErrorCode::NotStarter => {
                403
            }
            OobErrorCode::MalformedRequest
            | OobErrorCode::KeyUnsupported
            | OobErrorCode::PurposeUnsupported
            | OobErrorCode::ModeUnsupported => 400,
            _ => 409,
        }
    }
}
