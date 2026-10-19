//! The `auth/oob/*` wire types: the generated bindings in
//! `trust_tasks_rs::specs::auth::oob::*::v0_1` (dtgwg-trust-tasks-tf #738)
//! and the `prove` / `respond` / `grant` 0.2 beside them (#820), plus the
//! request states and error codes this service keeps.
//!
//! 0.2 differs from 0.1 only by `signingScope`: step 2 may offer to let the
//! starter's key sign some task families as the member for the session, and
//! the grant copies the offer. This service delegates nothing, so its step 2
//! never carries one and a 0.2 grant that does is a context mismatch. It
//! serves 0.2 because a wallet tries `prove/0.2` first ([`OobVersion`]).
//!
//! Every payload this service reads and every response it writes goes
//! through a generated type, so a member the schema does not allow, a missing
//! one, or a value outside its pattern is refused (or, on the way out, never
//! written). Deadlines and `notAfter` are integer epoch seconds (C9).
//!
//! The wire is unchanged from the local types these replaced: the responses
//! are serialised through `serde_json::Value`, whose maps are key-sorted, so
//! member order never depended on a struct's field order, and every member
//! keeps its name and encoding. `oob::tests::wire_fixtures_round_trip` pins
//! that against fixtures captured from the old types.
//!
//! The published `Origin` admits `https://` only, so the portal is `https`
//! (see [`super::http::portal_origin`], which refuses anything else).

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use trust_tasks_rs::Payload as _;
use trust_tasks_rs::specs::auth::oob as spec;

pub use spec::cancel::v0_1::{Payload as CancelPayload, Response as CancelResponse};
pub use spec::claim::v0_1::{Payload as ClaimPayload, Response as Step1Response};
pub use spec::grant::v0_1::{Payload as GrantPayload, PayloadDecision as GrantDecision};
pub use spec::grant::v0_2::Payload as GrantPayloadV0_2;
pub use spec::identify::v0_1::Payload as IdentifyPayload;
pub use spec::prove::v0_1::{Payload as ProvePayload, Response as Step2Response};
pub use spec::prove::v0_2::{Payload as ProvePayloadV0_2, Response as Step2ResponseV0_2};
pub use spec::redeem::v0_1::{Payload as RedeemPayload, Response as RedeemResponse};
pub use spec::request::v0_1::{Payload as RequestPayload, Response as RequestResponse};
pub use spec::respond::v0_1::{Payload as RespondPayload, Response as RespondResponse};
pub use spec::respond::v0_2::{Payload as RespondPayloadV0_2, Response as RespondResponseV0_2};

pub const TYPE_REQUEST: &str = RequestPayload::TYPE_URI;
pub const TYPE_CLAIM: &str = ClaimPayload::TYPE_URI;
pub const TYPE_PROVE: &str = ProvePayload::TYPE_URI;
pub const TYPE_IDENTIFY: &str = IdentifyPayload::TYPE_URI;
pub const TYPE_RESPOND: &str = RespondPayload::TYPE_URI;
pub const TYPE_GRANT: &str = GrantPayload::TYPE_URI;
pub const TYPE_REDEEM: &str = RedeemPayload::TYPE_URI;
pub const TYPE_CANCEL: &str = CancelPayload::TYPE_URI;
pub const TYPE_PROVE_V0_2: &str = ProvePayloadV0_2::TYPE_URI;
pub const TYPE_RESPOND_V0_2: &str = RespondPayloadV0_2::TYPE_URI;
pub const TYPE_GRANT_V0_2: &str = GrantPayloadV0_2::TYPE_URI;

/// The version a `prove` or `respond` arrives at. A `respond` carries the
/// `grant` of its own version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OobVersion {
    V0_1,
    V0_2,
}

impl OobVersion {
    pub fn prove_type(self) -> &'static str {
        match self {
            OobVersion::V0_1 => TYPE_PROVE,
            OobVersion::V0_2 => TYPE_PROVE_V0_2,
        }
    }

    pub fn respond_type(self) -> &'static str {
        match self {
            OobVersion::V0_1 => TYPE_RESPOND,
            OobVersion::V0_2 => TYPE_RESPOND_V0_2,
        }
    }

    pub fn grant_type(self) -> &'static str {
        match self {
            OobVersion::V0_1 => TYPE_GRANT,
            OobVersion::V0_2 => TYPE_GRANT_V0_2,
        }
    }
}

/// Read `value` into a generated type.
pub fn read<T: DeserializeOwned>(value: &Value) -> Result<T, String> {
    serde_json::from_value(value.clone()).map_err(|e| e.to_string())
}

/// Build a generated response from `value` and write it back out: the
/// response is exactly what the generated type serialises.
pub fn write<T: DeserializeOwned + Serialize>(value: Value) -> Result<Value, String> {
    let typed: T = read(&value)?;
    serde_json::to_value(typed).map_err(|e| e.to_string())
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
    /// The wire code, read from the generated `error_codes` of a task that
    /// declares it: `auth/oob:*` for the shared family, `auth/oob/<task>:*`
    /// for one task (C9), and the framework's own `malformedRequest`.
    pub fn as_str(self) -> &'static str {
        use spec::{claim, prove, redeem, request, respond};
        match self {
            OobErrorCode::PurposeUnsupported => {
                request::v0_1::error_codes::PURPOSE_UNSUPPORTED.code
            }
            OobErrorCode::ModeUnsupported => request::v0_1::error_codes::MODE_UNSUPPORTED.code,
            OobErrorCode::KeyUnsupported => request::v0_1::error_codes::KEY_UNSUPPORTED.code,
            OobErrorCode::RateLimited => request::v0_1::error_codes::RATE_LIMITED.code,
            OobErrorCode::RequestNotFound => redeem::v0_1::error_codes::REQUEST_NOT_FOUND.code,
            OobErrorCode::RequestExpired => redeem::v0_1::error_codes::REQUEST_EXPIRED.code,
            OobErrorCode::AlreadyClaimed => claim::v0_1::error_codes::ALREADY_CLAIMED.code,
            OobErrorCode::NotClaimant => prove::v0_1::error_codes::NOT_CLAIMANT.code,
            OobErrorCode::NumberMismatch => prove::v0_1::error_codes::NUMBER_MISMATCH.code,
            OobErrorCode::NotAuthorized => prove::v0_1::error_codes::NOT_AUTHORIZED.code,
            OobErrorCode::AlreadyDecided => respond::v0_1::error_codes::ALREADY_DECIDED.code,
            OobErrorCode::ContextMismatch => respond::v0_1::error_codes::CONTEXT_MISMATCH.code,
            OobErrorCode::Pending => redeem::v0_1::error_codes::PENDING.code,
            OobErrorCode::Declined => redeem::v0_1::error_codes::DECLINED.code,
            OobErrorCode::NotStarter => redeem::v0_1::error_codes::NOT_STARTER.code,
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
