//! Helpers for surfacing inbound DIDComm problem-reports in the logs.
//!
//! Problem-reports arrive as ordinary DIDComm messages; without explicit
//! handling they fall into the generic "unknown message type" bucket and
//! the diagnostic information they carry (`code`, `comment`, `args`,
//! `pthid`) is silently discarded. This module gives every DID Hosting service a
//! consistent way to log them.

use affinidi_tdk::didcomm::Message;
use tracing::warn;

/// True if `msg_type` is either the standard DIDComm v2 `report-problem`
/// type (`https://didcomm.org/report-problem/2.0/problem-report`) or a
/// WebVH-specific `*/problem-report` variant.
pub fn is_problem_report(msg_type: &str) -> bool {
    msg_type.contains("/problem-report") || msg_type.contains("/report-problem/")
}

/// Log an inbound problem-report at WARN with all useful diagnostic fields.
///
/// `service` is the short name of the receiving service (e.g. `"server"`,
/// `"control"`, `"witness"`) so multi-service log streams are easy to
/// disambiguate. Returns `true` if the message was a problem-report (and
/// was logged), so callers can short-circuit their fallback handler.
pub fn log_problem_report(service: &str, sender: Option<&str>, message: &Message) -> bool {
    if !is_problem_report(&message.typ) {
        return false;
    }

    let code = message
        .body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("(none)");
    let comment = message
        .body
        .get("comment")
        .and_then(|v| v.as_str())
        .unwrap_or("(none)");
    let args = message
        .body
        .get("args")
        .map(|v| v.to_string())
        .unwrap_or_else(|| "(none)".into());
    let escalate_to = message
        .body
        .get("escalate_to")
        .and_then(|v| v.as_str())
        .unwrap_or("(none)");

    warn!(
        service,
        msg_type = %message.typ,
        sender = sender.unwrap_or("unknown"),
        msg_id = %message.id,
        thid = message.thid.as_deref().unwrap_or("(none)"),
        pthid = message.pthid.as_deref().unwrap_or("(none)"),
        code = code,
        comment = comment,
        args = %args,
        escalate_to = escalate_to,
        "DIDComm problem-report received"
    );
    true
}
