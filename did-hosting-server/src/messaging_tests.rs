//! Tests for [`super`].

use super::*;
use crate::error::AppError;

/// The wait a deferred document is given: the refusal's own `retryAfter`
/// rounded up, never under a second, or the default when it names none.
/// Only a deferral has one.
#[test]
fn a_deferral_says_how_long_to_wait() {
    use trust_tasks_rs::RejectReason;
    let deferred = |retry_after| {
        Refusal::Deferred(RejectReason::Unavailable { retry_after })
            .deferred()
            .expect("a deferral")
            .retry_after_secs
    };
    let in_45 = chrono::Utc::now() + chrono::Duration::milliseconds(44_500);
    assert_eq!(deferred(Some(in_45)), 45, "rounded up");
    let past = chrono::Utc::now() - chrono::Duration::seconds(10);
    assert_eq!(deferred(Some(past)), 1, "never under a second");
    assert_eq!(deferred(None), DEFERRED_RETRY_AFTER_SECS);

    let replay_full = did_hosting_common::server::replay::ReplayError::Full.reject_reason();
    let secs = Refusal::Deferred(replay_full)
        .deferred()
        .unwrap()
        .retry_after_secs;
    let (least, most) = (
        did_hosting_common::server::replay::FULL_RETRY_AFTER_SECS,
        did_hosting_common::server::replay::FULL_RETRY_AFTER_SECS
            + did_hosting_common::server::replay::FULL_RETRY_JITTER_SECS,
    );
    assert!((least..=most).contains(&secs), "{secs}");

    assert!(
        Refusal::Unverified(RejectReason::ProofRequired)
            .deferred()
            .is_none()
    );
    assert!(
        Refusal::NotAuthorized {
            issuer: "did:example:x".into()
        }
        .deferred()
        .is_none()
    );
}

fn payload_of(err: OpError) -> Value {
    let doc: trust_tasks_rs::TrustTask<Value> = serde_json::from_value(json!({
        "id": "urn:uuid:00000000-0000-0000-0000-000000000001",
        "type": MSG_SYNC_UPDATE,
        "payload": {},
    }))
    .unwrap();
    serde_json::to_value(doc.reject_with("urn:uuid:x", err.reject_reason())).unwrap()["payload"]
        .clone()
}

/// A storage or I/O failure is this server's momentary problem: reported
/// retryable, so the control plane keeps the op queued instead of settling it.
#[test]
fn storage_failures_are_retryable() {
    for e in [
        AppError::Store("disk full".into()),
        AppError::Internal("lock poisoned".into()),
        AppError::Io(std::io::Error::other("eio")),
        AppError::store_throttled(),
    ] {
        let err = OpError::from(e);
        assert!(matches!(err, OpError::Transient(_)), "{err:?}");
        assert_eq!(payload_of(err)["retryable"], true);
    }
}

/// A refusal is final: reported non-retryable, so the control plane stops.
#[test]
fn refusals_are_final() {
    for err in [
        OpError::from(AppError::invalid("not an extension")),
        OpError::from("missing 'mnemonic'"),
    ] {
        assert!(matches!(err, OpError::Refused(_)), "{err:?}");
        assert_eq!(payload_of(err)["retryable"], false);
    }
}

/// A log over this server's store item limit is final but not invalid:
/// `taskFailed`, non-retryable, so the control plane stops re-sending it.
#[test]
fn a_store_size_refusal_is_final_and_not_an_invalid_log() {
    let err = OpError::from(AppError::quota(
        did_hosting_common::server::error::QuotaKind::Size,
        "item size 431916 bytes is over the store's per-item limit of 409600 bytes",
    ));
    assert!(matches!(err, OpError::Failed(_)), "{err:?}");
    let payload = payload_of(err);
    assert_eq!(payload["code"], "taskFailed");
    assert_eq!(payload["retryable"], false);
}

/// A sync refusal's code comes from the kind the check carried, never
/// from its wording: reworded messages keep their codes, and a message
/// that happens to mention "deactivated" is not a deactivation (#367).
#[test]
fn a_sync_refusal_is_classified_by_its_kind() {
    use crate::error::ValidationKind;
    let code_of = |e: AppError| match sync_refusal(e) {
        OpError::Declared(code, _) => code.code,
        other => panic!("expected a declared code, got {other:?}"),
    };
    assert_eq!(
        code_of(AppError::validation(ValidationKind::Deactivated, "x")),
        sync_update::error_codes::DEACTIVATED.code
    );
    assert_eq!(
        code_of(AppError::validation(ValidationKind::HistoryRewrite, "x")),
        sync_update::error_codes::HISTORY_REWRITE.code
    );
    assert_eq!(
        code_of(AppError::invalid(
            "a deactivated rollback that is not an extension of the high-water mark"
        )),
        sync_update::error_codes::INVALID_LOG.code
    );
}
