//! Unit tests for [`verify_log_extends`](super::verify_log_extends).

use super::{LogExtendError, verify_log_extends};

const V1: &str = r#"{"versionId":"1-a","parameters":{}}"#;
const V2: &str = r#"{"versionId":"2-b","parameters":{}}"#;
const V2_FORK: &str = r#"{"versionId":"2-x","parameters":{}}"#;
const V2_DEACT: &str = r#"{"versionId":"2-b","parameters":{"deactivated":true}}"#;
const V3: &str = r#"{"versionId":"3-c","parameters":{}}"#;

fn log(lines: &[&str]) -> String {
    lines.join("\n") + "\n"
}

#[test]
fn a_first_log_is_accepted() {
    verify_log_extends(None, &log(&[V1])).unwrap();
}

#[test]
fn appending_and_resending_are_accepted() {
    verify_log_extends(Some(&log(&[V1])), &log(&[V1, V2])).unwrap();
    verify_log_extends(Some(&log(&[V1, V2])), &log(&[V1, V2])).unwrap();
}

#[test]
fn a_shorter_log_is_a_rollback() {
    let err = verify_log_extends(Some(&log(&[V1, V2])), &log(&[V1])).unwrap_err();
    assert!(matches!(
        err,
        LogExtendError::HistoryRewrite {
            held: 2,
            received: 1
        }
    ));
    assert!(err.to_string().contains("rollback"), "{err}");
}

#[test]
fn a_diverging_log_is_a_fork() {
    let err = verify_log_extends(Some(&log(&[V1, V2])), &log(&[V1, V2_FORK, V3])).unwrap_err();
    assert!(matches!(err, LogExtendError::HistoryRewrite { .. }));
    assert!(err.to_string().contains("fork"), "{err}");
}

#[test]
fn a_deactivated_log_cannot_grow_or_be_replaced() {
    let held = log(&[V1, V2_DEACT]);
    verify_log_extends(Some(&held), &held).unwrap();
    let err = verify_log_extends(Some(&held), &log(&[V1, V2_DEACT, V3])).unwrap_err();
    assert_eq!(err, LogExtendError::Deactivated);
    // Replacing the deactivating entry is a fork, and refused as one.
    assert!(matches!(
        verify_log_extends(Some(&held), &log(&[V1, V2, V3])),
        Err(LogExtendError::HistoryRewrite { .. })
    ));
}
