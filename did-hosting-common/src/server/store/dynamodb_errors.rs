//! What the DynamoDB backends ([`super::dynamodb`], [`super::dynamodb_single`])
//! share about DynamoDB's own limits: which failures are throttling, and the
//! item size limit.

use aws_sdk_dynamodb::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError;
use tracing::warn;

use crate::server::error::AppError;

/// DynamoDB's error codes for a request refused because the table or the
/// account is over its throughput, after the SDK's own retries.
const THROTTLING_CODES: &[&str] = &[
    "ProvisionedThroughputExceededException",
    "ThrottlingException",
    "RequestLimitExceeded",
];

/// The same, as a reason a cancelled transaction gives for one of its items.
const THROTTLED_CANCELLATION_CODES: &[&str] = &["ThrottlingError", "ProvisionedThroughputExceeded"];

/// DynamoDB's item size limit, 400 KB: attribute names and values together.
pub(super) const MAX_ITEM_BYTES: usize = 400 * 1024;

/// Whether DynamoDB refused the request for throughput. A refused request
/// wrote nothing.
pub(super) fn is_throttled<E: ProvideErrorMetadata, R>(e: &SdkError<E, R>) -> bool {
    e.code()
        .is_some_and(|code| THROTTLING_CODES.contains(&code))
}

/// Whether a `TransactWriteItems` was cancelled because one of its items was
/// throttled. Nothing in it was written.
pub(super) fn cancelled_for_throttling<R>(e: &SdkError<TransactWriteItemsError, R>) -> bool {
    matches!(
        e.as_service_error(),
        Some(TransactWriteItemsError::TransactionCanceledException(cancelled))
            if cancelled.cancellation_reasons().iter().any(|reason| {
                reason
                    .code()
                    .is_some_and(|code| THROTTLED_CANCELLATION_CODES.contains(&code))
            })
    )
}

/// A failed request as an [`AppError`]: throttling is
/// [`AppError::RateLimited`], so it reaches the client as "retry later"
/// rather than as a fault; anything else is [`AppError::Store`], named
/// `"{backend} {op}"`.
pub(super) fn request_error<E, R>(backend: &str, op: &str, e: SdkError<E, R>) -> AppError
where
    E: ProvideErrorMetadata + std::error::Error + 'static,
    R: std::fmt::Debug,
{
    if is_throttled(&e) {
        warn!(backend, op, error = %DisplayErrorContext(&e), "dynamodb throttled");
        return AppError::store_throttled();
    }
    AppError::Store(format!("{backend} {op}: {e}"))
}

/// A transaction cancelled for throttling, as [`AppError::RateLimited`].
pub(super) fn throttled_transaction<R: std::fmt::Debug>(
    backend: &str,
    e: &SdkError<TransactWriteItemsError, R>,
) -> AppError {
    warn!(backend, error = %DisplayErrorContext(e), "dynamodb transaction throttled");
    AppError::store_throttled()
}

#[cfg(test)]
mod tests {
    use aws_sdk_dynamodb::error::ErrorMetadata;
    use aws_sdk_dynamodb::operation::get_item::GetItemError;
    use aws_sdk_dynamodb::types::CancellationReason;
    use aws_sdk_dynamodb::types::error::TransactionCanceledException;

    use super::*;

    fn get_failure(code: &str) -> SdkError<GetItemError, ()> {
        SdkError::service_error(
            GetItemError::generic(ErrorMetadata::builder().code(code).build()),
            (),
        )
    }

    fn cancelled(code: &str) -> SdkError<TransactWriteItemsError, ()> {
        SdkError::service_error(
            TransactWriteItemsError::TransactionCanceledException(
                TransactionCanceledException::builder()
                    .cancellation_reasons(CancellationReason::builder().code("None").build())
                    .cancellation_reasons(CancellationReason::builder().code(code).build())
                    .build(),
            ),
            (),
        )
    }

    #[test]
    fn throttling_is_rate_limited_and_other_failures_stay_store_errors() {
        for code in THROTTLING_CODES {
            let e = request_error("dynamodb", "get", get_failure(code));
            assert!(e.is_store_throttled(), "{code}: {e:?}");
        }
        assert!(matches!(
            request_error("dynamodb", "get", get_failure("ResourceNotFoundException")),
            AppError::Store(_)
        ));
    }

    #[test]
    fn only_a_cancellation_for_throttling_counts_as_throttled() {
        for code in THROTTLED_CANCELLATION_CODES {
            assert!(cancelled_for_throttling(&cancelled(code)), "{code}");
        }
        assert!(!cancelled_for_throttling(&cancelled(
            "ConditionalCheckFailed"
        )));
    }
}
