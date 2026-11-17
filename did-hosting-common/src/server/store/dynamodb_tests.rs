//! Tests for [`super`].

use std::sync::Mutex;

use aws_sdk_dynamodb::config::interceptors::BeforeTransmitInterceptorContextRef;
use aws_sdk_dynamodb::config::{
    BehaviorVersion, ConfigBag, Credentials, Intercept, Region, RuntimeComponents,
};
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

#[test]
fn throttling_is_rate_limited_and_other_failures_stay_store_errors() {
    for code in THROTTLING_CODES {
        let e = request_error("get", get_failure(code));
        assert!(e.is_store_throttled(), "{code}: {e:?}");
    }
    assert!(matches!(
        request_error("get", get_failure("ResourceNotFoundException")),
        AppError::Store(_)
    ));
}

#[test]
fn a_transaction_cancelled_for_throttling_is_rate_limited() {
    let cancelled = |code: &str| {
        SdkError::<_, ()>::service_error(
            TransactWriteItemsError::TransactionCanceledException(
                TransactionCanceledException::builder()
                    .cancellation_reasons(CancellationReason::builder().code("None").build())
                    .cancellation_reasons(CancellationReason::builder().code(code).build())
                    .build(),
            ),
            (),
        )
    };
    for code in THROTTLED_CANCELLATION_CODES {
        assert!(
            transact_error(cancelled(code)).is_store_throttled(),
            "{code}"
        );
    }
    assert!(matches!(
        transact_error(cancelled("ConditionalCheckFailed")),
        AppError::Store(_)
    ));
}

/// Records each request body and stops it before it leaves the process.
#[derive(Debug, Default, Clone)]
struct CaptureBodies(Arc<Mutex<Vec<String>>>);

impl Intercept for CaptureBodies {
    fn name(&self) -> &'static str {
        "CaptureBodies"
    }

    fn read_before_transmit(
        &self,
        context: &BeforeTransmitInterceptorContextRef<'_>,
        _runtime_components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let body = context.request().body().bytes().unwrap_or_default();
        self.0
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(body).into_owned());
        Err("request captured".into())
    }
}

fn offline_backend(capture: &CaptureBodies) -> DynamoDbBackend {
    let config = aws_sdk_dynamodb::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("eu-west-1"))
        .credentials_provider(Credentials::new("test", "test", None, None, "test"))
        .endpoint_url("http://127.0.0.1:1")
        .interceptor(capture.clone())
        .build();
    let client = Client::from_conf(config);
    DynamoDbBackend {
        tables: Arc::new(Tables {
            client: client.clone(),
            billing: Billing::PayPerRequest,
            auto_create: true,
            // Marked as present so `Tables::ensure` sends nothing.
            ready: RwLock::new(HashSet::from(["webvh_dids".to_string()])),
        }),
        client,
        table_prefix: "webvh".into(),
    }
}

/// A `DescribeTable` that fails for any reason but a missing table is
/// returned as it is: no `CreateTable` is sent, and the table is not
/// marked ready.
#[tokio::test]
async fn only_a_missing_table_is_created() {
    let capture = CaptureBodies::default();
    let backend = offline_backend(&capture);
    let (_, ops) = backend.keyspace("fresh").unwrap();
    let err = ops.get_raw(b"k".to_vec()).await.unwrap_err();
    assert!(err.to_string().contains("describe table"), "{err}");
    let bodies = std::mem::take(&mut *capture.0.lock().unwrap());
    assert_eq!(
        bodies,
        [r#"{"TableName":"webvh_fresh"}"#],
        "one DescribeTable"
    );
    assert!(!backend.tables.ready.read().await.contains("webvh_fresh"));
}

/// A batch makes sure each table it writes exists before its
/// transaction, as a single-key write does.
#[tokio::test]
async fn a_batch_ensures_every_table_it_writes() {
    let capture = CaptureBodies::default();
    let backend = offline_backend(&capture);
    let mut batch = backend.batch();
    batch.insert_raw("dids", b"did:a".to_vec(), b"x".to_vec());
    batch.insert_raw("fresh", b"k".to_vec(), b"x".to_vec());
    assert!(batch.commit().await.is_err());
    let bodies = std::mem::take(&mut *capture.0.lock().unwrap());
    // `webvh_dids` is ready; `webvh_fresh` is described first, and its
    // failure stops the batch before the transaction is sent.
    assert_eq!(bodies, [r#"{"TableName":"webvh_fresh"}"#]);
}

#[test]
fn billing_mode_defaults_to_on_demand_and_parses_provisioned() {
    assert_eq!(Billing::parse(None).unwrap(), Billing::PayPerRequest);
    assert_eq!(Billing::parse(Some("")).unwrap(), Billing::PayPerRequest);
    assert_eq!(
        Billing::parse(Some("PAY_PER_REQUEST")).unwrap(),
        Billing::PayPerRequest
    );
    assert_eq!(
        Billing::parse(Some("provisioned:10:5")).unwrap(),
        Billing::Provisioned { read: 10, write: 5 }
    );
    for bad in [
        "provisioned",
        "provisioned:10",
        "provisioned:0:5",
        "provisioned:a:b",
        "provisioned:1:2:3",
        "burst",
    ] {
        let err = Billing::parse(Some(bad)).unwrap_err();
        assert!(matches!(err, AppError::Config(_)), "{bad}: {err:?}");
    }
}

#[test]
fn only_active_or_updating_tables_are_usable() {
    assert!(is_usable(Some(&TableStatus::Active)));
    assert!(is_usable(Some(&TableStatus::Updating)));
    assert!(!is_usable(Some(&TableStatus::Creating)));
    assert!(!is_usable(None));
}

async fn read_requests(ops: Arc<dyn KeyspaceOps>, capture: &CaptureBodies) -> Vec<String> {
    assert!(ops.get_raw(b"did:a".to_vec()).await.is_err());
    assert!(ops.contains_key(b"did:a".to_vec()).await.is_err());
    std::mem::take(&mut *capture.0.lock().unwrap())
}

#[tokio::test]
async fn consistent_keyspace_reads_strongly_consistent() {
    let capture = CaptureBodies::default();
    let backend = offline_backend(&capture);

    let (_, ops) = backend.keyspace_consistent("dids").unwrap();
    let bodies = read_requests(ops, &capture).await;
    assert_eq!(bodies.len(), 2, "get_raw and contains_key: {bodies:?}");
    for body in &bodies {
        assert!(body.contains(r#""ConsistentRead":true"#), "{body}");
    }

    let (_, ops) = backend.keyspace("dids").unwrap();
    let bodies = read_requests(ops, &capture).await;
    assert_eq!(bodies.len(), 2, "get_raw and contains_key: {bodies:?}");
    for body in &bodies {
        assert!(!body.contains(r#""ConsistentRead":true"#), "{body}");
    }
}

#[tokio::test]
async fn only_a_with_scans_keyspace_scans_strongly_consistent() {
    let capture = CaptureBodies::default();
    let backend = offline_backend(&capture);
    let scan = async |ops: Arc<dyn KeyspaceOps>| {
        assert!(ops.prefix_iter_raw(b"did:".to_vec()).await.is_err());
        let bodies = std::mem::take(&mut *capture.0.lock().unwrap());
        assert_eq!(bodies.len(), 1, "one scan: {bodies:?}");
        bodies[0].contains(r#""ConsistentRead":true"#)
    };

    assert!(scan(backend.keyspace_consistent_with_scans("dids").unwrap().1).await);
    assert!(!scan(backend.keyspace_consistent("dids").unwrap().1).await);
    assert!(!scan(backend.keyspace("dids").unwrap().1).await);
}

/// A page is one `Scan` request of `limit` items, resumed from the
/// cursor as its `ExclusiveStartKey`, never a whole-table read.
#[tokio::test]
async fn a_prefix_page_is_one_scan_request_from_the_cursor() {
    let capture = CaptureBodies::default();
    let backend = offline_backend(&capture);
    let (_, ops) = backend.keyspace("dids").unwrap();

    assert!(
        ops.prefix_page_raw(b"ts:".to_vec(), None, 50)
            .await
            .is_err()
    );
    assert!(
        ops.prefix_page_raw(b"ts:".to_vec(), Some(b"ts:a:300".to_vec()), 50)
            .await
            .is_err()
    );
    let bodies = std::mem::take(&mut *capture.0.lock().unwrap());
    assert_eq!(bodies.len(), 2, "one scan a page: {bodies:?}");
    for body in &bodies {
        assert!(body.contains(r#""Limit":50"#), "{body}");
    }
    assert!(!bodies[0].contains("ExclusiveStartKey"), "{}", bodies[0]);
    // base64("ts:a:300")
    assert!(
        bodies[1].contains(r#""ExclusiveStartKey":{"pk":{"B":"dHM6YTozMDA="}}"#),
        "{}",
        bodies[1]
    );
}

fn batch_of(backend: &DynamoDbBackend, ops: &[(&[u8], Option<usize>)]) -> Box<dyn BatchOps> {
    let mut batch = backend.batch();
    for (key, value_len) in ops {
        match value_len {
            Some(len) => batch.insert_raw("dids", key.to_vec(), vec![b'x'; *len]),
            None => batch.remove("dids", key.to_vec()),
        }
    }
    batch
}

fn keys(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("did:{i}").into_bytes()).collect()
}

/// A batch is one transaction: up to 100 writes is sent as one request,
/// more is refused as a size quota with nothing sent, rather than split
/// into transactions that could land part-way.
#[tokio::test]
async fn an_atomic_batch_over_100_writes_is_refused_before_sending() {
    let capture = CaptureBodies::default();
    let backend = offline_backend(&capture);

    let keys = keys(101);
    let ops: Vec<_> = keys.iter().map(|k| (k.as_slice(), Some(10))).collect();

    // At the bound: sent (the offline client then fails the send).
    assert!(batch_of(&backend, &ops[..100]).commit().await.is_err());
    let bodies = std::mem::take(&mut *capture.0.lock().unwrap());
    assert_eq!(bodies.len(), 1, "{bodies:?}");
    assert_eq!(bodies[0].matches(r#"{"Put":"#).count(), 100);

    let err = batch_of(&backend, &ops).commit().await.unwrap_err();
    assert!(matches!(err, AppError::QuotaExceeded { .. }), "{err:?}");
    assert_eq!(err.quota_kind(), crate::server::error::QuotaKind::Size);
    assert!(capture.0.lock().unwrap().is_empty(), "nothing is sent");
}

/// Eleven items that each fit are over 4 MB together: refused, nothing sent.
#[tokio::test]
async fn an_atomic_batch_over_4_mb_is_refused_before_sending() {
    let capture = CaptureBodies::default();
    let backend = offline_backend(&capture);

    let keys = keys(11);
    let ops: Vec<_> = keys
        .iter()
        .map(|k| (k.as_slice(), Some(390 * 1024)))
        .collect();
    let err = batch_of(&backend, &ops).commit().await.unwrap_err();
    assert!(matches!(err, AppError::QuotaExceeded { .. }), "{err:?}");
    assert!(capture.0.lock().unwrap().is_empty(), "nothing is sent");
}

/// DynamoDB refuses a transaction naming an item twice, so a batch keeps
/// only each item's last operation: the one that decides its final state.
#[tokio::test]
async fn a_batch_writing_one_item_twice_sends_its_last_operation() {
    let capture = CaptureBodies::default();
    let backend = offline_backend(&capture);

    let ops: &[(&[u8], Option<usize>)] = &[
        (b"did:a", Some(1)),
        (b"did:b", None),
        (b"did:a", None),
        (b"did:b", Some(2)),
        (b"did:c", None),
    ];
    assert!(batch_of(&backend, ops).commit().await.is_err());
    let bodies = std::mem::take(&mut *capture.0.lock().unwrap());
    assert_eq!(bodies.len(), 1, "{bodies:?}");
    // did:a deleted, did:b put, did:c deleted.
    assert_eq!(bodies[0].matches(r#"{"Put":"#).count(), 1, "{}", bodies[0]);
    assert_eq!(
        bodies[0].matches(r#"{"Delete":"#).count(),
        2,
        "{}",
        bodies[0]
    );
}

/// `commit_in_parts` splits on both bounds, keeping every operation once
/// and in order.
#[test]
fn parts_stay_within_100_writes_and_4_mb() {
    let op = |key: Vec<u8>, len| DynamoDbBatchOp::Insert {
        table: "webvh_dids".into(),
        key,
        value: vec![b'x'; len],
    };

    let small: Vec<_> = keys(250).into_iter().map(|k| op(k, 10)).collect();
    let parts = split_transactions(&small);
    let lens: Vec<_> = parts.iter().map(|p| p.len()).collect();
    assert_eq!(lens, [100, 100, 50]);

    let large: Vec<_> = keys(30).into_iter().map(|k| op(k, 300 * 1024)).collect();
    let parts = split_transactions(&large);
    assert!(parts.len() > 1);
    for part in &parts {
        let bytes: usize = part.iter().map(DynamoDbBatchOp::size).sum();
        assert!(bytes <= MAX_TRANSACT_BYTES, "{bytes}");
        assert!(part.len() <= MAX_TRANSACT_ACTIONS);
    }
    let rejoined: Vec<_> = parts.iter().flat_map(|p| p.iter()).collect();
    assert_eq!(rejoined.len(), large.len());
    assert!(
        rejoined
            .iter()
            .zip(&large)
            .all(|(a, b)| a.target() == b.target())
    );
}

fn bin_item(pk: &[u8], val: &[u8]) -> HashMap<String, AttributeValue> {
    HashMap::from([
        (
            PK_ATTR.to_string(),
            AttributeValue::B(Blob::new(pk.to_vec())),
        ),
        (
            VAL_ATTR.to_string(),
            AttributeValue::B(Blob::new(val.to_vec())),
        ),
    ])
}

/// An item at DynamoDB's 400 KB limit is written; one byte over is
/// refused as a size quota, before anything is sent.
#[test]
fn item_over_400_kb_is_refused_as_a_size_quota() {
    let key = b"content:alice:log";
    let overhead = PK_ATTR.len() + key.len() + VAL_ATTR.len();
    let fits = vec![b'x'; MAX_ITEM_BYTES - overhead];
    check_item_size(key, &fits).unwrap();

    let over = vec![b'x'; MAX_ITEM_BYTES - overhead + 1];
    let err = check_item_size(key, &over).unwrap_err();
    let AppError::QuotaExceeded { message, .. } = &err else {
        panic!("expected a size quota, got {err:?}");
    };
    assert!(
        message.contains("per-item limit of 409600 bytes"),
        "{message}"
    );
    assert!(
        !message.contains("DynamoDB"),
        "the backend is not told to the caller"
    );
}

#[test]
fn keeps_only_matching_prefix() {
    let items = vec![
        bin_item(b"did:alice", b"a"),
        bin_item(b"did:bob", b"b"),
        bin_item(b"owner:alice", b"o"),
    ];
    let mut out = Vec::new();
    filter_items_by_prefix(items, b"did:", &mut out);
    assert_eq!(out.len(), 2);
    assert!(out.iter().any(|(k, _)| k == b"did:alice"));
    assert!(out.iter().any(|(k, _)| k == b"did:bob"));
    assert!(out.iter().all(|(k, _)| k.starts_with(b"did:")));
}

#[test]
fn matches_non_utf8_binary_prefix() {
    // Regression for the original bug: prefix matching is byte-oriented,
    // not UTF-8. A prefix that isn't valid UTF-8 must still match — this
    // is the case a DynamoDB `begins_with` filter on a Binary key got
    // wrong under motoserver.
    let items = vec![
        bin_item(&[0xff, 0x00, 0x01], b"v1"),
        bin_item(&[0xff, 0x00, 0x02], b"v2"),
        bin_item(&[0x00, 0xff, 0x01], b"nope"),
    ];
    let mut out = Vec::new();
    filter_items_by_prefix(items, &[0xff, 0x00], &mut out);
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|(k, _)| k.starts_with(&[0xff, 0x00])));
}

#[test]
fn empty_prefix_matches_everything() {
    let items = vec![bin_item(b"a", b"1"), bin_item(b"\x00\x01", b"2")];
    let mut out = Vec::new();
    filter_items_by_prefix(items, b"", &mut out);
    assert_eq!(out.len(), 2);
}

#[test]
fn skips_items_missing_binary_attrs() {
    // Missing val, and a String-typed pk — neither should be returned.
    let missing_val = HashMap::from([(
        PK_ATTR.to_string(),
        AttributeValue::B(Blob::new(b"did:x".to_vec())),
    )]);
    let string_pk = HashMap::from([
        (PK_ATTR.to_string(), AttributeValue::S("did:y".to_string())),
        (
            VAL_ATTR.to_string(),
            AttributeValue::B(Blob::new(b"v".to_vec())),
        ),
    ]);
    let items = vec![missing_val, string_pk, bin_item(b"did:z", b"v")];
    let mut out = Vec::new();
    filter_items_by_prefix(items, b"did:", &mut out);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, b"did:z");
}
