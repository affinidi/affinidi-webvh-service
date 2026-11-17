//! Tests for [`super`].

use super::*;

/// Every byte pattern of length `len`, sampled: all values in the first
/// and last positions, a spread in between.
fn samples(len: usize) -> Vec<Vec<u8>> {
    let edge: Vec<u8> = vec![
        0x00, 0x01, 0x3f, 0x40, 0x41, 0x7f, 0x80, 0xbf, 0xc0, 0xfe, 0xff,
    ];
    let mut out = Vec::new();
    for (i, a) in (0u8..=255).enumerate() {
        let mut v = vec![b'k'; len];
        v[0] = a;
        if len > 1 {
            v[len - 1] = edge[i % edge.len()];
        }
        out.push(v);
    }
    out
}

/// #342: an id-prefix query must find every key starting with the
/// prefix, whatever the prefix's length; the exact byte check after
/// decoding then drops the rest. Encoding the whole prefix found nothing
/// for most lengths (`did:` never matched `did:abc`).
#[test]
fn the_encoded_query_prefix_matches_every_key_with_the_byte_prefix() {
    let keys: Vec<Vec<u8>> = (1..=14).flat_map(samples).collect();
    for len in 1..=9 {
        for key in keys.iter().filter(|k| k.len() >= len) {
            let prefix = &key[..len];
            let query = encoded_query_prefix(prefix);
            assert!(
                BASE64.encode(key).starts_with(&query),
                "len {len}: {key:?} not found by {query:?}"
            );
        }
    }
    // The old encoding missed these.
    assert!(
        !BASE64
            .encode(b"did:abc")
            .starts_with(&BASE64.encode(b"did:"))
    );
    assert!(
        BASE64
            .encode(b"did:abc")
            .starts_with(&encoded_query_prefix(b"did:"))
    );
    assert_eq!(encoded_query_prefix(b"di"), "");
}

#[test]
fn ids_keep_keyspaces_apart() {
    // A keyspace name holding a NUL, the one way two ids could meet, is refused.
    assert!(
        CosmosDbKeyspace::valid_name("a\0b").is_err() && CosmosDbKeyspace::valid_name("").is_err()
    );
    assert_ne!(doc_id("dids", b"x"), doc_id("did", b"sx"));
    assert_eq!(
        decode("id", &doc_id("dids", b"did:x")).unwrap(),
        b"dids\0did:x"
    );
}

#[test]
fn a_batch_keeps_each_items_last_operation_and_its_bound() {
    let up = |id: &str| CosmosDbBatchOp::Upsert(value_doc(id.into(), b"v"));
    let ops = prepare_ops(vec![
        up("a"),
        CosmosDbBatchOp::Delete("b".into()),
        CosmosDbBatchOp::Delete("a".into()),
        up("b"),
    ])
    .unwrap();
    assert_eq!(ops.len(), 2);
    assert!(matches!(&ops[0], CosmosDbBatchOp::Delete(id) if id == "a"));
    assert!(matches!(&ops[1], CosmosDbBatchOp::Upsert(doc) if doc.id == "b"));

    let many: Vec<_> = (0..101).map(|i| up(&format!("k{i}"))).collect();
    check_one_batch(&many[..100]).unwrap();
    let err = check_one_batch(&many).unwrap_err();
    assert!(matches!(err, AppError::QuotaExceeded { .. }), "{err:?}");
    let lens: Vec<_> = split_batches(&many).iter().map(|p| p.len()).collect();
    assert_eq!(lens, [100, 1]);
}

#[test]
fn an_item_over_2_mb_after_encoding_is_refused() {
    let max = (MAX_DOC_BYTES - DOC_OVERHEAD) / 4 * 3;
    let id = doc_id("dids", b"k");
    check_doc_size(&value_doc(id.clone(), &vec![b'x'; max - 64])).unwrap();
    let err = check_doc_size(&value_doc(id, &vec![b'x'; max + 1])).unwrap_err();
    assert!(matches!(err, AppError::QuotaExceeded { .. }), "{err:?}");
}
