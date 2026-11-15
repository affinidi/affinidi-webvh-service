//! The `KeyspaceOps` / `BatchOps` contract, as one suite every backend runs.
//!
//! [`run`] takes an open [`Store`] and a namespace, and checks the semantics
//! callers rely on: round trips, byte-exact prefix scans (odd-length and
//! glob-looking prefixes included), paging, the keys-only listing and count,
//! all-or-nothing batches across keyspaces, the atomic `take`, `incr` and
//! compare-and-swap under contention, and the per-item limit.
//!
//! Every keyspace the suite opens is named `{namespace}_{name}`, so runs
//! sharing one Redis database or one emulator do not see each other's rows.
//! [`namespace`] makes a fresh one.
//!
//! fjall runs it in its unit tests; `tests/store_conformance.rs` runs it
//! against whichever backend the build enables, pointed at a real server or
//! emulator by environment variables (CI: Redis and DynamoDB Local on every
//! PR, the Firestore and Cosmos DB emulators on a schedule).

use std::collections::{BTreeMap, BTreeSet};

use super::{KeyspaceHandle, PrefixPage, Store};
use crate::server::error::AppError;

/// A namespace no other run uses: a letter, then 12 hex digits, so it is a
/// valid keyspace (table, container, collection) name prefix everywhere.
pub fn namespace() -> String {
    let id = uuid::Uuid::new_v4().simple().to_string();
    format!("c{}", &id[..12])
}

/// Run every check against `store`, opening keyspaces under `ns`. Panics
/// with the first contract violation.
pub async fn run(store: &Store, ns: &str) {
    round_trip(store, ns).await;
    keyspaces_are_isolated(store, ns).await;
    prefix_scans_are_byte_exact(store, ns).await;
    prefix_pages_walk_every_row_once(store, ns).await;
    a_page_walk_survives_deleting_behind_it(store, ns).await;
    batches_apply_across_keyspaces(store, ns).await;
    a_batch_keeps_each_keys_last_operation(store, ns).await;
    a_batch_of_100_writes_commits(store, ns).await;
    an_oversized_item_is_refused_and_its_batch_writes_nothing(store, ns).await;
    take_has_exactly_one_winner(store, ns).await;
    incr_never_loses_an_increment(store, ns).await;
    compare_and_swap_has_one_winner(store, ns).await;
}

fn ks(store: &Store, ns: &str, name: &str) -> KeyspaceHandle {
    store
        .keyspace(&format!("{ns}_{name}"))
        .expect("open keyspace")
}

fn show(key: &[u8]) -> String {
    String::from_utf8_lossy(key).into_owned()
}

/// Insert, overwrite, read, check and remove single keys, binary ones too.
pub async fn round_trip(store: &Store, ns: &str) {
    let ks = ks(store, ns, "roundtrip");
    assert_eq!(ks.get_raw("missing").await.unwrap(), None);
    assert!(!ks.contains_key("missing").await.unwrap());
    ks.remove("missing").await.expect("removing an absent key");

    ks.insert("json", &"hello").await.unwrap();
    assert_eq!(
        ks.get::<String>("json").await.unwrap().as_deref(),
        Some("hello")
    );
    ks.insert_raw("k", b"one".to_vec()).await.unwrap();
    ks.insert_raw("k", b"two".to_vec()).await.unwrap();
    assert_eq!(ks.get_raw("k").await.unwrap(), Some(b"two".to_vec()));
    assert!(ks.contains_key("k").await.unwrap());

    let binary_key = vec![0x00, 0xff, b'*', b'?', 0x80, b':'];
    let binary_value = (0u8..=255).collect::<Vec<_>>();
    ks.insert_raw(binary_key.clone(), binary_value.clone())
        .await
        .unwrap();
    assert_eq!(
        ks.get_raw(binary_key.clone()).await.unwrap(),
        Some(binary_value)
    );

    ks.remove("k").await.unwrap();
    assert_eq!(ks.get_raw("k").await.unwrap(), None);
    assert!(!ks.contains_key("k").await.unwrap());
    let left: BTreeSet<_> = ks.prefix_keys_raw("").await.unwrap().into_iter().collect();
    assert_eq!(
        left,
        BTreeSet::from([b"json".to_vec(), binary_key]),
        "only the live keys are listed"
    );
}

/// The same key in two keyspaces is two rows, and no scan crosses over.
pub async fn keyspaces_are_isolated(store: &Store, ns: &str) {
    let a = ks(store, ns, "iso_a");
    let b = ks(store, ns, "iso_b");
    // A keyspace whose name extends another's must not leak into it either.
    let ab = ks(store, ns, "iso_a_b");
    a.insert_raw("k", b"a".to_vec()).await.unwrap();
    b.insert_raw("k", b"b".to_vec()).await.unwrap();
    ab.insert_raw("k", b"ab".to_vec()).await.unwrap();
    assert_eq!(a.get_raw("k").await.unwrap(), Some(b"a".to_vec()));
    assert_eq!(b.get_raw("k").await.unwrap(), Some(b"b".to_vec()));
    assert_eq!(a.prefix_iter_raw("").await.unwrap().len(), 1);
    assert_eq!(a.prefix_count("").await.unwrap(), 1);
    a.remove("k").await.unwrap();
    assert_eq!(b.get_raw("k").await.unwrap(), Some(b"b".to_vec()));
    assert_eq!(ab.get_raw("k").await.unwrap(), Some(b"ab".to_vec()));
}

/// Keys chosen so an encoding-level prefix match (base64 of the prefix, a
/// glob pattern) would disagree with a byte-level one.
fn scan_keys() -> Vec<Vec<u8>> {
    let mut keys: Vec<Vec<u8>> = [
        "did:abc",
        "did:Abc",
        "did:0",
        "did:",
        "did;x",
        "di",
        "session:1",
        "session:abc",
        "session:Z",
        "sessions",
        "ts:a:1",
        "ts:a:2",
        "ts:b:1",
        "owner:x:y",
        "acl:did:key:z6Mk",
        "a*b",
        "a?b",
        "a[b]",
        "a\\b",
        "axb",
        "name:example.com:alice",
        "name:[::1]:bob",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect();
    keys.push(vec![0xff, 0x00, 0x01]);
    keys.push(vec![0xff, 0x00, 0x02]);
    keys.push(vec![0xff, 0xff]);
    keys.push(vec![0x00, 0xff, 0x01]);
    keys
}

/// Every prefix of every key, lengths 1 to 9 and the empty prefix: the scan,
/// the keys-only listing and the count each give exactly the keys that start
/// with it, once each.
pub async fn prefix_scans_are_byte_exact(store: &Store, ns: &str) {
    let ks = ks(store, ns, "scan");
    let keys = scan_keys();
    for key in &keys {
        let mut value = b"v:".to_vec();
        value.extend_from_slice(key);
        ks.insert_raw(key.clone(), value).await.unwrap();
    }
    let mut prefixes = BTreeSet::from([Vec::new(), b"a*".to_vec(), b"name:[".to_vec()]);
    for key in &keys {
        for len in 1..=key.len().min(9) {
            prefixes.insert(key[..len].to_vec());
        }
    }
    for prefix in prefixes {
        let expected: BTreeSet<Vec<u8>> = keys
            .iter()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();

        let rows = ks.prefix_iter_raw(prefix.clone()).await.unwrap();
        assert_eq!(
            rows.len(),
            expected.len(),
            "prefix {:?}: duplicate or missing rows: {:?}",
            show(&prefix),
            rows.iter().map(|(k, _)| show(k)).collect::<Vec<_>>()
        );
        for (k, v) in &rows {
            assert!(
                expected.contains(k),
                "prefix {:?}: {:?}",
                show(&prefix),
                show(k)
            );
            assert_eq!(&v[2..], k.as_slice(), "the value belongs to the key");
        }

        let listed = ks.prefix_keys_raw(prefix.clone()).await.unwrap();
        assert_eq!(listed.len(), expected.len(), "prefix {:?}", show(&prefix));
        assert_eq!(
            listed.into_iter().collect::<BTreeSet<_>>(),
            expected,
            "prefix {:?}",
            show(&prefix)
        );
        assert_eq!(
            ks.prefix_count(prefix.clone()).await.unwrap(),
            expected.len(),
            "prefix {:?}",
            show(&prefix)
        );
    }
}

/// Walk `prefix` page by page, checking each page's invariants. Returns the
/// rows in the order they came.
async fn walk(ks: &KeyspaceHandle, prefix: &[u8], limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut rows = Vec::new();
    let mut cursor = None;
    for _ in 0..10_000 {
        let page: PrefixPage = ks
            .prefix_page_raw(prefix.to_vec(), cursor.clone(), limit)
            .await
            .unwrap()
            .expect("every backend pages");
        assert!(
            page.rows.len() <= limit.max(1),
            "a page holds at most `limit` rows"
        );
        for (k, _) in &page.rows {
            assert!(k.starts_with(prefix), "{:?} outside the prefix", show(k));
        }
        if page.ordered {
            let mut sorted = page.rows.clone();
            sorted.sort();
            assert_eq!(page.rows, sorted, "an ordered page comes in key order");
            if let (Some(last), Some((first, _))) = (rows.last(), page.rows.first()) {
                let (last, _): &(Vec<u8>, Vec<u8>) = last;
                assert!(first > last, "ordered pages follow one another");
            }
        }
        rows.extend(page.rows);
        match page.next {
            Some(next) => cursor = Some(next),
            None => return rows,
        }
    }
    panic!("the walk of {:?} never ended", show(prefix));
}

/// A walk at any page size visits every row of the prefix exactly once and
/// nothing outside it.
pub async fn prefix_pages_walk_every_row_once(store: &Store, ns: &str) {
    let ks = ks(store, ns, "pages");
    let mut expected = BTreeMap::new();
    for i in 0..23 {
        let key = format!("p:{i:02}").into_bytes();
        ks.insert_raw(key.clone(), vec![i]).await.unwrap();
        expected.insert(key, vec![i]);
    }
    for key in ["o:1", "q:1", "p", "P:1"] {
        ks.insert_raw(key, b"x".to_vec()).await.unwrap();
    }
    for limit in [1, 2, 3, 7, 23, 100] {
        let rows = walk(&ks, b"p:", limit).await;
        let mut seen = BTreeMap::new();
        for (k, v) in rows {
            assert!(
                seen.insert(k.clone(), v).is_none(),
                "limit {limit}: {:?} twice",
                show(&k)
            );
        }
        assert_eq!(seen, expected, "limit {limit}");
    }
    assert!(walk(&ks, b"none:", 5).await.is_empty());
}

/// Deleting each page's rows before asking for the next does not lose or
/// stall the walk (the purge and cleanup sweeps page this way).
pub async fn a_page_walk_survives_deleting_behind_it(store: &Store, ns: &str) {
    let ks = ks(store, ns, "pagedel");
    for i in 0..17 {
        ks.insert_raw(format!("d:{i:02}"), b"x".to_vec())
            .await
            .unwrap();
    }
    ks.insert_raw("e:keep", b"x".to_vec()).await.unwrap();
    let mut removed = 0;
    let mut cursor = None;
    for _ in 0..1000 {
        let page = ks
            .prefix_page_raw(b"d:".to_vec(), cursor.clone(), 4)
            .await
            .unwrap()
            .expect("every backend pages");
        for (k, _) in &page.rows {
            ks.remove(k.clone()).await.unwrap();
            removed += 1;
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(removed, 17);
    assert_eq!(ks.prefix_count("d:").await.unwrap(), 0);
    assert_eq!(ks.prefix_count("").await.unwrap(), 1);
}

/// One batch writes and removes in two keyspaces; all of it lands. Removing
/// a key that is not there is not an error inside a batch, and an empty
/// batch commits.
pub async fn batches_apply_across_keyspaces(store: &Store, ns: &str) {
    let a = ks(store, ns, "batch_a");
    let b = ks(store, ns, "batch_b");
    a.insert_raw("gone", b"x".to_vec()).await.unwrap();
    store.batch().commit().await.expect("an empty batch");

    let mut batch = store.batch();
    batch.insert_raw(&a, "a1", b"1".to_vec());
    batch.insert(&b, "b1", &"two").unwrap();
    batch.remove(&a, "gone");
    batch.remove(&b, "never-there");
    batch.commit().await.unwrap();

    assert_eq!(a.get_raw("a1").await.unwrap(), Some(b"1".to_vec()));
    assert_eq!(b.get::<String>("b1").await.unwrap().as_deref(), Some("two"));
    assert_eq!(a.get_raw("gone").await.unwrap(), None);
    assert_eq!(b.prefix_keys_raw("").await.unwrap(), vec![b"b1".to_vec()]);

    // Through a keyspace handle's own batch, too.
    let mut batch = b.batch();
    batch.remove(&b, "b1");
    batch.insert_raw(&a, "a2", b"2".to_vec());
    batch.commit().await.unwrap();
    assert_eq!(b.prefix_count("").await.unwrap(), 0);
    assert_eq!(a.prefix_count("a").await.unwrap(), 2);
}

/// Applied in order, a batch leaves each key as its last operation says.
pub async fn a_batch_keeps_each_keys_last_operation(store: &Store, ns: &str) {
    let ks = ks(store, ns, "batch_order");
    ks.insert_raw("was", b"old".to_vec()).await.unwrap();
    let mut batch = store.batch();
    batch.insert_raw(&ks, "x", b"1".to_vec());
    batch.remove(&ks, "x");
    batch.remove(&ks, "y");
    batch.insert_raw(&ks, "y", b"2".to_vec());
    batch.insert_raw(&ks, "z", b"3".to_vec());
    batch.insert_raw(&ks, "z", b"4".to_vec());
    batch.remove(&ks, "was");
    batch.insert_raw(&ks, "was", b"new".to_vec());
    batch.commit().await.unwrap();
    assert_eq!(ks.get_raw("x").await.unwrap(), None);
    assert_eq!(ks.get_raw("y").await.unwrap(), Some(b"2".to_vec()));
    assert_eq!(ks.get_raw("z").await.unwrap(), Some(b"4".to_vec()));
    assert_eq!(ks.get_raw("was").await.unwrap(), Some(b"new".to_vec()));
}

/// 100 writes is within every backend's bound for one atomic batch.
pub async fn a_batch_of_100_writes_commits(store: &Store, ns: &str) {
    let ks = ks(store, ns, "batch_100");
    let mut batch = store.batch();
    for i in 0..100 {
        batch.insert_raw(&ks, format!("k:{i:03}"), vec![b'x'; 64]);
    }
    batch.commit().await.unwrap();
    assert_eq!(ks.prefix_count("k:").await.unwrap(), 100);
}

/// A write over [`Store::max_item_bytes`] is refused as a quota, alone or in
/// a batch, and the batch it was in writes nothing. One well under the limit
/// is stored.
pub async fn an_oversized_item_is_refused_and_its_batch_writes_nothing(store: &Store, ns: &str) {
    let Some(max) = store.max_item_bytes() else {
        return;
    };
    let ks = ks(store, ns, "big");
    let fits = vec![b'f'; max / 2];
    ks.insert_raw("fits", fits.clone()).await.unwrap();
    assert_eq!(ks.get_raw("fits").await.unwrap(), Some(fits));

    let over = vec![b'o'; max + 1];
    let err = ks.insert_raw("over", over.clone()).await.unwrap_err();
    assert!(matches!(err, AppError::QuotaExceeded { .. }), "{err:?}");
    assert_eq!(ks.get_raw("over").await.unwrap(), None);

    let mut batch = store.batch();
    batch.insert_raw(&ks, "first", b"1".to_vec());
    batch.insert_raw(&ks, "over", over);
    batch.remove(&ks, "fits");
    let err = batch.commit().await.unwrap_err();
    assert!(matches!(err, AppError::QuotaExceeded { .. }), "{err:?}");
    assert_eq!(ks.get_raw("first").await.unwrap(), None);
    assert!(ks.contains_key("fits").await.unwrap());
}

/// Of many callers taking one key, through separately opened handles,
/// exactly one gets the value.
pub async fn take_has_exactly_one_winner(store: &Store, ns: &str) {
    let name = format!("{ns}_take");
    let ks = store.keyspace(&name).unwrap();
    assert_eq!(ks.take_raw("absent").await.unwrap(), None);
    for round in 0..3 {
        let key = format!("refresh:{round}");
        ks.insert_raw(key.clone(), b"session".to_vec())
            .await
            .unwrap();
        let mut racers = Vec::new();
        for _ in 0..8 {
            let (store, name, key) = (store.clone(), name.clone(), key.clone());
            racers.push(tokio::spawn(async move {
                let ks = store.keyspace(&name).unwrap();
                ks.take_raw(key).await.unwrap()
            }));
        }
        let mut winners = 0;
        for racer in racers {
            if let Some(value) = racer.await.unwrap() {
                assert_eq!(value, b"session");
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "round {round}: exactly one take wins");
        assert!(!ks.contains_key(key.clone()).await.unwrap());
        assert_eq!(ks.prefix_count(key).await.unwrap(), 0);
    }
}

/// Counters start at 1, and concurrent increments through separate handles
/// each see a distinct value.
pub async fn incr_never_loses_an_increment(store: &Store, ns: &str) {
    let name = format!("{ns}_incr");
    let ks = store.keyspace(&name).unwrap();
    assert_eq!(ks.incr_raw("seq").await.unwrap(), 1);
    assert_eq!(ks.incr_raw("seq").await.unwrap(), 2);
    assert_eq!(ks.incr_raw("other").await.unwrap(), 1);

    // Few enough that an optimistic backend (Cosmos DB retries a lost
    // conditional write 16 times) cannot lose every round.
    const N: u64 = 10;
    let mut racers = Vec::new();
    for _ in 0..N {
        let (store, name) = (store.clone(), name.clone());
        racers.push(tokio::spawn(async move {
            let ks = store.keyspace(&name).unwrap();
            ks.incr_raw("race").await.unwrap()
        }));
    }
    let mut seen = Vec::new();
    for racer in racers {
        seen.push(racer.await.unwrap());
    }
    seen.sort_unstable();
    assert_eq!(seen, (1..=N).collect::<Vec<_>>(), "lost or repeated");
    // A counter is a key like any other.
    assert!(ks.contains_key("race").await.unwrap());
}

/// A swap writes only over the value it expects, and of many swapping from
/// the same value exactly one wins.
pub async fn compare_and_swap_has_one_winner(store: &Store, ns: &str) {
    let name = format!("{ns}_cas");
    let ks = store.keyspace(&name).unwrap();
    assert!(
        !ks.compare_and_swap_raw("mark", Some(b"a".to_vec()), b"b".to_vec())
            .await
            .unwrap()
    );
    assert_eq!(ks.get_raw("mark").await.unwrap(), None);
    assert!(
        ks.compare_and_swap_raw("mark", None, b"a".to_vec())
            .await
            .unwrap()
    );
    assert!(
        !ks.compare_and_swap_raw("mark", None, b"z".to_vec())
            .await
            .unwrap()
    );
    assert_eq!(ks.get_raw("mark").await.unwrap(), Some(b"a".to_vec()));
    assert_eq!(ks.prefix_count("mark").await.unwrap(), 1);

    let mut racers = Vec::new();
    for n in 0..8 {
        let (store, name) = (store.clone(), name.clone());
        racers.push(tokio::spawn(async move {
            let ks = store.keyspace(&name).unwrap();
            ks.compare_and_swap_raw("mark", Some(b"a".to_vec()), format!("b{n}"))
                .await
                .unwrap()
        }));
    }
    let mut winners = 0;
    for racer in racers {
        if racer.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1, "exactly one swap from the same value wins");
    let held = ks.get_raw("mark").await.unwrap().unwrap();
    assert!(held.starts_with(b"b"), "{held:?}");
}
