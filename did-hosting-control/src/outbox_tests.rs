//! Tests for the outbox: queue layout, reference rows, coalescing, settling,
//! backoff, and the migration of rows written by earlier versions.

use super::*;
use crate::control_tasks::harness;
use did_hosting_common::did_ops::{DidRecord, content_log_key, did_key};
use serde_json::json;

async fn state() -> (AppState, tempfile::TempDir) {
    harness::state().await
}

fn record(mnemonic: &str, did_id: &str, version_count: u64) -> DidRecord {
    DidRecord {
        services: None,
        owner: "did:example:owner".into(),
        mnemonic: mnemonic.into(),
        created_at: 1,
        updated_at: 1,
        version_count,
        did_id: Some(did_id.into()),
        content_size: 2,
        disabled: false,
        disabled_by_admin: false,
        deleted_at: None,
        method: "webvh".into(),
        domain: String::new(),
        agent_names: Vec::new(),
    }
}

/// Write a published slot straight to the store.
async fn put_slot(state: &AppState, mnemonic: &str, did_id: &str, version: u64) {
    state
        .dids_ks
        .insert(did_key(mnemonic), &record(mnemonic, did_id, version))
        .await
        .unwrap();
    state
        .dids_ks
        .insert_raw(
            content_log_key(mnemonic),
            format!("{{\"v\":{version}}}").into_bytes(),
        )
        .await
        .unwrap();
}

async fn delete_slot(state: &AppState, mnemonic: &str) {
    state.dids_ks.remove(did_key(mnemonic)).await.unwrap();
    state
        .dids_ks
        .remove(content_log_key(mnemonic))
        .await
        .unwrap();
}

fn did(mnemonic: &str) -> Subject {
    Subject::Did {
        mnemonic: mnemonic.into(),
    }
}

#[tokio::test]
async fn enqueue_then_list_targets_and_head_in_fifo_order() {
    let (state, _dir) = state().await;
    let store = &state.store;
    enqueue(store, "did:example:a", "ty/1.0", json!({"k":1}))
        .await
        .unwrap();
    enqueue(store, "did:example:b", "ty/1.0", json!({"k":2}))
        .await
        .unwrap();
    enqueue(store, "did:example:a", "ty/1.0", json!({"k":3}))
        .await
        .unwrap();

    assert_eq!(
        list_targets(store).await.unwrap(),
        vec!["did:example:a", "did:example:b"]
    );
    let a = list_pending_for_target(store, "did:example:a")
        .await
        .unwrap();
    assert_eq!(a.len(), 2);
    assert_eq!(a[0].1.body, json!({"k": 1}));
    assert_eq!(a[1].1.body, json!({"k": 3}));
    let (_, head_entry) = head(store, "did:example:a").await.unwrap().unwrap();
    assert_eq!(
        head_entry.body,
        json!({"k": 1}),
        "the head is the oldest row"
    );
}

/// One DID that extends another past a `:` (`did:web:h` and `did:web:h:p`)
/// has a queue of its own: neither's rows are read as the other's.
#[tokio::test]
async fn a_did_extending_another_does_not_share_its_queue() {
    let (state, _dir) = state().await;
    let store = &state.store;
    enqueue(store, "did:web:h:p", "ty/1.0", json!({"k": "longer"}))
        .await
        .unwrap();
    assert!(head(store, "did:web:h").await.unwrap().is_none());
    assert_eq!(target_backlog(store, "did:web:h").await.unwrap(), (0, None));
    enqueue(store, "did:web:h", "ty/1.0", json!({"k": "shorter"}))
        .await
        .unwrap();
    assert_eq!(
        head(store, "did:web:h").await.unwrap().unwrap().1.body,
        json!({"k": "shorter"})
    );
    assert_eq!(
        list_pending_for_target(store, "did:web:h:p")
            .await
            .unwrap()
            .len(),
        1
    );
}

/// The gauges read a count and the head, and an emptied target's marker goes.
#[tokio::test]
async fn backlog_counts_and_an_empty_target_is_forgotten() {
    let (state, _dir) = state().await;
    let store = &state.store;
    let key = enqueue(store, "did:example:a", "ty/1.0", json!({}))
        .await
        .unwrap();
    enqueue(store, "did:example:a", "ty/1.0", json!({}))
        .await
        .unwrap();
    let (count, oldest) = target_backlog(store, "did:example:a").await.unwrap();
    assert_eq!(count, 2);
    assert!(oldest.is_some());

    remove(store, key).await.unwrap();
    let (key, _) = head(store, "did:example:a").await.unwrap().unwrap();
    remove(store, key).await.unwrap();
    clear_marker_if_empty(store, "did:example:a").await.unwrap();
    assert!(list_targets(store).await.unwrap().is_empty());

    // A row queued after the marker went brings it back.
    enqueue(store, "did:example:a", "ty/1.0", json!({}))
        .await
        .unwrap();
    assert_eq!(list_targets(store).await.unwrap(), vec!["did:example:a"]);
}

#[tokio::test]
async fn record_failure_counts_a_hard_failure_and_backs_off() {
    let (state, _dir) = state().await;
    let store = &state.store;
    let key = enqueue(store, "did:example:a", "ty/1.0", json!({}))
        .await
        .unwrap();
    let (_, entry) = head(store, "did:example:a").await.unwrap().unwrap();
    record_failure(store, key, &entry, "boom").await.unwrap();
    let (_, after) = head(store, "did:example:a").await.unwrap().unwrap();
    assert_eq!(after.attempts, 1);
    assert_eq!(after.unacked, 0);
    assert_eq!(after.last_error.as_deref(), Some("boom"));
    assert!(after.next_attempt_at > entry.next_attempt_at);
}

#[test]
fn backoff_grows_then_caps() {
    assert_eq!(compute_backoff(0), 1);
    assert_eq!(compute_backoff(1), 2);
    assert_eq!(compute_backoff(4), 16);
    assert_eq!(compute_backoff(9), MAX_BACKOFF_SECS);
    assert_eq!(compute_backoff(50), MAX_BACKOFF_SECS);
    // Jitter adds at most a quarter.
    for _ in 0..100 {
        let j = jittered(100);
        assert!((100..=125).contains(&j), "{j}");
    }
}

/// An unacknowledged send waits longer each time — not a fixed minute — so an
/// offline edge is not sent a copy a minute.
#[test]
fn the_ack_wait_doubles_then_caps() {
    assert_eq!(ack_wait(0), ACK_TIMEOUT_SECS);
    assert_eq!(ack_wait(1), 2 * ACK_TIMEOUT_SECS);
    assert_eq!(ack_wait(3), 8 * ACK_TIMEOUT_SECS);
    assert_eq!(ack_wait(10), MAX_ACK_WAIT_SECS);
    assert_eq!(ack_wait(u32::MAX), MAX_ACK_WAIT_SECS);
    // The documented budget: MAX_UNACKED sends span roughly 19 hours.
    let total: u64 = (0..MAX_UNACKED).map(ack_wait).sum();
    assert!((18 * 3600..20 * 3600).contains(&total), "{total}");
    // And MAX_ATTEMPTS hard failures roughly 3.5 hours.
    let total: u64 = (1..=MAX_ATTEMPTS).map(compute_backoff).sum();
    assert!((3 * 3600..4 * 3600).contains(&total), "{total}");
}

#[tokio::test]
async fn sends_and_failures_are_counted_apart() {
    let (state, _dir) = state().await;
    let store = &state.store;
    let key = enqueue(store, "did:example:a", "ty/1.0", json!({}))
        .await
        .unwrap();
    let (_, entry) = head(store, "did:example:a").await.unwrap().unwrap();
    let sent = record_sent(store, key.clone(), &entry, "urn:uuid:1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((sent.unacked, sent.attempts), (1, 0));
    assert!(sent.next_attempt_at >= now_epoch() + ACK_TIMEOUT_SECS);
    let sent = record_sent(store, key, &sent, "urn:uuid:2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!((sent.unacked, sent.attempts), (2, 0));
    assert!(sent.next_attempt_at >= now_epoch() + 2 * ACK_TIMEOUT_SECS);
    assert_eq!(sent.sent_docs, vec!["urn:uuid:1", "urn:uuid:2"]);
}

/// A row dropped while the worker is delivering it stays dropped: the
/// worker's rewrite after the send must not bring back a purge that a
/// re-assign superseded.
#[tokio::test]
async fn a_row_dropped_mid_delivery_is_not_resurrected() {
    let (state, _dir) = state().await;
    let store = &state.store;
    enqueue(
        store,
        "did:example:edge",
        "purge",
        json!({"domain": "a.example"}),
    )
    .await
    .unwrap();
    let (key, entry) = head(store, "did:example:edge").await.unwrap().unwrap();
    let dropped = drop_queued(store, "did:example:edge", "purge", |_| true)
        .await
        .unwrap();
    assert_eq!(dropped, 1);
    assert!(
        record_sent(store, key.clone(), &entry, "urn:uuid:doc-1")
            .await
            .unwrap()
            .is_none(),
        "a row removed meanwhile is not recorded as sent (and so not sent)"
    );
    record_failure(store, key, &entry, "boom").await.unwrap();
    assert!(head(store, "did:example:edge").await.unwrap().is_none());
}

/// An entry is settled only on its own target's acknowledgement of a document
/// sent for it — not on send, not for another target, not for another
/// document — and an ack of an earlier copy settles it as well as the last.
#[tokio::test]
async fn an_entry_is_settled_only_by_its_targets_ack_of_a_sent_document() {
    let (state, _dir) = state().await;
    let store = &state.store;
    let key = enqueue(store, "did:example:edge", "ty/1.0", json!({"k": 1}))
        .await
        .unwrap();
    let (_, entry) = head(store, "did:example:edge").await.unwrap().unwrap();
    assert_eq!(head_action(&entry, now_epoch()), HeadAction::Send);
    let sent = record_sent(store, key.clone(), &entry, "urn:uuid:doc-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head_action(&sent, now_epoch()), HeadAction::Wait);
    assert_eq!(
        head_action(&sent, now_epoch() + MAX_ACK_WAIT_SECS * 2),
        HeadAction::Send
    );
    record_sent(store, key, &sent, "urn:uuid:doc-2")
        .await
        .unwrap()
        .unwrap();

    assert!(
        !acknowledge(&state, "did:example:other", "urn:uuid:doc-1")
            .await
            .unwrap()
    );
    assert!(
        !acknowledge(&state, "did:example:edge", "urn:uuid:other")
            .await
            .unwrap()
    );
    assert_eq!(
        target_backlog(store, "did:example:edge").await.unwrap().0,
        1
    );

    // The first copy's ack settles it, and leaves no ack index behind.
    assert!(
        acknowledge(&state, "did:example:edge", "urn:uuid:doc-1")
            .await
            .unwrap()
    );
    assert!(head(store, "did:example:edge").await.unwrap().is_none());
    assert!(
        !acknowledge(&state, "did:example:edge", "urn:uuid:doc-2")
            .await
            .unwrap()
    );
    let ks = outbox_ks(store).unwrap();
    assert!(ks.prefix_keys_raw("outbox-ack:").await.unwrap().is_empty());
}

// ── Reference rows ────────────────────────────────────────────────────────

/// A DID row carries no log; it is sent as the slot stands at send time —
/// an update while published, a delete once the slot is gone.
#[tokio::test]
async fn a_did_row_is_materialised_at_send_time() {
    let (state, _dir) = state().await;
    let edge = "did:example:edge";
    put_slot(&state, "alice", "did:webvh:Q1:h:alice", 1).await;
    assert!(enqueue_ref(&state, edge, did("alice")).await.unwrap());
    let (_, entry) = head(&state.store, edge).await.unwrap().unwrap();
    assert_eq!(entry.body, Value::Null, "the row carries no content");

    put_slot(&state, "alice", "did:webvh:Q1:h:alice", 2).await;
    let p = prepare(&state, &entry).await.unwrap().unwrap();
    assert_eq!(p.msg_type, MSG_SYNC_UPDATE);
    assert_eq!(
        p.body["versionCount"], 2,
        "the newest state, not the enqueued one"
    );

    delete_slot(&state, "alice").await;
    let p = prepare(&state, &entry).await.unwrap().unwrap();
    assert_eq!(p.msg_type, MSG_SYNC_DELETE);
    assert_eq!(p.body, json!({ "mnemonic": "alice" }));
}

/// A slot already queued for a target is not queued again.
#[tokio::test]
async fn a_queued_did_is_coalesced() {
    let (state, _dir) = state().await;
    let edge = "did:example:edge";
    put_slot(&state, "alice", "did:webvh:Q1:h:alice", 1).await;
    assert!(enqueue_ref(&state, edge, did("alice")).await.unwrap());
    assert!(!enqueue_ref(&state, edge, did("alice")).await.unwrap());
    assert!(enqueue_ref(&state, edge, did("bob")).await.unwrap());
    assert!(
        enqueue_ref(&state, "did:example:other", did("alice"))
            .await
            .unwrap()
    );
    assert_eq!(target_backlog(&state.store, edge).await.unwrap().0, 2);
}

/// The ack of a send that a later change superseded re-arms the row instead
/// of settling it: the coalesced change is never lost.
#[tokio::test]
async fn an_ack_of_a_superseded_state_re_arms_the_row() {
    let (state, _dir) = state().await;
    let edge = "did:example:edge";
    put_slot(&state, "alice", "did:webvh:Q1:h:alice", 1).await;
    enqueue_ref(&state, edge, did("alice")).await.unwrap();
    let (key, entry) = head(&state.store, edge).await.unwrap().unwrap();
    let p = prepare(&state, &entry).await.unwrap().unwrap();
    record_prepared_sent(&state.store, key.clone(), &p, "urn:uuid:v1")
        .await
        .unwrap()
        .unwrap();

    // Published again while in flight: coalesced onto the queued row.
    put_slot(&state, "alice", "did:webvh:Q1:h:alice", 2).await;
    assert!(!enqueue_ref(&state, edge, did("alice")).await.unwrap());

    assert!(acknowledge(&state, edge, "urn:uuid:v1").await.unwrap());
    let (_, rearmed) = head(&state.store, edge)
        .await
        .unwrap()
        .expect("still queued");
    assert_eq!(rearmed.awaiting_ack, None);
    assert_eq!(head_action(&rearmed, now_epoch()), HeadAction::Send);
    let p = prepare(&state, &rearmed).await.unwrap().unwrap();
    assert_eq!(p.body["versionCount"], 2);

    // The ack of the current state settles it, index and all.
    record_prepared_sent(&state.store, key, &p, "urn:uuid:v2")
        .await
        .unwrap()
        .unwrap();
    assert!(acknowledge(&state, edge, "urn:uuid:v2").await.unwrap());
    assert!(head(&state.store, edge).await.unwrap().is_none());
    assert!(
        enqueue_ref(&state, edge, did("alice")).await.unwrap(),
        "the index went with it"
    );
}

/// A resync batch names its slots; one deleted before the send is left out,
/// and a batch with nothing left is not sent.
#[tokio::test]
async fn a_batch_row_sends_the_slots_still_published() {
    let (state, _dir) = state().await;
    let edge = "did:example:edge";
    put_slot(&state, "a", "did:webvh:Q1:h:a", 1).await;
    put_slot(&state, "b", "did:webvh:Q1:h:b", 1).await;
    enqueue_batch(&state.store, edge, vec!["a".into(), "b".into()])
        .await
        .unwrap();
    let (_, entry) = head(&state.store, edge).await.unwrap().unwrap();
    delete_slot(&state, "a").await;
    let p = prepare(&state, &entry).await.unwrap().unwrap();
    assert_eq!(p.msg_type, MSG_SYNC_BATCH);
    let updates = p.body["updates"].as_array().unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0]["mnemonic"], "b");
    assert_eq!(
        p.entry.subject,
        Some(Subject::DidBatch {
            mnemonics: vec!["b".into()]
        })
    );
    delete_slot(&state, "b").await;
    assert!(prepare(&state, &entry).await.unwrap().is_none());
}

/// Every row is constant-size whatever the log's: nothing a store's per-item
/// limit can refuse.
#[tokio::test]
async fn a_did_row_does_not_grow_with_the_log() {
    let (state, _dir) = state().await;
    let edge = "did:example:edge";
    state
        .dids_ks
        .insert(did_key("big"), &record("big", "did:webvh:Q1:h:big", 1))
        .await
        .unwrap();
    state
        .dids_ks
        .insert_raw(content_log_key("big"), vec![b'x'; 1024 * 1024])
        .await
        .unwrap();
    enqueue_ref(&state, edge, did("big")).await.unwrap();
    let (key, _) = head(&state.store, edge).await.unwrap().unwrap();
    let raw = outbox_ks(&state.store)
        .unwrap()
        .get_raw(key)
        .await
        .unwrap()
        .unwrap();
    assert!(raw.len() < 1024, "{} bytes", raw.len());
}

// ── Migration ─────────────────────────────────────────────────────────────

/// A row queued by an earlier version (old key layout, literal body, awaiting
/// an ack) is re-keyed on boot, keeps its place ahead of newer rows, drains
/// as its literal body, and the late ack of the document sent before the
/// upgrade still settles it.
#[tokio::test]
async fn rows_queued_by_an_earlier_version_still_drain() {
    let (state, _dir) = state().await;
    let store = &state.store;
    let target = "did:webvh:QmAbc:edge.example.com";
    let legacy = json!({
        "target_did": target,
        "msg_type": MSG_SYNC_UPDATE,
        "body": { "mnemonic": "alice", "didId": "did:webvh:Q:h:alice", "logContent": "{}", "versionCount": 1, "disabled": false },
        "enqueued_at": now_epoch(),
        "attempts": 3,
        "next_attempt_at": now_epoch(),
        "last_error": null,
        "awaiting_ack": "urn:uuid:before-upgrade",
    });
    let ks = outbox_ks(store).unwrap();
    ks.insert(
        format!("outbox:{target}:{:020}:abcdef012345", 1u64),
        &legacy,
    )
    .await
    .unwrap();
    let second = json!({
        "target_did": target, "msg_type": MSG_REPLICA_DOMAIN_ASSIGN, "body": {"domain": "a.example"},
        "enqueued_at": now_epoch(), "attempts": 0, "next_attempt_at": now_epoch(), "last_error": null,
    });
    ks.insert(
        format!("outbox:{target}:{:020}:abcdef012346", 2u64),
        &second,
    )
    .await
    .unwrap();
    // Not visible to the worker until migrated.
    assert!(list_targets(store).await.unwrap().is_empty());

    assert_eq!(migrate_legacy_rows(store).await.unwrap(), 2);
    assert_eq!(migrate_legacy_rows(store).await.unwrap(), 0, "idempotent");
    // A row queued now goes behind them.
    enqueue(store, target, "ty/1.0", json!({"new": true}))
        .await
        .unwrap();

    assert_eq!(list_targets(store).await.unwrap(), vec![target.to_string()]);
    let (_, entry) = head(store, target).await.unwrap().unwrap();
    assert_eq!(entry.attempts, 3);
    assert_eq!(entry.body["mnemonic"], "alice");
    let p = prepare(&state, &entry).await.unwrap().unwrap();
    assert_eq!(p.msg_type, MSG_SYNC_UPDATE);
    assert_eq!(p.body, legacy["body"]);

    assert!(
        acknowledge(&state, target, "urn:uuid:before-upgrade")
            .await
            .unwrap()
    );
    let rest: Vec<_> = list_pending_for_target(store, target)
        .await
        .unwrap()
        .into_iter()
        .map(|(_, e)| e.msg_type)
        .collect();
    assert_eq!(
        rest,
        vec![MSG_REPLICA_DOMAIN_ASSIGN.to_string(), "ty/1.0".into()]
    );
    assert!(
        ks.prefix_keys_raw(format!("outbox:{target}:"))
            .await
            .unwrap()
            .into_iter()
            .all(|k| String::from_utf8(k).unwrap().contains('|')),
        "no row is left under the old layout"
    );
}

// ── Transactional enqueue ─────────────────────────────────────────────────

async fn register_edge(state: &AppState, edge: &str) {
    let instance: crate::registry::ServiceInstance = serde_json::from_value(json!({
        "instanceId": crate::registry::instance_id_for(edge),
        "serviceType": "server",
        "url": "https://edge.example",
        "status": "active",
        "registeredAt": now_epoch(),
        "metadata": { "did": edge },
    }))
    .unwrap();
    crate::registry::register_instance(&state.registry_ks, &instance)
        .await
        .unwrap();
}

/// A DID mutation's rows commit with it — they are there when the mutation
/// returns, with no detached task to wait for — and a delete goes out as one.
#[tokio::test]
async fn a_did_mutation_queues_its_sync_in_the_same_commit() {
    let (state, _dir) = state().await;
    let edge = "did:example:edge-tx";
    register_edge(&state, edge).await;
    put_slot(&state, "alice", "did:webvh:Q1:h:alice", 1).await;

    let _guard = state.path_locks.guard("alice").await;
    let mut batch = state.store.batch();
    batch
        .insert(
            &state.dids_ks,
            did_key("alice"),
            &record("alice", "did:webvh:Q1:h:alice", 2),
        )
        .unwrap();
    let staged = crate::server_push::stage_did_sync(
        &state,
        &mut batch,
        "alice",
        crate::server_push::DidChange::Published { log: "{}" },
    )
    .await;
    // Nothing is queued until the mutation commits.
    assert!(head(&state.store, edge).await.unwrap().is_none());
    batch.commit().await.unwrap();
    staged.finish(&state).await;
    let (_, entry) = head(&state.store, edge)
        .await
        .unwrap()
        .expect("queued with the commit");
    assert_eq!(entry.subject, Some(did("alice")));

    // A delete committed while the update is still queued is coalesced onto
    // it, and the row goes out as the delete.
    let mut batch = state.store.batch();
    batch.remove(&state.dids_ks, did_key("alice"));
    batch.remove(&state.dids_ks, content_log_key("alice"));
    let staged = crate::server_push::stage_did_sync(
        &state,
        &mut batch,
        "alice",
        crate::server_push::DidChange::Deleted,
    )
    .await;
    batch.commit().await.unwrap();
    staged.finish(&state).await;
    assert_eq!(target_backlog(&state.store, edge).await.unwrap().0, 1);
    let p = prepare(&state, &entry).await.unwrap().unwrap();
    assert_eq!(p.msg_type, MSG_SYNC_DELETE);
}
