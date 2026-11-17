//! The gate model: bound-key rows, and every other row exactly as before.

use super::*;

// ---------------------------------------------------------------------------
// The gate model: bound-key rows, and every other row exactly as before
// ---------------------------------------------------------------------------

/// Every row that is not a bound-key row keeps the rule it had before
/// bound-key rows existed — so the gate refuses for each exactly what it
/// refused (the table-wide tests above run over these same rows).
#[test]
fn existing_rows_keep_their_proof_rules() {
    const BEFORE: &[(&str, ProofRule)] = &[
        (
            "https://trusttasks.org/spec/did-management/did/check-name/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/register/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/info/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/list/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/delete/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/change-owner/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/set-state/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/rollback/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/did/log/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/webvh/witness/publish/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/agent-name/update/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/agent-name/remove/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/agent-name/list/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/agent-name/check/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/agent-name/resolve/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/me/domains/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/list/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/create/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/update/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/set-state/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/set-default/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/purge/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/assign/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/domain/unassign/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/registry/list/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/registry/get/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/registry/check/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/registry/admin-register/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/registry/deregister/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/registry/purge-domain/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/server/info/0.1",
            ProofRule::Optional,
        ),
        (
            "https://trusttasks.org/spec/did-management/server/config/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/server/metrics/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/stats/get/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/stats/set-resolution/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/stats/timeseries/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/identity/list/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/did-management/identity/retire/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/step-up/start/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/step-up/approve-response/0.7",
            ProofRule::AssertionMethod,
        ),
        (
            "https://trusttasks.org/spec/auth/revoke-session/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/login/start/0.2",
            ProofRule::Optional,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/login/finish/0.2",
            ProofRule::SessionKey,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/invite/0.3",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/redeem/start/0.1",
            ProofRule::Optional,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/redeem/finish/0.1",
            ProofRule::Optional,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/start/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/finish/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/invite/list/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/invite/update/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/enroll/invite/revoke/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/list/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/admin-list/0.1",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/revoke/start/0.2",
            ProofRule::Authentication,
        ),
        (
            "https://trusttasks.org/spec/auth/passkey/revoke/finish/0.2",
            ProofRule::Authentication,
        ),
    ];
    let now: Vec<_> = did_signed_rows().copied().collect();
    assert_eq!(now, BEFORE);
}

/// The bound-key rows are exactly wallet sign-in's six outer tasks, each at
/// its latest version only, each accepting the two proof purposes its
/// clients sign for. `identify` and `grant` are carried, never rows.
#[test]
fn bound_key_rows_are_wallet_sign_in_and_nothing_else() {
    use crate::oob::types::*;
    let bound: Vec<_> = TASKS
        .iter()
        .filter_map(|(uri, rule)| match rule {
            ProofRule::BoundKey(purposes) => Some((*uri, *purposes)),
            _ => None,
        })
        .collect();
    let purposes: &[&str] = &["authentication", "assertionMethod"];
    assert_eq!(
        bound,
        [
            TYPE_REQUEST,
            TYPE_CLAIM,
            TYPE_PROVE,
            TYPE_RESPOND,
            TYPE_REDEEM,
            TYPE_CANCEL
        ]
        .map(|uri| (uri, purposes))
    );
    for carried in [TYPE_IDENTIFY, TYPE_GRANT] {
        assert_eq!(
            super::super::proof_rule(carried),
            None,
            "{carried} is not a row"
        );
    }
    // Only a bound-key row sets the bearer session and the shared replay
    // cache aside.
    for (uri, rule) in TASKS {
        let bound = matches!(rule, ProofRule::BoundKey(_));
        assert_eq!(rule.admits_bearer(), !bound, "{uri}");
        assert_eq!(rule.uses_shared_replay_cache(), !bound, "{uri}");
        assert_eq!(
            crate::messaging::session_key_may_sign(uri),
            *rule == ProofRule::Authentication,
            "{uri}"
        );
    }
}

/// A `redeem` from a starter key `K_b`, for `request_id`.
pub(super) async fn redeem_doc(starter: &Caller, request_id: &str, purpose: &str) -> Value {
    let doc = request(
        crate::oob::types::TYPE_REDEEM,
        &starter.did,
        json!({ "requestId": request_id }),
    );
    match purpose {
        "authentication" => signed(doc, &starter.key).await,
        "assertionMethod" => signed_as_assertion(doc, &starter.key).await,
        other => {
            use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};
            sign_trust_task(
                &doc,
                &starter.key,
                SignOptions::new()
                    .with_proof_purpose(other)
                    .with_cryptosuite(CryptoSuite::EddsaJcs2022),
            )
            .await
            .expect("sign")
        }
    }
}

pub(super) const NO_SUCH_REQUEST: &str = "AAAAAAAAAAAAAAAAAAAAAA";

/// A bound-key document reaches its row over HTTPS, and nowhere else: on the
/// messaging transports the gate refuses it before anything else.
#[tokio::test]
async fn bound_key_rows_are_served_over_https_only() {
    let (state, _dir) = state().await;
    let starter = stranger(60);
    for via in VIAS {
        let doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
        let reply = send(&state, via, &starter, doc).await;
        match via {
            // Reached the state machine: no such request.
            Via::Https => assert_eq!(code(&reply), "auth/oob:requestNotFound", "{reply}"),
            _ => {
                assert_eq!(code(&reply), "permissionDenied", "{via:?}: {reply}");
                assert!(
                    reply["payload"]["message"]
                        .as_str()
                        .is_some_and(|m| m.contains("HTTPS only")),
                    "{via:?}: {reply}"
                );
            }
        }
    }
}

/// A wallet sends `prove` at the newest version it knows and falls back only
/// on an `unsupportedType` refusal (pnm-browser-plugin `sign-in-flows`). Both
/// versions this service serves reach the state machine over HTTPS, and a
/// version it does not serve, signed by a stranger's `did:key`, must be
/// refused with exactly that code, or the wallet gives up instead of falling
/// back.
#[tokio::test]
async fn an_unserved_prove_version_is_unsupported_so_a_wallet_falls_back() {
    let (state, _dir) = state().await;
    let approver = stranger(64);
    let prove = |type_uri: &'static str| {
        let approver = &approver;
        async move {
            let mut doc = request(type_uri, &approver.did, json!({ "identify": {} }));
            doc["parentThreadId"] = json!(NO_SUCH_REQUEST);
            signed(doc, &approver.key).await
        }
    };
    let served = crate::oob::types::TYPE_PROVE;
    let reply = https(&state, None, prove(served).await).await;
    assert_ne!(code(&reply), "unsupportedType", "{served}: {reply}");
    // Only the latest version is served: an older one is refused exactly as
    // a newer one nobody serves is.
    for unserved in [
        "https://trusttasks.org/spec/auth/oob/prove/0.1",
        "https://trusttasks.org/spec/auth/oob/prove/0.2",
        "https://trusttasks.org/spec/auth/oob/prove/0.99",
    ] {
        let reply = https(&state, None, prove(unserved).await).await;
        assert!(
            code(&reply).ends_with("unsupportedType"),
            "{unserved}: {reply}"
        );
    }
}

/// A bearer session sent with a bound-key document is ignored. Were it
/// context, the session-binding check would refuse a proof by `K_b` — which is
/// neither the session subject's key nor its session key — as `proofInvalid`.
#[tokio::test]
async fn bound_key_rows_ignore_a_bearer_session() {
    let (state, _dir) = state().await;
    let admin = member(&state, 61, Role::Admin).await;
    let bearer = crate::auth::AuthClaims {
        did: admin.did.clone(),
        role: Role::Admin,
        session_id: "s".into(),
        session_pubkey_b58btc: None,
        amr: vec!["did".into()],
        acr: "aal2".into(),
    };
    let starter = stranger(62);
    let doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
    let reply = https(&state, Some(bearer), doc).await;
    assert_eq!(code(&reply), "auth/oob:requestNotFound", "{reply}");
}

/// The gate's proof check for a bound-key row: an Ed25519 `did:key` issuer,
/// a proof by exactly that key, for a purpose the row lists. Each refusal is
/// in the family's own codes, as the state machine itself would refuse.
#[tokio::test]
async fn bound_key_rows_need_a_proof_by_the_issuer_key_for_a_listed_purpose() {
    let (state, _dir) = state().await;
    let starter = stranger(63);
    for purpose in ["authentication", "assertionMethod"] {
        let doc = redeem_doc(&starter, NO_SUCH_REQUEST, purpose).await;
        let reply = https(&state, None, doc).await;
        assert_eq!(
            code(&reply),
            "auth/oob:requestNotFound",
            "{purpose}: {reply}"
        );
    }
    // A purpose the row does not list.
    let doc = redeem_doc(&starter, NO_SUCH_REQUEST, "capabilityInvocation").await;
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:notAuthorized"
    );
    // Unsigned.
    let doc = request(
        crate::oob::types::TYPE_REDEEM,
        &starter.did,
        json!({ "requestId": NO_SUCH_REQUEST }),
    );
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:notAuthorized"
    );
    // Signed by another key than the one the issuer names.
    let other = stranger(64);
    let mut doc = redeem_doc(&other, NO_SUCH_REQUEST, "authentication").await;
    doc["issuer"] = json!(starter.did);
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:notAuthorized"
    );
    // Tampered after signing.
    let mut doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
    doc["payload"]["requestId"] = json!("BBBBBBBBBBBBBBBBBBBBBB");
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:notAuthorized"
    );
    // An issuer that is not an Ed25519 did:key, even one in the ACL: decided
    // from the identifier, before any DID is resolved.
    let admin = member(&state, 65, Role::Admin).await;
    let mut doc = redeem_doc(&admin, NO_SUCH_REQUEST, "authentication").await;
    doc["issuer"] = json!("did:webvh:abc:control.test:alice");
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:keyUnsupported"
    );
}

/// The shared replay cache is not spent by a bound-key document — the row's
/// own cache is (and only for a live request, `oob::tests`): keys like these
/// cost nothing to mint, and the shared cache fails closed for every task.
#[tokio::test]
async fn bound_key_rows_do_not_touch_the_shared_replay_cache() {
    let (state, _dir) = state().await;
    let starter = stranger(66);
    let doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
    let id = doc["id"].as_str().unwrap().to_string();
    let before = state.replay_cache.len();
    let reply = https(&state, None, doc).await;
    assert_eq!(code(&reply), "auth/oob:requestNotFound", "{reply}");
    assert_eq!(state.replay_cache.len(), before);
    assert!(
        state
            .replay_cache
            .check(&starter.did, &id, Some(chrono::Utc::now()))
            .is_ok()
    );
}

/// A bound-key row is not behind the ACL pre-filter: its parties are keys
/// the ACL never lists, so neither a stranger's key nor an ACL store that
/// cannot be read stops the document reaching its row.
#[tokio::test]
async fn bound_key_rows_skip_the_acl_pre_filter() {
    let (mut state, _dir) = state().await;
    let starter = stranger(69);
    let doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:requestNotFound"
    );
    state.acl_ks = state.acl_ks.failing_reads_after(
        0,
        did_hosting_common::server::error::AppError::store_throttled,
    );
    let doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:requestNotFound"
    );
}

/// A bound-key row's admission runs before the gate does any proof work: past
/// its per-address limit, a document is refused as rate limited whether or
/// not its proof would verify.
///
/// The limit is counted over a day here rather than a minute: at the default
/// an address gets a document back every half second, and these requests can
/// take longer than that on a loaded machine, which would admit the one past
/// the limit. A day returns one every 12 minutes.
#[tokio::test]
async fn bound_key_admission_runs_before_the_proof_check() {
    use crate::oob::http::OTHER_MAX_PER_MINUTE;
    let (mut state, _dir) = state().await;
    state.oob = std::sync::Arc::new(crate::oob::OobRuntime::default().with_other_window(86_400));
    let starter = stranger(67);
    for n in 0..OTHER_MAX_PER_MINUTE {
        let mut doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
        doc["proof"]["proofValue"] = json!("zBad");
        let reply = https(&state, None, doc).await;
        assert_eq!(code(&reply), "auth/oob:notAuthorized", "{n}: {reply}");
    }
    let mut doc = redeem_doc(&starter, NO_SUCH_REQUEST, "authentication").await;
    doc["proof"]["proofValue"] = json!("zBad");
    assert_eq!(
        code(&https(&state, None, doc).await),
        "auth/oob:rateLimited"
    );
}

/// A bound-key document over the family's 32 KiB cap is refused at
/// admission, before its proof is looked at — even one that would verify.
#[tokio::test]
async fn bound_key_rows_refuse_an_oversized_document_before_its_proof() {
    use crate::oob::http::MAX_OOB_DOCUMENT_BYTES;
    let (state, _dir) = state().await;
    let starter = stranger(68);
    let mut doc = request(
        crate::oob::types::TYPE_REDEEM,
        &starter.did,
        json!({ "requestId": NO_SUCH_REQUEST }),
    );
    // Under the router's own 64 KiB default, over the family's cap.
    doc["pad"] = json!("x".repeat(MAX_OOB_DOCUMENT_BYTES));
    let doc = signed(doc, &starter.key).await;
    let reply = https(&state, None, doc).await;
    assert_eq!(code(&reply), "malformedRequest", "{reply}");
    assert_eq!(reply["payload"]["message"], "document too large", "{reply}");
}

/// A throttled ACL read says nothing about the caller: it is answered as
/// `unavailable` with a retry time (HTTPS: 503 with `Retry-After`), never as
/// "not present in the maintainer's ACL", which reads as a revoked grant.
#[tokio::test]
async fn a_throttled_acl_lookup_asks_for_a_retry_not_a_new_grant() {
    use axum::response::IntoResponse;

    let (mut state, _dir) = state().await;
    let admin = member(&state, 53, Role::Admin).await;
    state.acl_ks = state.acl_ks.throttled_reads();
    let list = t("did-management/domain/list/0.1");

    let reply = call(&state, Via::Tsp, &admin, &list, json!({})).await;
    assert_eq!(code(&reply), "unavailable", "{reply}");
    assert!(reply["payload"]["retryAfter"].is_string(), "{reply}");

    let doc = signed(request(&list, &admin.did, json!({})), &admin.key).await;
    let response = crate::routes::trust_tasks::dispatch_trust_task(
        None,
        axum::extract::State(state.clone()),
        None,
        &axum::http::HeaderMap::new(),
        axum::body::Bytes::from(serde_json::to_vec(&doc).unwrap()),
    )
    .await
    .into_response();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        response.headers().get(axum::http::header::RETRY_AFTER),
        Some(&axum::http::HeaderValue::from(
            did_hosting_common::server::error::STORE_THROTTLED_RETRY_AFTER_SECS
        )),
        "the store's hint, not rounded down"
    );
}

/// Past the gate, a task's own ACL read can still be the one throttled: the
/// shared engine's `cx.admin()` and the `acl/*` handlers answer it the same
/// way as the gate, never as "not in the ACL".
#[tokio::test]
async fn a_throttled_acl_read_after_the_gate_asks_for_a_retry() {
    let (state, _dir) = state().await;
    let admin = member(&state, 54, Role::Admin).await;
    let acl_ks = state.acl_ks.clone();
    for slug in ["did-management/domain/list/0.1", "acl/list/0.3"] {
        let mut state = state.clone();
        // One read for the gate, then throttled.
        state.acl_ks = acl_ks.failing_reads_after(
            1,
            did_hosting_common::server::error::AppError::store_throttled,
        );
        let reply = call(&state, Via::Tsp, &admin, &t(slug), json!({})).await;
        assert_eq!(code(&reply), "unavailable", "{slug}: {reply}");
        assert!(
            reply["payload"]["retryAfter"].is_string(),
            "{slug}: {reply}"
        );
    }
}

/// A lookup that fails for any other reason is the maintainer's fault, not a
/// refusal of the sender: `internalError`, which names nothing internal.
#[tokio::test]
async fn a_failed_acl_lookup_is_an_internal_error_not_a_refusal() {
    let (mut state, _dir) = state().await;
    let admin = member(&state, 55, Role::Admin).await;
    state.acl_ks = state.acl_ks.failing_reads_after(0, || {
        did_hosting_common::server::error::AppError::Store("disk failure".into())
    });
    let reply = call(
        &state,
        Via::Tsp,
        &admin,
        &t("did-management/domain/list/0.1"),
        json!({}),
    )
    .await;
    assert_eq!(code(&reply), "internalError", "{reply}");
    assert!(!reply.to_string().contains("disk failure"), "{reply}");
}

/// A document refused as `unavailable` did not run, so sending the very same
/// signed document again is a retry, not a replay.
#[tokio::test]
async fn a_document_refused_as_unavailable_can_be_sent_again() {
    let (state, _dir) = state().await;
    let admin = member(&state, 56, Role::Admin).await;
    let list = t("did-management/domain/list/0.1");
    let doc = signed(request(&list, &admin.did, json!({})), &admin.key).await;

    let mut throttled = state.clone();
    throttled.acl_ks = state.acl_ks.failing_reads_after(
        1,
        did_hosting_common::server::error::AppError::store_throttled,
    );
    let reply = send(&throttled, Via::Tsp, &admin, doc.clone()).await;
    assert_eq!(code(&reply), "unavailable", "{reply}");

    let reply = send(&state, Via::Tsp, &admin, doc.clone()).await;
    conforms(&reply);
    ok(&reply, &list);
    // Run once, it is remembered again.
    assert_eq!(
        code(&send(&state, Via::Tsp, &admin, doc).await),
        "idConflict"
    );
}

/// A task refused as `unavailable` after it attempted a write may have applied
/// part of it, so the same document is not run again: a retry is a new one.
#[tokio::test]
async fn a_document_refused_as_unavailable_after_a_write_is_not_run_again() {
    let (state, _dir) = state().await;
    let admin = member(&state, 57, Role::Admin).await;
    let grant = t("acl/grant/0.2");
    let entry = json!({
        "entry": {
            "subject": "did:example:a-new-member",
            "role": "owner",
            "act": { "scope": "all" },
            "keys": { "scope": "none" },
            "capabilities": { "scope": "ceiling" }
        }
    });
    let doc = signed(request(&grant, &admin.did, entry), &admin.key).await;

    let mut throttled = state.clone();
    throttled.acl_ks = state
        .acl_ks
        .throttled_writes_after(std::sync::Arc::new(0.into()));
    let reply = send(&throttled, Via::Tsp, &admin, doc.clone()).await;
    assert_eq!(code(&reply), "unavailable", "{reply}");

    assert_eq!(
        code(&send(&state, Via::Tsp, &admin, doc).await),
        "idConflict"
    );
}

/// A store's per-item size refusal reaches a task that declares no size code
/// (such as `did/register`) as `taskFailed` with the limit in its message,
/// not as an internal failure that hides why.
#[test]
fn a_store_size_refusal_is_a_task_failure_naming_the_limit() {
    use did_hosting_common::server::error::AppError;
    let payload = super::super::TaskError::App(AppError::quota(
        did_hosting_common::server::error::QuotaKind::Size,
        "item size 431916 bytes is over the store's per-item limit of 409600 bytes",
    ))
    .payload(&[]);
    let payload = serde_json::to_value(payload).expect("serialise the error payload");
    assert_eq!(payload["code"], "taskFailed", "{payload}");
    let message = payload["message"].as_str().unwrap_or_default();
    assert!(message.contains("409600"), "{payload}");
}
