//! Tests for [`super`].

use super::*;
// Only the tests read the spec constants; importing it at module scope
// would be dead weight in a non-test build.
use trust_tasks_rs::Payload as PayloadSpec;

/// `owns` must claim exactly the three request URIs — and in particular
/// not the `#response` forms, which are documents *we* emit and must
/// never route back into ourselves.
#[test]
fn owns_the_three_request_uris_and_not_their_responses() {
    for uri in [
        <challenge::Payload as PayloadSpec>::TYPE_URI,
        <authenticate::Payload as PayloadSpec>::TYPE_URI,
        <refresh::Payload as PayloadSpec>::TYPE_URI,
    ] {
        assert!(owns(uri), "{uri} must be owned");
        assert!(
            !owns(&format!("{uri}#response")),
            "{uri}#response must NOT be owned",
        );
    }
}

#[test]
fn owns_nothing_outside_the_family() {
    assert!(!owns("https://trusttasks.org/spec/acl/list/0.1"));
    assert!(!owns("https://trusttasks.org/spec/auth/whoami/0.1"));
    // Superseded versions are no longer served.
    assert!(!owns("https://trusttasks.org/spec/auth/authenticate/0.2"));
    assert!(!owns("https://trusttasks.org/spec/auth/refresh/0.1"));
    assert!(!owns("not a uri"));
}

/// The validity window a mandate must carry, checked at a fixed instant.
#[test]
fn a_mandate_must_name_a_bounded_validity_window() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-11-12T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let hour = chrono::Duration::hours(1);
    let mandate = |issued: Option<chrono::DateTime<chrono::Utc>>,
                   expires: Option<chrono::DateTime<chrono::Utc>>| {
        let mut doc = serde_json::json!({
            "id": "urn:uuid:00000000-0000-4000-8000-000000000000",
            "type": MANDATE_EVIDENCE_TYPE_URI,
            "payload": { "delegate": "did:example:delegate" },
        });
        if let Some(t) = issued {
            doc["issuedAt"] = serde_json::json!(t.to_rfc3339());
        }
        if let Some(t) = expires {
            doc["expiresAt"] = serde_json::json!(t.to_rfc3339());
        }
        serde_json::from_value::<TrustTask<Value>>(doc).unwrap()
    };
    let max = chrono::Duration::seconds(MAX_MANDATE_LIFETIME_SECS);

    assert_eq!(
        mandate_validity(&mandate(Some(now - hour), Some(now + hour)), now),
        Ok(u64::try_from((now + hour).timestamp()).unwrap())
    );
    assert!(mandate_validity(&mandate(Some(now), Some(now + max)), now).is_ok());

    for (case, issued, expires) in [
        ("no expiresAt", Some(now), None),
        ("no issuedAt", None, Some(now + hour)),
        ("expired", Some(now - hour - hour), Some(now - hour)),
        ("expires at issue", Some(now), Some(now)),
        (
            "issued in the future",
            Some(now + hour),
            Some(now + hour + hour),
        ),
        (
            "valid too long",
            Some(now),
            Some(now + max + chrono::Duration::seconds(1)),
        ),
    ] {
        assert!(
            mandate_validity(&mandate(issued, expires), now).is_err(),
            "{case} was accepted"
        );
    }
}

/// A mandate is checked as a decision: from a principal whose `did:webvh`
/// is deactivated it is refused, though the same mandate from a live one
/// verifies; and an `assertionMethod` proof by a key the principal lists
/// only under `authentication` is refused.
#[tokio::test]
async fn a_mandate_is_checked_as_the_principals_decision() {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
    use affinidi_tdk::did_common::Document;
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};

    let (mut state, _dir) = crate::control_tasks::harness::state().await;
    let delegate = "did:key:z6MkDelegate";
    let key = |seed: u8, did: &str| {
        let mut secret = Secret::generate_ed25519(None, Some(&[seed; 32]));
        secret.id = format!("{did}#key-1");
        secret
    };
    let document = |did: &str, signer: &Secret, assertion: bool| -> Document {
        let mut doc = serde_json::json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#key-1"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": signer.get_public_keymultibase().unwrap(),
            }],
            "authentication": [format!("{did}#key-1")],
        });
        if assertion {
            doc["assertionMethod"] = serde_json::json!([format!("{did}#key-1")]);
        }
        serde_json::from_value(doc).unwrap()
    };
    let live = "did:webvh:QmLive:live.example";
    let dead = "did:webvh:QmDead:dead.example";
    let auth_only = "did:webvh:QmAuth:auth-only.example";
    let (live_key, dead_key, auth_key) = (key(1, live), key(2, dead), key(3, auth_only));
    let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .unwrap();
    client
        .add_did_document(live, document(live, &live_key, true))
        .await;
    client
        .add_did_document(dead, document(dead, &dead_key, true))
        .await;
    client
        .add_did_document(auth_only, document(auth_only, &auth_key, false))
        .await;
    let verifier = did_hosting_common::server::trust_tasks::build_verifier(Some(&client)).unwrap();
    for did in [live, auth_only] {
        verifier.record_deactivation_verdict(did, false);
    }
    verifier.record_deactivation_verdict(dead, true);
    state.trust_tasks_verifier = Some(verifier);

    let evidence = |principal: String, signer: Secret| async move {
        let now = chrono::Utc::now();
        let mandate = serde_json::json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": MANDATE_EVIDENCE_TYPE_URI,
            "issuer": principal,
            "recipient": crate::control_tasks::harness::CONTROL,
            "issuedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "expiresAt": (now + chrono::Duration::hours(1))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": { "delegate": delegate },
        });
        let signed = sign_trust_task(
            &mandate,
            &signer,
            SignOptions::new()
                .with_proof_purpose("assertionMethod")
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .unwrap();
        serde_json::from_value::<authenticate::PayloadDelegationEvidence>(serde_json::json!({
            "kind": MANDATE_EVIDENCE_KIND,
            "credential": signed,
        }))
        .unwrap()
    };

    let ok = evidence(live.to_string(), live_key).await;
    verify_delegation_evidence(&state, live, delegate, "challenge", &ok)
        .await
        .expect("a live principal's mandate verifies");

    let refused = evidence(dead.to_string(), dead_key).await;
    let err = verify_delegation_evidence(&state, dead, delegate, "challenge", &refused)
        .await
        .unwrap_err();
    assert!(err.contains("deactivated"), "{err}");

    let refused = evidence(auth_only.to_string(), auth_key).await;
    verify_delegation_evidence(&state, auth_only, delegate, "challenge", &refused)
        .await
        .expect_err("an authentication-only key made a decision");
}
