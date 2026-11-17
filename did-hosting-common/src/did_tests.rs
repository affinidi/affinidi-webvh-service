//! Tests for [`super`].

use super::*;

/// A self-created DID lists its did:scid alias by default (VTI-KEY-166),
/// and signing the first entry fills the SCID into it.
#[tokio::test]
async fn a_new_document_lists_its_scid_alias_by_default() {
    let doc = build_did_document(
        "example.com",
        "services/control",
        "z6MkKey",
        &Default::default(),
    );
    assert_eq!(
        doc["alsoKnownAs"],
        json!(["did:scid:vh:1:{SCID}?src=example.com/services/control"])
    );

    let secret = Secret::generate_ed25519(None, None);
    let pk = secret.get_public_keymultibase().unwrap();
    let doc = build_did_document("example.com", "services/control", &pk, &Default::default());
    let (scid, jsonl) = create_log_entry(&doc, &secret).await.unwrap();
    let entry: serde_json::Value = serde_json::from_str(jsonl.lines().last().unwrap()).unwrap();
    assert_eq!(
        entry["state"]["alsoKnownAs"],
        json!([format!(
            "did:scid:vh:1:{scid}?src=example.com/services/control"
        )])
    );
}

#[test]
fn the_scid_alias_can_be_left_out() {
    let doc = build_did_document(
        "example.com",
        ".well-known",
        "z6MkKey",
        &DidDocumentOptions {
            omit_scid_alias: true,
            ..Default::default()
        },
    );
    assert!(doc.get("alsoKnownAs").is_none());
}

/// Keyring VTI-18: a self-managed daemon with no mediator used to mint a
/// document with no `service` member at all. The hosting entry alone must
/// be enough to create one.
#[test]
fn hosting_is_advertised_on_a_document_with_no_services() {
    let mut doc = build_did_document("example.com", ".well-known", "z6MkKey", &Default::default());
    assert!(
        doc.get("service").is_none(),
        "precondition: no transport, no services"
    );

    add_webvh_hosting_service(&mut doc, "https://example.com");

    let services = doc["service"]
        .as_array()
        .expect("a service array now exists");
    assert_eq!(services.len(), 1);
    // Exactly the shape VTI's `did-host-http` template emits and a VTA's
    // `servers add` reads: an object endpoint carrying `uri`.
    assert_eq!(services[0]["type"], "WebVHHosting");
    assert_eq!(
        services[0]["serviceEndpoint"],
        json!({ "uri": "https://example.com" })
    );
    assert_eq!(
        services[0]["id"],
        json!(format!("{}#webvh-hosting", doc["id"].as_str().unwrap()))
    );
}

/// With transports present it goes last, keeping the canonical order —
/// TSP, then DIDComm, then HTTP — rather than displacing either.
#[test]
fn hosting_goes_after_the_transport_services() {
    let mut doc = build_did_document(
        "example.com",
        ".well-known",
        "z6MkKey",
        &DidDocumentOptions {
            key_agreement_multibase: Some("z6LSKa"),
            mediator_endpoint: Some("did:web:mediator.example"),
            tsp_endpoint: Some("did:web:mediator.example"),
            omit_scid_alias: false,
        },
    );
    add_webvh_hosting_service(&mut doc, "https://example.com");

    let types: Vec<&str> = doc["service"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["TSPTransport", "DIDCommMessaging", "WebVHHosting"]);
}

/// The `TrustTaskHTTPS` sibling of the VTI-18 fix above: a self-managed
/// daemon builds its document locally rather than through a `vta-sdk`
/// template, so it needs the same explicit entry the template would
/// otherwise have supplied for free.
#[test]
fn trust_task_https_is_advertised_with_the_api_base_as_endpoint() {
    let mut doc = build_did_document("example.com", ".well-known", "z6MkKey", &Default::default());
    add_webvh_hosting_service(&mut doc, "https://example.com");
    add_trust_task_https_service(&mut doc, "https://example.com/api");

    let services = doc["service"].as_array().expect("service array");
    assert_eq!(services.len(), 2);
    assert_eq!(services[1]["type"], "TrustTaskHTTPS");
    // A bare string endpoint (the Trust-Task base) — unlike `WebVHHosting`'s
    // `{ "uri": ... }` object shape.
    assert_eq!(services[1]["serviceEndpoint"], "https://example.com/api");
    assert_eq!(
        services[1]["id"],
        json!(format!("{}#trust-tasks", doc["id"].as_str().unwrap()))
    );
}

/// Contract C4: `{ id: <did>#sign-in-portal, type: SignInPortal,
/// serviceEndpoint: <login page URL> }`, a bare string endpoint.
#[test]
fn sign_in_portal_is_advertised_with_the_login_page_as_endpoint() {
    let mut doc = build_did_document("example.com", ".well-known", "z6MkKey", &Default::default());
    add_trust_task_https_service(&mut doc, "https://example.com/api");
    add_sign_in_portal_service(&mut doc, "https://example.com/login");

    let services = doc["service"].as_array().expect("service array");
    assert_eq!(services[1]["type"], SERVICE_TYPE_SIGN_IN_PORTAL);
    assert_eq!(services[1]["serviceEndpoint"], "https://example.com/login");
    assert_eq!(
        services[1]["id"],
        json!(format!("{}#sign-in-portal", doc["id"].as_str().unwrap()))
    );
}

#[test]
fn only_https_qualifies_for_a_sign_in_portal() {
    assert!(is_sign_in_portal_url("https://example.com/login"));
    assert!(is_sign_in_portal_url("https://example.com:8443/login"));
    // Loopback http is fine for TrustTaskHTTPS, never for a portal.
    assert!(!is_sign_in_portal_url("http://localhost:8534/login"));
    assert!(!is_sign_in_portal_url("http://127.0.0.1:8534/login"));
    assert!(!is_sign_in_portal_url("https://user@example.com/login"));
    assert!(!is_sign_in_portal_url("not a url"));
}

#[test]
fn https_and_loopback_http_qualify_for_trust_task_https() {
    assert!(is_https_or_loopback("https://example.com/api"));
    assert!(is_https_or_loopback("http://localhost:8534/api"));
    assert!(is_https_or_loopback("http://127.0.0.1:8534/api"));
    assert!(is_https_or_loopback("http://[::1]:8534/api"));
}

#[test]
fn plaintext_http_to_a_real_host_does_not_qualify() {
    assert!(!is_https_or_loopback("http://example.com/api"));
    assert!(!is_https_or_loopback("http://webvh.example.com/api"));
    // Lookalikes that only start with a loopback name are not loopback.
    assert!(!is_https_or_loopback("http://localhost.evil.example/api"));
    assert!(!is_https_or_loopback("http://127.0.0.1.evil.example/api"));
    assert!(!is_https_or_loopback("http://localhostevil.example/api"));
    assert!(!is_https_or_loopback("http://user@localhost/api"));
    assert!(!is_https_or_loopback("http://evil.example@127.0.0.1/api"));
    assert!(!is_https_or_loopback("ftp://localhost/api"));
    assert!(!is_https_or_loopback("not a url"));
    assert!(is_https_or_loopback("http://127.0.0.2:8534/api"));
    assert!(is_https_or_loopback("HTTP://LOCALHOST:8534/api"));
}

#[test]
fn encode_host_with_port() {
    let result = encode_host("http://localhost:8085").unwrap();
    assert_eq!(result, "localhost%3A8085");
}

#[test]
fn encode_host_without_port() {
    let result = encode_host("https://example.com").unwrap();
    assert_eq!(result, "example.com");
}

#[test]
fn encode_host_invalid_url() {
    assert!(encode_host("not-a-url").is_err());
}

#[test]
fn build_did_web_id_simple() {
    assert_eq!(
        build_did_web_id("https://example.com", "my-did").unwrap(),
        "did:web:example.com:my-did"
    );
}

#[test]
fn build_did_web_id_with_port() {
    assert_eq!(
        build_did_web_id("http://localhost:8530", "my-did").unwrap(),
        "did:web:localhost%3A8530:my-did"
    );
}

#[test]
fn build_did_web_id_nested_path() {
    assert_eq!(
        build_did_web_id("https://example.com", "people/staff").unwrap(),
        "did:web:example.com:people:staff"
    );
}

#[test]
fn build_did_web_id_well_known() {
    assert_eq!(
        build_did_web_id("https://example.com", ".well-known").unwrap(),
        "did:web:example.com"
    );
}

#[test]
fn build_did_web_id_invalid_url() {
    assert!(build_did_web_id("not-a-url", "test").is_err());
}

#[test]
fn build_did_document_correct_did_id() {
    let doc = build_did_document(
        "example.com%3A8085",
        "mypath",
        "z6Mk...",
        &Default::default(),
    );
    let id = doc["id"].as_str().unwrap();
    assert!(id.starts_with("did:webvh:{SCID}:example.com%3A8085:"));
    assert!(id.ends_with(":mypath"));
}

#[test]
fn build_did_document_nested_path() {
    let doc = build_did_document(
        "example.com",
        "people/staff/glenn",
        "z6Mk...",
        &Default::default(),
    );
    let id = doc["id"].as_str().unwrap();
    assert!(id.contains(":people:staff:glenn"));
    assert!(!id.contains('/'));
}

#[test]
fn build_did_document_structure() {
    let doc = build_did_document("example.com", "test", "z6MkPubKey", &Default::default());
    let context = doc["@context"].as_array().expect("@context is array");
    assert_eq!(
        context,
        &vec![
            serde_json::Value::String("https://www.w3.org/ns/did/v1".to_string()),
            serde_json::Value::String("https://www.w3.org/ns/cid/v1".to_string()),
        ]
    );
    assert!(doc["authentication"].is_array());
    assert!(doc["verificationMethod"].is_array());
    let vm = &doc["verificationMethod"][0];
    assert_eq!(vm["type"], "Multikey");
    assert_eq!(vm["publicKeyMultibase"], "z6MkPubKey");
    assert!(doc.get("service").is_none());
}

#[test]
fn build_did_document_with_vta_didcomm_service() {
    let doc = build_did_document(
        "example.com",
        "test",
        "z6MkPubKey",
        &DidDocumentOptions {
            mediator_endpoint: Some("did:example:mediator"),
            ..Default::default()
        },
    );
    let service = &doc["service"];
    assert!(service.is_array());
    let svc = &service[0];
    assert!(svc["id"].as_str().unwrap().ends_with("#vta-didcomm"));
    assert_eq!(svc["type"], "DIDCommMessaging");
    assert_eq!(svc["serviceEndpoint"][0]["uri"], "did:example:mediator");
    assert_eq!(svc["serviceEndpoint"][0]["accept"][0], "didcomm/v2");
}

/// Locks the local builder's output to the shape produced by the VTA
/// webvh VTA templates. Update both sides together if either ever
/// moves. Covers: contexts, key-0 and key-1 verification method IDs,
/// `#vta-didcomm` service ID, single-entry service array.
#[test]
fn build_did_document_matches_webvh_service_template() {
    let doc = build_did_document(
        "example.com",
        "control",
        "z6MkSigning",
        &DidDocumentOptions {
            key_agreement_multibase: Some("z6LSKA"),
            mediator_endpoint: Some("did:webvh:QmMED:mediator.example.com"),
            ..Default::default()
        },
    );
    let did_id = doc["id"].as_str().unwrap();

    // @context
    assert_eq!(
        doc["@context"][0], "https://www.w3.org/ns/did/v1",
        "first context entry"
    );
    assert_eq!(
        doc["@context"][1], "https://www.w3.org/ns/cid/v1",
        "second context entry (cid v1)"
    );
    assert_eq!(
        doc["@context"].as_array().unwrap().len(),
        2,
        "no extra contexts"
    );

    // Verification methods
    let vm = doc["verificationMethod"].as_array().unwrap();
    assert_eq!(vm.len(), 2);
    assert_eq!(vm[0]["id"], format!("{did_id}#key-0"));
    assert_eq!(vm[0]["type"], "Multikey");
    assert_eq!(vm[0]["controller"], did_id);
    assert_eq!(vm[1]["id"], format!("{did_id}#key-1"));
    assert_eq!(vm[1]["type"], "Multikey");

    // Purpose relations
    assert_eq!(doc["assertionMethod"][0], format!("{did_id}#key-0"));
    assert_eq!(doc["authentication"][0], format!("{did_id}#key-0"));
    assert_eq!(doc["keyAgreement"][0], format!("{did_id}#key-1"));

    // Service — single entry with `#vta-didcomm`
    let service = doc["service"].as_array().unwrap();
    assert_eq!(service.len(), 1, "exactly one service entry");
    assert_eq!(service[0]["id"], format!("{did_id}#vta-didcomm"));
    assert_eq!(service[0]["type"], "DIDCommMessaging");
    assert_eq!(
        service[0]["serviceEndpoint"][0]["uri"],
        "did:webvh:QmMED:mediator.example.com"
    );
    assert_eq!(service[0]["serviceEndpoint"][0]["accept"][0], "didcomm/v2");
}

/// Locks the local builder's TSP output to the `vta-sdk`
/// `did-host-http-didcomm.json` / `did-host-didcomm.json` templates:
/// the `#tsp` `TSPTransport` service is emitted **first** (canonical
/// preference order), before `#vta-didcomm`, and its `serviceEndpoint`
/// is a bare string (the mediator VID), not the DIDComm
/// array-of-objects shape. Update both sides together if either moves.
#[test]
fn build_did_document_matches_webvh_tsp_template_ordering() {
    let doc = build_did_document(
        "example.com",
        "control",
        "z6MkSigning",
        &DidDocumentOptions {
            key_agreement_multibase: Some("z6LSKA"),
            mediator_endpoint: Some("did:webvh:QmMED:mediator.example.com"),
            tsp_endpoint: Some("did:webvh:QmMED:mediator.example.com"),
            omit_scid_alias: false,
        },
    );
    let did_id = doc["id"].as_str().unwrap();
    let service = doc["service"].as_array().unwrap();
    assert_eq!(service.len(), 2, "TSP + DIDComm service entries");

    // TSP first — matches the template's canonical service order.
    assert_eq!(service[0]["id"], format!("{did_id}#tsp"));
    assert_eq!(service[0]["type"], "TSPTransport");
    assert_eq!(
        service[0]["serviceEndpoint"], "did:webvh:QmMED:mediator.example.com",
        "TSP serviceEndpoint is a bare string, not an array-of-objects"
    );

    // DIDComm second, unchanged.
    assert_eq!(service[1]["id"], format!("{did_id}#vta-didcomm"));
    assert_eq!(service[1]["type"], "DIDCommMessaging");
    assert_eq!(
        service[1]["serviceEndpoint"][0]["uri"],
        "did:webvh:QmMED:mediator.example.com"
    );
}

// ---- service_types_from_doc ----

#[test]
fn service_types_reads_bare_string_and_array_type_shapes() {
    // `did-host-*` templates emit a bare string; `ai-agent-peer` emits
    // a single-element array. Both must be understood.
    let doc = serde_json::json!({
        "service": [
            { "id": "#webvh-hosting", "type": "WebVHHosting" },
            { "id": "#auth", "type": ["Authentication"] },
        ]
    });
    assert_eq!(
        service_types_from_doc(&doc),
        vec!["WebVHHosting".to_string(), "Authentication".to_string()]
    );
}

#[test]
fn service_types_preserves_document_order_and_dedupes() {
    let doc = serde_json::json!({
        "service": [
            { "type": "TSPTransport" },
            { "type": "DIDCommMessaging" },
            { "type": "TSPTransport" },
        ]
    });
    // TSP first (the canonical template order) and the repeat collapses.
    assert_eq!(
        service_types_from_doc(&doc),
        vec!["TSPTransport".to_string(), "DIDCommMessaging".to_string()]
    );
}

#[test]
fn service_types_handles_multi_type_service() {
    let doc = serde_json::json!({
        "service": [{ "type": ["TSPTransport", "DIDCommMessaging"] }]
    });
    let types = service_types_from_doc(&doc);
    assert!(advertises_tsp(&types));
    assert!(advertises_didcomm(&types));
}

#[test]
fn service_types_absent_or_malformed_yields_empty() {
    assert!(service_types_from_doc(&serde_json::json!({})).is_empty());
    // `service` present but not an array.
    assert!(service_types_from_doc(&serde_json::json!({ "service": "nope" })).is_empty());
    // Entries with no usable `type` contribute nothing.
    let doc = serde_json::json!({ "service": [{ "id": "#x" }, { "type": 42 }, { "type": "" }] });
    assert!(service_types_from_doc(&doc).is_empty());
}

/// The read side must agree with the write side: whatever
/// `build_did_document` emits is what `service_types_from_doc` reports.
#[test]
fn service_types_round_trips_build_did_document() {
    let doc = build_did_document(
        "example.com",
        "alice",
        "z6MkTest",
        &DidDocumentOptions {
            key_agreement_multibase: None,
            mediator_endpoint: Some("did:webvh:QmMED:mediator.example.com"),
            tsp_endpoint: Some("did:webvh:QmMED:mediator.example.com"),
            omit_scid_alias: false,
        },
    );
    let types = service_types_from_doc(&doc);
    // TSP before DIDComm, matching the canonical template order.
    assert_eq!(
        types,
        vec!["TSPTransport".to_string(), "DIDCommMessaging".to_string()]
    );
    assert!(advertises_tsp(&types));
    assert!(advertises_didcomm(&types));
}

/// A conforming did:webvh resolver injects `#whois`
/// (`LinkedVerifiablePresentation`) and `#files` (`relativeRef`) into
/// every document. They are not operator-declared and must not surface
/// as advertised services — otherwise every resolved DID grows a
/// permanent, meaningless `Other` badge.
#[test]
fn service_types_skips_resolver_injected_implicit_services() {
    let did = "did:webvh:QmSCID:webvh.example.com:server1";
    let doc = serde_json::json!({
        "service": [
            {
                "id": format!("{did}#webvh-hosting"),
                "type": "WebVHHosting",
                "serviceEndpoint": { "uri": "https://webvh.example.com/server1" }
            },
            {
                "id": format!("{did}#whois"),
                "type": "LinkedVerifiablePresentation",
                "serviceEndpoint": "https://webvh.example.com/server1/whois.vp"
            },
            {
                "id": format!("{did}#files"),
                "type": "relativeRef",
                "serviceEndpoint": "https://webvh.example.com/server1/files"
            },
        ]
    });
    assert_eq!(
        service_types_from_doc(&doc),
        vec!["WebVHHosting".to_string()],
        "only the operator-declared service should surface"
    );
}

/// The filter keys on the `id` fragment, not the type — an operator who
/// declares a `LinkedVerifiablePresentation` under their own fragment is
/// genuinely advertising it and keeps the badge.
#[test]
fn service_types_keeps_operator_declared_linked_vp() {
    let did = "did:webvh:QmSCID:example.com:x";
    let doc = serde_json::json!({
        "service": [{
            "id": format!("{did}#my-presentation"),
            "type": "LinkedVerifiablePresentation",
            "serviceEndpoint": "https://example.com/vp"
        }]
    });
    assert_eq!(
        service_types_from_doc(&doc),
        vec!["LinkedVerifiablePresentation".to_string()]
    );
}

#[test]
fn implicit_service_predicate_matches_only_whois_and_files() {
    assert!(is_implicit_webvh_service("did:webvh:Q:h:p#whois"));
    assert!(is_implicit_webvh_service("did:webvh:Q:h:p#files"));
    assert!(!is_implicit_webvh_service("did:webvh:Q:h:p#tsp"));
    assert!(!is_implicit_webvh_service("did:webvh:Q:h:p#vta-didcomm"));
    assert!(!is_implicit_webvh_service("did:webvh:Q:h:p#webvh-hosting"));
    // Substring, not suffix, must not match.
    assert!(!is_implicit_webvh_service("did:webvh:Q:h:p#whois-extra"));
    assert!(!is_implicit_webvh_service(""));
}

/// The resolver path feeds `is_implicit_webvh_service` a `Url::as_str()`,
/// not a raw string. Pin that the `did:` scheme round-trips its fragment
/// intact — otherwise the filter silently stops matching and every server
/// grows an `Other` badge again.
#[test]
fn implicit_predicate_matches_url_parsed_service_ids() {
    let base =
        "did:webvh:QmRUN4vrMp6cS1xqWSH46bCipf9W95VrFDyyFBm8XXcZ1E:webvh.storm.ws:webvh-server1"; // retired-name-ok: a real DID
    for frag in ["whois", "files"] {
        let parsed = url::Url::parse(&format!("{base}#{frag}")).expect("parse service id");
        assert!(
            is_implicit_webvh_service(parsed.as_str()),
            "Url::as_str() must preserve the #{frag} fragment; got {}",
            parsed.as_str()
        );
    }
    let hosting = url::Url::parse(&format!("{base}#webvh-hosting")).expect("parse");
    assert!(!is_implicit_webvh_service(hosting.as_str()));
}

#[test]
fn service_types_empty_when_document_advertises_none() {
    let doc = build_did_document(
        "example.com",
        "alice",
        "z6MkTest",
        &DidDocumentOptions {
            key_agreement_multibase: None,
            mediator_endpoint: None,
            tsp_endpoint: None,
            omit_scid_alias: false,
        },
    );
    assert!(service_types_from_doc(&doc).is_empty());
    assert!(!advertises_tsp(&service_types_from_doc(&doc)));
}
