//! Tests for [`super`]: DID shapes, template selection and the setup flows.

use super::*;

/// Mint a plain `vta_sdk::sealed_transfer::BootstrapRequest` and
/// persist its seed to a file. Used by the export/import-migration
/// tests, which seal to a *plain* recipient request (not the
/// VP-framed shape the offline-setup wizard now produces).
fn write_plain_bootstrap_request_for_test(
    request_path: &Path,
    seed_path: &Path,
    label: Option<&str>,
) {
    use rand::RngExt;
    use vta_sdk::sealed_transfer::{BootstrapRequest, generate_ed25519_keypair};

    let (seed, ed_pub) = generate_ed25519_keypair();
    let mut nonce = [0u8; 16];
    rand::rng().fill(&mut nonce);
    let request = BootstrapRequest::new(ed_pub, nonce, label.map(String::from));
    let request_json = serde_json::to_string_pretty(&request).expect("serialize request");
    std::fs::write(request_path, request_json).expect("write request");
    let seed_bytes: [u8; 32] = *seed;
    std::fs::write(seed_path, seed_bytes).expect("write seed");
}

#[tokio::test]
async fn offline_request_produces_valid_bootstrap_request_and_in_memory_seed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let request_path = tmp.path().join("bootstrap-request.json");

    let ask = build_webvh_provision_ask(
        "webvh-test-ctx",
        &WebvhDidShape::DidcommOnly {
            mediator_did: "did:key:z6MkMockMediator",
        },
        Some("did-hosting-control-test"),
    );
    let info = write_offline_bootstrap_request(&request_path, &ask)
        .await
        .expect("write request");

    // Request file: VP-framed BootstrapRequest as produced by
    // `ProvisionRequestBuilder::sign_ephemeral`.
    let raw = std::fs::read_to_string(&request_path).expect("read request");
    let parsed: vta_sdk::provision_integration::BootstrapRequest =
        serde_json::from_str(&raw).expect("parse VP request");
    assert!(
        parsed.holder.starts_with("did:key:z6Mk"),
        "holder must be an Ed25519 did:key, got {}",
        parsed.holder
    );
    assert_eq!(parsed.label.as_deref(), Some("did-hosting-control-test"));
    // Nonce is base64url(16 bytes) — 22 chars no padding.
    assert_eq!(parsed.nonce.len(), 22, "nonce length");

    // Returned info matches the written artifact, and the seed is
    // returned in memory only — the helper doesn't touch disk for
    // it.
    assert_eq!(info.client_did, parsed.holder);
    assert_eq!(info.nonce, parsed.nonce);
    assert_eq!(info.request_path, request_path);
    assert_ne!(info.seed, [0u8; 32], "seed must not be all zeros");
}

/// Full webvh ↔ VTA sealed-bootstrap roundtrip in-process.
///
/// Phase 1 (webvh): `write_offline_bootstrap_request` produces the
/// VP-framed BootstrapRequest the operator hands to the VTA admin.
/// Phase 2 (simulated VTA): we verify that VP, build a synthetic
/// `TemplateBootstrapPayload`, and seal it with `seal_payload` —
/// the same primitive `vta bootstrap provision-integration` uses on
/// the VTA side. Phase 3 (webvh): `open_offline_bootstrap_response`
/// opens the armored bundle, verifies the OOB digest, and surfaces
/// the integration DID + signing keys + key-agreement keys + admin
/// material + VTA trust bundle.
///
/// This is the contract test for the end-to-end offline-bootstrap
/// shape did-hosting-server, did-hosting-control, and webvh-witness setup
/// wizards depend on. A regression in any of:
/// - the VP-framed request sign/verify path (provision_integration);
/// - HPKE seal / open (sealed_transfer);
/// - `TemplateBootstrapPayload` field shape;
/// - SHA-256 digest binding;
/// - Ed25519→X25519 derivation symmetry between consumer and
///   producer;
/// would surface here rather than the next time an operator runs
/// the wizard against a real VTA.
#[tokio::test]
async fn offline_bootstrap_full_webvh_to_vta_roundtrip() {
    use std::collections::BTreeMap;
    use vta_sdk::provision_integration::payload::{
        DidKeyMaterial, KeyPair, TemplateBootstrapConfig, TemplateBootstrapPayload, TemplateOutput,
        VtaTrustBundle,
    };
    use vta_sdk::sealed_transfer::bundle::AssertionProof;
    use vta_sdk::sealed_transfer::{
        InMemoryNonceStore, ProducerAssertion, SealedPayloadV1, armor, bundle_digest, seal_payload,
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let request_path = tmp.path().join("bootstrap-request.json");

    // -------- Phase 1: webvh produces the VP-framed request ----------
    let ask = build_webvh_provision_ask(
        "webvh-roundtrip-ctx",
        &WebvhDidShape::DidcommOnly {
            mediator_did: "did:key:z6MkMockMediator",
        },
        Some("roundtrip-full"),
    );
    let info = write_offline_bootstrap_request(&request_path, &ask)
        .await
        .expect("write request");

    // -------- Phase 2: simulated VTA opens, builds, seals ------------
    // Verify the VP exactly as a real VTA would, surfacing the holder
    // and the recipient X25519 pubkey for HPKE.
    let raw_vp = std::fs::read_to_string(&request_path).expect("read request");
    let request: vta_sdk::provision_integration::BootstrapRequest =
        serde_json::from_str(&raw_vp).expect("parse VP");
    let verified = request.verify().expect("VP verifies");
    let recipient_x25519_pub = verified
        .decode_client_x25519_pub()
        .expect("derive X25519 pub");
    let bundle_id = verified.decode_nonce().expect("decode nonce");
    // Sanity: the consumer-side info matches what the VTA would see.
    assert_eq!(verified.holder(), info.client_did);

    // Synthetic VTA-issued material. Keys are placeholders — the
    // sealing flow doesn't crypto-verify the inner secrets, only the
    // envelope. The webvh-side consumer is responsible for using the
    // returned multibase strings to reconstruct working `Secret`s.
    let integration_did = "did:webvh:roundtrip:integration.example.com";
    let admin_did = "did:key:z6MkAdminRotated";
    let mut secrets = BTreeMap::new();
    secrets.insert(
        integration_did.to_string(),
        DidKeyMaterial {
            did: integration_did.into(),
            signing_key: KeyPair {
                key_id: format!("{integration_did}#key-0"),
                public_key_multibase: "z6MkSigningPub".into(),
                private_key_multibase: "zSigningPriv".into(),
            },
            ka_key: KeyPair {
                key_id: format!("{integration_did}#key-1"),
                public_key_multibase: "z6LSKaPub".into(),
                private_key_multibase: "zKaPriv".into(),
            },
        },
    );
    secrets.insert(
        admin_did.to_string(),
        DidKeyMaterial {
            did: admin_did.into(),
            signing_key: KeyPair {
                key_id: format!("{admin_did}#key-0"),
                public_key_multibase: "z6MkAdminPub".into(),
                private_key_multibase: "zAdminPriv".into(),
            },
            ka_key: KeyPair {
                key_id: format!("{admin_did}#key-1"),
                public_key_multibase: "z6LSAdminKa".into(),
                private_key_multibase: "zAdminKaPriv".into(),
            },
        },
    );
    let payload = TemplateBootstrapPayload {
        authorization: serde_json::json!({
            "type": ["VerifiableCredential", "VtaAuthorizationCredential"],
            "credentialSubject": { "id": admin_did, "vtaContext": "webvh-roundtrip-ctx" },
        }),
        secrets,
        config: TemplateBootstrapConfig {
            template_name: "did-hosting-server".into(),
            template_kind: "integration".into(),
            did_document: serde_json::json!({ "id": integration_did }),
            outputs: vec![TemplateOutput::WebvhLog {
                did: integration_did.into(),
                log: "{\"versionId\":\"1-roundtrip\"}\n".into(),
            }],
            vta_url: Some("https://vta.example.com".into()),
            vta_trust: VtaTrustBundle {
                vta_did: "did:webvh:vta.example.com".into(),
                vta_did_document: serde_json::json!({ "id": "did:webvh:vta.example.com" }),
                vta_did_log: None,
            },
        },
    };
    let sealed_payload = SealedPayloadV1::TemplateBootstrap(Box::new(payload));

    // PinnedOnly producer assertion: the consumer trusts the
    // out-of-band digest as the integrity anchor. Mirrors the
    // simplest VTA configuration.
    let producer = ProducerAssertion {
        producer_did: "did:key:z6MkProducerSyntheticForTest".into(),
        proof: AssertionProof::PinnedOnly,
    };
    let nonce_store = InMemoryNonceStore::default();
    let bundle = seal_payload(
        &recipient_x25519_pub,
        bundle_id,
        producer,
        &sealed_payload,
        &nonce_store,
    )
    .await
    .expect("seal");
    let digest = bundle_digest(&bundle);
    let armored = armor::encode(&bundle);

    // -------- Phase 3: webvh opens the bundle ------------------------
    let result = open_offline_bootstrap_response(&armored, &digest, &info.seed)
        .expect("open sealed response");

    // Round-trip assertions: every operator-facing field must survive
    // the seal/open trip intact.
    assert_eq!(result.did, integration_did);
    assert_eq!(result.signing_key_multibase, "zSigningPriv");
    assert_eq!(result.key_agreement_multibase, "zKaPriv");
    assert_eq!(result.vta_did, "did:webvh:vta.example.com");
    assert_eq!(result.vta_url.as_deref(), Some("https://vta.example.com"));
    // `WebvhLog` output → log entry surfaces under `log_entry` for
    // the webvh wizard to write to disk.
    assert_eq!(
        result.log_entry.as_deref(),
        Some("{\"versionId\":\"1-roundtrip\"}\n")
    );
    // Admin rollover material — the original bug silently dropped
    // these on the floor. The wizard needs them to seed the ACL
    // with the operator's long-term identity.
    assert_eq!(result.admin_did.as_deref(), Some(admin_did));
    assert_eq!(
        result.admin_signing_key_multibase.as_deref(),
        Some("zAdminPriv")
    );

    // Bad digest must reject in constant time. Flip the first hex
    // character; constant-time-eq still rejects, and the failure
    // path is what the operator sees if the OOB digest was tampered.
    let mut bad = digest.clone();
    bad.replace_range(0..1, if bad.starts_with('0') { "1" } else { "0" });
    let err = open_offline_bootstrap_response(&armored, &bad, &info.seed)
        .expect_err("bad digest must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("digest") || msg.contains("Digest"),
        "expected digest-mismatch error, got: {msg}"
    );
}

#[tokio::test]
async fn sealed_did_secrets_export_open_roundtrip_pinned_only() {
    // PinnedOnly path: exporter emits no signature, opener trusts
    // only the OOB digest.
    let tmp = tempfile::tempdir().expect("tempdir");
    let request_path = tmp.path().join("bootstrap-request.json");
    let seed_path = tmp.path().join("seed.bin");
    let bundle_path = tmp.path().join("sealed.txt");

    // Migration / export-sealed seals to a *plain* BootstrapRequest
    // (created by `pnm bootstrap request` on the recipient side),
    // not the VP-framed shape the offline-setup wizard produces.
    write_plain_bootstrap_request_for_test(&request_path, &seed_path, Some("roundtrip-test"));

    let producer_did = "did:webvh:QmPROD:producer.example.com".to_string();
    let exported_did = "did:webvh:QmEXP:example.com:services/export".to_string();
    let signing_mb = "z3uFakeEd25519SigningKey".to_string();
    let ka_mb = "z3uFakeX25519KaKey".to_string();

    let export = export_sealed_did_secrets(
        &request_path,
        &bundle_path,
        &producer_did,
        &exported_did,
        signing_mb.clone(),
        ka_mb.clone(),
        ExportAssertionMode::PinnedOnly,
    )
    .await
    .expect("export");

    assert_eq!(export.out_path, bundle_path);
    assert_eq!(export.digest.len(), 64, "SHA-256 hex");
    assert!(export.recipient_did.starts_with("did:key:z6Mk"));
    assert_eq!(export.bundle_id_hex.len(), 32, "16 bytes hex");

    let armor = std::fs::read_to_string(&bundle_path).expect("read bundle");
    let opened = open_sealed_did_secrets(&armor, &export.digest, &seed_path, None).expect("open");

    assert_eq!(opened.did, exported_did);
    assert_eq!(opened.signing_key_multibase, signing_mb);
    assert_eq!(opened.key_agreement_multibase, ka_mb);
    assert_eq!(opened.producer_did, producer_did);
    assert!(
        !opened.assertion_verified,
        "PinnedOnly should not report verified"
    );

    // Digest binding: a flipped digest must reject the bundle.
    let mut bad = export.digest.clone();
    bad.replace_range(0..1, if bad.starts_with('0') { "1" } else { "0" });
    let err = open_sealed_did_secrets(&armor, &bad, &seed_path, None).expect_err("bad digest");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("digest"),
        "expected digest mismatch error, got {msg}"
    );
}

#[tokio::test]
async fn sealed_did_secrets_export_open_roundtrip_did_signed() {
    // DidSigned path: exporter signs with a real Ed25519 key; opener
    // pins the matching pubkey and verifies the assertion.
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    let tmp = tempfile::tempdir().expect("tempdir");
    let request_path = tmp.path().join("bootstrap-request.json");
    let seed_path = tmp.path().join("seed.bin");
    let bundle_path = tmp.path().join("sealed.txt");

    // Same migration path as the PinnedOnly test — plain
    // BootstrapRequest, not VP-framed.
    write_plain_bootstrap_request_for_test(&request_path, &seed_path, Some("ds-test"));

    // Producer-side signing key — generate fresh so we have both
    // halves available for the round-trip.
    let signer = Secret::generate_ed25519(None, None);
    let signer_priv = signer.get_private_keymultibase().expect("priv mb");
    let signer_pub_mb = signer.get_public_keymultibase().expect("pub mb");

    // Decode the pub multibase back to raw [u8; 32] for the opener.
    let (_, pub_raw) = multibase::decode(&signer_pub_mb).expect("decode pub mb");
    let signer_pub_bytes: [u8; 32] =
        if pub_raw.len() == 34 && pub_raw[0] == 0xed && pub_raw[1] == 0x01 {
            pub_raw[2..].try_into().expect("32 bytes")
        } else {
            pub_raw[..].try_into().expect("32 bytes")
        };

    let producer_did = "did:webvh:QmPROD:producer.example.com".to_string();
    let exported_did = "did:webvh:QmEXP:example.com:services/export".to_string();
    let ka_mb = "z3uFakeX25519KaKey".to_string();

    let export = export_sealed_did_secrets(
        &request_path,
        &bundle_path,
        &producer_did,
        &exported_did,
        signer_priv.clone(),
        ka_mb.clone(),
        ExportAssertionMode::DidSigned {
            signing_key_multibase: signer_priv.clone(),
            verification_method: format!("{producer_did}#key-0"),
        },
    )
    .await
    .expect("export");

    let armor = std::fs::read_to_string(&bundle_path).expect("read bundle");

    // With the correct pinned pubkey, verification succeeds.
    let opened =
        open_sealed_did_secrets(&armor, &export.digest, &seed_path, Some(&signer_pub_bytes))
            .expect("open");
    assert!(opened.assertion_verified, "DidSigned should verify");
    assert_eq!(opened.producer_did, producer_did);

    // With a wrong pinned pubkey, verification fails.
    let mut wrong = signer_pub_bytes;
    wrong[0] ^= 0x01;
    let err = open_sealed_did_secrets(&armor, &export.digest, &seed_path, Some(&wrong))
        .expect_err("wrong pubkey");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("didsigned") || msg.contains("signature") || msg.contains("verify"),
        "expected signature verification failure, got {msg}"
    );
}

#[tokio::test]
async fn offline_request_unique_client_did_per_call() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let r1 = tmp.path().join("r1.json");
    let r2 = tmp.path().join("r2.json");

    let ask = || {
        build_webvh_provision_ask(
            "webvh-test-ctx",
            &WebvhDidShape::DidcommOnly {
                mediator_did: "did:key:z6MkMockMediator",
            },
            None,
        )
    };
    let a = write_offline_bootstrap_request(&r1, &ask()).await.unwrap();
    let b = write_offline_bootstrap_request(&r2, &ask()).await.unwrap();

    // Each call mints a fresh Ed25519 seed → different did:key,
    // different nonce, different seed.
    assert_ne!(a.client_did, b.client_did, "new keypair per call");
    assert_ne!(a.nonce, b.nonce, "new nonce per call");
    assert_ne!(a.seed, b.seed, "new seed per call");
}

#[test]
fn build_ask_hosted_serverless_folds_path_no_webvh_vars() {
    let ask = build_webvh_provision_ask(
        "webvh",
        &WebvhDidShape::Hosted {
            origin: "https://did.example.com",
            did_path: "services/control",
            mediator_did: Some("did:key:z6MkMed"),
            transport: TransportSelection::Both,
            remote: None,
        },
        Some("lbl"),
    );
    // Mediator-configured → the no-WebVHHosting DIDComm template. The DID
    // is still URL-hosted: the `URL` var is set so the VTA publishes the
    // log at the folded path, even though it isn't advertised as a service.
    assert_eq!(
        ask.integration_template.as_deref(),
        Some("did-host-didcomm")
    );
    assert_eq!(
        ask.integration_template_vars.get("URL"),
        Some(&serde_json::Value::String(
            "https://did.example.com/services/control".into()
        )),
    );
    assert_eq!(
        ask.integration_template_vars.get("MEDIATOR_DID"),
        Some(&serde_json::Value::String("did:key:z6MkMed".into())),
    );
    assert!(!ask.integration_template_vars.contains_key("WEBVH_SERVER"));
    assert_eq!(ask.label.as_deref(), Some("lbl"));
}

#[test]
fn build_ask_hosted_tsp_only_uses_tsp_template() {
    let ask = build_webvh_provision_ask(
        "webvh",
        &WebvhDidShape::Hosted {
            origin: "https://did.example.com",
            did_path: "services/control",
            mediator_did: Some("did:key:z6MkMed"),
            transport: TransportSelection::Tsp,
            remote: None,
        },
        None,
    );
    assert_eq!(ask.integration_template.as_deref(), Some("did-host-tsp"));
    assert_eq!(
        ask.integration_template_vars.get("MEDIATOR_DID"),
        Some(&serde_json::Value::String("did:key:z6MkMed".into())),
    );
    // URL-hosted even though TSP-only advertises no HTTP endpoint.
    assert_eq!(
        ask.integration_template_vars.get("URL"),
        Some(&serde_json::Value::String(
            "https://did.example.com/services/control".into()
        )),
    );
}

#[test]
fn build_ask_hosted_didcomm_selection_advertises_tsp_and_didcomm() {
    // Both/Didcomm map to did-host-didcomm, which advertises TSP + DIDComm
    // and NO WebVHHosting endpoint.
    let ask = build_webvh_provision_ask(
        "webvh",
        &WebvhDidShape::Hosted {
            origin: "https://did.example.com",
            did_path: "services/control",
            mediator_did: Some("did:key:z6MkMed"),
            transport: TransportSelection::Didcomm,
            remote: None,
        },
        None,
    );
    assert_eq!(
        ask.integration_template.as_deref(),
        Some("did-host-didcomm")
    );
}

#[test]
fn build_ask_hosted_no_mediator_uses_daemon_template() {
    let ask = build_webvh_provision_ask(
        "webvh",
        &WebvhDidShape::Hosted {
            origin: "https://did.example.com",
            did_path: ".well-known",
            mediator_did: None,
            transport: TransportSelection::Both,
            remote: None,
        },
        None,
    );
    assert_eq!(ask.integration_template.as_deref(), Some("did-host-http"));
    // `.well-known` carries no path segment, so the URL is the origin.
    assert_eq!(
        ask.integration_template_vars.get("URL"),
        Some(&serde_json::Value::String("https://did.example.com".into())),
    );
}

#[test]
fn build_ask_hosted_server_managed_injects_webvh_vars_and_keeps_origin() {
    let ask = build_webvh_provision_ask(
        "webvh",
        &WebvhDidShape::Hosted {
            origin: "https://daemon.example.com",
            // ignored for the URL in server-managed mode
            did_path: "ignored",
            mediator_did: None,
            transport: TransportSelection::Both,
            remote: Some(WebvhRemoteTarget {
                server_id: "srv-1",
                domain: Some("hosting.example.com"),
                path: Some("acme"),
            }),
        },
        None,
    );
    // URL stays the daemon's own origin (not folded with did_path).
    assert_eq!(
        ask.integration_template_vars.get("URL"),
        Some(&serde_json::Value::String(
            "https://daemon.example.com".into()
        )),
    );
    assert_eq!(
        ask.integration_template_vars.get("WEBVH_SERVER"),
        Some(&serde_json::Value::String("srv-1".into())),
    );
    assert_eq!(
        ask.integration_template_vars.get("WEBVH_DOMAIN"),
        Some(&serde_json::Value::String("hosting.example.com".into())),
    );
    assert_eq!(
        ask.integration_template_vars.get("WEBVH_PATH"),
        Some(&serde_json::Value::String("acme".into())),
    );
}

#[test]
fn build_ask_server_managed_omits_domain_when_none() {
    let ask = build_webvh_provision_ask(
        "webvh",
        &WebvhDidShape::Hosted {
            origin: "https://daemon.example.com",
            did_path: ".well-known",
            mediator_did: None,
            transport: TransportSelection::Both,
            remote: Some(WebvhRemoteTarget {
                server_id: "srv-1",
                domain: None,
                path: Some("acme"),
            }),
        },
        None,
    );
    assert!(ask.integration_template_vars.contains_key("WEBVH_SERVER"));
    assert!(!ask.integration_template_vars.contains_key("WEBVH_DOMAIN"));
    assert!(ask.integration_template_vars.contains_key("WEBVH_PATH"));
}

#[test]
fn build_ask_didcomm_only_uses_server_template_no_url() {
    let ask = build_webvh_provision_ask(
        "webvh",
        &WebvhDidShape::DidcommOnly {
            mediator_did: "did:key:z6MkMed",
        },
        None,
    );
    assert_eq!(
        ask.integration_template.as_deref(),
        Some("did-host-didcomm")
    );
    assert!(!ask.integration_template_vars.contains_key("URL"));
    assert_eq!(
        ask.integration_template_vars.get("MEDIATOR_DID"),
        Some(&serde_json::Value::String("did:key:z6MkMed".into())),
    );
}
