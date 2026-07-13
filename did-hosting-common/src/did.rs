use std::sync::Arc;

use affinidi_tdk::dids::{DID, KeyType};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::parameters::Parameters;
use serde_json::json;

use crate::error::{Result, WebVHError};

/// Generate a new Ed25519 did:key identity.
///
/// Returns `(did, secret)` where `did` is the DID string and `secret`
/// is the signing key needed for authentication and DID operations.
pub fn generate_ed25519_identity() -> Result<(String, Secret)> {
    DID::generate_did_key(KeyType::Ed25519)
        .map_err(|e| WebVHError::DIDComm(format!("failed to generate did:key: {e}")))
}

/// Encode a server URL into the host component used in `did:webvh` identifiers.
///
/// Ports are percent-encoded (`:` becomes `%3A`), matching the did:webvh spec.
///
/// # Examples
/// - `http://localhost:8085` -> `localhost%3A8085`
/// - `https://example.com`   -> `example.com`
pub fn encode_host(server_url: &str) -> Result<String> {
    let parsed = url::Url::parse(server_url)
        .map_err(|e| WebVHError::DIDComm(format!("invalid server URL: {e}")))?;

    let host_str = parsed
        .host_str()
        .ok_or_else(|| WebVHError::DIDComm("server URL has no host".into()))?;

    Ok(match parsed.port() {
        Some(port) => format!("{host_str}%3A{port}"),
        None => host_str.to_string(),
    })
}

/// Construct a `did:web` identifier from a server URL and mnemonic.
///
/// Follows the did:web method spec:
/// - `did:web:example.com` for the root DID (mnemonic = `.well-known`)
/// - `did:web:host:path` for path-based DIDs
/// - Ports are percent-encoded (`:` → `%3A`)
/// - Path separators (`/`) become `:`
///
/// # Examples
/// ```
/// # use did_hosting_common::did::build_did_web_id;
/// assert_eq!(build_did_web_id("https://example.com", "my-did").unwrap(), "did:web:example.com:my-did");
/// assert_eq!(build_did_web_id("https://example.com", ".well-known").unwrap(), "did:web:example.com");
/// ```
pub fn build_did_web_id(server_url: &str, mnemonic: &str) -> Result<String> {
    let host = encode_host(server_url)?;
    if mnemonic == ".well-known" {
        Ok(format!("did:web:{host}"))
    } else {
        let path = mnemonic.replace('/', ":");
        Ok(format!("did:web:{host}:{path}"))
    }
}

/// Options for building a DID document beyond the required signing key.
#[derive(Default)]
pub struct DidDocumentOptions<'a> {
    /// X25519 key agreement public key (multibase-encoded). When set, a
    /// `keyAgreement` verification method (`#key-1`) is added to the document.
    /// Required for DIDComm encrypted messaging.
    pub key_agreement_multibase: Option<&'a str>,
    /// Mediator DID or URL for the `DIDCommMessaging` service endpoint.
    /// When set, a `DIDCommMessaging` service is added so other parties
    /// know how to route messages to this DID.
    pub mediator_endpoint: Option<&'a str>,
    /// Mediator DID (or URL) for the `TSPTransport` service endpoint.
    /// When set, a `TSPTransport` service (`#tsp`) is added so other
    /// parties know they can reach this DID over the Trust Spanning
    /// Protocol. Emitted *before* `DIDCommMessaging` to match the VTA
    /// webvh templates' canonical preference order (TSP over DIDComm) —
    /// see `resolve_transport` / `didcomm_profile::resolve_mediator_did`.
    pub tsp_endpoint: Option<&'a str>,
}

/// Build a standard DID document with `{SCID}` placeholders.
///
/// The returned JSON value uses the did:webvh identifier format with an
/// Ed25519 verification method at `#key-0`. Additional keys and services
/// can be added via [`DidDocumentOptions`].
///
/// An empty `mnemonic` builds the **root** DID for the host —
/// `did:webvh:{SCID}:<host>` with no path segments, which per did:webvh
/// resolves at `https://<host>/.well-known/did.jsonl`. Without this an
/// empty mnemonic would emit a trailing `:` and a malformed identifier.
pub fn build_did_document(
    host: &str,
    mnemonic: &str,
    public_key_multibase: &str,
    opts: &DidDocumentOptions<'_>,
) -> serde_json::Value {
    let did_path = mnemonic.replace('/', ":");
    let did_id = if did_path.is_empty() {
        format!("did:webvh:{{SCID}}:{host}")
    } else {
        format!("did:webvh:{{SCID}}:{host}:{did_path}")
    };

    let mut vm = vec![json!({
        "id": format!("{did_id}#key-0"),
        "type": "Multikey",
        "controller": &did_id,
        "publicKeyMultibase": public_key_multibase,
    })];

    // @context matches the upstream webvh VTA templates' output (W3C DID v1 +
    // CID v1). Keep these two in sync: the setup wizards have the VTA render
    // most webvh DIDs via the template, but bootstrap_did() still builds the
    // `.well-known` root DID locally with this helper — both shapes must be
    // identical so callers and resolvers don't see drift.
    let mut doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://www.w3.org/ns/cid/v1",
        ],
        "id": did_id,
        "authentication": [format!("{did_id}#key-0")],
        "assertionMethod": [format!("{did_id}#key-0")],
    });

    // Add X25519 key agreement key
    if let Some(ka_key) = opts.key_agreement_multibase {
        vm.push(json!({
            "id": format!("{did_id}#key-1"),
            "type": "Multikey",
            "controller": &did_id,
            "publicKeyMultibase": ka_key,
        }));
        doc["keyAgreement"] = json!([format!("{did_id}#key-1")]);
    }

    doc["verificationMethod"] = json!(vm);

    // Add services. Service ids (`#tsp`, `#vta-didcomm`) and the
    // ordering (TSP first, then DIDComm) match the VTA webvh templates
    // — see `vta-sdk`'s `did-host-*didcomm.json`. The `#vta-didcomm`
    // fragment is deliberate (not the older `#didcomm` convention).
    let mut services = vec![];
    if let Some(tsp) = opts.tsp_endpoint {
        // `TSPTransport`'s `serviceEndpoint` is a bare string (the
        // mediator VID), unlike DIDComm's array-of-objects shape.
        services.push(json!({
            "id": format!("{did_id}#tsp"),
            "type": "TSPTransport",
            "serviceEndpoint": tsp,
        }));
    }
    if let Some(mediator) = opts.mediator_endpoint {
        services.push(json!({
            "id": format!("{did_id}#vta-didcomm"),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{
                "accept": ["didcomm/v2"],
                "uri": mediator,
            }],
        }));
    }
    if !services.is_empty() {
        doc["service"] = json!(services);
    }

    doc
}

// ---------------------------------------------------------------------------
// Service-type introspection
// ---------------------------------------------------------------------------

/// HTTP DID-log hosting endpoint (`did-host-http*` templates).
pub const SERVICE_TYPE_WEBVH_HOSTING: &str = "WebVHHosting";
/// Legacy read-only alias for [`SERVICE_TYPE_WEBVH_HOSTING`]. Never written;
/// accepted on read per `docs/did-hosting-client-crate-spec.md` §5.
pub const SERVICE_TYPE_WEBVH_HOSTING_LEGACY: &str = "WebVHHostingService";
/// Trust Spanning Protocol transport (`#tsp`).
pub const SERVICE_TYPE_TSP: &str = "TSPTransport";
/// DIDComm v2 transport (`#vta-didcomm`).
pub const SERVICE_TYPE_DIDCOMM: &str = "DIDCommMessaging";

/// True for the services the did:webvh spec *implies* rather than the
/// operator declaring.
///
/// A conforming did:webvh resolver synthesises `#whois`
/// (`LinkedVerifiablePresentation`) and `#files` (`relativeRef`) into every
/// resolved document when they aren't already present — see
/// `didwebvh-rs`'s `resolve::implicit::update_implicit_services`. They are
/// therefore on 100% of resolved webvh DIDs and carry no operator intent.
///
/// This matters because the two read paths disagree about them. Reading a
/// stored `did.jsonl` (the DID-list badge cache) never sees them; resolving
/// the DID (the registry probe, the control-plane self-check) always does.
/// Left unfiltered, the same DID renders a spurious `Other` badge on the
/// Servers list and none on the DID list.
///
/// Matched on the `id` fragment, which is how the resolver itself detects
/// them — an operator who declares a `LinkedVerifiablePresentation` under
/// some other fragment genuinely is advertising something, and keeps its
/// badge.
pub fn is_implicit_webvh_service(service_id: &str) -> bool {
    service_id.ends_with("#whois") || service_id.ends_with("#files")
}

/// Extract the `type` of every entry in a DID document's `service` array.
///
/// The single canonical reader for "what does this document advertise",
/// shared by the DID-list badge cache, the registry's per-instance
/// capability probe, and the control plane's advertised-vs-enabled check.
/// It is the read-side counterpart to [`build_did_document`], which writes
/// the same services.
///
/// Handles both shapes the ecosystem's templates emit: a bare string
/// (`"type": "TSPTransport"`, the webvh `did-host-*` templates) and a
/// single-element array (`"type": ["DIDCommMessaging"]`, `ai-agent-peer`).
/// A service carrying several types contributes all of them.
///
/// Order is the document's own — the webvh templates render hosting, then
/// TSP, then DIDComm, so callers that surface the first match inherit the
/// same TSP-over-DIDComm preference [`crate::server::didcomm_profile::resolve_transport`]
/// applies. Duplicates are collapsed, keeping first occurrence.
///
/// Spec-implied services (`#whois`, `#files`) are skipped — see
/// [`is_implicit_webvh_service`]. Without this, resolved documents would
/// always report two extra types that no operator declared, and the stored-log
/// and resolved read paths would disagree about the same DID.
///
/// Returns an empty vector when `service` is absent, not an array, or
/// contains no usable `type`. Callers that need to distinguish "no services"
/// from "document unavailable" should wrap the result in an `Option`
/// themselves — see `DidRecord::services`.
pub fn service_types_from_doc(doc: &serde_json::Value) -> Vec<String> {
    let Some(services) = doc.get("service").and_then(|s| s.as_array()) else {
        return Vec::new();
    };

    let mut out: Vec<String> = Vec::new();
    let mut push = |t: &str| {
        if !t.is_empty() && !out.iter().any(|seen| seen == t) {
            out.push(t.to_string());
        }
    };

    for svc in services {
        let id = svc.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if is_implicit_webvh_service(id) {
            continue;
        }
        match svc.get("type") {
            Some(serde_json::Value::String(t)) => push(t),
            Some(serde_json::Value::Array(types)) => {
                for t in types.iter().filter_map(|t| t.as_str()) {
                    push(t);
                }
            }
            _ => {}
        }
    }
    out
}

/// True when `types` contains a service advertising the TSP transport.
pub fn advertises_tsp(types: &[String]) -> bool {
    types.iter().any(|t| t == SERVICE_TYPE_TSP)
}

/// True when `types` contains a service advertising the DIDComm transport.
pub fn advertises_didcomm(types: &[String]) -> bool {
    types.iter().any(|t| t == SERVICE_TYPE_DIDCOMM)
}

/// Create a WebVH log entry from a DID document and signing secret.
///
/// Returns `(scid, jsonl)` where:
/// - `scid` is the self-certifying identifier derived from the log entry
/// - `jsonl` is the serialized log entry ready for upload to the server
pub async fn create_log_entry(
    did_document: &serde_json::Value,
    secret: &Secret,
) -> Result<(String, String)> {
    let public_key_multibase = secret
        .get_public_keymultibase()
        .map_err(|e| WebVHError::DIDComm(format!("failed to get public key multibase: {e}")))?;

    // didwebvh-rs 0.3 requires the signing key's verification_method to
    // contain '#' followed by the multibase public key.
    let mut signing_key = secret.clone();
    if !signing_key.id.contains('#') {
        signing_key.id = format!("did:key:{public_key_multibase}#{public_key_multibase}");
    }

    let mut state = DIDWebVHState::default();
    let params = Parameters {
        update_keys: Some(Arc::new(vec![public_key_multibase.into()])),
        ..Default::default()
    };

    state
        .create_log_entry(None, did_document, &params, &signing_key)
        .await
        .map_err(|e| WebVHError::DIDComm(format!("failed to create WebVH log entry: {e}")))?;

    let scid = state.scid().to_string();

    let lines: Vec<String> = state
        .log_entries()
        .iter()
        .map(|e| {
            serde_json::to_string(&e.log_entry)
                .map_err(|e| WebVHError::DIDComm(format!("failed to serialize log entry: {e}")))
        })
        .collect::<Result<Vec<_>>>()?;
    let jsonl = lines.join("\n");

    Ok((scid, jsonl))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let doc =
            serde_json::json!({ "service": [{ "id": "#x" }, { "type": 42 }, { "type": "" }] });
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
            "did:webvh:QmRUN4vrMp6cS1xqWSH46bCipf9W95VrFDyyFBm8XXcZ1E:webvh.storm.ws:webvh-server1";
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
            },
        );
        assert!(service_types_from_doc(&doc).is_empty());
        assert!(!advertises_tsp(&service_types_from_doc(&doc)));
    }
}
