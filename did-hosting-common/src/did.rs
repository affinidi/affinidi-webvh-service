//! Building did:webvh DIDs and their documents: key generation, the service
//! entries a node advertises, and the first log entry.

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
    /// Leave the `did:scid:vh:1:<scid>?src=…` alias out of `alsoKnownAs`.
    /// By default the document lists it, linking the DID's did:webvh and
    /// did:scid forms as one subject (VTI-KEY-166 of the VTI specification);
    /// a service sets this from `hosting.scid_also_known_as = false`.
    pub omit_scid_alias: bool,
}

/// Advertise a `WebVHHosting` service at `uri` on a document built by
/// [`build_did_document`], after any transport services it already has.
///
/// The shape is exactly what VTI's `did-host-http` template emits, and what a
/// VTA's `servers add` reads: an object endpoint carrying `uri`, not a bare
/// string.
///
/// Keyring VTI-18. A self-managed hosting daemon minted without a mediator
/// had **no services at all** — the transport services both need one — so it
/// served DIDs perfectly well and no VTA could register it: `servers add`
/// requires a `TSPTransport`, `DIDCommMessaging` or `WebVHHosting` entry. A
/// hosting daemon serves HTTP whatever else it speaks, so this entry is simply
/// true of it and needs nothing the operator has not already configured.
///
/// Appended rather than folded into [`DidDocumentOptions`]: that struct is
/// public and built by literal, so a new field would break every caller.
/// Appending also keeps the canonical order — TSP, then DIDComm, then HTTP.
pub fn add_webvh_hosting_service(doc: &mut serde_json::Value, uri: &str) {
    let did_id = doc["id"].as_str().unwrap_or_default().to_string();
    let entry = json!({
        "id": format!("{did_id}#webvh-hosting"),
        "type": "WebVHHosting",
        "serviceEndpoint": { "uri": uri },
    });
    match doc.get_mut("service").and_then(|s| s.as_array_mut()) {
        Some(services) => services.push(entry),
        None => doc["service"] = json!([entry]),
    }
}

/// Advertise a `TrustTaskHTTPS` service at `base_uri` on a document built by
/// [`build_did_document`] (typically alongside [`add_webvh_hosting_service`]).
///
/// `base_uri` is the Trust-Task **base**, not the request URL — HTTPS binding
/// 0.2 §6 makes the advertised endpoint the base and the caller composes
/// `<base>/trust-tasks`. The control plane nests its whole API under `/api`
/// off the origin root (`did-hosting-control`'s `routes/mod.rs`), so
/// `base_uri` is `{public_url}/api`; this matches every `vta-sdk`
/// `did-host-http*` template exactly (`vta-sdk`'s
/// `TRUST_TASK_HTTPS_SERVICE_TYPE`).
///
/// `WebVHHosting` is not this endpoint — it says where DID *documents* are
/// served, a different claim — so without this entry a VTA either can't find
/// the Trust-Task endpoint, or falls back to posting Trust Tasks at the
/// hosting origin, which never agreed to accept them. A VTA-provisioned DID
/// gets this entry for free from the `vta-sdk` template; a **self-managed**
/// daemon builds its own document locally instead, so it needs the same
/// explicit fix `add_webvh_hosting_service` got for `WebVHHosting` (Keyring
/// VTI-18 sibling).
///
/// Callers should gate this on [`is_https_or_loopback`] first — a VTA must
/// never be told to POST Trust Tasks over plaintext HTTP to a real host.
pub fn add_trust_task_https_service(doc: &mut serde_json::Value, base_uri: &str) {
    let did_id = doc["id"].as_str().unwrap_or_default().to_string();
    let entry = json!({
        "id": format!("{did_id}#trust-tasks"),
        "type": "TrustTaskHTTPS",
        "serviceEndpoint": base_uri,
    });
    match doc.get_mut("service").and_then(|s| s.as_array_mut()) {
        Some(services) => services.push(entry),
        None => doc["service"] = json!([entry]),
    }
}

/// Advertise a `SignInPortal` service at `endpoint` on a document built by
/// [`build_did_document`]: the page where this service's people sign in with
/// a wallet (contract C4, VTI-LNK-102).
///
/// A wallet reading a sign-in trigger link compares the origin of
/// `serviceEndpoint` with the page the link was activated from, and refuses
/// a mismatch (`wrong-origin`, VTI-LNK-105). So `endpoint` must be the
/// console's login page on the origin that serves it; for a hosting daemon
/// that is `{origin}/login`. The `auth/oob/*` tasks themselves travel over
/// the `TrustTaskHTTPS` service ([`add_trust_task_https_service`]).
///
/// Callers should gate this on [`is_sign_in_portal_url`] — stricter than the
/// `TrustTaskHTTPS` entry's [`is_https_or_loopback`]: `https` only.
pub fn add_sign_in_portal_service(doc: &mut serde_json::Value, endpoint: &str) {
    let did_id = doc["id"].as_str().unwrap_or_default().to_string();
    let entry = json!({
        "id": format!("{did_id}#sign-in-portal"),
        "type": SERVICE_TYPE_SIGN_IN_PORTAL,
        "serviceEndpoint": endpoint,
    });
    match doc.get_mut("service").and_then(|s| s.as_array_mut()) {
        Some(services) => services.push(entry),
        None => doc["service"] = json!([entry]),
    }
}

/// Whether `uri` may be advertised as a `SignInPortal` (contract C4), and so
/// serve wallet sign-in with a trigger link: `https://` with a host, and no
/// userinfo.
///
/// Stricter than [`is_https_or_loopback`] on purpose: the portal's origin is
/// what `auth/oob/*` binds a sign-in to, and the published `Origin` type
/// (`crate::tasks::auth::oob`) admits `https://` only, so a plain-
/// http portal — even on loopback — could never complete a conforming
/// sign-in (a wallet refuses to approve one). The control plane applies the
/// same rule to its `public_url` before it serves the family at all
/// (`did-hosting-control`'s `oob::http::portal_origin`).
pub fn is_sign_in_portal_url(uri: &str) -> bool {
    url::Url::parse(uri).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

/// Whether `uri` is safe to advertise as a `TrustTaskHTTPS` endpoint.
///
/// `https://` always qualifies. Plain `http://` qualifies only for loopback
/// (`localhost`, `127.0.0.1`, `[::1]`) — acceptable for a local dev daemon,
/// never for a real deployment a VTA might actually route Trust Tasks to.
///
/// The URL is parsed and its host compared exactly, never by text prefix:
/// `http://localhost.evil.example` and `http://127.0.0.1.evil.example` are
/// not loopback, and neither is a URL carrying userinfo. `127.0.0.0/8`
/// counts, as every address in it is loopback.
pub fn is_https_or_loopback(uri: &str) -> bool {
    let Ok(url) = url::Url::parse(uri) else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => url.host().is_some(),
        "http" => match url.host() {
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        },
        _ => false,
    }
}

/// Build a standard DID document with `{SCID}` placeholders.
///
/// The returned JSON value uses the did:webvh identifier format with an
/// Ed25519 verification method at `#key-0`. Additional keys and services
/// can be added via [`DidDocumentOptions`].
///
/// An empty mnemonic — or `.well-known`, the slot the root DID is *stored*
/// under — builds the **root** DID for the host: `did:webvh:{SCID}:<host>`
/// with no path segments, which per did:webvh resolves at
/// `https://<host>/.well-known/did.jsonl`.
///
/// `.well-known` is a storage location, not part of the identifier. Emitting it
/// inside the DID produces an id no conforming resolver can round-trip: it maps
/// the pathless form to `/.well-known/did.jsonl` implicitly, so on the way back
/// it strips the suffix and then rejects the document because the `id` inside no
/// longer matches the DID it was asked to resolve —
///
/// ```text
/// DID being resolved (did:webvh:Qm…:did.example.com)
/// does not match the top-level 'id' in any DIDDoc version
/// ```
///
/// The document serves fine; the *identifier* is what fails to round-trip. This
/// mirrors [`build_did_web_id`] and `setup_recipe::apply::hosting_url_for`,
/// which both already fold `.well-known` to the root.
pub fn build_did_document(
    host: &str,
    mnemonic: &str,
    public_key_multibase: &str,
    opts: &DidDocumentOptions<'_>,
) -> serde_json::Value {
    let did_path = if mnemonic == ".well-known" {
        String::new()
    } else {
        mnemonic.replace('/', ":")
    };
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

    // `{SCID}` is still a placeholder here; signing the first log entry fills
    // it in, in the alias as everywhere else in the document.
    if !opts.omit_scid_alias {
        doc["alsoKnownAs"] = json!([DIDWebVHState::convert_webvh_id_to_scid_id(&did_id)]);
    }

    doc
}

// ---------------------------------------------------------------------------
// Service-type introspection
// ---------------------------------------------------------------------------

/// HTTP DID-log hosting endpoint (`did-host-http*` templates).
pub const SERVICE_TYPE_WEBVH_HOSTING: &str = "WebVHHosting";
/// Legacy read-only alias for [`SERVICE_TYPE_WEBVH_HOSTING`]. Never written;
/// accepted on read.
pub const SERVICE_TYPE_WEBVH_HOSTING_LEGACY: &str = "WebVHHostingService";
/// Trust Spanning Protocol transport (`#tsp`).
pub const SERVICE_TYPE_TSP: &str = "TSPTransport";
/// DIDComm v2 transport (`#vta-didcomm`).
pub const SERVICE_TYPE_DIDCOMM: &str = "DIDCommMessaging";
/// Trust-Task HTTPS binding endpoint (`#trust-tasks`), HTTPS binding 0.2 §6.
/// Kept in sync with `vta-sdk`'s `TRUST_TASK_HTTPS_SERVICE_TYPE`.
pub const SERVICE_TYPE_TRUST_TASK_HTTPS: &str = "TrustTaskHTTPS";
/// The page where people sign in with a wallet (`#sign-in-portal`), contract
/// C4 / VTI-LNK-102.
pub const SERVICE_TYPE_SIGN_IN_PORTAL: &str = "SignInPortal";

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
#[path = "did_tests.rs"]
mod tests;
