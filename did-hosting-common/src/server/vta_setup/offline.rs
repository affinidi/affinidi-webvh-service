//! Offline (sealed-bundle) bootstrap for air-gapped VTAs, and the DID shape
//! every setup path asks for ([`WebvhDidShape`], [`build_webvh_provision_ask`]).

use super::*;

// ---------------------------------------------------------------------------
// Offline (sealed-bundle) bootstrap
//
// The online flow above calls the VTA directly over DIDComm. For air-gapped
// VTA deployments the consumer instead:
//
//   1. Generates an ephemeral Ed25519 keypair + nonce and writes a
//      `bootstrap-request.json` file. The operator ferries this to the VTA
//      admin box and runs `vta bootstrap seal --request …` against the
//      pinned context, producing an ASCII-armored sealed bundle plus a
//      SHA-256 digest of the ciphertext (communicated out-of-band).
//   2. Copies the armored bundle back, and runs the open step with the
//      expected digest. Open:
//         - verifies the canonical digest,
//         - opens the HPKE-sealed chunks with the persisted seed,
//         - extracts the VTA-rendered DID document, key material, and
//           signed-DID log from the `TemplateBootstrapPayload`.
//
// The same template (`did-hosting-daemon`, `did-hosting-control`, `did-hosting-server`)
// drives both the online and offline paths, so the persisted DID shape
// is identical to what `online_provision_setup` above produces.
// ---------------------------------------------------------------------------

/// Information returned after writing an offline bootstrap request.
///
/// The operator uses `client_did` + `nonce` to eyeball that the request
/// they're sealing is the one we just produced (no swapping).
#[derive(Debug, Clone)]
pub struct OfflineRequestInfo {
    /// Ephemeral `did:key:z6Mk…` identifying this request.
    pub client_did: String,
    /// Base64url-encoded 16-byte nonce. Becomes the bundle_id after seal.
    pub nonce: String,
    /// Path of the written request JSON.
    pub request_path: std::path::PathBuf,
    /// Raw 32-byte ephemeral seed. **Treat as secret.** The caller is
    /// responsible for persisting this in their secret store
    /// (`SecretStore::set_bootstrap_seed`); it is the X25519-derivable
    /// private half needed to open the sealed response in phase 2.
    pub seed: [u8; 32],
}

/// Rich result of opening an offline bootstrap response.
///
/// Shaped to feed the same secret-store / DID-bootstrap plumbing the
/// online path uses, plus the extra VTA trust material the sealed
/// bundle carries (authorization VC, pinned VTA DID, trust bundle).
#[derive(Debug, Clone)]
pub struct OfflineBootstrapResult {
    /// Integration DID — the service's own `did:webvh:…` identifier.
    pub did: String,
    /// Multibase-encoded Ed25519 private signing key for the integration DID.
    pub signing_key_multibase: String,
    /// Multibase-encoded X25519 private key agreement key for the integration DID.
    pub key_agreement_multibase: String,
    /// Rendered DID document (published verbatim on the webvh host).
    pub did_document: serde_json::Value,
    /// JSONL DID log when the template emitted a `WebvhLog` output. Most
    /// webvh consumers will get one; `None` indicates the template did
    /// not ask the VTA to produce a signed log.
    pub log_entry: Option<String>,
    /// VTA-issued authorization credential (opaque VC).
    pub authorization_vc: serde_json::Value,
    /// Pinned VTA DID (store for future offline VC verification).
    pub vta_did: String,
    /// VTA REST URL (store for future online re-auth, if we ever need it).
    pub vta_url: Option<String>,
    /// Admin DID — the long-term operator DID the VTA rolled over to.
    /// Present when the VTA's `vta-admin` template ran during provision-
    /// integration; absent when the VTA disabled rollover and the
    /// integration DID is also the admin identity. Use for seeding the
    /// service's ACL with the operator's long-term identity.
    pub admin_did: Option<String>,
    /// Multibase-encoded Ed25519 private signing key for the admin DID.
    /// Present iff `admin_did` is. Use for downstream operations that
    /// need to authenticate as the admin (passkey enrolment, manual
    /// DIDComm flows, etc.).
    pub admin_signing_key_multibase: Option<String>,
}

/// Where a service publishes its own `did:webvh` document, and what
/// services that DID document advertises. This is the single input that
/// decides the VTA template + variable bindings, so every setup path —
/// interactive or recipe-driven, online or offline — packages its DID the
/// same way via [`build_webvh_provision_ask`].
pub enum WebvhDidShape<'a> {
    /// A URL-hosted node DID. `did_path` is folded into `origin` via
    /// [`hosting_url_for`] so the minted DID, the local import, and resolution
    /// all agree on the location — the DID is always resolvable at its host,
    /// which is derivable from the identifier itself.
    ///
    /// What the document *advertises* depends on `mediator_did`:
    /// - `mediator_did` set → the messaging transport(s) only, per `transport`:
    ///   [`TransportSelection::Both`]/[`TransportSelection::Didcomm`] →
    ///   `did-host-didcomm` (TSP + DIDComm); [`TransportSelection::Tsp`] →
    ///   `did-host-tsp` (TSP only). **No `WebVHHosting` service is emitted** —
    ///   the HTTP endpoint is derivable and unused for discovery, so it is not
    ///   advertised. The hosting `URL` is still passed so the VTA publishes the
    ///   log at the right host; it just doesn't appear in the document.
    /// - no mediator → `did-host-http` (HTTP-only): a `WebVHHosting` service is
    ///   the node's only advertisement, since it has no messaging transport.
    Hosted {
        origin: &'a str,
        did_path: &'a str,
        mediator_did: Option<&'a str>,
        /// Which messaging transport(s) the DID advertises at `mediator_did`.
        /// Ignored when `mediator_did` is `None`.
        transport: TransportSelection,
        /// Server-managed publication on a registered hosting server
        /// (daemon multi-tenant / delegated hosting). When set, the minted
        /// DID's canonical host is the remote server: `origin` becomes the
        /// document's own `WebVHHosting` URL (no path fold), and
        /// `WEBVH_SERVER`/`WEBVH_DOMAIN`/`WEBVH_PATH` pin the remote
        /// publication.
        remote: Option<WebvhRemoteTarget<'a>>,
    },
    /// The DID is DIDComm-only — it carries a `DIDCommMessaging` service but
    /// no `WebVHHosting` endpoint (template `did-hosting-server`). Used by
    /// `webvh-witness`, whose own DID is reachable only over DIDComm even
    /// though its `did.jsonl` is hosted on a did-hosting-server.
    DidcommOnly { mediator_did: &'a str },
}

/// Server-managed publication target — the registered hosting server (and
/// optional tenant domain / path) a `Hosted` DID is published on instead of
/// self-hosting. Maps to the `WEBVH_SERVER`/`WEBVH_DOMAIN`/`WEBVH_PATH`
/// template variables.
pub struct WebvhRemoteTarget<'a> {
    pub server_id: &'a str,
    pub domain: Option<&'a str>,
    pub path: Option<&'a str>,
}

/// Build the canonical `ProvisionAsk` for a webvh service's own DID.
///
/// This is the one place template selection, path-folding, and
/// `WEBVH_*`/`MEDIATOR_DID`/`URL` variable wiring happen. Both the online
/// round-trip and the offline sealed-bundle request consume the result, so
/// the two paths cannot mint structurally different DIDs.
pub fn build_webvh_provision_ask(
    context_id: &str,
    shape: &WebvhDidShape<'_>,
    label: Option<&str>,
) -> vta_sdk::provision_client::ProvisionAsk {
    use serde_json::Value as JsonValue;
    use vta_sdk::provision_client::ProvisionAsk;

    let mut ask = match shape {
        WebvhDidShape::Hosted {
            origin,
            did_path,
            mediator_did,
            transport,
            remote,
        } => {
            // Serverless folds the path into the URL so the minted DID and
            // the local import agree. Server-managed keeps the daemon's own
            // origin as the document URL — the path rides in WEBVH_PATH.
            let url = match remote {
                Some(_) => origin.trim_end_matches('/').to_string(),
                None => hosting_url_for(origin, did_path),
            };
            // Template selection. With a mediator the node advertises its
            // messaging transport(s) and NOT a `WebVHHosting` endpoint: the DID
            // is still URL-hosted (the VTA publishes the log at `url`, and the
            // resolution URL is derivable from the identifier), but the HTTP
            // endpoint is unused for discovery — inter-node traffic is
            // DIDComm/TSP and clients reach `POST /api/trust-tasks` by explicit config —
            // so advertising it only confused readers. TSP-only → `did-host-tsp`;
            // Both/Didcomm → `did-host-didcomm`; both carry the hosting `URL`
            // var so the VTA knows where to publish the log, though it does not
            // appear in the rendered document. No mediator → HTTP-only
            // `did-host-http`, whose `WebVHHosting` service is then the node's
            // only advertisement.
            let mut ask = match (mediator_did, transport) {
                (Some(med), TransportSelection::Tsp) => {
                    let mut a = ProvisionAsk::did_host_tsp(context_id, *med);
                    a.integration_template_vars
                        .insert("URL".to_string(), JsonValue::String(url));
                    a
                }
                (Some(med), _) => {
                    let mut a = ProvisionAsk::did_host_didcomm(context_id, *med);
                    a.integration_template_vars
                        .insert("URL".to_string(), JsonValue::String(url));
                    a
                }
                (None, _) => ProvisionAsk::did_host_http(context_id, url),
            };
            if let Some(r) = remote {
                ask.integration_template_vars.insert(
                    "WEBVH_SERVER".to_string(),
                    JsonValue::String(r.server_id.to_string()),
                );
                if let Some(domain) = r.domain {
                    ask.integration_template_vars.insert(
                        "WEBVH_DOMAIN".to_string(),
                        JsonValue::String(domain.to_string()),
                    );
                }
                if let Some(path) = r.path {
                    ask.integration_template_vars.insert(
                        "WEBVH_PATH".to_string(),
                        JsonValue::String(path.to_string()),
                    );
                }
            }
            ask
        }
        WebvhDidShape::DidcommOnly { mediator_did } => {
            ProvisionAsk::did_host_didcomm(context_id, *mediator_did)
        }
    };
    if let Some(l) = label {
        ask = ask.with_label(l.to_string());
    }
    ask
}

/// Write an offline bootstrap request and return the in-memory ephemeral seed.
///
/// The target DID is described entirely by `ask` — the *same*
/// `ProvisionAsk` the online flow would send. Build it with
/// [`build_webvh_provision_ask`] so template selection, path-folding, and
/// variable bindings live in one place and the online/offline paths can't
/// drift apart. The ask's `context` becomes the VP's `contextHint` (so the
/// VTA admin can run `vta bootstrap provision-integration` without
/// `--context`) and its `label` is carried through for audit. The VP's
/// `validUntil` is forced to 7 days here — longer than the online default —
/// to give operators headroom for the manual seal/return round-trip.
///
/// The resulting **VP-framed** `BootstrapRequest` is what `vta bootstrap
/// provision-integration` consumes on the producer side.
///
/// The caller hands `request_path` to the VTA operator and persists the
/// returned `seed` in their secret store via
/// `SecretStore::set_bootstrap_seed` — never to disk. The seed is the
/// X25519-derivable private half needed to open the sealed response in
/// phase 2.
pub async fn write_offline_bootstrap_request(
    request_path: &Path,
    ask: &vta_sdk::provision_client::ProvisionAsk,
) -> Result<OfflineRequestInfo, Box<dyn std::error::Error>> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use vta_sdk::provision_integration::ProvisionRequestBuilder;

    let template = ask.integration_template.as_deref().ok_or(
        "ProvisionAsk has no integration template — offline bootstrap requires a minted DID",
    )?;
    // 7-day window: the offline ferry round-trip needs more headroom than
    // the online default the ask carries.
    let mut builder = ProvisionRequestBuilder::new(template)
        .context_hint(&ask.context)
        .validity(chrono::Duration::days(7));
    for (k, v) in &ask.integration_template_vars {
        builder = builder.var(k.clone(), v.clone());
    }
    if let Some(l) = &ask.label {
        builder = builder.label(l.clone());
    }

    let signed = builder.sign_ephemeral().await?;
    let request_json = serde_json::to_string_pretty(&signed.request)?;

    if let Some(parent) = request_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(request_path, request_json)?;

    // Copy the seed out of the Zeroizing wrapper so it can be persisted
    // by the secret store — caller is responsible for handling it
    // carefully from here on.
    let seed_bytes: [u8; 32] = *signed.seed;
    let nonce_b64 = B64.encode(signed.bundle_id);

    Ok(OfflineRequestInfo {
        client_did: signed.client_did,
        nonce: nonce_b64,
        request_path: request_path.to_path_buf(),
        seed: seed_bytes,
    })
}

/// Open a sealed bootstrap response and extract the provisioned identity.
///
/// `bundle_armor` is the ASCII-armored sealed bundle the operator
/// ferries back (contents of what `vta bootstrap seal` produced).
/// `expect_digest` is the lowercase hex SHA-256 the operator communicated
/// out-of-band; `open_bundle` rejects the bundle in constant time if it
/// doesn't match, and for `PinnedOnly` producer assertions this is the
/// only trust anchor.
///
/// `seed` is the 32-byte ephemeral seed `write_offline_bootstrap_request`
/// returned and the caller persisted in their secret store
/// (`SecretStore::set_bootstrap_seed`). Phase 2 reads it back via
/// `SecretStore::get_bootstrap_seed`.
pub fn open_offline_bootstrap_response(
    bundle_armor: &str,
    expect_digest: &str,
    seed: &[u8; 32],
) -> Result<OfflineBootstrapResult, Box<dyn std::error::Error>> {
    use vta_sdk::sealed_transfer::template_bootstrap::TemplateOutput;
    use vta_sdk::sealed_transfer::{
        SealedPayloadV1, armor, ed25519_seed_to_x25519_secret, open_bundle,
    };

    let recipient_secret = ed25519_seed_to_x25519_secret(seed);

    // Decode the armor. We only expect a single bundle per response.
    let bundles = armor::decode(bundle_armor)?;
    let bundle = match bundles.as_slice() {
        [one] => one,
        other => {
            return Err(format!(
                "expected exactly 1 sealed bundle in armor, got {}",
                other.len()
            )
            .into());
        }
    };

    // `open_bundle` handles digest check, HPKE open, chunk reassembly,
    // and the PinnedOnly → digest-required coupling check.
    let opened = open_bundle(&recipient_secret, bundle, Some(expect_digest))?;

    let payload = match opened.payload {
        SealedPayloadV1::TemplateBootstrap(boxed) => *boxed,
        _ => return Err("sealed response was not a TemplateBootstrap payload".into()),
    };

    // Pick the integration DID's key material by matching against
    // `config.did_document.id`. The payload carries a map keyed by DID
    // and may include both an integration entry and an admin-rolled-over
    // entry when the VTA enabled admin rollover; relying on the BTreeMap
    // iteration order would silently pick the alphabetically-first DID
    // (typically the admin did:key, since "did:key:..." sorts before
    // "did:webvh:...").
    let integration_did = payload
        .config
        .did_document
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or("sealed payload missing config.did_document.id")?
        .to_string();
    let mut secrets_map = payload.secrets;
    let integration_key_material = secrets_map
        .remove(&integration_did)
        .or_else(|| {
            // Forward-compat fallback: if the payload doesn't carry a
            // matching entry (e.g. because a future template renames the
            // canonical DID field), accept the first secret as a last
            // resort. Logged so an operator can correlate with the wire.
            tracing::warn!(
                integration_did = %integration_did,
                "sealed payload secrets map does not contain integration DID; falling back to first entry",
            );
            // Take the first remaining entry without consuming the whole
            // map — the next block needs the leftover entries to find
            // the admin material.
            let key = secrets_map.keys().next().cloned()?;
            secrets_map.remove(&key)
        })
        .ok_or("sealed payload has no secrets")?;

    // Any remaining entry is the admin DID rolled over by the VTA's
    // `vta-admin` template. Surface it so the wizard can seed the
    // service's ACL with the operator's long-term identity. The VTA
    // emits at most one rolled-over admin per provision-integration; if
    // future templates emit more we'd surface only the first and log,
    // matching the integration DID fallback.
    let admin_entry = secrets_map.into_iter().next();
    let (admin_did, admin_signing_key_multibase) = match admin_entry {
        Some((_did, mat)) => (Some(mat.did), Some(mat.signing_key.private_key_multibase)),
        None => (None, None),
    };

    let log_entry = payload.config.outputs.iter().find_map(|o| match o {
        TemplateOutput::WebvhLog { log, .. } => Some(log.clone()),
        _ => None,
    });

    Ok(OfflineBootstrapResult {
        did: integration_key_material.did,
        signing_key_multibase: integration_key_material.signing_key.private_key_multibase,
        key_agreement_multibase: integration_key_material.ka_key.private_key_multibase,
        did_document: payload.config.did_document,
        log_entry,
        authorization_vc: payload.authorization,
        vta_did: payload.config.vta_trust.vta_did,
        vta_url: payload.config.vta_url,
        admin_did,
        admin_signing_key_multibase,
    })
}
