//! Recipe → typed-config helpers shared by every binary's headless setup.
//!
//! The per-binary `AppConfig` / `DaemonConfig` structs differ in name and
//! field set, so the final assembly stays in each binary's setup.rs. The
//! helpers here cover everything in between — VTA round-trip,
//! offline-bundle open, derived paths — so the per-binary code is mostly
//! struct construction.

use std::path::PathBuf;
use std::sync::Arc;

use vta_sdk::provision_client::{EphemeralSetupKey, OperatorMessages, ProvisionAsk};

use crate::server::error::AppError;
use crate::server::vta_setup::{
    OfflineBootstrapResult, OnlineProvisionInputs, OnlineProvisionOutcome, online_provision_setup,
    open_offline_bootstrap_response, write_offline_bootstrap_request,
};

use super::schema::{AdminMode, SetupRecipe, VtaMode};

/// Standardised header printed at the top of every headless run so the
/// log output is greppable in CI (`grep -F "[setup-recipe]"`).
pub fn print_recipe_banner(service_name: &str, recipe: &SetupRecipe) {
    eprintln!();
    eprintln!("  [setup-recipe] service       = {}", service_name);
    eprintln!(
        "  [setup-recipe] vta_mode      = {}",
        super::load::vta_mode_str(recipe.deployment.vta_mode)
    );
    eprintln!(
        "  [setup-recipe] config_path   = {}",
        recipe.output.config_path.display()
    );
    if let Some(ref url) = recipe.identity.public_url {
        eprintln!("  [setup-recipe] public_url    = {url}");
    }
    eprintln!();
}

/// Derive a DID path from a public URL the same way every interactive
/// wizard does: `<scheme>://<host>` → `.well-known`; `<scheme>://<host>/p`
/// → `p`.
pub fn derive_did_path(public_url: &str) -> String {
    let after_scheme = public_url
        .find("://")
        .map(|i| &public_url[i + 3..])
        .unwrap_or(public_url);
    let path = after_scheme
        .find('/')
        .map(|i| after_scheme[i..].trim_matches('/'))
        .unwrap_or("");
    if path.is_empty() {
        ".well-known".to_string()
    } else {
        path.to_string()
    }
}

/// Split an operator-entered URL into its origin (`scheme://host[:port]`,
/// trailing slash stripped) and the DID path encoded in its path component.
/// An empty path maps to `.well-known`, the webvh root. The inverse of
/// [`hosting_url_for`]: `split_origin_and_did_path(hosting_url_for(o, p))
/// == (o, p)` for any already-trimmed origin.
pub fn split_origin_and_did_path(public_url: &str) -> (String, String) {
    let trimmed = public_url.trim_end_matches('/');
    let scheme_end = trimmed.find("://").map(|i| i + 3).unwrap_or(0);
    match trimmed[scheme_end..].find('/') {
        Some(rel) => {
            let at = scheme_end + rel;
            let path = trimmed[at..].trim_matches('/');
            let did_path = if path.is_empty() {
                ".well-known".to_string()
            } else {
                path.to_string()
            };
            (trimmed[..at].to_string(), did_path)
        }
        None => (trimmed.to_string(), ".well-known".to_string()),
    }
}

/// Fold a DID path back into a hosting origin so the VTA mints the DID at
/// the matching web location. The VTA derives the DID's path segment from
/// this URL, and the local import path must match. `.well-known` is the
/// webvh root and carries no path segment, so the origin is returned
/// unchanged. This is the inverse of [`derive_did_path`]:
/// `derive_did_path(hosting_url_for(o, p)) == p` for any non-empty origin.
pub fn hosting_url_for(origin: &str, did_path: &str) -> String {
    if did_path == ".well-known" {
        origin.trim_end_matches('/').to_string()
    } else {
        format!(
            "{}/{}",
            origin.trim_end_matches('/'),
            did_path.trim_matches('/')
        )
    }
}

/// What the recipe-driven flow needs out of the VTA round-trip when the
/// mode is `online` — flattened so binaries don't have to plumb the SDK
/// types around.
pub enum VtaSetupOutcome {
    /// Online round-trip succeeded.
    Online(OnlineProvisionOutcome),
    /// Offline phase 2: sealed bundle opened.
    Offline(OfflineBootstrapResult),
    /// Self-managed (daemon-only): keys generated locally; no VTA was
    /// contacted. The returned tuple is `(signing_key_priv_mb,
    /// signing_key_pub_mb, ka_key_priv_mb, ka_key_pub_mb,
    /// did_log_jsonl_entry)`.
    SelfManaged(SelfManagedKeys),
    /// Offline phase 1: request file + state TOML were written; nothing
    /// to persist beyond `--from`. Carrying a stub so the caller can
    /// short-circuit out of the apply flow.
    OfflinePreparedOnly(OfflinePreparedInfo),
}

pub struct SelfManagedKeys {
    pub signing_priv_mb: String,
    pub signing_pub_mb: String,
    pub ka_priv_mb: String,
    pub ka_pub_mb: String,
    pub did_log_jsonl: String,
}

pub struct OfflinePreparedInfo {
    /// Path of the bootstrap-request.json the caller (or recipe) asked
    /// us to write.
    pub request_path: PathBuf,
    /// Ephemeral X25519-derivable private seed. Treat as secret. The
    /// caller MUST persist this via [`SecretStore::set_bootstrap_seed`]
    /// before returning, otherwise phase 2 cannot open the sealed
    /// response.
    pub seed: [u8; 32],
    /// Public ephemeral did:key embedded in the bootstrap request. The
    /// VTA admin uses this to grant the request context-create
    /// permission. Printed in operator-facing next-steps.
    pub client_did: String,
    /// Base64url-encoded 16-byte nonce. Becomes the bundle_id once the
    /// VTA admin seals the response — printed so the operator can
    /// eyeball-match the returned bundle.
    pub nonce: String,
}

/// Drive whichever VTA path the recipe asks for. The caller supplies:
///
/// - `ask`: a pre-built [`ProvisionAsk`] for online mode (template name
///   + vars). Ignored for self-managed / offline-complete / offline-prepare.
/// - `messages`: per-binary operator-message labels.
/// - `setup_key`: required for `vta_mode = "online"` (the ephemeral
///   did:key the operator enrolled via Phase 1).
/// - `offline_prepare_template` / `offline_prepare_vars`: only used when
///   `vta_mode = "offline-prepare"` — describes the sealed-bundle
///   template to embed in the bootstrap request.
/// - `offline_prepare_seed_sink`: invoked with the 32-byte ephemeral
///   seed after writing the request — the caller persists it in their
///   configured secret store. Only consulted for `offline-prepare`.
/// - `offline_complete_seed`: the seed the secret store handed back for
///   `offline-complete`.
///
/// Errors are surfaced via [`AppError`] so binaries can map to their
/// chosen exit codes (see [`super::exit_codes`]).
pub async fn run_vta_for_recipe(
    recipe: &SetupRecipe,
    ask: Option<ProvisionAsk>,
    messages: Arc<dyn OperatorMessages>,
    setup_key: Option<EphemeralSetupKey>,
    offline_complete_seed: Option<[u8; 32]>,
) -> Result<VtaSetupOutcome, AppError> {
    match recipe.deployment.vta_mode {
        VtaMode::Online => {
            let ask = ask.ok_or_else(|| {
                AppError::Config("internal: online mode requires a ProvisionAsk".into())
            })?;
            let setup_key = setup_key.ok_or_else(|| {
                AppError::Config(
                    "online vta_mode requires --setup-key-file <path> — run \
                     `setup --setup-key-out <path>` first to mint an ephemeral did:key, \
                     enrol it at the VTA, then re-run with --setup-key-file"
                        .into(),
                )
            })?;
            let vta_did = recipe.vta.did.clone().ok_or_else(|| {
                AppError::Config("recipe vta.did is required for vta_mode = \"online\"".into())
            })?;
            let context_id = recipe
                .vta
                .context_id
                .clone()
                .unwrap_or_else(|| "webvh".to_string());
            let inputs = OnlineProvisionInputs {
                vta_did,
                context_id,
                ask,
                messages,
                setup_key,
            };
            let outcome = online_provision_setup(inputs)
                .await
                .map_err(|e| AppError::Config(format!("VTA provision-integration failed: {e}")))?;
            Ok(VtaSetupOutcome::Online(outcome))
        }
        VtaMode::OfflinePrepare => {
            let request_path = recipe.vta.request_path.clone().ok_or_else(|| {
                AppError::Config(
                    "recipe vta.request_path is required for vta_mode = \"offline-prepare\"".into(),
                )
            })?;
            // Offline-prepare ferries the *same* ask the online flow would
            // send — template, vars, context, and label all ride on it.
            let ask = ask.ok_or_else(|| {
                AppError::Config("internal: offline-prepare mode requires a ProvisionAsk".into())
            })?;
            let info = write_offline_bootstrap_request(&request_path, &ask)
                .await
                .map_err(|e| {
                    AppError::Config(format!("offline bootstrap-request write failed: {e}"))
                })?;
            // Surface the seed to the caller — they own the secret
            // store and persist it via `set_bootstrap_seed` so phase 2
            // can open the sealed reply. Phase 2 reads the *same*
            // recipe (with vta_mode flipped to "offline-complete" and
            // bundle_path + expect_digest populated) and pulls the
            // seed back out of the same backend.
            Ok(VtaSetupOutcome::OfflinePreparedOnly(OfflinePreparedInfo {
                request_path: info.request_path,
                seed: info.seed,
                client_did: info.client_did,
                nonce: info.nonce,
            }))
        }
        VtaMode::OfflineComplete => {
            let bundle_path = recipe.vta.bundle_path.as_ref().ok_or_else(|| {
                AppError::Config(
                    "recipe vta.bundle_path is required for vta_mode = \"offline-complete\"".into(),
                )
            })?;
            let expect_digest = recipe.vta.expect_digest.as_ref().ok_or_else(|| {
                AppError::Config(
                    "recipe vta.expect_digest is required for vta_mode = \"offline-complete\""
                        .into(),
                )
            })?;
            let seed = offline_complete_seed.ok_or_else(|| {
                AppError::Config(
                    "bootstrap seed missing from secret store — phase 1 (offline-prepare) \
                     may not have run, or you're using a different secrets backend now"
                        .into(),
                )
            })?;
            let armor = std::fs::read_to_string(bundle_path).map_err(|e| {
                AppError::Config(format!("failed to read sealed bundle {bundle_path:?}: {e}"))
            })?;
            let result = open_offline_bootstrap_response(&armor, expect_digest, &seed)
                .map_err(|e| AppError::Config(format!("sealed-bundle open failed: {e}")))?;
            Ok(VtaSetupOutcome::Offline(result))
        }
        VtaMode::SelfManaged => generate_self_managed_keys(recipe).await,
    }
}

async fn generate_self_managed_keys(recipe: &SetupRecipe) -> Result<VtaSetupOutcome, AppError> {
    use affinidi_tdk::secrets_resolver::secrets::Secret;

    use crate::did::{DidDocumentOptions, build_did_document, create_log_entry, encode_host};

    let public_url = recipe.identity.public_url.as_deref().ok_or_else(|| {
        AppError::Config("self-managed mode requires identity.public_url in the recipe".into())
    })?;

    let signing = Secret::generate_ed25519(None, None);
    let ka = Secret::generate_x25519(None, None)
        .map_err(|e| AppError::Config(format!("x25519 generation failed: {e}")))?;
    let signing_priv_mb = signing
        .get_private_keymultibase()
        .map_err(|e| AppError::Config(format!("encode signing private: {e}")))?;
    let signing_pub_mb = signing
        .get_public_keymultibase()
        .map_err(|e| AppError::Config(format!("encode signing public: {e}")))?;
    let ka_priv_mb = ka
        .get_private_keymultibase()
        .map_err(|e| AppError::Config(format!("encode ka private: {e}")))?;
    let ka_pub_mb = ka
        .get_public_keymultibase()
        .map_err(|e| AppError::Config(format!("encode ka public: {e}")))?;

    let did_path = derive_did_path(public_url);
    let host_encoded = encode_host(public_url)
        .map_err(|e| AppError::Config(format!("failed to encode host from public URL: {e}")))?;
    let doc = build_did_document(
        &host_encoded,
        &did_path,
        &signing_pub_mb,
        &DidDocumentOptions {
            key_agreement_multibase: Some(&ka_pub_mb),
            mediator_endpoint: recipe.identity.mediator_did.as_deref(),
            // Wired to the recipe's transport selection in the wizard/config
            // phase; None keeps the DIDComm-only shape for now.
            tsp_endpoint: None,
        },
    );
    let (_scid, jsonl) = create_log_entry(&doc, &signing)
        .await
        .map_err(|e| AppError::Config(format!("failed to create DID log entry: {e}")))?;

    Ok(VtaSetupOutcome::SelfManaged(SelfManagedKeys {
        signing_priv_mb,
        signing_pub_mb,
        ka_priv_mb,
        ka_pub_mb,
        did_log_jsonl: jsonl,
    }))
}

/// Resolve the recipe's `[admin]` choice into a concrete DID (or `None`
/// for skip). Generates a fresh did:key on `mode = "generate"`, printing
/// the private half to stderr exactly once.
pub fn resolve_admin_did(recipe: &SetupRecipe) -> Option<String> {
    match recipe.admin.mode {
        AdminMode::Skip => None,
        AdminMode::Did => recipe.admin.did.clone(),
        AdminMode::Generate => {
            let (did, sk) = crate::server::vta_setup::generate_admin_did_key();
            eprintln!(
                "  Generated admin did:key: {did}\n  Private key (save now, not re-shown): {sk}"
            );
            Some(did)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_did_path_well_known_for_bare_host() {
        assert_eq!(derive_did_path("https://example.com"), ".well-known");
        assert_eq!(derive_did_path("https://example.com/"), ".well-known");
    }

    #[test]
    fn derive_did_path_uses_url_path() {
        assert_eq!(
            derive_did_path("https://did.example.com/services/control"),
            "services/control"
        );
        assert_eq!(derive_did_path("https://x.io/a/b/c"), "a/b/c");
    }

    #[test]
    fn hosting_url_for_folds_path() {
        assert_eq!(
            hosting_url_for("https://did.example.com", "services/control"),
            "https://did.example.com/services/control"
        );
        // Trailing slashes on either side normalise away.
        assert_eq!(
            hosting_url_for("https://did.example.com/", "/services/control/"),
            "https://did.example.com/services/control"
        );
    }

    #[test]
    fn hosting_url_for_well_known_returns_origin() {
        assert_eq!(
            hosting_url_for("https://did.example.com", ".well-known"),
            "https://did.example.com"
        );
    }

    #[test]
    fn hosting_url_for_is_inverse_of_derive_did_path() {
        for (origin, did_path) in [
            ("https://did.example.com", "services/control"),
            ("http://localhost:8532", "a/b/c"),
            ("https://did.example.com", ".well-known"),
        ] {
            assert_eq!(
                derive_did_path(&hosting_url_for(origin, did_path)),
                did_path
            );
        }
    }

    #[test]
    fn split_origin_and_did_path_cases() {
        assert_eq!(
            split_origin_and_did_path("https://webvh.example.com"),
            (
                "https://webvh.example.com".to_string(),
                ".well-known".to_string()
            )
        );
        assert_eq!(
            split_origin_and_did_path("https://webvh.example.com/"),
            (
                "https://webvh.example.com".to_string(),
                ".well-known".to_string()
            )
        );
        assert_eq!(
            split_origin_and_did_path("https://webvh.example.com/dids/daemon"),
            (
                "https://webvh.example.com".to_string(),
                "dids/daemon".to_string()
            )
        );
        // Port is preserved in the origin.
        assert_eq!(
            split_origin_and_did_path("http://localhost:8534/svc"),
            ("http://localhost:8534".to_string(), "svc".to_string())
        );
    }

    #[test]
    fn fold_then_split_round_trips() {
        // VTA-mode correctness depends on this: the path folded into the URL
        // (handed to the VTA) is exactly the path split back out for the
        // local store import.
        for (origin, did_path) in [
            ("https://webvh.example.com", ".well-known"),
            ("https://webvh.example.com", "dids/daemon"),
            ("http://localhost:8534", "svc"),
        ] {
            let url = hosting_url_for(origin, did_path);
            assert_eq!(
                split_origin_and_did_path(&url),
                (origin.to_string(), did_path.to_string()),
                "round-trip failed for {origin} + {did_path}"
            );
        }
    }
}
