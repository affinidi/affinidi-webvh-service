//! Signing the *request* leg of outbound approval Trust Tasks with the
//! control plane's own DID key.
//!
//! Both approval families this service initiates — `task-consent/request/0.1`
//! and `auth/step-up/approve-request/0.2` — mark the request's Data Integrity
//! proof REQUIRED: the approver renders the request's prose (`note`,
//! `effects`, `reason`) as the basis of a human decision, so the request must
//! be attributable to this control plane by signature, not merely by
//! transport attribution (issue #147). The ecosystem-wide contract is:
//! every request leg an approver renders is a well-formed Trust Task
//! document signed by its issuer with `eddsa-jcs-2022` /
//! `proofPurpose: assertionMethod`, and the `issuer` DID equals the DID of
//! `proof.verificationMethod` — exactly the binding this repo's own
//! [`did_hosting_common::server::trust_tasks::TransportBoundVerifier`]
//! enforces on inbound decisions, so a wallet can verify our requests the
//! same way we verify its answers.
//!
//! Signing itself is delegated to `trust_tasks_proof::affinidi::sign_trust_task`
//! (0.2.2+), which additionally pre-flights the in-band `issuer` against the
//! signing key's DID — so a document whose `issuer` doesn't match the key is
//! refused at sign time rather than shipped and refused by the wallet.

use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::Value;
use trust_tasks_proof::affinidi::{CryptoSuite, SignOptions, sign_trust_task};

use crate::error::AppError;
use crate::server::AppState;

/// Load the control DID's assertion key as a signing [`Secret`].
///
/// Sourced from [`AppState::identity`], not `signing_key_bytes`: the identity
/// is the single source of truth for *which kid* the key answers to — its
/// current generation's `signing_kid` is resolved from the DID document's
/// `authentication` entry (the same key `build_did_document` also lists under
/// `assertionMethod`), and a rotation replaces the live set in place, so the
/// proof's `verificationMethod` always names a key the published document
/// still advertises. `signing_key_bytes` is the same seed but decoded once at
/// boot with no kid attached, so it goes stale across a rotation.
///
/// `control_did` must be the configured `server_did`; a mismatch with the
/// current identity generation means the identity store and config disagree,
/// and signing with either would produce a proof that fails the
/// issuer == verificationMethod-DID binding on the wallet side.
pub fn control_assertion_secret(state: &AppState, control_did: &str) -> Result<Secret, AppError> {
    let identity = state.identity.as_deref().ok_or_else(|| {
        AppError::Internal(
            "service identity not loaded; cannot sign the outbound request document".into(),
        )
    })?;
    let generation = identity.current();
    if generation.did != control_did {
        return Err(AppError::Internal(format!(
            "current identity generation DID {} does not match the configured server_did {control_did}",
            generation.did
        )));
    }
    identity
        .secrets()
        .into_iter()
        .find(|s| s.id == generation.signing_kid)
        .ok_or_else(|| {
            AppError::Internal(format!(
                "no signing secret loaded for {}; cannot sign the outbound request document",
                generation.signing_kid
            ))
        })
}

/// Sign an unsigned Trust Task document (no `proof` member) and return it
/// with the `proof` attached.
///
/// `eddsa-jcs-2022`, `proofPurpose: assertionMethod`; the proof's
/// `verificationMethod` is the signing secret's `id` (a `{did}#{fragment}`
/// DID URL), which callers must ensure belongs to the document's `issuer` —
/// [`control_assertion_secret`] guarantees this for the control DID.
pub async fn sign_trust_task_document(
    unsigned: Value,
    signing_secret: &Secret,
) -> Result<Value, AppError> {
    debug_assert!(
        unsigned.get("proof").is_none(),
        "document to sign must not already carry a proof"
    );
    sign_trust_task(
        &unsigned,
        signing_secret,
        SignOptions::new()
            .with_proof_purpose("assertionMethod")
            .with_cryptosuite(CryptoSuite::EddsaJcs2022),
    )
    .await
    .map_err(|e| AppError::Internal(format!("sign trust task document: {e}")))
}

#[cfg(test)]
pub(crate) mod test_util {
    use super::*;

    /// A fresh ed25519 `did:key` signer for round-trip tests: returns the
    /// bare DID (the test's "control DID") and a [`Secret`] whose `id` is
    /// the `did:key` verification method, so
    /// [`affinidi_data_integrity::DidKeyResolver`] resolves it without I/O.
    pub(crate) fn did_key_signer(seed: &[u8; 32]) -> (String, Secret) {
        let secret = Secret::generate_ed25519(None, Some(seed));
        let pk_mb = secret.get_public_keymultibase().expect("multibase pubkey");
        let did = format!("did:key:{pk_mb}");
        let mut signer = secret;
        signer.id = format!("{did}#{pk_mb}");
        (did, signer)
    }
}
