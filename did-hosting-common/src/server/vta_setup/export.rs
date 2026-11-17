//! Offline export: sealing an already-provisioned DID's secrets for migration
//! or onboarding elsewhere, and opening such a bundle.

use super::*;

// ---------------------------------------------------------------------------
// Offline export (sealed outbound for migration / onboarding)
//
// The inverse of the offline bootstrap: take an already-provisioned webvh
// identity (DID + signing + KA keys) and hand it to another party through
// an HPKE-sealed bundle that matches the format their `open_bundle` path
// expects. The receiver must have already produced a
// `bootstrap-request.json` (same shape `write_offline_bootstrap_request`
// writes), containing their ephemeral did:key + nonce.
//
// Two assertion modes. `PinnedOnly` relies on the OOB digest as the
// sole integrity anchor; `DidSigned` additionally signs a domain-tagged
// message (`b"vta-sealed-transfer/v1\0" || client_x25519_pub ||
// bundle_id`) with the producer's Ed25519 key so the receiver can verify
// against the producer DID's `#key-0` pubkey. Prefer DidSigned when both
// sides have the pubkey available; fall back to PinnedOnly for
// pinned-digest-only deployments.
// ---------------------------------------------------------------------------

/// How the exporter builds its `ProducerAssertion`.
#[derive(Debug, Clone)]
pub enum ExportAssertionMode {
    /// No in-band proof. The receiver must verify the SHA-256 digest
    /// out-of-band — that's the only trust anchor.
    PinnedOnly,
    /// Sign a domain-tagged assertion with the exporter's Ed25519 key.
    /// `signing_key_multibase` is the private key (raw seed in multibase
    /// form, same shape we persist to the secret store). `verification_method`
    /// goes on the assertion verbatim — typically `{producer_did}#key-0`.
    DidSigned {
        signing_key_multibase: String,
        verification_method: String,
    },
}

/// Result of a successful export. Use `digest` as the OOB value the
/// receiver will pass as `--expect-digest` when opening the bundle.
#[derive(Debug, Clone)]
pub struct SealedExportInfo {
    /// Where the armored sealed bundle was written.
    pub out_path: std::path::PathBuf,
    /// SHA-256 of the bundle ciphertext, lowercase hex. Communicate
    /// this to the receiver out-of-band (email, phone, etc.). For a
    /// `PinnedOnly` producer assertion this is the *only* integrity
    /// anchor protecting the seal.
    pub digest: String,
    /// The receiver's ephemeral did:key (for the operator to
    /// eyeball-check which request they just sealed to).
    pub recipient_did: String,
    /// Hex-encoded 16-byte bundle id (same as the receiver's nonce).
    pub bundle_id_hex: String,
}

/// Seal an existing DID + its signing and key-agreement private keys as
/// a `DidSecrets` payload directed at the receiver described in
/// `request_path`.
///
/// `producer_did` goes into the `ProducerAssertion::producer_did` field —
/// typically the exporting service's own DID (e.g. `config.server_did`).
/// `did` is the DID the exported keys belong to (usually the same).
/// `signing_key_multibase` / `ka_key_multibase` are the private multibase
/// strings from the local secret store. Key IDs are derived as
/// `<did>#key-0` / `<did>#key-1` to match the upstream webvh templates.
pub async fn export_sealed_did_secrets(
    request_path: &Path,
    out_path: &Path,
    producer_did: &str,
    did: &str,
    signing_key_multibase: String,
    ka_key_multibase: String,
    assertion: ExportAssertionMode,
) -> Result<SealedExportInfo, Box<dyn std::error::Error>> {
    use vta_sdk::did_secrets::{DidSecretsBundle, SecretEntry};
    use vta_sdk::keys::KeyType;
    use vta_sdk::sealed_transfer::bundle::{AssertionProof, DidSignedAssertion, ProducerAssertion};
    use vta_sdk::sealed_transfer::verify::DID_SIGNED_DOMAIN_TAG;
    use vta_sdk::sealed_transfer::{
        BootstrapRequest, InMemoryNonceStore, SealedPayloadV1, armor, bundle_digest, seal_payload,
    };

    let req_json = std::fs::read_to_string(request_path)
        .map_err(|e| format!("read {}: {e}", request_path.display()))?;
    let request: BootstrapRequest = serde_json::from_str(&req_json)
        .map_err(|e| format!("parse {}: {e}", request_path.display()))?;

    let recipient_x25519 = request.decode_client_x25519_pub()?;
    let bundle_id = request.decode_nonce()?;

    let secrets = DidSecretsBundle {
        did: did.to_string(),
        secrets: vec![
            SecretEntry {
                key_id: format!("{did}#key-0"),
                key_type: KeyType::Ed25519,
                private_key_multibase: signing_key_multibase,
            },
            SecretEntry {
                key_id: format!("{did}#key-1"),
                key_type: KeyType::X25519,
                private_key_multibase: ka_key_multibase,
            },
        ],
    };
    let payload = SealedPayloadV1::DidSecrets(Box::new(secrets));

    let proof = match &assertion {
        ExportAssertionMode::PinnedOnly => AssertionProof::PinnedOnly,
        ExportAssertionMode::DidSigned {
            signing_key_multibase,
            verification_method,
        } => {
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
            use ed25519_dalek::{Signer, SigningKey};

            // Extract the raw 32-byte Ed25519 seed from the multibase
            // private key string. We go through the affinidi-tdk Secret
            // helper so the multicodec framing matches however the key
            // was persisted at setup time.
            let signer_secret = Secret::from_multibase(signing_key_multibase, None)
                .map_err(|e| format!("invalid signing key: {e}"))?;
            let seed_bytes: [u8; 32] = signer_secret
                .get_private_bytes()
                .try_into()
                .map_err(|_| "signing key is not a 32-byte Ed25519 seed")?;
            let sk = SigningKey::from_bytes(&seed_bytes);

            // Domain-tagged message — matches the producer side of the
            // VTA's `build_did_signed_assertion` and what
            // `verify_did_signed_assertion_with_pubkey` checks.
            let mut msg = Vec::with_capacity(
                DID_SIGNED_DOMAIN_TAG.len() + recipient_x25519.len() + bundle_id.len(),
            );
            msg.extend_from_slice(DID_SIGNED_DOMAIN_TAG);
            msg.extend_from_slice(&recipient_x25519);
            msg.extend_from_slice(&bundle_id);
            let sig = sk.sign(&msg);

            AssertionProof::DidSigned(DidSignedAssertion {
                did: producer_did.to_string(),
                signature_b64: B64URL.encode(sig.to_bytes()),
                verification_method: verification_method.clone(),
            })
        }
    };

    let producer = ProducerAssertion {
        producer_did: producer_did.to_string(),
        proof,
    };

    // Each export is a one-shot operation, so a fresh in-memory nonce
    // store is sufficient — we only need the "is this bundle_id reused
    // within this call?" check, not cross-invocation history (the
    // receiver's nonce is a fresh 16-byte value anyway).
    let nonce_store = InMemoryNonceStore::new();

    let sealed = seal_payload(
        &recipient_x25519,
        bundle_id,
        producer,
        &payload,
        &nonce_store,
    )
    .await?;
    let digest = bundle_digest(&sealed);
    let armored = armor::encode(&sealed);

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out_path, &armored).map_err(|e| format!("write {}: {e}", out_path.display()))?;

    Ok(SealedExportInfo {
        out_path: out_path.to_path_buf(),
        digest,
        recipient_did: request.client_did,
        bundle_id_hex: hex::encode(bundle_id),
    })
}

/// Result of opening a sealed `DidSecrets` migration bundle — the inverse
/// of [`export_sealed_did_secrets`]. Carries just the DID + key material
/// the exporter included (no DID document, no VTA trust bundle — those
/// live in a `TemplateBootstrap` bundle, not a `DidSecrets` one).
#[derive(Debug, Clone)]
pub struct SealedDidSecretsResult {
    pub did: String,
    pub signing_key_multibase: String,
    pub key_agreement_multibase: String,
    /// The producer DID the sealer claimed. With `PinnedOnly` assertions
    /// this is informational only; with `DidSigned` + a caller-supplied
    /// pubkey it has been cryptographically verified and `assertion_verified`
    /// is true.
    pub producer_did: String,
    /// True when the producer assertion was `DidSigned` and successfully
    /// verified against `expected_producer_pubkey`. False when the
    /// assertion was `PinnedOnly` (digest-only trust) or when no
    /// expected pubkey was supplied and the assertion was informational.
    pub assertion_verified: bool,
}

/// Open a sealed migration bundle produced by
/// [`export_sealed_did_secrets`] and surface the private key material
/// the exporter included.
///
/// Reads the ephemeral seed the receiver persisted at
/// `write_offline_bootstrap_request` time, verifies the OOB digest,
/// opens the HPKE-sealed payload, and asserts it is the `DidSecrets`
/// variant carrying one Ed25519 (signing) + one X25519 (key agreement)
/// entry keyed to the same DID.
///
/// `expected_producer_pubkey` enables `DidSigned` verification: when
/// supplied, the assertion MUST be `DidSigned`, its `producer_did` must
/// match the chunk header, and its signature must verify against the
/// given 32-byte Ed25519 pubkey. When `None`, the opener accepts both
/// `PinnedOnly` and `DidSigned` assertions and treats the producer
/// identity as informational (the OOB digest is the only anchor).
pub fn open_sealed_did_secrets(
    bundle_armor: &str,
    expect_digest: &str,
    seed_path: &Path,
    expected_producer_pubkey: Option<&[u8; 32]>,
) -> Result<SealedDidSecretsResult, Box<dyn std::error::Error>> {
    use vta_sdk::didcomm_light::ed25519_pub_to_x25519_pub;
    use vta_sdk::keys::KeyType;
    use vta_sdk::sealed_transfer::bundle::AssertionProof;
    use vta_sdk::sealed_transfer::verify::verify_did_signed_assertion_with_pubkey;
    use vta_sdk::sealed_transfer::{
        SealedPayloadV1, armor, ed25519_seed_to_x25519_secret, open_bundle,
    };

    let seed_bytes = std::fs::read(seed_path).map_err(|e| {
        format!(
            "failed to read ephemeral seed at {}: {e}",
            seed_path.display()
        )
    })?;
    if seed_bytes.len() != 32 {
        return Err(format!(
            "ephemeral seed at {} has {} bytes (expected 32)",
            seed_path.display(),
            seed_bytes.len()
        )
        .into());
    }
    let seed: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .expect("checked length above");
    let recipient_secret = ed25519_seed_to_x25519_secret(&seed);

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

    let opened = open_bundle(&recipient_secret, bundle, Some(expect_digest))?;

    // If the caller pinned the producer's Ed25519 pubkey, demand a
    // DidSigned assertion and verify the signature. Otherwise the
    // OOB digest stays the only anchor (matches the original behaviour).
    let mut assertion_verified = false;
    if let Some(expected_pubkey) = expected_producer_pubkey {
        match &opened.producer.proof {
            AssertionProof::DidSigned(assertion) => {
                // Derive client_x25519_pub from our own seed (what the
                // producer signed over). Ed25519 pub → X25519 pub is the
                // Montgomery-form conversion of the verifying key.
                use ed25519_dalek::SigningKey;
                let client_ed_pub = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
                let client_x_pub = ed25519_pub_to_x25519_pub(&client_ed_pub)
                    .map_err(|e| format!("derive client X25519 pubkey: {e}"))?;
                verify_did_signed_assertion_with_pubkey(
                    assertion,
                    &opened.producer.producer_did,
                    expected_pubkey,
                    &client_x_pub,
                    &opened.bundle_id,
                )
                .map_err(|e| format!("DidSigned verification failed: {e}"))?;
                assertion_verified = true;
            }
            AssertionProof::PinnedOnly => {
                return Err(
                    "expected DidSigned producer assertion but bundle carries PinnedOnly — \
                     either drop the expected pubkey to accept PinnedOnly, or ask the \
                     exporter to sign"
                        .into(),
                );
            }
            AssertionProof::Attested(_) => {
                return Err(
                    "expected DidSigned producer assertion but bundle carries Attested (Nitro); \
                     not supported in this flow"
                        .into(),
                );
            }
        }
    }

    let did_secrets = match opened.payload {
        SealedPayloadV1::DidSecrets(boxed) => *boxed,
        _ => return Err("sealed bundle was not a DidSecrets payload".into()),
    };

    let mut signing = None;
    let mut ka = None;
    for entry in did_secrets.secrets {
        match entry.key_type {
            KeyType::Ed25519 if signing.is_none() => signing = Some(entry.private_key_multibase),
            KeyType::X25519 if ka.is_none() => ka = Some(entry.private_key_multibase),
            _ => {}
        }
    }

    Ok(SealedDidSecretsResult {
        did: did_secrets.did,
        signing_key_multibase: signing
            .ok_or("sealed DidSecrets bundle has no Ed25519 signing key")?,
        key_agreement_multibase: ka
            .ok_or("sealed DidSecrets bundle has no X25519 key agreement key")?,
        producer_did: opened.producer.producer_did,
        assertion_verified,
    })
}
