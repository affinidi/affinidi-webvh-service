//! Freshness bounds for signed messages and documents, and verification of a
//! SIOPv2 self-issued `id_token` against its issuer's resolved DID document.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_tdk::did_common::DocumentExt;
use affinidi_tdk::didcomm::jws::envelope::JwsProtectedHeader;
use base64::Engine;

use super::error::AppError;

/// Maximum age of a signed message or document accepted, in seconds.
/// Older ones are refused as stale; replay caches keep entries at least
/// this long, so one still fresh enough to accept is still tracked for
/// replay detection.
pub const FRESHNESS_WINDOW_SECS: u64 = 300;

/// How far into the future a signed message or document's timestamp may sit
/// and still be accepted, absorbing ordinary clock skew between peers.
pub const FUTURE_SKEW_SECS: u64 = 60;

/// Resolve an Ed25519 verifying key from a DID document given a key ID (DID URL fragment).
///
/// Rejects verification methods whose `type` declares them as X25519
/// key-agreement keys. Ed25519 (signing) and X25519 (DH) keys are both 32
/// bytes, so the length check below would not catch a kid that points at
/// the wrong key type — the operator would just see a mysterious "unpack
/// failed" downstream. An explicit type-class check produces a precise
/// error and avoids confusing-key-purpose attacks where a DID document
/// publishes both signing and key-agreement keys under predictable
/// fragments.
async fn resolve_verifying_key(
    did_resolver: &DIDCacheClient,
    kid: &str,
) -> Result<[u8; 32], AppError> {
    let base_did = kid.split('#').next().unwrap_or(kid);

    let resolved = did_resolver
        .resolve(base_did)
        .await
        .map_err(|e| AppError::Authentication(format!("failed to resolve DID {base_did}: {e}")))?;

    // Signing in is authentication, so the key must be one the DID lists under
    // `authentication` — not merely any key in its document (an
    // `assertionMethod` key is for attestations, a `keyAgreement` key for
    // encryption).
    let fragment = kid.find('#').map(|i| &kid[i..]);
    let refers = |id: &str| id == kid || fragment.is_some_and(|f| id == f);
    let listed = resolved.doc.authentication.iter().any(|r| {
        match r {
        affinidi_tdk::did_common::verification_method::VerificationRelationship::Reference(id) => {
            refers(id)
        }
        affinidi_tdk::did_common::verification_method::VerificationRelationship::VerificationMethod(
            m,
        ) => refers(m.id.as_str()),
        _ => false,
    }
    });
    if !listed {
        return Err(AppError::Authentication(format!(
            "verification method {kid} is not an authentication key of {base_did}"
        )));
    }

    let vm = resolved.doc.get_verification_method(kid).ok_or_else(|| {
        AppError::Authentication(format!(
            "verification method {kid} not found in DID document"
        ))
    })?;

    // Reject obvious key-agreement (X25519) types. We don't whitelist Ed25519
    // types because the spec admits several names (Ed25519VerificationKey2018,
    // Ed25519VerificationKey2020, Multikey with a z6Mk… prefix, JsonWebKey2020
    // with crv:Ed25519) — but X25519 has narrow, well-known type names that
    // are unambiguous to refuse.
    let vm_type = vm.type_.as_str();
    if matches!(
        vm_type,
        "X25519KeyAgreementKey2020" | "X25519KeyAgreementKey2019"
    ) {
        return Err(AppError::Authentication(format!(
            "verification method {kid} is an X25519 key-agreement key; expected an Ed25519 signing key"
        )));
    }

    let pk_bytes = vm
        .get_public_key_bytes()
        .map_err(|e| AppError::Authentication(format!("failed to get public key bytes: {e}")))?;

    pk_bytes
        .try_into()
        .map_err(|_| AppError::Authentication("public key must be 32 bytes".into()))
}

// ---------------------------------------------------------------------------
// SIOPv2 self-issued `id_token` verification
// ---------------------------------------------------------------------------

/// Verified claims of a SIOPv2 self-issued `id_token`.
///
/// Only constructable via [`verify_siop_id_token`]. A function that
/// takes this type is guaranteed to be looking at a token whose
/// signature was verified against the `iss` DID's resolved Ed25519
/// authentication key, with `iss == sub`. Caller-relevant claims are
/// surfaced eagerly so consumers don't re-parse the JWS.
#[derive(Debug, Clone)]
pub struct VerifiedSiopIdToken {
    /// `iss` (== `sub`): the self-issued `did:key`. This is the
    /// authenticated subject DID.
    pub issuer: String,
    /// `aud`: the relying-party identifier the wallet targeted.
    pub audience: String,
    /// `nonce`: must be matched against the challenge by the caller.
    pub nonce: String,
    /// `iat`: issued-at (unix seconds).
    pub issued_at: u64,
    /// `exp`: expiry (unix seconds).
    pub expires_at: u64,
}

/// Pre-verification view of the `id_token` payload JSON. Anyone with
/// the compact JWS can produce this; nothing here is trustworthy until
/// the signature is verified.
#[derive(serde::Deserialize)]
struct SiopClaims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<String>,
    nonce: Option<String>,
    iat: Option<u64>,
    exp: Option<u64>,
}

/// Decode the multibase tail of an Ed25519 `did:key` to its raw 32-byte
/// public key. Rejects anything that isn't `did:key:z…` with the
/// multicodec `0xed01` (Ed25519) prefix followed by exactly 32 bytes.
fn ed25519_pubkey_from_did_key(did: &str) -> Result<[u8; 32], AppError> {
    let multibase = did
        .strip_prefix("did:key:")
        .ok_or_else(|| AppError::Authentication("id_token `iss` is not a did:key".into()))?;
    // did:key uses base58btc multibase (`z` prefix). `multibase::decode`
    // handles the prefix and returns the raw multicodec-prefixed bytes.
    let (_base, bytes) = multibase::decode(multibase)
        .map_err(|e| AppError::Authentication(format!("id_token `iss` multibase invalid: {e}")))?;
    // Multicodec 0xed01 (varint) = Ed25519 public key, then 32 key bytes.
    let key = bytes.strip_prefix(&[0xed, 0x01]).ok_or_else(|| {
        AppError::Authentication("id_token `iss` is not an Ed25519 did:key".into())
    })?;
    key.try_into()
        .map_err(|_| AppError::Authentication("id_token `iss` Ed25519 key is not 32 bytes".into()))
}

/// The `iss` a compact SIOPv2 `id_token` claims, read without verifying
/// anything — so a caller can refuse a token naming a DID it would never
/// accept before [`verify_siop_id_token`] resolves that DID. `None` when the
/// token is not a compact JWS with a JSON payload carrying `iss`.
pub fn siop_id_token_claimed_issuer(id_token: &str) -> Option<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload_b64 = id_token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    serde_json::from_slice::<SiopClaims>(&bytes).ok()?.iss
}

/// Verify a SIOPv2 self-issued `id_token` (compact EdDSA JWS).
///
/// Performs the cryptographic security checks; envelope/session/TTL
/// checks (`nonce` ↔ challenge, session state, `iss` ↔ session DID,
/// `aud` ↔ RP id) are the caller's responsibility because they need
/// session and config state this module does not own.
///
/// Steps:
/// 1. Split the compact JWS into `header.payload.signature`.
/// 2. Parse the payload JSON (pre-verify) and require `iss` present and
///    `iss == sub`.
/// 3. Resolve the authentication key for `iss`. The `kid` is honoured
///    for the verification-method lookup (resolved via
///    [`resolve_verifying_key`], which also requires the key to be listed
///    under `authentication`), and the resolved
///    key's base DID must equal `iss`. Works for any DID method the
///    resolver supports — `did:key` (in-tree) and `did:webvh` (DID
///    document fetched) alike. For `did:key`, which is self-certifying,
///    the resolved key is *additionally* pinned against the key encoded
///    in the DID string, so a header pointing at a foreign DID's key
///    cannot impersonate the `iss`. For document-based methods the
///    resolved DID document is the authority.
/// 4. EdDSA-verify the signature over the ASCII `header.payload`.
///
/// Returns the [`VerifiedSiopIdToken`] with eagerly-parsed claims.
pub async fn verify_siop_id_token(
    id_token: &str,
    did_resolver: &DIDCacheClient,
) -> Result<VerifiedSiopIdToken, AppError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // 1. Split the compact JWS.
    let mut parts = id_token.split('.');
    let (header_b64, payload_b64, sig_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => {
                return Err(AppError::Authentication(
                    "id_token is not a compact JWS (header.payload.signature)".into(),
                ));
            }
        };

    // 2. Parse the payload JSON (pre-verify) and check iss == sub.
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| AppError::Authentication(format!("id_token payload not base64url: {e}")))?;
    let claims: SiopClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AppError::Authentication(format!("id_token payload not JSON: {e}")))?;

    let iss = claims
        .iss
        .ok_or_else(|| AppError::Authentication("id_token missing `iss`".into()))?;
    let sub = claims
        .sub
        .ok_or_else(|| AppError::Authentication("id_token missing `sub`".into()))?;
    if iss != sub {
        return Err(AppError::Authentication(
            "id_token `iss` does not equal `sub`".into(),
        ));
    }

    // 3. Resolve the Ed25519 key. The header `kid` drives the
    //    verification-method lookup; the resolved key's base DID must be
    //    `iss`. We additionally pin against the key encoded directly in
    //    the `iss` did:key so a `kid` pointing at a foreign DID can't
    //    sneak past resolution.
    let kid = extract_signer_kid_compact(header_b64)?;
    let kid_base = kid.split('#').next().unwrap_or(&kid);
    if kid_base != iss {
        return Err(AppError::Authentication(
            "id_token header `kid` DID does not match `iss`".into(),
        ));
    }
    // Resolve `iss`'s authentication key. The resolver handles any DID
    // method it supports — `did:key` in-tree, `did:webvh` by fetching
    // the DID document, etc. For `did:key` (self-certifying) we
    // additionally pin the resolved key against the key encoded directly
    // in the DID string, so a `kid` can't point at a foreign key. For
    // document-based methods (`did:webvh`, `did:peer`) the resolved DID
    // document is the authority — there is no in-string key to pin to.
    let resolved_key = resolve_verifying_key(did_resolver, &kid).await?;
    if iss.starts_with("did:key:") {
        let did_key_pub = ed25519_pubkey_from_did_key(&iss)?;
        if resolved_key != did_key_pub {
            return Err(AppError::Authentication(
                "id_token `iss` did:key does not match its resolved authentication key".into(),
            ));
        }
    }

    // 4. EdDSA-verify the signature over the ASCII `header.payload`
    //    against the resolved authentication key.
    let verifying_key = VerifyingKey::from_bytes(&resolved_key)
        .map_err(|e| AppError::Authentication(format!("invalid Ed25519 public key: {e}")))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| AppError::Authentication(format!("id_token signature not base64url: {e}")))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| AppError::Authentication(format!("id_token signature malformed: {e}")))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| AppError::Authentication("id_token signature verification failed".into()))?;

    Ok(VerifiedSiopIdToken {
        issuer: iss,
        audience: claims
            .aud
            .ok_or_else(|| AppError::Authentication("id_token missing `aud`".into()))?,
        nonce: claims
            .nonce
            .ok_or_else(|| AppError::Authentication("id_token missing `nonce`".into()))?,
        issued_at: claims
            .iat
            .ok_or_else(|| AppError::Authentication("id_token missing `iat`".into()))?,
        expires_at: claims
            .exp
            .ok_or_else(|| AppError::Authentication("id_token missing `exp`".into()))?,
    })
}

/// Extract the `kid` from a base64url-encoded compact-JWS protected
/// header, the compact serialization SIOPv2 uses.
fn extract_signer_kid_compact(header_b64: &str) -> Result<String, AppError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| AppError::Authentication(format!("id_token header not base64url: {e}")))?;
    let header: JwsProtectedHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| AppError::Authentication(format!("id_token header not JSON: {e}")))?;
    header
        .kid
        .ok_or_else(|| AppError::Authentication("id_token header missing kid".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SIOPv2 id_token helpers ----

    /// A 32-byte Ed25519 public key encodes to a `did:key:z6Mk…` whose
    /// multibase tail decodes back to the same key bytes. Round-trips
    /// the exact `0xed01 ‖ 32-byte` multicodec shape the verifier pins
    /// `iss` against.
    #[test]
    fn ed25519_pubkey_from_did_key_round_trips() {
        let pk = [7u8; 32];
        // 0xed01 multicodec prefix + raw key, base58btc multibase.
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(&pk);
        let multibase = multibase::encode(multibase::Base::Base58Btc, &multicodec);
        assert!(multibase.starts_with("z6Mk"), "got {multibase}");
        let did = format!("did:key:{multibase}");
        let decoded = ed25519_pubkey_from_did_key(&did).unwrap();
        assert_eq!(decoded, pk);
    }

    #[test]
    fn ed25519_pubkey_from_did_key_rejects_non_did_key() {
        assert!(ed25519_pubkey_from_did_key("did:web:example.com").is_err());
    }

    /// A did:key whose multicodec prefix is X25519 (`0xec01`) must be
    /// rejected — only Ed25519 (`0xed01`) signing keys are admissible
    /// issuers.
    #[test]
    fn ed25519_pubkey_from_did_key_rejects_x25519_multicodec() {
        let mut multicodec = vec![0xec, 0x01];
        multicodec.extend_from_slice(&[9u8; 32]);
        let multibase = multibase::encode(multibase::Base::Base58Btc, &multicodec);
        let did = format!("did:key:{multibase}");
        assert!(ed25519_pubkey_from_did_key(&did).is_err());
    }

    #[test]
    fn extract_signer_kid_compact_reads_header_kid() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": "did:key:z6MkABC#z6MkABC",
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let kid = extract_signer_kid_compact(&header_b64).unwrap();
        assert_eq!(kid, "did:key:z6MkABC#z6MkABC");
    }

    #[test]
    fn extract_signer_kid_compact_rejects_missing_kid() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT" });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        assert!(extract_signer_kid_compact(&header_b64).is_err());
    }

    /// End-to-end: a wallet-shaped token (EdDSA over `header.payload`,
    /// `iss == sub`, header `kid` == `<iss>#<multibase>`) verifies, and
    /// the eagerly-parsed claims surface. Uses the in-crate `did:key`
    /// resolver so no network is touched.
    #[tokio::test]
    async fn verify_siop_id_token_accepts_well_formed_token() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(&pk);
        let multibase = multibase::encode(multibase::Base::Base58Btc, &multicodec);
        let did = format!("did:key:{multibase}");

        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": format!("{did}#{multibase}"),
        });
        let payload = serde_json::json!({
            "iss": did,
            "sub": did,
            "aud": "did:key:server-rp",
            "nonce": "deadbeef",
            "iat": 1_700_000_000u64,
            "exp": 1_700_003_600u64,
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = sk.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let token = format!("{signing_input}.{sig_b64}");

        let resolver = DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .expect("did:key resolver");
        let verified = verify_siop_id_token(&token, &resolver)
            .await
            .expect("well-formed token verifies");
        assert_eq!(verified.issuer, did);
        assert_eq!(verified.audience, "did:key:server-rp");
        assert_eq!(verified.nonce, "deadbeef");
        assert_eq!(verified.issued_at, 1_700_000_000);
        assert_eq!(verified.expires_at, 1_700_003_600);
    }

    /// A flipped signature must be rejected even though everything else
    /// is well-formed — the EdDSA check is the security boundary.
    #[tokio::test]
    async fn verify_siop_id_token_rejects_bad_signature() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(&pk);
        let multibase = multibase::encode(multibase::Base::Base58Btc, &multicodec);
        let did = format!("did:key:{multibase}");

        let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": format!("{did}#{multibase}") });
        let payload = serde_json::json!({
            "iss": did, "sub": did, "aud": "rp", "nonce": "n", "iat": 1u64, "exp": 2u64,
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let sig = sk.sign(format!("{header_b64}.{payload_b64}").as_bytes());
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[0] ^= 0xff; // tamper
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);
        let token = format!("{header_b64}.{payload_b64}.{sig_b64}");

        let resolver = DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .expect("did:key resolver");
        assert!(verify_siop_id_token(&token, &resolver).await.is_err());
    }

    /// A signed sign-in or refresh must use a key the DID lists under
    /// `authentication`; an `assertionMethod`-only key is refused.
    #[tokio::test]
    async fn sign_in_keys_must_be_authentication_keys() {
        use affinidi_secrets_resolver::secrets::Secret;
        let secret = Secret::generate_ed25519(None, Some(&[4u8; 32]));
        let pk = secret.get_public_keymultibase().unwrap();
        let mut resolver = DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        for (did, rel) in [
            ("did:web:auth.example", "authentication"),
            ("did:web:assert.example", "assertionMethod"),
        ] {
            let doc: affinidi_tdk::did_common::Document =
                serde_json::from_value(serde_json::json!({
                    "id": did,
                    "verificationMethod": [{
                        "id": format!("{did}#key-1"),
                        "type": "Multikey",
                        "controller": did,
                        "publicKeyMultibase": pk,
                    }],
                    rel: [format!("{did}#key-1")],
                }))
                .unwrap();
            resolver.add_did_document(did, doc).await;
        }
        resolve_verifying_key(&resolver, "did:web:auth.example#key-1")
            .await
            .expect("authentication key accepted");
        let err = resolve_verifying_key(&resolver, "did:web:assert.example#key-1")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("not an authentication key"),
            "{err}"
        );
    }
}
