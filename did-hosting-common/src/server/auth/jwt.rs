use crate::server::error::AppError;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Idempotently install the process-level `jsonwebtoken::CryptoProvider`.
///
/// `jsonwebtoken` 10.x supports two providers (`rust_crypto` + `aws_lc_rs`)
/// and refuses to auto-pick when both features are compiled in. That state
/// is reachable when this crate is built alongside another that pulls in
/// `aws_lc_rs` — feature unification turns on both — for example
/// `affinidi-messaging-test-mediator` in dev-deps. We always pick
/// `rust_crypto` (matches our workspace dep declaration), and the
/// `OnceLock` makes the install a no-op on subsequent calls.
///
/// Safe to call from any thread, any number of times. Always called
/// before encode/decode so JWT operations work regardless of which
/// downstream crate enables which feature.
fn ensure_jwt_crypto_provider() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        // When both providers are unified by cargo (e.g. when our build
        // also pulls in `aws_lc_rs` via test-mediator dev-deps), install
        // `rust_crypto` explicitly to match the workspace dep declaration.
        // When only one provider is active the call is redundant —
        // `install_default` returns `Err(already installed)` and we ignore.
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
    });
}

/// Default authentication methods (`amr`) for a base login: a single
/// `did` factor (did:key over REST SIOP / DIDComm authcrypt). Step-up
/// adds factors (`webauthn`, `vta`) and bumps `acr` to `aal2`.
fn default_amr() -> Vec<String> {
    vec!["did".to_string()]
}

/// Default assurance level (`acr`) for a base login. Step-up elevates to
/// `aal2`. Tokens minted before this field existed decode as `aal1`.
fn default_acr() -> String {
    "aal1".to_string()
}

/// JWT claims for WebVH access tokens.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub aud: String,
    pub sub: String,
    pub session_id: String,
    pub role: String,
    pub exp: u64,
    /// Issued-at timestamp (RFC 7519 §4.1.6).
    #[serde(default)]
    pub iat: u64,
    /// Unique token ID — rotated on each refresh so old tokens are invalidated.
    #[serde(default)]
    pub jti: String,
    /// Authentication methods references (RFC 8176-style). Base login is
    /// `["did"]`; step-up appends `"webauthn"` or `"vta"`.
    #[serde(default = "default_amr")]
    pub amr: Vec<String>,
    /// Authentication context class / assurance level. `"aal1"` for a base
    /// login, `"aal2"` after a step-up. RP gates sensitive ops on this.
    #[serde(default = "default_acr")]
    pub acr: String,
}

/// Holds the JWT encoding and decoding keys derived from an Ed25519 seed.
pub struct JwtKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl JwtKeys {
    /// Create JWT keys from raw 32-byte Ed25519 private key bytes.
    ///
    /// Computes the public key and wraps both in DER format as required
    /// by `jsonwebtoken`'s `from_ed_der()` methods.
    pub fn from_ed25519_bytes(private_bytes: &[u8; 32]) -> Result<Self, AppError> {
        ensure_jwt_crypto_provider();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(private_bytes);
        let public_bytes = signing_key.verifying_key().to_bytes();

        // Build PKCS8 v1 DER for the private key (used by EncodingKey).
        // Structure follows RFC 8410 §7 (Ed25519 private key) and SEC 1 §C.4:
        //   SEQUENCE { INTEGER 0, AlgorithmIdentifier(Ed25519), OCTET STRING { OCTET STRING key } }
        let mut pkcs8 = Vec::with_capacity(48);
        pkcs8.extend_from_slice(&[
            0x30, 0x2e, // SEQUENCE, 46 bytes
            0x02, 0x01, 0x00, // INTEGER 0 (version v1)
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier (Ed25519)
            0x04, 0x22, 0x04, 0x20, // OCTET STRING { OCTET STRING, 32 bytes }
        ]);
        pkcs8.extend_from_slice(private_bytes);

        let encoding = EncodingKey::from_ed_der(&pkcs8);
        // rust_crypto backend expects raw 32-byte public key, not SPKI DER
        let decoding = DecodingKey::from_ed_der(&public_bytes);

        Ok(Self { encoding, decoding })
    }

    /// Encode claims into a signed JWT access token.
    pub fn encode(&self, claims: &Claims) -> Result<String, AppError> {
        let header = Header::new(Algorithm::EdDSA);
        jsonwebtoken::encode(&header, claims, &self.encoding)
            .map_err(|e| AppError::Internal(format!("JWT encode failed: {e}")))
    }

    /// Decode and validate a JWT access token, returning the claims.
    pub fn decode(&self, token: &str) -> Result<Claims, AppError> {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["WebVH"]);
        validation.set_required_spec_claims(&["exp", "sub", "aud", "session_id", "role"]);

        jsonwebtoken::decode::<Claims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                debug!(error = %e, "JWT decode failed");
                AppError::Unauthorized(format!("invalid token: {e}"))
            })
    }

    /// Create claims for a new access token.
    pub fn new_claims(sub: String, session_id: String, role: String, expiry_secs: u64) -> Claims {
        // `unwrap_or_default()` mirrors `now_epoch()` — a system clock
        // set before 1970 yields 0 here rather than panicking the JWT
        // issue path.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Claims {
            aud: "WebVH".to_string(),
            sub,
            session_id,
            role,
            exp: now + expiry_secs,
            iat: now,
            jti: uuid::Uuid::new_v4().to_string(),
            amr: default_amr(),
            acr: default_acr(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> JwtKeys {
        JwtKeys::from_ed25519_bytes(&[7u8; 32]).expect("test key")
    }

    fn other_keys() -> JwtKeys {
        JwtKeys::from_ed25519_bytes(&[42u8; 32]).expect("other test key")
    }

    fn make_claims(role: &str, expiry_secs: u64) -> Claims {
        JwtKeys::new_claims(
            "did:example:caller".into(),
            "session-abc".into(),
            role.into(),
            expiry_secs,
        )
    }

    #[test]
    fn encode_decode_round_trip() {
        let keys = keys();
        let claims = make_claims("admin", 60);
        let token = keys.encode(&claims).unwrap();
        let decoded = keys.decode(&token).unwrap();
        assert_eq!(decoded.aud, "WebVH");
        assert_eq!(decoded.sub, "did:example:caller");
        assert_eq!(decoded.session_id, "session-abc");
        assert_eq!(decoded.role, "admin");
        assert_eq!(decoded.exp, claims.exp);
        assert_eq!(decoded.jti, claims.jti);
    }

    #[test]
    fn decode_rejects_token_signed_by_different_key() {
        let issuer = keys();
        let attacker = other_keys();
        let claims = make_claims("admin", 60);
        let token = attacker.encode(&claims).unwrap();
        assert!(issuer.decode(&token).is_err());
    }

    #[test]
    fn decode_rejects_expired_token() {
        let keys = keys();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // jsonwebtoken's default leeway is 60s, so put expiry well past it.
        let claims = Claims {
            aud: "WebVH".into(),
            sub: "did:example:expired".into(),
            session_id: "s".into(),
            role: "owner".into(),
            exp: now - 3600,
            iat: now - 7200,
            jti: "j".into(),
        };
        let token = keys.encode(&claims).unwrap();
        let err = keys.decode(&token).unwrap_err();
        assert!(matches!(err, AppError::Unauthorized(_)));
    }

    #[test]
    fn decode_rejects_wrong_audience() {
        let keys = keys();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = Claims {
            aud: "OtherAudience".into(),
            sub: "did:example:wrong-aud".into(),
            session_id: "s".into(),
            role: "owner".into(),
            exp: now + 60,
            iat: now,
            jti: "j".into(),
        };
        let token = keys.encode(&claims).unwrap();
        assert!(keys.decode(&token).is_err());
    }

    #[test]
    fn decode_rejects_garbage_token() {
        let keys = keys();
        assert!(keys.decode("not-a-jwt").is_err());
        assert!(keys.decode("ey.ey.ey").is_err());
        assert!(keys.decode("").is_err());
    }

    #[test]
    fn decode_rejects_alg_none_attempt() {
        // Manually construct a JWT with `alg: none`. Decoder must refuse.
        // Header `{"alg":"none","typ":"JWT"}` base64url = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
        let header_b64 = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
        // Payload with valid claim shape so the only failure is the alg check
        let payload = serde_json::json!({
            "aud": "WebVH",
            "sub": "did:attacker",
            "session_id": "s",
            "role": "admin",
            "exp": 9999999999u64,
            "iat": 0u64,
            "jti": "j",
        });
        let payload_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_vec(&payload).unwrap(),
        );
        let unsigned = format!("{header_b64}.{payload_b64}.");
        assert!(keys().decode(&unsigned).is_err());
    }

    #[test]
    fn new_claims_populates_fresh_jti_and_iat_each_call() {
        let a = JwtKeys::new_claims("did:s".into(), "s".into(), "owner".into(), 60);
        let b = JwtKeys::new_claims("did:s".into(), "s".into(), "owner".into(), 60);
        assert_ne!(a.jti, b.jti);
        assert!(a.iat > 0);
        assert!(a.exp > a.iat);
        assert_eq!(a.exp - a.iat, 60);
    }
}
