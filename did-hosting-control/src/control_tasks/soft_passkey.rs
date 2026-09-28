//! A software WebAuthn authenticator, for the enrolment tests.
//!
//! It answers the creation and request options the control plane sends with
//! a real `none` attestation and real ES256 assertions, so a test runs the
//! whole ceremony — challenges, origin, user verification, counters —
//! through `webauthn-rs` exactly as a browser's would.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::Private;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The origin the harness's relying party expects.
pub(crate) const ORIGIN: &str = "http://control.test";

/// One authenticator holding one credential.
pub(crate) struct SoftPasskey {
    key: EcKey<Private>,
    pub cred_id: Vec<u8>,
    counter: u32,
    /// Whether it reports user verification (a real one always would here).
    pub user_verified: bool,
}

impl SoftPasskey {
    pub fn new() -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        Self {
            key: EcKey::generate(&group).unwrap(),
            cred_id: rand::random::<[u8; 16]>().to_vec(),
            counter: 0,
            user_verified: true,
        }
    }

    /// The credential id as the wire carries it.
    pub fn id(&self) -> String {
        B64.encode(&self.cred_id)
    }

    fn flags(&self, attested: bool) -> u8 {
        let mut f = 0x01; // UP
        if self.user_verified {
            f |= 0x04; // UV
        }
        if attested {
            f |= 0x40; // AT
        }
        f
    }

    fn cose_key(&self) -> Vec<u8> {
        let group = self.key.group();
        let mut ctx = BigNumContext::new().unwrap();
        let mut x = openssl::bn::BigNum::new().unwrap();
        let mut y = openssl::bn::BigNum::new().unwrap();
        self.key
            .public_key()
            .affine_coordinates(group, &mut x, &mut y, &mut ctx)
            .unwrap();
        let pad = |b: openssl::bn::BigNum| b.to_vec_padded(32).unwrap();
        cbor::map(&[
            (cbor::int(1), cbor::int(2)),  // kty: EC2
            (cbor::int(3), cbor::int(-7)), // alg: ES256
            (cbor::int(-1), cbor::int(1)), // crv: P-256
            (cbor::int(-2), cbor::bytes(&pad(x))),
            (cbor::int(-3), cbor::bytes(&pad(y))),
        ])
    }

    fn client_data(kind: &str, challenge: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": kind,
            "challenge": challenge,
            "origin": ORIGIN,
            "crossOrigin": false,
        }))
        .unwrap()
    }

    /// `navigator.credentials.create` over `options` (the `options` member of
    /// an enrolment start).
    pub fn attest(&mut self, options: &Value) -> Value {
        let challenge = options["challenge"].as_str().expect("a challenge");
        let rp_id = options["rp"]["id"].as_str().expect("an rp id");
        let client_data = Self::client_data("webauthn.create", challenge);
        self.counter += 1;
        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(self.flags(true));
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
        auth_data.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.cred_id);
        auth_data.extend_from_slice(&self.cose_key());
        let attestation_object = cbor::map(&[
            (cbor::text("fmt"), cbor::text("none")),
            (cbor::text("attStmt"), cbor::map(&[])),
            (cbor::text("authData"), cbor::bytes(&auth_data)),
        ]);
        json!({
            "id": self.id(),
            "rawId": self.id(),
            "type": "public-key",
            "response": {
                "attestationObject": B64.encode(attestation_object),
                "clientDataJSON": B64.encode(client_data),
            },
            "clientExtensionResults": {},
        })
    }

    /// `navigator.credentials.get` over `options` (request options: a
    /// login's `options`, or an enrolment's `uvOptions`).
    pub fn assert(&mut self, options: &Value) -> Value {
        let challenge = options["challenge"].as_str().expect("a challenge");
        let rp_id = options["rpId"].as_str().unwrap_or("control.test");
        let client_data = Self::client_data("webauthn.get", challenge);
        self.counter += 1;
        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(self.flags(false));
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let sig = EcdsaSig::sign(&Sha256::digest(&signed), &self.key)
            .unwrap()
            .to_der()
            .unwrap();
        json!({
            "id": self.id(),
            "rawId": self.id(),
            "type": "public-key",
            "response": {
                "authenticatorData": B64.encode(auth_data),
                "clientDataJSON": B64.encode(client_data),
                "signature": B64.encode(sig),
            },
            "clientExtensionResults": {},
        })
    }
}

/// Just enough CBOR (RFC 8949) for an attestation object and a COSE key.
mod cbor {
    fn head(major: u8, n: u64) -> Vec<u8> {
        let m = major << 5;
        match n {
            0..=23 => vec![m | n as u8],
            24..=0xff => vec![m | 24, n as u8],
            0x100..=0xffff => {
                let mut v = vec![m | 25];
                v.extend_from_slice(&(n as u16).to_be_bytes());
                v
            }
            _ => {
                let mut v = vec![m | 26];
                v.extend_from_slice(&(n as u32).to_be_bytes());
                v
            }
        }
    }

    pub fn int(i: i64) -> Vec<u8> {
        if i >= 0 {
            head(0, i as u64)
        } else {
            head(1, (-1 - i) as u64)
        }
    }

    pub fn bytes(b: &[u8]) -> Vec<u8> {
        let mut v = head(2, b.len() as u64);
        v.extend_from_slice(b);
        v
    }

    pub fn text(s: &str) -> Vec<u8> {
        let mut v = head(3, s.len() as u64);
        v.extend_from_slice(s.as_bytes());
        v
    }

    pub fn map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut v = head(5, entries.len() as u64);
        for (k, val) in entries {
            v.extend_from_slice(k);
            v.extend_from_slice(val);
        }
        v
    }
}
