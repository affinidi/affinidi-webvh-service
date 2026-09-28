//! A client for a webvh-witness service, over its Trust Task listener.
//!
//! Every call is a Trust Task document signed by the requester
//! (`proofPurpose: authentication`) and addressed to the witness service's
//! DID, posted to the witness's HTTPS binding (`POST {url}/api/trust-tasks`).
//! The witness authorises on that proof alone — there is no session, token or
//! sign-in — and every reply it sends is signed; the client verifies the reply
//! against the witness DID before it believes a word of it.
//!
//! The witness DID and URL come from configuration, never from a response of
//! the service being called.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::{Value, json};
use trust_tasks_rs::Payload;
use trust_tasks_rs::specs::webvh::witness::{
    key::{create::v0_1 as key_create, delete::v0_1 as key_delete, list::v0_1 as key_list},
    sign::v0_1 as sign,
};

use crate::error::{Result, WebVHError};
use crate::server::trust_tasks::send::{build_signed_request, post_trust_task_https};

/// A client for one webvh-witness service, acting as one requester.
pub struct WitnessClient {
    url: String,
    witness_did: String,
    requester_did: String,
    signer: Secret,
    did_resolver: DIDCacheClient,
}

impl WitnessClient {
    /// A client for the witness at `server_url` whose DID is `witness_did`,
    /// signing as `requester_did` with `signer` (one of the requester's
    /// `authentication` keys). `did_resolver` resolves the witness DID to
    /// verify its replies.
    pub fn new(
        server_url: &str,
        witness_did: &str,
        requester_did: &str,
        signer: Secret,
        did_resolver: DIDCacheClient,
    ) -> Self {
        Self {
            url: format!("{}/api/trust-tasks", server_url.trim_end_matches('/')),
            witness_did: witness_did.to_string(),
            requester_did: requester_did.to_string(),
            signer,
            did_resolver,
        }
    }

    /// `webvh/witness/sign/0.1`: ask witness identity `witness_id` to witness
    /// the last entry of `log_content`, whose versionId is `version_id`. The
    /// witness verifies the log first. Returns the witness proof, to be carried
    /// into the DID's `did-witness.json`.
    pub async fn sign(
        &self,
        witness_id: &str,
        version_id: &str,
        log_content: &str,
    ) -> Result<sign::Response> {
        self.call(
            sign::Payload::TYPE_URI,
            json!({
                "witnessId": witness_id,
                "versionId": version_id,
                "logContent": log_content,
            }),
        )
        .await
    }

    /// `webvh/witness/key/list/0.1`: every witness identity the service holds.
    pub async fn list_keys(&self) -> Result<key_list::Response> {
        self.call(key_list::Payload::TYPE_URI, json!({})).await
    }

    /// `webvh/witness/key/create/0.1`: have the service generate a new witness
    /// identity.
    pub async fn create_key(&self, label: Option<&str>) -> Result<key_create::Response> {
        let payload = match label {
            Some(label) => json!({ "label": label }),
            None => json!({}),
        };
        self.call(key_create::Payload::TYPE_URI, payload).await
    }

    /// `webvh/witness/key/delete/0.1`: destroy a witness identity.
    pub async fn delete_key(&self, witness_id: &str) -> Result<key_delete::Response> {
        self.call(
            key_delete::Payload::TYPE_URI,
            json!({ "witnessId": witness_id }),
        )
        .await
    }

    /// The witness's Trust Task endpoint this client posts to.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Send one signed request and read the verified reply as `R`.
    async fn call<R: serde::de::DeserializeOwned>(
        &self,
        type_uri: &str,
        payload: Value,
    ) -> Result<R> {
        let doc = build_signed_request(
            type_uri,
            &self.requester_did,
            &self.witness_did,
            payload,
            &self.signer,
        )
        .await
        .map_err(|e| WebVHError::Transport(e.to_string()))?;
        let reply = post_trust_task_https(
            &self.requester_did,
            &self.witness_did,
            &self.url,
            &doc,
            Some(&self.did_resolver),
        )
        .await
        .map_err(|e| WebVHError::Transport(e.to_string()))?;
        read_reply(type_uri, reply)
    }
}

/// The payload of a verified reply to a `type_uri` request: its `#response`,
/// or the refusal it carries.
pub(crate) fn read_reply<R: serde::de::DeserializeOwned>(
    type_uri: &str,
    reply: trust_tasks_rs::TrustTask<Value>,
) -> Result<R> {
    let reply_type = reply.type_uri.to_string();
    if reply_type == format!("{type_uri}#response") {
        return Ok(serde_json::from_value(reply.payload)?);
    }
    if reply_type.contains("/trust-task-error/") {
        let field = |name: &str| {
            reply
                .payload
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        return Err(WebVHError::Refused {
            code: field("code"),
            message: crate::error::redact_server_message(&field("message")),
        });
    }
    Err(WebVHError::Transport(format!(
        "the service answered {type_uri} with a {reply_type} document"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(type_uri: &str, payload: Value) -> trust_tasks_rs::TrustTask<Value> {
        serde_json::from_value(json!({
            "id": "urn:uuid:00000000-0000-0000-0000-000000000002",
            "type": type_uri,
            "payload": payload,
        }))
        .unwrap()
    }

    #[test]
    fn a_response_is_read_as_its_payload() {
        let r: key_delete::Response = read_reply(
            key_delete::Payload::TYPE_URI,
            reply(
                &format!("{}#response", key_delete::Payload::TYPE_URI),
                json!({ "witnessId": "w1", "deletedAt": "2026-09-27T09:40:01Z" }),
            ),
        )
        .unwrap();
        assert_eq!(r.witness_id.as_str(), "w1");
    }

    #[test]
    fn an_error_document_is_a_refusal_with_its_code() {
        let err = read_reply::<key_delete::Response>(
            key_delete::Payload::TYPE_URI,
            reply(
                "https://trusttasks.org/spec/trust-task-error/0.5",
                json!({
                    "code": "webvh/witness/key/delete:notFound",
                    "message": "no such key",
                    "retryable": false,
                }),
            ),
        )
        .unwrap_err();
        assert!(
            matches!(err, WebVHError::Refused { ref code, .. } if code == "webvh/witness/key/delete:notFound"),
            "{err:?}"
        );
    }

    #[test]
    fn a_reply_of_another_type_is_refused() {
        let err = read_reply::<key_delete::Response>(
            key_delete::Payload::TYPE_URI,
            reply(
                &format!("{}#response", key_list::Payload::TYPE_URI),
                json!({ "keys": [] }),
            ),
        )
        .unwrap_err();
        assert!(matches!(err, WebVHError::Transport(_)), "{err:?}");
    }
}
