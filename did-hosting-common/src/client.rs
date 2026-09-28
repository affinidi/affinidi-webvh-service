//! A client for a DID Hosting control plane, over its Trust Task listener.
//!
//! Every call is a Trust Task document signed by the requester
//! (`proofPurpose: authentication`) and addressed to the service's DID, posted
//! to the control plane's HTTPS binding (`POST {url}/api/trust-tasks`). The
//! control plane authorises on that proof and the requester's ACL entry alone
//! — there is no session or bearer token — and every reply it sends is signed;
//! the client verifies the reply against the service DID before it believes a
//! word of it.

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde::Deserialize;
use serde_json::{Value, json};
use trust_tasks_rs::Payload;
use trust_tasks_rs::specs::did_management::{
    agent_name::{
        check as agent_name_check, remove as agent_name_remove, update as agent_name_update,
    },
    did::{check_name, delete, info, list, register},
    server::info as server_info,
};

use crate::did::{build_did_document, create_log_entry, encode_host};
use crate::error::{Result, WebVHError};
use crate::server::trust_tasks::send::{build_signed_request, post_trust_task_https};
use crate::types::*;

/// The requester a [`WebVHClient`] signs as, and the service it addresses.
struct Requester {
    did: String,
    signer: Secret,
    service_did: String,
    did_resolver: DIDCacheClient,
}

/// A client for one DID Hosting control plane.
pub struct WebVHClient {
    server_url: String,
    /// Public hosting URL used as the `host` segment of newly minted
    /// `did:webvh:` identifiers. When `None`, the host is derived from
    /// `server_url`. Control-plane deployments must set this to the public
    /// hosting URL, since the control plane's URL is not where DID logs are
    /// served from.
    hosting_url: Option<String>,
    requester: Option<Requester>,
}

/// One slot of a `did/list` reply: the members a caller acts on.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidSummary {
    pub mnemonic: String,
    #[serde(default)]
    pub did_id: Option<String>,
    #[serde(default)]
    pub version_count: u64,
    #[serde(default)]
    pub disabled: bool,
}

impl WebVHClient {
    /// Create a new client pointing at the given control plane URL.
    pub fn new(server_url: &str) -> Self {
        Self {
            server_url: server_url.trim_end_matches('/').to_string(),
            hosting_url: None,
            requester: None,
        }
    }

    /// Set a separate public hosting URL to embed in DIDs created via
    /// [`create_did`](Self::create_did). Use this when management
    /// (`server_url`) and hosting are at different origins, e.g. a
    /// control plane at `admin.example.com` minting DIDs that resolve
    /// at `webvh.example.com`.
    pub fn with_hosting_url(mut self, hosting_url: impl Into<String>) -> Self {
        self.hosting_url = Some(hosting_url.into().trim_end_matches('/').to_string());
        self
    }

    /// Sign every request from here on as `did`, with `signer` (one of its
    /// `authentication` keys), addressed to the service DID `service_did`.
    ///
    /// Nothing is sent: each request carries its own proof, and `did` must
    /// hold an ACL entry on the control plane for any of them to succeed.
    pub async fn sign_as(&mut self, did: &str, signer: &Secret, service_did: &str) -> Result<()> {
        let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .map_err(|e| WebVHError::Resolver(e.to_string()))?;
        self.requester = Some(Requester {
            did: did.to_string(),
            signer: signer.clone(),
            service_did: service_did.to_string(),
            did_resolver,
        });
        Ok(())
    }

    // -------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------

    /// `server/info/0.1`: what the service publishes about itself (its DID,
    /// whether `/@name` redirects are served, …), signed by that DID.
    pub async fn server_info(&self) -> Result<Value> {
        self.call(server_info::v0_1::Payload::TYPE_URI, json!({}))
            .await
    }

    /// `did/check-name/0.1`: is a custom path free?
    pub async fn check_name(&self, path: &str) -> Result<check_name::v0_1::Response> {
        self.call(check_name::v0_1::Payload::TYPE_URI, json!({ "path": path }))
            .await
    }

    /// Reserve a DID slot (`did/check-name/0.1` with `reserve: true`). If
    /// `path` is `Some`, the server uses that custom path; otherwise it
    /// generates a random mnemonic.
    pub async fn request_uri(&self, path: Option<&str>) -> Result<RequestUriResponse> {
        let mut payload = json!({ "reserve": true });
        if let Some(p) = path {
            payload["path"] = json!(p);
        }
        let resp: Value = self
            .call(check_name::v0_1::Payload::TYPE_URI, payload)
            .await?;
        if resp.get("reserved").and_then(Value::as_bool) != Some(true) {
            return Err(WebVHError::Refused {
                code: "did/check-name:notReserved".into(),
                message: "the path is not available".into(),
            });
        }
        let record = resp
            .get("record")
            .ok_or_else(|| WebVHError::Transport("reservation reply carries no record".into()))?;
        let field = |name: &str| {
            record
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| WebVHError::Transport(format!("reserved record has no `{name}`")))
        };
        Ok(RequestUriResponse {
            mnemonic: field("mnemonic")?,
            did_url: field("didUrl")?,
        })
    }

    /// `did/register/0.1`: publish a signed `did.jsonl` to the slot at
    /// `mnemonic`.
    pub async fn upload_did(&self, mnemonic: &str, content: &str) -> Result<()> {
        let _: Value = self
            .call(
                register::v0_1::Payload::TYPE_URI,
                json!({ "path": mnemonic, "method": "webvh", "didData": content }),
            )
            .await?;
        Ok(())
    }

    /// `did/delete/0.1`.
    pub async fn delete_did(&self, mnemonic: &str) -> Result<()> {
        let _: Value = self
            .call(
                delete::v0_1::Payload::TYPE_URI,
                json!({ "mnemonic": mnemonic }),
            )
            .await?;
        Ok(())
    }

    /// `did/list/0.1`: every slot the requester owns (every slot, for an
    /// administrator), read page by page.
    pub async fn list_dids(&self) -> Result<Vec<DidSummary>> {
        #[derive(Deserialize)]
        struct Page {
            records: Vec<DidSummary>,
            total: u64,
        }
        const PAGE: u64 = 100;
        let mut out = Vec::new();
        loop {
            let page: Page = self
                .call(
                    list::v0_1::Payload::TYPE_URI,
                    json!({ "limit": PAGE, "offset": out.len() }),
                )
                .await?;
            let got = page.records.len();
            out.extend(page.records);
            if got == 0 || out.len() as u64 >= page.total {
                return Ok(out);
            }
        }
    }

    /// `did/info/0.1`: one slot's record, including its agent-name registry
    /// (under the record's `ext`). Returned as raw JSON so a caller can read
    /// fields without this crate mirroring the response type.
    pub async fn get_did_detail(&self, mnemonic: &str) -> Result<Value> {
        self.call(
            info::v0_1::Payload::TYPE_URI,
            json!({ "mnemonic": mnemonic }),
        )
        .await
    }

    /// `agent-name/check/0.1`: is an agent name free on `domain`? The reply
    /// carries `available` and `reserved` — the latter distinct so a caller
    /// can say *why* a name is unavailable.
    pub async fn check_agent_name(&self, name: &str, domain: Option<&str>) -> Result<Value> {
        let mut payload = json!({ "name": name });
        if let Some(d) = domain {
            payload["domain"] = json!(d);
        }
        self.call(agent_name_check::v0_1::Payload::TYPE_URI, payload)
            .await
    }

    /// Drive an agent-name mutation — `op` is one of `set` / `enable`
    /// (`agent-name/update`, `state: active`), `disable` (`agent-name/update`,
    /// `state: parked`) or `remove` (`agent-name/remove`) — by submitting the
    /// freshly signed `did.jsonl` whose `alsoKnownAs` claims (`set`/`enable`)
    /// or no longer claims (`remove`/`disable`) the name. Returns the
    /// `{record}` reply.
    pub async fn agent_name_op(
        &self,
        op: &str,
        mnemonic: &str,
        name: &str,
        did_log: &str,
    ) -> Result<Value> {
        let base = json!({ "mnemonic": mnemonic, "name": name, "didData": did_log });
        let (type_uri, payload) = match op {
            "set" | "enable" => (
                agent_name_update::v0_1::Payload::TYPE_URI,
                with_member(base, "state", "active"),
            ),
            "disable" => (
                agent_name_update::v0_1::Payload::TYPE_URI,
                with_member(base, "state", "parked"),
            ),
            "remove" => (agent_name_remove::v0_1::Payload::TYPE_URI, base),
            other => {
                return Err(WebVHError::Transport(format!(
                    "unknown agent-name operation `{other}`"
                )));
            }
        };
        self.call(type_uri, payload).await
    }

    /// Returns the control plane URL this client is configured with.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// High-level: reserve a slot, build the DID document, create the WebVH
    /// log entry, publish it, and return everything the caller needs.
    pub async fn create_did(&self, secret: &Secret, path: Option<&str>) -> Result<CreateDidResult> {
        let create_resp = self.request_uri(path).await?;

        // The host segment must match where the DID log will actually
        // be served — the public hosting URL when management is split
        // off onto a separate control plane, otherwise just server_url.
        let host_url = self.hosting_url.as_deref().unwrap_or(&self.server_url);
        let host = encode_host(host_url)?;
        let public_key_multibase = secret
            .get_public_keymultibase()
            .map_err(|e| WebVHError::DIDComm(format!("failed to get public key: {e}")))?;

        let did_doc = build_did_document(
            &host,
            &create_resp.mnemonic,
            &public_key_multibase,
            &Default::default(),
        );
        let (scid, jsonl) = create_log_entry(&did_doc, secret).await?;

        self.upload_did(&create_resp.mnemonic, &jsonl).await?;

        let did_path = create_resp.mnemonic.replace('/', ":");
        let did = format!("did:webvh:{scid}:{host}:{did_path}");

        Ok(CreateDidResult {
            mnemonic: create_resp.mnemonic,
            did_url: create_resp.did_url,
            scid,
            did,
            public_key_multibase,
        })
    }

    /// Resolve a DID log from the hosting URL (public, no proof required).
    pub async fn resolve_did(&self, mnemonic: &str) -> Result<String> {
        let host_url = self.hosting_url.as_deref().unwrap_or(&self.server_url);
        let resp = crate::http::outbound_client()
            .get(format!("{host_url}/{mnemonic}/did.jsonl"))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(WebVHError::Server {
                status: status.as_u16(),
                message: format!("HTTP {status}"),
            });
        }
        Ok(resp.text().await?)
    }

    // -------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------

    /// Send one signed request and read the verified reply as `R`.
    async fn call<R: serde::de::DeserializeOwned>(
        &self,
        type_uri: &str,
        payload: Value,
    ) -> Result<R> {
        let requester = self
            .requester
            .as_ref()
            .ok_or(WebVHError::NotAuthenticated)?;
        let doc = build_signed_request(
            type_uri,
            &requester.did,
            &requester.service_did,
            payload,
            &requester.signer,
        )
        .await
        .map_err(|e| WebVHError::Transport(e.to_string()))?;
        let reply = post_trust_task_https(
            &requester.did,
            &requester.service_did,
            &format!("{}/api/trust-tasks", self.server_url),
            &doc,
            Some(&requester.did_resolver),
        )
        .await
        .map_err(|e| WebVHError::Transport(e.to_string()))?;
        crate::witness_client::read_reply(type_uri, reply)
    }
}

/// `value` with `key` set to `member`.
fn with_member(mut value: Value, key: &str, member: &str) -> Value {
    value[key] = json!(member);
    value
}
