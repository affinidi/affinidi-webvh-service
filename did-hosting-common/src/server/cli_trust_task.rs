//! Shared `send-trust-task` CLI logic: sign one Trust Task with a `did:key`,
//! `POST` it to a running control plane's `/api/trust-tasks`, verify the
//! signed reply, and print the response payload as JSON.
//!
//! Every management operation is a Trust Task (`docs/trust-tasks.md`), so this
//! is the operator's command-line path to all of them — the runbooks use it
//! for `identity/list`, `identity/retire`, `domain/assign`,
//! `registry/purge-domain` and the rest. `did-hosting-control` and
//! `did-hosting-daemon` both expose it; `fetch-metrics`
//! ([`super::cli_metrics`]) is this with a fixed type and a narrower output.
//!
//! The signer is authorised exactly as any other client is: on its own proof
//! and its ACL entry. Nothing here bypasses the gate.

use std::path::Path;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy as CacheHostPolicy;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use serde_json::Value;
use vta_sdk::provision_client::EphemeralSetupKey;

use super::trust_tasks::send::{build_signed_request, post_trust_task_https_verified};
use super::trust_tasks::{HostPolicy, TransportBoundVerifier};

/// The registry prefix every Type URI this workspace speaks starts with.
const SPEC_PREFIX: &str = "https://trusttasks.org/spec/";

/// The pinned task versions, the same file the generated types are built
/// from: a `type_uri = "…"` line per task.
const LOCK: &str = include_str!("../../trust-tasks.lock");

/// Every Type URI pinned in `trust-tasks.lock`, plus the framework's own
/// discovery task.
pub fn known_type_uris() -> Vec<String> {
    let mut uris: Vec<String> = LOCK
        .lines()
        .filter_map(|line| line.trim().strip_prefix("type_uri = "))
        .map(|v| v.trim().trim_matches('"').to_owned())
        .collect();
    uris.push(
        <trust_tasks_rs::specs::trust_task_discovery::v0_4::Payload as trust_tasks_rs::Payload>::TYPE_URI
            .to_owned(),
    );
    uris
}

/// Resolve `--type`: a full Type URI, or its `<slug>/<version>` short form
/// (`identity/list/0.1` for `…/spec/did-management/identity/list/0.1`, or the
/// full slug `did-management/identity/list/0.1`). Refuses a type this
/// workspace does not pin, and an ambiguous short form, naming the candidates.
pub fn resolve_type_uri(input: &str) -> Result<String, String> {
    let known = known_type_uris();
    let input = input.trim();
    if input.contains('#') {
        return Err(format!(
            "`{input}` names a response; give the request's Type URI or slug/version"
        ));
    }
    if input.starts_with("https://") {
        return known
            .iter()
            .find(|u| *u == input)
            .cloned()
            .ok_or_else(|| format!("`{input}` is not a Trust Task this workspace speaks"));
    }
    let short = input.trim_start_matches('/');
    let exact = format!("{SPEC_PREFIX}{short}");
    if known.contains(&exact) {
        return Ok(exact);
    }
    let suffix = format!("/{short}");
    let matches: Vec<&String> = known.iter().filter(|u| u.ends_with(&suffix)).collect();
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(format!(
            "`{input}` is not a Trust Task this workspace speaks (see docs/trust-tasks.md; \
             give `<slug>/<version>`, e.g. `identity/list/0.1`)"
        )),
        many => Err(format!(
            "`{input}` is ambiguous; give the full slug: {}",
            many.iter()
                .map(|u| u.trim_start_matches(SPEC_PREFIX))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Parse the request payload: `--payload` JSON, or the contents of
/// `--payload-file`, or `{}` when neither is given. It must be a JSON object.
pub fn parse_payload(inline: Option<&str>, file: Option<&Path>) -> Result<Value, String> {
    let text = match (inline, file) {
        (Some(_), Some(_)) => return Err("give --payload or --payload-file, not both".into()),
        (Some(s), None) => s.to_owned(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .map_err(|e| format!("could not read {}: {e}", path.display()))?,
        (None, None) => "{}".to_owned(),
    };
    let value: Value =
        serde_json::from_str(&text).map_err(|e| format!("the payload is not JSON: {e}"))?;
    if !value.is_object() {
        return Err("the payload must be a JSON object".into());
    }
    Ok(value)
}

/// Sign `payload` as a `type_uri` request from the `--key` did:key, POST it to
/// `server_did`'s `/api/trust-tasks`, verify the reply is `server_did`'s own
/// signed `#response`, and return its payload. A signed `trust-task-error`
/// (and an unsigned refusal) is returned as an error naming its code.
///
/// `url` overrides the endpoint; when absent the base is derived from
/// `default_host` / `default_port` (a wildcard bind is dialled as loopback).
pub async fn send_signed_task(
    server_did: &str,
    key_path: &Path,
    url: Option<String>,
    default_host: &str,
    default_port: u16,
    type_uri: &str,
    payload: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let base = url.unwrap_or_else(|| loopback_base_url(default_host, default_port));
    let endpoint = format!("{}/api/trust-tasks", base.trim_end_matches('/'));

    // Same did:key JSON `setup --setup-key-out` writes.
    let key = EphemeralSetupKey::load_from(key_path)?;
    let from = key.did.clone();
    let mut signer = Secret::from_multibase(key.private_key_multibase(), None)
        .map_err(|e| format!("the key is not a usable signing key: {e}"))?;
    // Pin the signer's verificationMethod to the did:key's own VM
    // (`did:key:<mb>#<mb>`). `from_multibase` leaves a hash-derived id the
    // issuer does not control, so the recipient would reject the proof.
    let public_mb = signer
        .get_public_keymultibase()
        .map_err(|e| format!("the key has no usable public key: {e}"))?;
    signer.id = format!("{from}#{public_mb}");

    let doc = build_signed_request(type_uri, &from, server_did, payload, &signer)
        .await
        .map_err(|e| format!("failed to sign the request: {e}"))?;

    // Resolve `server_did` to verify its signed reply — proves the answer came
    // from the real service DID, not another process holding the port.
    // `AllowPrivate`: this command dials a loopback/private endpoint by
    // default, and a service provisioned on `localhost` serves its DID log
    // from a host the default `PublicOnly` policy would refuse.
    let resolver = DIDCacheClient::new(
        DIDCacheConfigBuilder::default()
            .with_host_policy(CacheHostPolicy::AllowPrivate)
            .build(),
    )
    .await
    .map_err(|e| format!("could not build a DID resolver: {e}"))?;
    let verifier =
        TransportBoundVerifier::with_did_cache_and_host_policy(resolver, HostPolicy::AllowPrivate);

    let reply = post_trust_task_https_verified(&from, server_did, &endpoint, &doc, &verifier)
        .await
        .map_err(|e| format!("request to {endpoint} failed: {e}"))?;

    // A verified document from the real service DID. `read_reply` demands it
    // be this task's `#response` and reports a signed `trust-task-error` by
    // its code.
    let payload: Value = crate::witness_client::read_reply(type_uri, reply)
        .map_err(|e| format!("request to {endpoint}: {e}"))?;
    Ok(payload)
}

/// The `send-trust-task` command: resolve `--type`, parse the payload, send,
/// and print the response payload as pretty JSON on stdout.
// One argument per CLI flag; a struct would only rename them.
#[allow(clippy::too_many_arguments)]
pub async fn run_send_trust_task(
    server_did: &str,
    key_path: &Path,
    url: Option<String>,
    default_host: &str,
    default_port: u16,
    task_type: &str,
    payload: Option<&str>,
    payload_file: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let type_uri = resolve_type_uri(task_type)?;
    let payload = parse_payload(payload, payload_file)?;
    let response = send_signed_task(
        server_did,
        key_path,
        url,
        default_host,
        default_port,
        &type_uri,
        payload,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// The default base URL when `--url` is not given.
///
/// `host` is the service's configured bind host. A bare IPv6 literal (`::1`, a
/// global address) must be bracketed in a URL authority, and an unspecified
/// bind (`0.0.0.0` / `::`) is not itself dialable — map it to the matching
/// loopback. Parsing through `IpAddr` and formatting via `SocketAddr` gets the
/// bracketing right for every case; a non-IP host (a DNS name) is used verbatim.
pub(crate) fn loopback_base_url(host: &str, port: u16) -> String {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => {
            let dial = match ip {
                std::net::IpAddr::V4(v4) if v4.is_unspecified() => {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                }
                std::net::IpAddr::V6(v6) if v6.is_unspecified() => {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                }
                other => other,
            };
            format!("http://{}", std::net::SocketAddr::new(dial, port))
        }
        Err(_) => format!("http://{host}:{port}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_uri_is_a_spec_uri() {
        let known = known_type_uris();
        assert!(
            known.len() > 50,
            "the lock pins every task: {}",
            known.len()
        );
        assert!(
            known.iter().all(|u| u.starts_with(SPEC_PREFIX)),
            "{known:?}"
        );
    }

    #[test]
    fn resolves_short_forms_and_full_uris() {
        let full = "https://trusttasks.org/spec/did-management/identity/list/0.1";
        assert_eq!(resolve_type_uri(full).unwrap(), full);
        assert_eq!(resolve_type_uri("identity/list/0.1").unwrap(), full);
        assert_eq!(
            resolve_type_uri("did-management/identity/list/0.1").unwrap(),
            full
        );
        assert_eq!(
            resolve_type_uri("registry/purge-domain/0.1").unwrap(),
            "https://trusttasks.org/spec/did-management/registry/purge-domain/0.1"
        );
        assert_eq!(
            resolve_type_uri("acl/list/0.3").unwrap(),
            "https://trusttasks.org/spec/acl/list/0.3"
        );
    }

    #[test]
    fn refuses_unknown_versions_responses_and_ambiguity() {
        // A version the lock does not pin.
        assert!(resolve_type_uri("identity/list/9.9").is_err());
        assert!(resolve_type_uri("https://trusttasks.org/spec/nope/0.1").is_err());
        // A reply is not something to send.
        assert!(resolve_type_uri("identity/list/0.1#response").is_err());
        // `list/0.1` is a suffix of several tasks; the error names them.
        let err = resolve_type_uri("list/0.1").unwrap_err();
        assert!(err.contains("ambiguous"), "{err}");
    }

    #[test]
    fn the_metrics_task_resolves_to_the_generated_type() {
        use crate::tasks::did_management::server::metrics::v0_1;
        use trust_tasks_rs::Payload;
        assert_eq!(
            resolve_type_uri("server/metrics/0.1").unwrap(),
            <v0_1::Payload as Payload>::TYPE_URI
        );
    }

    #[test]
    fn payload_parsing() {
        assert_eq!(parse_payload(None, None).unwrap(), serde_json::json!({}));
        assert_eq!(
            parse_payload(Some(r#"{"domain":"a.example"}"#), None).unwrap(),
            serde_json::json!({"domain": "a.example"})
        );
        assert!(parse_payload(Some("[1]"), None).is_err());
        assert!(parse_payload(Some("not json"), None).is_err());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.json");
        std::fs::write(&path, r#"{"generation": 0}"#).unwrap();
        assert_eq!(
            parse_payload(None, Some(&path)).unwrap(),
            serde_json::json!({"generation": 0})
        );
        assert!(parse_payload(Some("{}"), Some(&path)).is_err());
    }

    #[test]
    fn maps_wildcard_binds_to_loopback() {
        assert_eq!(loopback_base_url("0.0.0.0", 8530), "http://127.0.0.1:8530");
        assert_eq!(loopback_base_url("::", 8530), "http://[::1]:8530");
    }

    #[test]
    fn brackets_ipv6_literals_and_leaves_others_verbatim() {
        assert_eq!(loopback_base_url("::1", 8530), "http://[::1]:8530");
        assert_eq!(
            loopback_base_url("2001:db8::1", 443),
            "http://[2001:db8::1]:443"
        );
        assert_eq!(
            loopback_base_url("127.0.0.1", 8530),
            "http://127.0.0.1:8530"
        );
        assert_eq!(
            loopback_base_url("localhost", 8530),
            "http://localhost:8530"
        );
    }
}
