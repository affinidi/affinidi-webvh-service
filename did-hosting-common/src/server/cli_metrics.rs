//! Shared `fetch-metrics` CLI logic: scrape a running service's counters over
//! the authenticated `server/metrics/0.1` Trust Task and print them as JSON.
//!
//! Both `did-hosting-daemon` and standalone `did-hosting-control` serve the
//! `server/metrics/0.1` task to `MetricsReader` keys, so both expose a
//! `fetch-metrics` command. The sign / POST / verify work lives here (the same
//! `cli_*` convention as [`super::cli_acl`]) so neither binary carries its own
//! copy and they cannot drift.

use std::path::Path;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
use affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy as CacheHostPolicy;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use vta_sdk::provision_client::EphemeralSetupKey;

use super::trust_tasks::send::{build_signed_request, post_trust_task_https_verified};
use super::trust_tasks::{HostPolicy, TransportBoundVerifier, metrics_request_type_uri};

/// Read `server_did`'s counters over the authenticated `server/metrics/0.1`
/// Trust Task and print them as JSON (`[{ "name": …, "value": … }]`) on stdout.
///
/// The counters live in the running service's process memory and are reachable
/// only through this signed task — there is no unauthenticated scrape endpoint.
/// We sign as the `--key` DID (granted `MetricsReader` in the ACL), POST to the
/// service's `/api/trust-tasks`, and verify the reply is the server's own signed
/// response before trusting the numbers. Gauges require Admin and are not
/// returned to a `MetricsReader`, so we never request them.
///
/// `url` overrides the endpoint; when absent the base is derived from
/// `default_host` / `default_port` via [`loopback_base_url`] (a wildcard bind is
/// dialled as loopback).
pub async fn fetch_metrics(
    server_did: &str,
    key_path: &Path,
    url: Option<String>,
    default_host: &str,
    default_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    // The request type comes from the generated spec (the same source the
    // control-task router keys on), never a hand-typed literal.
    let request_type = metrics_request_type_uri();

    let base = url.unwrap_or_else(|| loopback_base_url(default_host, default_port));
    let endpoint = format!("{}/api/trust-tasks", base.trim_end_matches('/'));

    // Load the signer DID + key. Same did:key JSON `setup --setup-key-out`
    // writes; for the sidecar this is a dedicated MetricsReader key.
    let key = EphemeralSetupKey::load_from(key_path)?;
    let from = key.did.clone();
    let mut signer = Secret::from_multibase(key.private_key_multibase(), None)
        .map_err(|e| format!("metrics key is not a usable signing key: {e}"))?;
    // Pin the signer's verificationMethod to the did:key's own VM
    // (`did:key:<mb>#<mb>`). `from_multibase` leaves a hash-derived id the
    // issuer does not control, so the recipient rejects the proof when it
    // checks the verificationMethod against the document issuer — the signature
    // would fail before the request ever reaches the server.
    let public_mb = signer
        .get_public_keymultibase()
        .map_err(|e| format!("metrics key has no usable public key: {e}"))?;
    signer.id = format!("{from}#{public_mb}");

    let doc = build_signed_request(
        request_type,
        &from,
        server_did,
        serde_json::json!({}),
        &signer,
    )
    .await
    .map_err(|e| format!("failed to sign the metrics request: {e}"))?;

    // Resolve `server_did` to verify its signed reply — proves the counters came
    // from the real server DID, not another process holding the port.
    //
    // `AllowPrivate` on both the resolver cache and the verifier's `did:webvh`
    // log reads: this command dials a loopback/private endpoint by default, and
    // a service provisioned on `localhost` serves its DID log from a private
    // host that the default `PublicOnly` policy would refuse — reply
    // verification would then fail for exactly the local scrape this is built
    // for.
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
        .map_err(|e| format!("metrics request to {endpoint} failed: {e}"))?;

    // A reply that reaches this point is a verified document from the real
    // server DID. `read_reply` demands it be the task's `#response` (so a
    // wrong-typed but verified reply can't print `[]` and exit 0, making a failed
    // scrape look like a service that counted nothing), and reports a signed
    // `trust-task-error` by its code — the same reading every other client of a
    // signed Trust Task reply uses. An unsigned refusal never gets here:
    // `post_trust_task_https_verified` reports it by its code.
    let payload: serde_json::Value = crate::witness_client::read_reply(request_type, reply)
        .map_err(|e| format!("metrics request to {endpoint}: {e}"))?;

    // Require the counters array to be present — a malformed response is an
    // error, not an empty scrape.
    let counters = payload
        .get("snapshot")
        .and_then(|snapshot| snapshot.get("counters"))
        .filter(|counters| counters.is_array())
        .ok_or_else(|| {
            format!(
                "metrics response from {server_did} carried no snapshot.counters array: {}",
                serde_json::to_string(&payload).unwrap_or_default()
            )
        })?;
    println!("{}", serde_json::to_string(counters)?);
    Ok(())
}

/// The default base URL `fetch-metrics` dials when `--url` is not given.
///
/// `host` is the service's configured bind host. A bare IPv6 literal (`::1`, a
/// global address) must be bracketed in a URL authority, and an unspecified
/// bind (`0.0.0.0` / `::`) is not itself dialable — map it to the matching
/// loopback. Parsing through `IpAddr` and formatting via `SocketAddr` gets the
/// bracketing right for every case; a non-IP host (a DNS name) is used verbatim.
/// Without this, a `server.host` of `::` built `http://:::<port>/…`, which
/// reqwest cannot parse, so the default scrape always failed.
fn loopback_base_url(host: &str, port: u16) -> String {
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
    use super::loopback_base_url;

    /// `read_reply` expects `{request}#response`; the generated spec must agree,
    /// or every verified scrape would be reported as the wrong type.
    #[test]
    fn the_metrics_response_type_is_the_request_type_with_a_response_fragment() {
        use crate::tasks::did_management::server::metrics::v0_1;
        use trust_tasks_rs::Payload;
        assert_eq!(
            format!("{}#response", super::metrics_request_type_uri()),
            <v0_1::Response as Payload>::TYPE_URI
        );
    }

    #[test]
    fn maps_wildcard_binds_to_loopback() {
        assert_eq!(loopback_base_url("0.0.0.0", 8530), "http://127.0.0.1:8530");
        assert_eq!(loopback_base_url("::", 8530), "http://[::1]:8530");
    }

    #[test]
    fn brackets_ipv6_literals_and_leaves_others_verbatim() {
        // A concrete IPv6 literal is dialled as-is, bracketed.
        assert_eq!(loopback_base_url("::1", 8530), "http://[::1]:8530");
        assert_eq!(
            loopback_base_url("2001:db8::1", 443),
            "http://[2001:db8::1]:443"
        );
        // IPv4 and DNS names are used verbatim.
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
