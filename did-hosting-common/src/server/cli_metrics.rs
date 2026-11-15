//! Shared `fetch-metrics` CLI logic: scrape a running service's counters over
//! the authenticated `server/metrics/0.1` Trust Task and print them as JSON.
//!
//! Both `did-hosting-daemon` and standalone `did-hosting-control` serve the
//! `server/metrics/0.1` task to `MetricsReader` keys, so both expose a
//! `fetch-metrics` command. It is `send-trust-task`
//! ([`super::cli_trust_task`]) with a fixed type and a narrower output, so the
//! sign / POST / verify work is written once.

use std::path::Path;

use super::cli_trust_task::send_signed_task;
use super::trust_tasks::metrics_request_type_uri;

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
/// `default_host` / `default_port` (a wildcard bind is dialled as loopback).
pub async fn fetch_metrics(
    server_did: &str,
    key_path: &Path,
    url: Option<String>,
    default_host: &str,
    default_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    // The request type comes from the generated spec (the same source the
    // control-task router keys on), never a hand-typed literal.
    let payload = send_signed_task(
        server_did,
        key_path,
        url,
        default_host,
        default_port,
        metrics_request_type_uri(),
        serde_json::json!({}),
    )
    .await
    .map_err(|e| format!("metrics {e}"))?;

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

#[cfg(test)]
mod tests {
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
}
