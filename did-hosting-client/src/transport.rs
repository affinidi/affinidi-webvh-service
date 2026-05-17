//! Transport — base-URL resolution + HTTPS enforcement (T46).
//!
//! Two concerns:
//!
//! 1. **Resolving the server's base URL** from whatever DID-doc
//!    representation the integrator uses. The client crate
//!    deliberately does NOT pull in a DID-document parser; instead
//!    it asks the integrator to implement [`ServiceEntry`] over
//!    their own type. The resolver inspects the service set,
//!    finds the `DIDCommMessaging` (or fallback) endpoint, and
//!    returns the parsed `Url`.
//! 2. **HTTPS enforcement** for any base URL the client is about
//!    to talk to. Loopback hosts are exempt so dev workflows work,
//!    but everything else MUST be HTTPS. Per spec §5.4, the check
//!    uses `url::Host::is_loopback()` semantics — *not* a string
//!    allowlist, because the IPv6 `[::1]` form fails it.

use url::Url;

use crate::error::ClientError;

/// Integrator-provided adapter that exposes the daemon's HTTPS
/// endpoint URL out of a DID document or registry record.
///
/// The client crate deliberately doesn't depend on a DID-document
/// type — it would force every integrator to either pull in our
/// DID parser or convert to ours. Instead, integrators implement
/// this minimal trait over whatever shape their service-entry
/// resolution gives them.
///
/// Implementations should return the base URL up to and including
/// the host (e.g. `https://example.com`) — without `/api`. The
/// client appends `/api/...` per route.
pub trait ServiceEntry {
    /// The HTTPS endpoint the client should POST to. `Some(url)`
    /// when the service entry has a usable endpoint; `None` when
    /// the entry exists but doesn't expose a transport (e.g.
    /// pure-DID-only resolution targets).
    fn http_endpoint(&self) -> Option<&str>;
}

/// Resolve the server's base URL from a [`ServiceEntry`] and run
/// the HTTPS-or-loopback gate against it.
///
/// Returns the parsed [`Url`] ready for the client to prefix
/// `/api/...` paths against, or a [`ClientError::Validation`] for
/// either missing-endpoint or non-HTTPS-on-non-loopback inputs.
pub fn resolve_server_transport<E: ServiceEntry>(entry: &E) -> Result<Url, ClientError> {
    let raw = entry
        .http_endpoint()
        .ok_or_else(|| ClientError::Validation("service entry has no http_endpoint".into()))?;
    let url = Url::parse(raw)
        .map_err(|e| ClientError::Validation(format!("invalid service endpoint '{raw}': {e}")))?;
    enforce_transport_security(&url)?;
    Ok(url)
}

/// Enforce the spec §5.4 HTTPS rule: scheme must be `https`,
/// EXCEPT when the host is loopback (RFC 3330 / RFC 5156 +
/// `localhost`). The IPv6 `[::1]` form is correctly recognised via
/// [`url::Host::Ipv6::is_loopback`].
///
/// Returns `Ok(())` when the URL is acceptable, otherwise
/// `ClientError::Validation` naming the bad URL.
pub fn enforce_transport_security(url: &Url) -> Result<(), ClientError> {
    if url.scheme() == "https" {
        return Ok(());
    }
    let host = url
        .host()
        .ok_or_else(|| ClientError::Validation(format!("URL has no host component: {url}")))?;
    if is_loopback_host(&host) {
        return Ok(());
    }
    Err(ClientError::Validation(format!(
        "non-HTTPS base URL not allowed for non-loopback host: {url} \
         (use https:// in production; localhost or 127.0.0.1 / [::1] for dev)"
    )))
}

/// Predicate over [`url::Host`] for the loopback exemption.
///
/// Why not a string allowlist: the parsed `url::Host` exposes typed
/// `Ipv4Addr` / `Ipv6Addr` whose `is_loopback()` covers the full
/// loopback ranges (127.0.0.0/8, ::1). Comparing strings would
/// either miss the IPv6 `[::1]` form or accidentally accept
/// `127.0.0.1-attacker.example`. The typed predicate is the
/// version that's correct without a corner-case checklist.
pub fn is_loopback_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(s) => *s == "localhost",
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Entry(Option<String>);
    impl ServiceEntry for Entry {
        fn http_endpoint(&self) -> Option<&str> {
            self.0.as_deref()
        }
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    // ---- enforce_transport_security ----

    #[test]
    fn https_url_accepted() {
        assert!(enforce_transport_security(&url("https://example.com")).is_ok());
        assert!(enforce_transport_security(&url("https://example.com:8443/foo")).is_ok());
    }

    #[test]
    fn http_localhost_accepted_for_dev() {
        assert!(enforce_transport_security(&url("http://localhost:8530")).is_ok());
        assert!(enforce_transport_security(&url("http://127.0.0.1:8530")).is_ok());
        assert!(enforce_transport_security(&url("http://[::1]:8530")).is_ok());
        assert!(enforce_transport_security(&url("http://127.5.5.5:8530")).is_ok());
    }

    #[test]
    fn http_on_non_loopback_rejected() {
        let err = enforce_transport_security(&url("http://example.com")).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("non-HTTPS"));
        assert!(msg.contains("example.com"));
    }

    /// Suffix attack — `127.0.0.1-attacker.example` could only pass
    /// a naive string check. The typed predicate sees it as a
    /// `Domain`, not an IP, and falls through to the strict gate.
    #[test]
    fn http_suffix_attacker_rejected() {
        assert!(enforce_transport_security(&url("http://127.0.0.1-attacker.example")).is_err());
    }

    #[test]
    fn http_with_no_host_rejected() {
        // `data:` is a URL scheme with no host component. Must
        // reject; not loopback, not HTTPS.
        let parsed = Url::parse("data:text/plain,hello").unwrap();
        assert!(enforce_transport_security(&parsed).is_err());
    }

    // ---- is_loopback_host ----

    #[test]
    fn is_loopback_host_recognises_v4_v6_localhost() {
        let cases = [
            "http://localhost",
            "http://127.0.0.1",
            "http://127.5.5.5",
            "http://[::1]",
        ];
        for u in cases {
            let parsed = Url::parse(u).unwrap();
            assert!(
                is_loopback_host(&parsed.host().unwrap()),
                "expected loopback for {u}"
            );
        }
    }

    #[test]
    fn is_loopback_host_rejects_lan_addresses() {
        let cases = [
            "http://10.0.0.1",
            "http://192.168.1.1",
            "http://example.com",
            "http://[fe80::1]",
        ];
        for u in cases {
            let parsed = Url::parse(u).unwrap();
            assert!(
                !is_loopback_host(&parsed.host().unwrap()),
                "expected non-loopback for {u}"
            );
        }
    }

    // ---- resolve_server_transport ----

    #[test]
    fn resolve_returns_parsed_url() {
        let entry = Entry(Some("https://example.com:8443".into()));
        let url = resolve_server_transport(&entry).expect("valid HTTPS endpoint");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), Some(8443));
    }

    #[test]
    fn resolve_rejects_missing_endpoint() {
        let entry = Entry(None);
        let err = resolve_server_transport(&entry).expect_err("missing endpoint must reject");
        assert!(err.to_string().contains("no http_endpoint"));
    }

    #[test]
    fn resolve_rejects_unparseable_url() {
        let entry = Entry(Some("not a url".into()));
        let err = resolve_server_transport(&entry).expect_err("garbage must reject");
        assert!(err.to_string().contains("invalid service endpoint"));
    }

    #[test]
    fn resolve_rejects_non_https_non_loopback() {
        let entry = Entry(Some("http://example.com".into()));
        let err = resolve_server_transport(&entry).expect_err("plain HTTP must reject");
        assert!(err.to_string().contains("non-HTTPS"));
    }

    #[test]
    fn resolve_accepts_loopback_http_for_dev() {
        let entry = Entry(Some("http://127.0.0.1:8530".into()));
        assert!(resolve_server_transport(&entry).is_ok());
    }
}
