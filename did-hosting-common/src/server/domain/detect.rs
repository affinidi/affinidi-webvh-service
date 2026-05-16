//! Request-host extractor with trusted-CIDR gating.
//!
//! Per `docs/multi-domain-spec.md` §3 row "Reverse proxy trust":
//!
//! - **Inside** the trusted-CIDR set: honour `Forwarded` (RFC 7239)
//!   `host=` parameter first, then `X-Forwarded-Host` (first value
//!   only — last is closest to the server and attacker-controllable),
//!   else `Host`.
//! - **Outside** the trusted-CIDR set: always `Host`, regardless of
//!   what forwarded headers the request claims.
//!
//! This is the read-side of the multi-domain feature: every inbound
//! request gets its "intended domain" extracted here, normalised via
//! [`super::normalize::normalize_domain_name`], and then matched
//! against the active-domain set (T20 / T21 enforcement).
//!
//! ## What this module ships
//!
//! - [`HostHeaders`] — the small struct callers pass in. Decouples
//!   the resolver from Axum so it can be unit-tested without a full
//!   request.
//! - [`resolve_request_host`] — the resolver. Returns the raw host
//!   string the client claims; normalisation is the caller's job
//!   (so the caller can decide whether a non-canonical value 404s,
//!   400s, or is silently lowercased depending on the caller's
//!   error surface).
//! - [`parse_forwarded_host`] — public for unit testing of edge
//!   cases. Implements the minimum subset of RFC 7239 needed for the
//!   `host=` parameter; full RFC parsing is out of scope (we don't
//!   consume `for=` / `by=` / `proto=`).
//!
//! The Axum middleware wiring lives in `did-hosting-{server,control}`
//! and lands with T20 — that's the first task that actually consumes
//! the resolved domain.

use std::net::IpAddr;
use std::str::FromStr;

use ipnetwork::IpNetwork;
use tracing::warn;

/// Headers + peer IP the resolver needs. Decoupled from Axum so this
/// is testable as a pure function.
pub struct HostHeaders<'a> {
    /// `Host` header. Always populated by any HTTP/1.1+ client.
    pub host: Option<&'a str>,
    /// `Forwarded` header (RFC 7239). May be `None` even behind a
    /// proxy; many CDNs emit `X-Forwarded-*` only.
    pub forwarded: Option<&'a str>,
    /// `X-Forwarded-Host` header. May carry a comma-separated list
    /// if the request traversed multiple proxies; the resolver
    /// honours the **first** value (the original client's claim;
    /// later values are added by intermediate proxies and are
    /// attacker-controllable relative to the original).
    pub x_forwarded_host: Option<&'a str>,
}

/// Resolve the "intended host" for an inbound request.
///
/// `peer_ip` is the direct TCP peer (what `request.connection_info()
/// .peer_addr()` would report) — NOT a value extracted from a
/// forwarded header. The trust check runs against this; an
/// X-Forwarded-Host spoof from a non-trusted peer has no effect.
///
/// Returns the host string as the caller-claimed value (un-
/// normalised — the caller normalises afterwards). `None` when
/// neither the trusted-path headers nor `Host` is set, which is
/// only reachable in pathological cases (e.g. an HTTP/1.0 client
/// without a Host header).
pub fn resolve_request_host<'a>(
    headers: &'a HostHeaders<'_>,
    peer_ip: Option<IpAddr>,
    trusted_cidrs: &[IpNetwork],
) -> Option<&'a str> {
    let peer_is_trusted = peer_is_trusted(peer_ip, trusted_cidrs);

    if peer_is_trusted {
        // Inside the trusted set: prefer Forwarded `host=`, then
        // X-Forwarded-Host (first value), then Host.
        if let Some(fwd) = headers.forwarded
            && let Some(host) = parse_forwarded_host(fwd)
        {
            return Some(host);
        }
        if let Some(xfh) = headers.x_forwarded_host
            && let Some(first) = first_xff_value(xfh)
        {
            return Some(first);
        }
    } else if headers.forwarded.is_some() || headers.x_forwarded_host.is_some() {
        // Outside the trusted set and the request is *claiming* a
        // forwarded host. Almost always benign (a misconfigured load
        // balancer, a curl with `-H "X-Forwarded-Host: ..."` from a
        // dev box), but it's worth a warn-log so operators can spot
        // a deployment misconfig before it bites them in production.
        warn!(
            peer = ?peer_ip,
            "request from untrusted peer claims Forwarded / X-Forwarded-Host; ignoring"
        );
    }

    headers.host
}

/// True when `peer_ip` matches any of `trusted_cidrs`. An unset peer
/// IP is treated as untrusted (the safe default — we can't prove the
/// origin).
fn peer_is_trusted(peer_ip: Option<IpAddr>, trusted_cidrs: &[IpNetwork]) -> bool {
    let Some(ip) = peer_ip else {
        return false;
    };
    trusted_cidrs.iter().any(|cidr| cidr.contains(ip))
}

/// Take the first comma-separated value from an `X-Forwarded-Host`
/// header, trimmed of surrounding whitespace. Empty result → `None`.
///
/// **First** is correct: multiple proxies prepend their own values
/// to the list; the original client's claim is at index 0 and the
/// later ones are added by intermediate trusted proxies (or by an
/// attacker controlling an intermediate hop, in which case the
/// trusted-CIDR gate above is what stops the spoof).
fn first_xff_value(header: &str) -> Option<&str> {
    let first = header.split(',').next()?.trim();
    if first.is_empty() { None } else { Some(first) }
}

/// Parse the `host=` parameter from an RFC 7239 `Forwarded` header
/// value. Returns the value with surrounding quotes stripped and IPv6
/// bracket preserved. `None` if no `host=` parameter is present or
/// the header is malformed.
///
/// Supports:
/// - Multiple forwarded-element groups (comma-separated). Honours
///   the **first** group's `host=` (same rationale as
///   [`first_xff_value`]).
/// - Quoted (`host="example.com"`) and unquoted (`host=example.com`)
///   parameter values.
/// - Case-insensitive parameter names (`Host=`, `HOST=`).
/// - Other parameters in the same group (`for=`, `by=`, `proto=`)
///   are tolerated and ignored.
///
/// Out of scope: full RFC 7239 parser. We only need `host=`; the
/// other parameters are consumed by other middleware (or not at all).
pub fn parse_forwarded_host(header: &str) -> Option<&str> {
    let first_group = header.split(',').next()?;
    for raw_pair in first_group.split(';') {
        let pair = raw_pair.trim();
        let (name, value) = pair.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("host") {
            continue;
        }
        let value = value.trim();
        // Strip outer double-quotes, if present.
        let stripped = value
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(value);
        if stripped.is_empty() {
            return None;
        }
        return Some(stripped);
    }
    None
}

/// Parse a list of CIDR strings (the `trusted_proxy_cidrs` config
/// field). Returns the parsed CIDRs and a list of any strings that
/// failed to parse (so the caller can warn-log them but still boot).
pub fn parse_trusted_cidrs(input: &[String]) -> (Vec<IpNetwork>, Vec<String>) {
    let mut ok = Vec::with_capacity(input.len());
    let mut bad = Vec::new();
    for s in input {
        match IpNetwork::from_str(s) {
            Ok(net) => ok.push(net),
            Err(_) => bad.push(s.clone()),
        }
    }
    (ok, bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str) -> IpNetwork {
        IpNetwork::from_str(s).expect("valid cidr")
    }

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).expect("valid ip")
    }

    fn h(host: Option<&'static str>, fwd: Option<&'static str>, xfh: Option<&'static str>)
        -> HostHeaders<'static>
    {
        HostHeaders {
            host,
            forwarded: fwd,
            x_forwarded_host: xfh,
        }
    }

    // ---- peer trust ----

    #[test]
    fn peer_inside_cidr_is_trusted() {
        let cidrs = vec![cidr("10.0.0.0/8")];
        assert!(peer_is_trusted(Some(ip("10.1.2.3")), &cidrs));
    }

    #[test]
    fn peer_outside_cidr_is_untrusted() {
        let cidrs = vec![cidr("10.0.0.0/8")];
        assert!(!peer_is_trusted(Some(ip("172.16.1.1")), &cidrs));
    }

    #[test]
    fn empty_cidr_list_trusts_no_one() {
        assert!(!peer_is_trusted(Some(ip("10.0.0.1")), &[]));
        assert!(!peer_is_trusted(Some(ip("127.0.0.1")), &[]));
    }

    #[test]
    fn missing_peer_ip_is_untrusted() {
        assert!(!peer_is_trusted(None, &[cidr("0.0.0.0/0")]));
    }

    // ---- resolve_request_host: untrusted path ----

    #[test]
    fn untrusted_peer_uses_host_header() {
        let headers = h(
            Some("example.com"),
            Some("host=evil.example"),
            Some("evil.example"),
        );
        let cidrs = vec![cidr("10.0.0.0/8")];
        let resolved = resolve_request_host(&headers, Some(ip("8.8.8.8")), &cidrs);
        assert_eq!(resolved, Some("example.com"));
    }

    #[test]
    fn untrusted_peer_xfh_spoof_has_no_effect() {
        // Classic spoof: client sends X-Forwarded-Host claiming a
        // different domain. From outside the trusted CIDR set this
        // must NOT change the resolved host.
        let headers = h(Some("real.example.com"), None, Some("victim.example"));
        let resolved = resolve_request_host(&headers, Some(ip("8.8.8.8")), &[]);
        assert_eq!(resolved, Some("real.example.com"));
    }

    #[test]
    fn missing_host_yields_none() {
        let headers = h(None, None, None);
        let resolved = resolve_request_host(&headers, Some(ip("8.8.8.8")), &[]);
        assert_eq!(resolved, None);
    }

    // ---- resolve_request_host: trusted path ----

    #[test]
    fn trusted_peer_prefers_forwarded_over_xfh_over_host() {
        let headers = h(
            Some("fallback.example"),
            Some("host=forwarded.example"),
            Some("xfh.example"),
        );
        let cidrs = vec![cidr("10.0.0.0/8")];
        let resolved = resolve_request_host(&headers, Some(ip("10.1.2.3")), &cidrs);
        assert_eq!(resolved, Some("forwarded.example"));
    }

    #[test]
    fn trusted_peer_uses_xfh_when_forwarded_absent() {
        let headers = h(Some("fallback.example"), None, Some("xfh.example"));
        let cidrs = vec![cidr("10.0.0.0/8")];
        let resolved = resolve_request_host(&headers, Some(ip("10.1.2.3")), &cidrs);
        assert_eq!(resolved, Some("xfh.example"));
    }

    #[test]
    fn trusted_peer_xfh_first_value_wins() {
        // Multi-proxy: client claim is index 0, intermediate proxies
        // append. First wins.
        let headers = h(None, None, Some("client.example, proxy1.example, proxy2.example"));
        let cidrs = vec![cidr("10.0.0.0/8")];
        let resolved = resolve_request_host(&headers, Some(ip("10.0.0.5")), &cidrs);
        assert_eq!(resolved, Some("client.example"));
    }

    #[test]
    fn trusted_peer_falls_back_to_host_when_forwarded_headers_empty() {
        let headers = h(Some("only.example"), None, None);
        let cidrs = vec![cidr("10.0.0.0/8")];
        let resolved = resolve_request_host(&headers, Some(ip("10.1.2.3")), &cidrs);
        assert_eq!(resolved, Some("only.example"));
    }

    // ---- Forwarded parser ----

    #[test]
    fn forwarded_parses_unquoted_host() {
        assert_eq!(
            parse_forwarded_host("host=example.com"),
            Some("example.com")
        );
    }

    #[test]
    fn forwarded_parses_quoted_host() {
        assert_eq!(
            parse_forwarded_host(r#"host="example.com""#),
            Some("example.com")
        );
    }

    #[test]
    fn forwarded_parses_with_other_params() {
        assert_eq!(
            parse_forwarded_host("for=192.0.2.60;host=example.com;proto=https"),
            Some("example.com")
        );
    }

    #[test]
    fn forwarded_is_case_insensitive_for_param_name() {
        assert_eq!(parse_forwarded_host("HOST=example.com"), Some("example.com"));
        assert_eq!(parse_forwarded_host("Host=example.com"), Some("example.com"));
    }

    #[test]
    fn forwarded_multiple_groups_honours_first() {
        assert_eq!(
            parse_forwarded_host("host=first.example, host=second.example"),
            Some("first.example")
        );
    }

    #[test]
    fn forwarded_missing_host_param() {
        assert_eq!(
            parse_forwarded_host("for=192.0.2.60;proto=https"),
            None
        );
    }

    #[test]
    fn forwarded_empty_value_returns_none() {
        assert_eq!(parse_forwarded_host("host="), None);
        assert_eq!(parse_forwarded_host(r#"host="""#), None);
    }

    #[test]
    fn forwarded_handles_ipv6_bracketed_host() {
        // RFC 7239 §4: IPv6 in Forwarded must be quoted + bracketed.
        // Our parser strips the outer quotes; the brackets stay.
        assert_eq!(
            parse_forwarded_host(r#"host="[2001:db8::1]:8080""#),
            Some("[2001:db8::1]:8080")
        );
    }

    // ---- CIDR list parser ----

    #[test]
    fn parse_trusted_cidrs_separates_good_and_bad() {
        let inputs = vec![
            "10.0.0.0/8".to_string(),
            "garbage".to_string(),
            "2001:db8::/32".to_string(),
            "192.168.1.300/24".to_string(), // invalid octet
        ];
        let (ok, bad) = parse_trusted_cidrs(&inputs);
        assert_eq!(ok.len(), 2);
        assert_eq!(bad, vec!["garbage", "192.168.1.300/24"]);
    }

    // ---- end-to-end smoke ----

    #[test]
    fn realistic_aws_alb_scenario() {
        // AWS ALB sits in 10.0.0.0/16 and adds `X-Forwarded-Host`
        // when forwarding to the app. Forwarded is not emitted by
        // ALB (yet) — so the resolver should pick XFH from the ALB
        // and trust it.
        let cidrs = vec![cidr("10.0.0.0/16")];
        let alb_ip = Some(ip("10.0.5.42"));
        let headers = h(
            Some("internal.example"),
            None,
            Some("tenant-a.example.com"),
        );
        assert_eq!(
            resolve_request_host(&headers, alb_ip, &cidrs),
            Some("tenant-a.example.com")
        );
    }

    #[test]
    fn realistic_direct_request_no_proxy() {
        // No proxy, no trusted CIDRs configured — only Host is used.
        let headers = h(Some("example.com"), None, None);
        let resolved = resolve_request_host(&headers, Some(ip("8.8.8.8")), &[]);
        assert_eq!(resolved, Some("example.com"));
    }
}
