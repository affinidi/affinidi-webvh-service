//! Unit tests for `[server] trusted_proxies` parsing and env overrides.

use super::*;

/// Addresses and CIDR ranges both parse; an address is its own
/// one-address network and is written back as it was given.
#[test]
fn addresses_and_ranges_parse_and_round_trip() {
    let s: ServerConfig = toml::from_str(
        "trusted_proxies = [\"10.0.0.1\", \"10.20.0.0/16\", \"2001:db8::/48\", \" 192.0.2.7 \"]\n",
    )
    .unwrap();
    let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    assert!(s.trusted_proxies[0].contains(ip("10.0.0.1")));
    assert!(!s.trusted_proxies[0].contains(ip("10.0.0.2")));
    assert!(s.trusted_proxies[1].contains(ip("10.20.255.1")));
    assert!(s.trusted_proxies[2].contains(ip("2001:db8:0:1::5")));

    let written = toml::to_string(&s).unwrap();
    assert!(
        written.contains(
            r#"trusted_proxies = ["10.0.0.1", "10.20.0.0/16", "2001:db8::/48", "192.0.2.7"]"#
        ),
        "{written}"
    );
    let back: ServerConfig = toml::from_str(&written).unwrap();
    assert_eq!(back.trusted_proxies, s.trusted_proxies);
}

/// A bad entry stops the load and is named, rather than being dropped
/// (which left the proxy untrusted and every client in one bucket).
#[test]
fn a_bad_entry_is_refused_by_name() {
    for bad in ["proxy.internal", "10.0.0.0/33", "10.0.0.0/"] {
        let err = toml::from_str::<ServerConfig>(&format!("trusted_proxies = [\"{bad}\"]\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains(bad), "{err}");
    }
    let s: ServerConfig = toml::from_str("host = \"0.0.0.0\"").unwrap();
    assert!(s.trusted_proxies.is_empty());
}
