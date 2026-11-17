//! `[server]`: the HTTP listener, trusted proxies and client addressing.

use crate::server::error::AppError;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use super::resolve::{ResolveCacheConfig, ResolveRateLimitConfig};

/// Serde for a list of networks written as strings: an address
/// (`"10.0.0.1"`, its own one-address network) or a CIDR (`"10.0.0.0/8"`).
/// A bad entry is a load error that names it, not a silently dropped one.
pub mod ip_networks {
    use ipnetwork::IpNetwork;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(nets: &[IpNetwork], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(nets.iter().map(|n| match n.prefix() {
            // A one-address network reads back as the address it was written as.
            p if p == max_prefix(n) => n.ip().to_string(),
            _ => n.to_string(),
        }))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<IpNetwork>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|entry| parse(entry).map_err(serde::de::Error::custom))
            .collect()
    }

    /// One entry: an address or a CIDR range, surrounding whitespace ignored.
    /// The error names the entry. A range covering every address
    /// (`0.0.0.0/0`, `::/0`) is refused: trusting every peer lets any client
    /// name its own client address.
    pub fn parse(entry: &str) -> Result<IpNetwork, String> {
        let network = entry.trim().parse::<IpNetwork>().map_err(|_| {
            format!(
                "invalid network `{entry}`: expected an IP address (`10.0.0.1`) \
                 or a CIDR range (`10.0.0.0/8`, `2001:db8::/32`)"
            )
        })?;
        if network.prefix() == 0 {
            return Err(format!(
                "network `{entry}` covers every address; list the proxies' own ranges"
            ));
        }
        Ok(network)
    }

    fn max_prefix(n: &IpNetwork) -> u8 {
        match n {
            IpNetwork::V4(_) => 32,
            IpNetwork::V6(_) => 128,
        }
    }
}

/// Deserialise `[server] trusted_proxy_cidrs`, naming the key in the error.
fn deserialize_trusted_proxy_cidrs<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<IpNetwork>, D::Error> {
    Vec::<String>::deserialize(d)?
        .iter()
        .map(|entry| {
            ip_networks::parse(entry)
                .map_err(|e| serde::de::Error::custom(format!("[server] trusted_proxy_cidrs: {e}")))
        })
        .collect()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Trusted reverse proxies whose `X-Forwarded-For` header is
    /// honoured for client-IP attribution — addresses or CIDR ranges
    /// (`"10.0.0.1"`, `"10.20.0.0/16"`, `"2001:db8::/48"`), the same shape
    /// as the VTC's `trust_xff_cidrs`. Empty (default) = X-Forwarded-For is
    /// ignored and the direct TCP peer is used — safe behind nothing or
    /// behind a CDN that strips XFF, but wrong behind a load balancer
    /// (every request appears to come from the LB, so per-IP rate limits
    /// become a global cap). List only your actual reverse proxies: see
    /// [`crate::server::rate_limit::ClientIps`]. An entry that is
    /// neither an address nor a CIDR, or a range covering every address, is
    /// refused at load.
    ///
    /// **Set together with [`Self::trusted_proxy_cidrs`].** The two lists
    /// answer different questions (who the client is; which host the request
    /// addresses), so a deployment behind a reverse proxy normally lists the
    /// same proxies in both. The edge and the daemon warn at startup when
    /// only one is set. Trusted proxies are also exempt from the listener's
    /// per-address connection cap.
    #[serde(default, with = "ip_networks")]
    pub trusted_proxies: Vec<IpNetwork>,
    /// The network prefix an IPv6 client is counted by in every per-address
    /// limit (the Trust Task listener, sign-in, invite redemption, wallet
    /// sign-in, the large-document budget, and `resolve_rate_limit`): one
    /// host is normally given a whole block, and could otherwise draw a fresh
    /// allowance from each address in it. Default 64; 1 to 128 (128 counts
    /// each address on its own). An IPv4 client is always counted by its
    /// address. See [`crate::server::rate_limit::ClientIps::key_of`].
    #[serde(default = "default_client_ipv6_prefix")]
    pub client_ipv6_prefix: u8,
    /// Trusted reverse-proxy CIDRs whose `Forwarded` (RFC 7239) and
    /// `X-Forwarded-Host` headers are honoured for **request host /
    /// domain detection** (multi-domain feature). Distinct from
    /// `trusted_proxies` above: that one is for client-IP
    /// attribution; this one is for which host the request is
    /// claiming to address. Outside this set, the daemon always uses
    /// the literal `Host` header.
    ///
    /// Empty (default) disables `Forwarded` / `X-Forwarded-Host`
    /// trust — appropriate for deployments not behind a reverse
    /// proxy. Entries are addresses or CIDR ranges (`10.0.0.1`,
    /// `1.2.3.0/24`, `2001:db8::/32`). Behind a proxy, list it here **and**
    /// in `trusted_proxies`.
    ///
    /// Parsed when the config is loaded: an entry that is neither an address
    /// nor a CIDR range, or a range covering every address, stops the
    /// service at startup, naming this key and the entry.
    #[serde(
        default,
        serialize_with = "ip_networks::serialize",
        deserialize_with = "deserialize_trusted_proxy_cidrs"
    )]
    pub trusted_proxy_cidrs: Vec<IpNetwork>,
    /// `Cache-Control` policy for public DID-resolution responses
    /// (`[server.resolve_cache]`). Read only by the binaries that serve
    /// resolution — the server, the watcher and the daemon.
    #[serde(default)]
    pub resolve_cache: ResolveCacheConfig,
    /// Per-client-address limit on public DID resolution
    /// (`[server.resolve_rate_limit]`). Off by default. Read only by the
    /// binaries that serve resolution — the server, the watcher and the
    /// daemon.
    #[serde(default)]
    pub resolve_rate_limit: ResolveRateLimitConfig,
}

impl ServerConfig {
    /// Apply `{prefix}_SERVER_TRUSTED_PROXIES` (comma-separated addresses or
    /// CIDR ranges; an empty value clears the list), refusing any entry that
    /// is neither.
    pub fn apply_trusted_proxies_env_override(&mut self, prefix: &str) -> Result<(), AppError> {
        self.apply_trusted_proxies_override(prefix, |var| std::env::var(var).ok())
    }

    /// [`Self::apply_trusted_proxies_env_override`] reading variables through
    /// `lookup`.
    pub(super) fn apply_trusted_proxies_override(
        &mut self,
        prefix: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<(), AppError> {
        let var = format!("{prefix}_SERVER_TRUSTED_PROXIES");
        if let Some(v) = lookup(&var) {
            self.trusted_proxies = v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|entry| {
                    ip_networks::parse(entry).map_err(|e| AppError::Config(format!("{var}: {e}")))
                })
                .collect::<Result<_, _>>()?;
        }
        Ok(())
    }
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

/// The `server.client_ipv6_prefix` default.
pub fn default_client_ipv6_prefix() -> u8 {
    crate::server::rate_limit::DEFAULT_CLIENT_IPV6_PREFIX
}

fn default_port() -> u16 {
    8530
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            trusted_proxies: Vec::new(),
            client_ipv6_prefix: default_client_ipv6_prefix(),
            trusted_proxy_cidrs: Vec::new(),
            resolve_cache: Default::default(),
            resolve_rate_limit: Default::default(),
        }
    }
}
