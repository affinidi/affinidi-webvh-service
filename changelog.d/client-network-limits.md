### Changed — per-address limits count an IPv6 client by its /64, and proven callers keep a share of the large-document budget

Every per-address limit counted an IPv6 client by its full address, so one
host could draw a fresh allowance from each address in its block. Only the
resolution limit counted a /64. Now every one does: the Trust Task listener
limit on the edge, witness and watcher, `POST /api/auth/challenge`, passkey
invite redemption and login start over HTTPS, wallet sign-in (`auth/oob/*`)
and its open-poll cap, the sign-in replay quota per source, and the
large-document budget per address.

- New `[server] client_ipv6_prefix` (default `64`, `1` to `128`) sets the
  network an IPv6 client is counted by, for those limits and for
  `[server.resolve_rate_limit]`. A value outside the range stops the service
  at startup. IPv4 clients are counted by their address, as before.
- The large-document budget across all addresses (60 a minute) is split. An
  address whose large `did/register` verified as the issuer it claimed in the
  last hour draws on 40 of those that no other address can spend. Every other
  address shares the remaining 20, and a proven address falls back to them
  once its own 40 are spent. A claim that does not verify ends the address's
  proven standing.
- The forced re-resolution of a signer's DID is limited per DID with any
  path, query and fragment removed. Before, only a `did:scid`'s lone `?src=`
  was removed, so a `src` with further parameters, or another query, counted
  as a different DID.

Behaviour change (R3.6): no wire shapes change. Clients in one IPv6 /64
now share one allowance on each of the limits above, so several hosts behind
one /64 (or a deployment that hands out addresses from one) can be refused
sooner; set `client_ipv6_prefix = 128` to count each address alone. A
caller's first large document, before it has verified once, and every large
document from a new address, competes for the 20-a-minute share. Log lines
for a limited IPv6 client name its network, not its address.

### Breaking — `did-hosting-common` `ServerConfig` has a `client_ipv6_prefix` field

Rust callers that build `did_hosting_common::server::config::ServerConfig`
with a struct literal must set `client_ipv6_prefix`; use
`did_hosting_common::server::config::default_client_ipv6_prefix()` or
`..ServerConfig::default()`. Build a service's `ClientIps` with
`ClientIps::from_server_config(&config.server)` so the setting applies;
`ClientIps::new` still works and counts an IPv6 client by its /64.
Configuration files need no change.
