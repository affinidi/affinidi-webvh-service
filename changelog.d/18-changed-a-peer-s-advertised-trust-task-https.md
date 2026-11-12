### Changed — a peer's advertised Trust Task HTTPS endpoint must be public `https`

When a peer's DID document advertises `TrustTaskHTTPS` (and no TSP or DIDComm
service), the control plane's pushes and health pings, and an edge's
registration, stats and replication sends, `POST` to that endpoint. The URL is
the peer's to name, so it is now held to an outbound policy (via
`affinidi-net-guard`): `https` to a public host only. An endpoint on loopback,
a private, link-local or carrier-grade NAT range, or a special-use name
(`localhost`, `*.internal`, single-label names) is treated as not advertised:
the send falls back to the configured mediator, or fails as unroutable. What
the name resolves to is checked again when the request connects. Redirects
are not followed, timeouts are finite and the reply is capped at 1 MiB, as
before. A non-2xx reply body is sanitised and truncated before it reaches a
log line or an outbox error.

- **Behaviour change:** a peer that advertises `TrustTaskHTTPS` at
  `http://localhost:…`, `http://127.0.0.1:…` or a private address is no
  longer sent to. Advertise a public `https` endpoint, or a TSP / DIDComm
  service.
- URLs an operator configures (`WebVHClient`'s server URL, `WitnessClient`'s
  witness URL) are unaffected.
- Setup (interactive and recipe) and the control plane's sign-in self-check
  now note when this node's own advertised `TrustTaskHTTPS` endpoint is one
  other nodes will not send to.
- There is no setting yet to admit private address ranges; a deployment whose
  nodes reach each other only over a private network uses TSP/DIDComm through
  a mediator.
- A peer whose endpoint is refused is warned about once per process; repeats
  are logged at debug.
