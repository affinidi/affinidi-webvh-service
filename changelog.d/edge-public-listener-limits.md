### Changed — the edge and the daemon serve HTTP under connection and time limits

The public listener of `did-hosting-server` and `did-hosting-daemon` now runs
on the shared bounded listener the witness and watcher already use. It
limits connections to 256 at once and 32 per address (IPv4 address or IPv6
/64; `server.trusted_proxies` exempt), allows 20 s for request headers, and
closes a connection after 60 s idle. The edge's `POST /api/trust-tasks` reads
its body after the per-address limit rather than before, bounded in size as
before and now in time (30 s; `408` past it, `413` over the size).

Behaviour change (R3.6): a client past these limits is disconnected or refused
where it was served before.

### Fixed — DID resolution answers only `GET` and `HEAD`

A `POST`, `PUT`, `DELETE` or other method to a DID path (`/{path}/did.jsonl`,
`did.json`, `did-witness.json`, `keri.cesr`) returned the document and counted
as a resolution. It is now `405 Method Not Allowed` with `Allow: GET, HEAD`, on
the edge, the daemon and the watcher.

### Fixed — an agent name on a disabled domain no longer redirects

`GET /@{name}` skipped the domain check the DID's own documents pass, so a
name on a disabled domain still redirected to a DID that answered `503`. It
now answers as the DID's documents do.

### Fixed — per-request warnings are rate-limited

The warnings for a `Forwarded` / `X-Forwarded-Host` header from a peer outside
`server.trusted_proxy_cidrs`, for resolution with no domain configured, and
for a request with no resolvable host are now written at most once a minute,
with a count of those held back. The rest go to `debug`. Any client could
trigger them on every request.

### Changed — a registration acknowledgement is logged only when it verifies

An edge logged "registration acknowledged by control plane" at `info`, with
the `instanceId` from the document, for any `server/register` response that
reached it, including one posted to its HTTPS listener by anyone. The
acknowledgement is now checked as the control plane's, as every control-plane
document is. An unverified one is logged at `debug` without its contents.

### Changed — `server.trusted_proxies` and `server.trusted_proxy_cidrs` are documented together

The two lists answer different questions: which client sent a request
(`trusted_proxies`) and which host it addresses (`trusted_proxy_cidrs`).
Behind a reverse proxy, list the proxy in both. The edge and the daemon now
warn at startup when only one of them is set.
