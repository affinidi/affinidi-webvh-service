### Changed — rate limits run on `affinidi-rate-limit`

Every per-address and per-source rate limit (resolution, each Trust Task
listener, the challenge, invite redemption, wallet sign-in, and the
per-address and service-wide large-document budgets), and the rule for which
address a request comes from, now use the `affinidi-rate-limit` crate the mediator and the DID resolver cache use. Each limit is still stated
as requests per window, with the same numbers, but is now a token bucket: a
client may spend its allowance at once and regains one request every
`window / max`, so `Retry-After` is the time to its next request rather than
to the end of the window, and there is no double burst across a window
boundary. Refusals are logged once per client per window. Idle clients are
swept every minute, and at most 250,000 are tracked per limit (previously
10,000, with the map cleared when full). The `429` keeps its shape. Its `message`
changes: the resolution limit sends the crate's generic text, and the other
limits share one template naming their numbers, replacing the challenge's and
redemption's own wording. The large-document budget keeps its own penalty (an
address whose claimed issuer did not verify pays double for its next large
document) on top of the crate's buckets, and tracks at most 10,000 addresses.

Four refusals change. A chain from a trusted proxy that cannot be read (a
malformed entry, more than 64 entries, or a header that is not visible ASCII)
is refused with `400` instead of being charged to the proxy's address, which
handed its sender a second budget and hid a misbehaving proxy; the first such
chain from a proxy each minute is logged as a warning naming it. The `400`
carries the same body everywhere a request is charged to an address — `{
"error": "invalid_forwarded_for", "limiter": "<limiter>", "message": "..." }`
with `x-rate-limit-source: did-host` — except `POST /api/trust-tasks` on the
control plane, which refuses it, like everything else it refuses, with a
`trust-task-error` document (`malformedRequest`).
`server.trusted_proxies` refuses a range covering every address (`0.0.0.0/0`,
`::/0`) at startup. A resolution request with no peer address, a wiring
fault, is refused with `403` instead of `500`. And when a limit already
tracks 250,000 clients that are still within their budget, a new client is
refused with `429` and `Retry-After: 60` until room frees up, rather than the
limit forgetting everyone.
