### Fixed — the daemon sends the standard response headers

`did-hosting-daemon` now sets the same response headers as the standalone
control plane, server, witness and watcher: `Content-Security-Policy`
(`default-src 'self'`, …), `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Strict-Transport-Security`, and `Cache-Control: no-store` on any response whose
handler sets no `Cache-Control` of its own. They cover the management console and
its assets, `POST /api/trust-tasks`, the embedded witness and watcher, and DID
resolution, which keeps its configured `[server.resolve_cache]` value.
`/health` is unchanged. Before this the daemon sent only the console's own HTML
headers, so Trust Task replies and error responses could be cached. Operators
whose reverse proxy already adds these headers will now see them twice and may
want to drop one copy.
