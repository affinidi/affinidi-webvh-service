### Fixed — the witness and watcher listeners bound slow connections and read a body only after admission

The witness's and the watcher's HTTP listeners had no header, body or idle
timeout and accepted connections without bound, and `POST /api/trust-tasks`
read the whole body (up to 1 MiB) before its per-address rate limit ran. A
client that sent a request slowly, or not at all, kept its connection, and
the limiter never saw a request whose body did not finish.

Both now serve through a shared listener (`did_hosting_common::server::listener`):

- at most 256 connections are served at once; more wait in the backlog for a
  free slot;
- at most 32 of them come from one IPv4 address or one IPv6 /64; more are
  closed as soon as they are accepted. Addresses in `server.trusted_proxies`
  are exempt, since every client behind a proxy shares its address;
- a request's headers must arrive within 20 seconds of its first byte, and a
  new connection must send its first request within the same time; sending a
  byte at a time does not extend it;
- a connection waiting for its next request, or not reading its response, is
  closed after 60 seconds;
- a connection that opens with the HTTP/2 preface is held to the 20-second
  header deadline, renewed only when the service writes to it, never by the
  peer's bytes alone.

`POST /api/trust-tasks` now checks the sender's address before it reads the
body, so a refused address gets its `429` without its body being read. An
admitted body is read up to 1 MiB, as before, and within 30 seconds: one
declared or sent over the limit is answered `413`, one that stops arriving
`408`, both with `Connection: close`. An over-size body was already refused
with `413`; a body that stopped arriving was waited for without limit.

The daemon's embedded witness gets the same order (rate limit, then body)
and the same body bound and timeout; the daemon's own listener is unchanged.
Both READMEs now say a reverse proxy is still expected in front.

For library users: `webvh_witness::routes::trust_tasks::receive` and
`webvh_watcher::routes::trust_tasks::receive` now take the request body as
`axum::body::Body` rather than `Bytes`, and each crate's `AppState` has a
`body_read_timeout`.
