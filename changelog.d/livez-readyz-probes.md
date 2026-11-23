### Added — `/livez` and `/readyz` probes on every HTTP listener

Every binary that runs an HTTP listener (edge, control plane, witness,
watcher, daemon) now serves Kubernetes-style probes at the root,
unauthenticated and outside the rate limits like `/api/health`, which is
unchanged.

- **`GET /livez`** checks nothing beyond the HTTP server answering: always
  `200 {"status":"ok"}`, so storage or control-plane trouble never gets a
  process restarted.
- **`GET /readyz`** answers `200 {"status":"ready","storage":"ok"}`, or `503`
  with `"status":"notReady"` and the failed check `"unavailable"`.
  `storage` covers every store the binary serves from (the daemon's main and
  witness stores): on fjall, that the data directory still holds the database
  (an open database goes on answering from memory after its volume is gone)
  and that fjall has not been poisoned by an I/O error; on the network
  backends, one point read. It never writes. The edge adds `serving`, the
  condition its `/api/health` reports (its own DID served locally, within the
  replication staleness bound); the daemon adds `serving` for its own DID
  when its server is on. Mediator connectivity is not part of readiness.
- The checks run at most once a second, shared by concurrent probes, and
  give up after 800 ms (not ready). The body never carries the cause, which
  is logged at `warn`.

See `docs/deployment.md` ("Health checks", and "Containers and Kubernetes"
for a probe example).
