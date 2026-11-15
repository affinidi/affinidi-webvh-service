### Changed — background work is supervised, and shutdown is ordered and bounded

`did-hosting-server`, `did-hosting-control` and `did-hosting-daemon` now run
their background work under a supervisor. A task that stops on its own while
the service is running is logged at `error`: the restartable ones (the
outbox, the purge and identity sweeps, the registry health check, the edge's
registration, reconcile and stats-sync loops) are restarted with backoff
(1 s, doubling to 60 s); the critical ones (the HTTP listener and the storage
thread or task, which persists the store) shut the service down with a
non-zero exit so the orchestrator restarts it. Before this a dead worker was
noticed only at shutdown, and the service kept answering `/api/health` while
replication, identity expiry or the statistics flush had stopped.

Shutdown runs in stages, each given at most 30 seconds: the workers, then the
messaging service (awaited — "DIDComm service stopped" is now logged only
once it has), then HTTP, then work requests handed off (an edge's resync),
then the storage thread's last flush and the store's persist — which
therefore runs after the outbox worker has stopped. The daemon's HTTP server
had no deadline, so one stalled connection could hold up `SIGTERM`
indefinitely; it now has the edge's 30 s.

An edge (and the control plane, and the daemon) now retries starting its
messaging service with backoff instead of giving up after one warning, so an
edge whose mediator is briefly unreachable at boot still comes to reconcile
with its control plane.

### Changed — the daemon's `/health` reports the real check

`GET /health` on `did-hosting-daemon` answered `ok` unconditionally. It now
answers `200` only while the daemon's own DID is served from its store, and
`503` with `"status": "degraded"` otherwise — the check the standalone
services' `/api/health` makes. Its body gains a `version` field.

### Added — the daemon has every subcommand the standalone binaries have

`did-hosting-daemon` gains `export-sealed`, `import-sealed`, `vta-request` and
`vta-open`. The subcommands the binaries share are now defined once and
shared by all three, so they behave the same everywhere:

- `import-secrets` and `import-sealed` take an optional `--jwt-key` on every
  binary, and `import-sealed` on `did-hosting-control` now keeps the retired
  key material of superseded identity generations, as the other binaries
  already did.
- `vta-request` takes `--public-url` (`--did-hosting-url` remains an alias),
  an optional `--mediator-did` and `--transport` on every binary; on
  `did-hosting-control` `--mediator-did` is no longer required (without it
  the request is for an HTTP-only DID). `--label` defaults to the binary's
  name.
- `vta-open`'s output files default to `<service>-did.json`,
  `<service>-did.jsonl` and `<service>-secrets.json`, where `<service>` is
  `server`, `control` or `daemon`.
- `remove-did` and `recreate-did` on `did-hosting-server` now remove the
  slot's domain index row and usage counter with it, and `recreate-did`
  removes the owner index entry of the record's actual owner, as the daemon's
  did.

### Removed — `did-hosting-daemon migrate-from-webvh-config`

The subcommand was a stub: it printed instructions, ignored `--force` and
wrote nothing. There is no configuration file content to migrate (the rename
from `webvh-*` changed binary names and environment variable prefixes, not
config keys), so it is removed rather than finished.

### Changed — `did_hosting_control::server::AppState` is built by `AppState::build`

For crates embedding the control plane: `AppState` drops the unused
`http_client` field and gains `background` (the tracker of work handed off by
a request, awaited at shutdown). Build one with `AppState::build(config,
store, secrets, identity, AppStateOverrides { .. })` — the recipe the
standalone control plane, the daemon and `test_support` all use — and run
its boot steps with `server::startup`, rather than writing the literal.
