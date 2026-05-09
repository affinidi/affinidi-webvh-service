# WebVH Service — Project Instructions

## webvh-daemon: the unified binary

`webvh-daemon` is a self-contained, single-binary deployment that embeds
**all the main features** of `webvh-server`, `webvh-witness`,
`webvh-watcher`, and `webvh-control` in one process. It is the
recommended deployment for single-host operators; it is not a strict
superset of the standalone services.

The daemon shares the same on-disk store, the same DID-management
surface, the same DIDComm protocol, and the same UI as a standalone
control + server pair. Where standalone deployments coordinate over the
network (HTTP stats sync, server-push, registry health checks against
remote instances), the daemon coordinates in-process — same outcomes,
fewer wires.

### What the daemon mirrors from the standalone services

When you add capability to `webvh-server` or `webvh-control`, mirror it
in the daemon if it falls into any of these buckets:

- **CLI commands.** Subcommands added to either standalone binary
  should also be reachable through `webvh-daemon`.
- **Startup initialisation.** Auto-bootstrap, integrity checks, stats
  seeding, registry seeding, key/secret loading — anything the
  standalone services do at boot belongs in `run_daemon()` too.
- **Background tasks.** Session cleanup, DID cleanup, stats flush, and
  similar periodic work runs in `run_daemon_storage_task` (a single
  unified task, rather than one per service). New periodic work in
  standalone services should land here.
- **Route changes.** The daemon merges server (public DID resolution
  only) + control (full management API + UI) at root. The server's
  `/api/*` routes are not exposed — the control plane provides all
  management routes. Route additions to either service must be tested
  in daemon mode.
- **DIDComm message types.** The daemon runs the control plane's
  inbound DIDComm listener (`build_control_router`). Any new `MSG_*`
  routed there is automatically picked up; no separate daemon wiring
  needed.

### What the daemon intentionally does NOT mirror

These are deliberate omissions, not parity violations. If you find
yourself about to "fix" one of these, check first whether it makes
sense in the all-in-one model.

- **The server's own DIDComm listener.** The daemon's embedded server
  does not run its own DIDComm — the control plane's listener handles
  the full provisioning protocol on the authoritative store. The
  server's DIDComm path applies only to the distributed deployment
  where it receives sync updates from a remote control plane.
- **HTTP stats sync.** The standalone server periodically POSTs stats
  deltas to the standalone control plane. In the daemon, stats are
  shared in-process via `Arc<StatsCollector>` — there is no HTTP
  round-trip and the sync task is not spawned.
- **Outbound ATM / mediator client for inter-service sync.** No
  external servers exist to push DID updates to from a daemon's
  control plane, so `server_push` is effectively a no-op against an
  empty registry. Don't conditionally skip it — the no-op is cheap and
  the same code keeps working if an operator does register a remote
  instance.
- **Registry health-check loop.** The standalone control plane pings
  registered service instances periodically. In a default daemon
  deployment the registry is empty (the daemon is self-contained), so
  the health-check is redundant and not spawned. The daemon *can* host
  remote service instances if an operator populates
  `[[registry.instances]]` or accepts inbound `MSG_SERVER_REGISTER`
  messages — that's an unusual deployment, and in that case the
  dashboard's "last seen" indicator will be stale until you switch to
  standalone control or wire the loop in manually. Use standalone
  control for managing remote services as the supported path.
- **Self-registration with an external control plane.** A daemon does
  not register itself anywhere — it *is* the control plane.

### When in doubt

Contributors hesitating between "mirror this in the daemon" and "skip
it" should ask: *does this capability require coordinating with
something outside this process?* If yes, it's probably one of the
intentional omissions above. If no, it's parity work and belongs in
`run_daemon()` or `run_daemon_storage_task`.
