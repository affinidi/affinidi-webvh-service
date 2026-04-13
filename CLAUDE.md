# WebVH Service — Project Instructions

## Daemon Parity

The `webvh-daemon` is the unified binary that embeds server, witness, watcher, and control plane into a single process. It must be kept in sync with the standalone `webvh-server` and `webvh-control` capabilities where it makes sense as a self-contained service.

When making changes to `webvh-server` or `webvh-control`, check whether the same capability needs to be reflected in `webvh-daemon`. Key areas to keep aligned:

- **CLI commands**: Any new CLI subcommand added to webvh-server or webvh-control should also be added to webvh-daemon.
- **Background tasks**: Session cleanup, DID cleanup, stats flush, and health checks run in a unified storage task in the daemon. New periodic tasks in standalone services should be added to `run_daemon_storage_task`.
- **Startup initialization**: Auto-bootstrap, integrity checks, stats seeding, registry seeding — any new startup-time logic in standalone services should be mirrored in `run_daemon()`.
- **Route changes**: The daemon merges server (public-only) and control (full API + UI) at root. Server `/api` routes are NOT included — the control plane provides all management routes. Route additions to either service must be tested in daemon mode.
- **DIDComm**: The daemon starts the **control plane's** inbound DIDComm listener when `didcomm = true`. This handles the full VTA provisioning protocol (did/request, did/publish, etc.) and operates on the control plane's authoritative store. The server does **not** run its own DIDComm service in daemon mode — it only receives sync updates in distributed mode. No outbound ATM is needed in daemon mode since there are no external servers to sync with.

The daemon is always self-contained — it does **not** register with an external control plane, and stats are shared in-process via `Arc<StatsCollector>` (no HTTP stats sync).
