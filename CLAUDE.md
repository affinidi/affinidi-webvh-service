# DID Hosting Service — Project Instructions

## did-hosting-daemon: the unified binary

`did-hosting-daemon` is a self-contained, single-binary deployment that embeds
**all the main features** of `did-hosting-server`, `webvh-witness`,
`webvh-watcher`, and `did-hosting-control` in one process. It is the
recommended deployment for single-host operators; it is not a strict
superset of the standalone services.

The daemon shares the same on-disk store, the same DID-management
surface, the same DIDComm protocol, and the same UI as a standalone
control + server pair. Where standalone deployments coordinate over the
network (HTTP stats sync, server-push, registry health checks against
remote instances), the daemon coordinates in-process — same outcomes,
fewer wires.

### What the daemon mirrors from the standalone services

When you add capability to `did-hosting-server` or `did-hosting-control`, mirror it
in the daemon if it falls into any of these buckets:

- **CLI commands.** Subcommands added to either standalone binary
  should also be reachable through `did-hosting-daemon`.
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
- **Service identity rotation.** The daemon's *own* DID identity — the
  generation model, the rotation trigger, the expiry sweep, and the
  old-mediator drain — is owned by the **control plane**, because in
  daemon mode the control plane runs the only DIDComm listener. The
  embedded server's and witness's rotation paths are inert by
  construction: neither starts a listener, so their `didcomm_service`
  slot stays empty and `rebuild_listener` no-ops. **Do not mirror
  rotation into the embedded server** — the no-op falls out of the
  daemon's existing shape and needs no conditional skip. See
  `docs/identity-rotation-design.md`.

- **TSP transport.** The daemon inherits TSP for free: it starts the
  control plane's `start_didcomm_service`, which carries TSP on the same
  mediator socket when `features.tsp` is set (it tracks `features.didcomm`
  by default). Inbound TSP frames dispatch through the same
  transport-agnostic `dispatch_inbound` core, so new Trust-Task handlers
  are reachable over TSP with no separate daemon wiring. See
  `docs/tsp-transport.md`.

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
  dashboard's "last seen" indicator and each instance's advertised-service
  badges (`ServiceInstance.advertised_services`, refreshed on the same
  loop) will be stale until you switch to standalone control or wire the
  loop in manually. Instances still get their badges resolved once, at
  registration. Use standalone control for managing remote services as
  the supported path.
- **Self-registration with an external control plane.** A daemon does
  not register itself anywhere — it *is* the control plane.

### When in doubt

Contributors hesitating between "mirror this in the daemon" and "skip
it" should ask: *does this capability require coordinating with
something outside this process?* If yes, it's probably one of the
intentional omissions above. If no, it's parity work and belongs in
`run_daemon()` or `run_daemon_storage_task`.

## Source of record: control plane authoritative, edges ephemeral

There is one source of record for DID hosting: **the control plane.** It owns
the authoritative state — the `DidRecord`, the signed `did.jsonl`, the
**agent-name registry** (`record.agent_names` + the `name:{domain}:{name}`
index), owner and domain assignments. Everything else is downstream of it.

- **The agent (VTA) is an external publisher *into* the control plane.** It
  holds the DID's update key and produces signed `did.jsonl` versions, but it
  publishes them *to* the control plane (`publish_did`, `register_did_atomic`,
  the agent-name ops). It is a source of *documents*, not of record — the
  control plane decides what is stored and served.

- **Hosting servers (edges) are lossy and ephemeral — treat them as caches.**
  An edge *derives* its view (served names, the index) from the logs the
  control plane syncs to it (`control_register::apply_single_update`); it can
  be wiped and rebuilt from the control plane at any time. Never keep state on
  an edge that isn't reconstructible from a control-plane sync, and never treat
  an edge's derived view as authoritative.

**The load-bearing consequence:** every control-plane write must keep the
authoritative state correct *by itself* — you cannot lean on an edge to hold or
repair it. Concretely, `publish_did`/`register_did_atomic` **reconcile the
agent-name registry against the published document** (`reconcile_agent_names`):
a name the signed document claims via `alsoKnownAs` is registered `enabled` with
its index; a previously-served name the document drops is released; a **parked**
(`enabled: false`) name is preserved even though it's absent from the document
(parking deliberately drops the claim while holding the reservation, which the
log alone can't express). This is why a name can be bound by a *plain* publish
(the VTA editing `alsoKnownAs`) and then parked — the registry is authoritative
and always in step, not dependent on the explicit `agent-name/*` ops having been
the one to add it. Edge derivation mirrors the same rule so an edge structurally
cannot serve a name the document doesn't claim (Layer-1), but the control plane's
reconciled registry — not the edge — is the truth.

**Reconciling is not trusting.** Deriving the registry from `alsoKnownAs` says
what a document *claims*, never that the claim is allowed. So both reconcile
sites apply the same preconditions the explicit `set` verb does — reserved names
refused, a name held by another DID refused, all under `path_locks.guard` — and
the invariant to preserve when touching any of this is:

> **A name only ever changes owner through an explicit `remove` by its current
> holder.**

Layer-1 verification cannot enforce that for you, and it is worth understanding
why: after a hijack the new holder's document genuinely claims the name and the
index genuinely points at them, so a resolver's `alsoKnownAs` round-trip passes.
Layer-1 proves a served name is claimed by the DID it resolves to; it says
nothing about *who was entitled to claim it*. That check exists only here.

## Cross-service networking & integration discipline

This service's primary client is the VTA's `webvh_client`
(verifiable-trust-infrastructure) — its DID publish/update/delete lifecycle
depends on this server's exact wire behavior. Before changing any route,
validation rule, or response shape, read the ecosystem doc set in
`../design-docs/`:

- **`vti-stack-development-guide.md`** — binding rules (R-numbers below);
  paste its pre-merge checklist into PRs.
- **`vti-networking-remediation-plan.md`** — deliverable **D4** covers the
  VTA↔webvh boundary; two of its findings need server-side changes here.
- **`vti-architectural-direction.md`** — design-level rationale.

Rules that bite hardest here:

- **R3.6 — the request contract includes what you *ignore*.** The VTA sends
  `?domain=` on publish/delete as a cross-tenant safety check and documents a
  `did-management:unknown_domain` rejection — but the handlers here have no
  `Query` extractor, so axum silently drops it and the advertised protection
  doesn't exist on the wire. Either enforce a parameter or coordinate its
  removal; never silently accept-and-ignore.
- **Validation rules are contract too:** `validate_mnemonic`'s lowercase-only
  rule rejects every mixed-case base58 SCID, which (combined with the
  slot-reservation requirement) makes the VTA's final-mode create impossible.
  Changing or relying on validation behavior requires checking the VTA-side
  callers in the same pass.
- **R3.2 — reject unknown fields on state-changing bodies** rather than
  ignoring them; a field a client sends and the server drops is a latent
  cross-tenant or authorization bug.

## Node DID transport model — the document is authoritative

Every node (server, control, daemon, witness) mints its own `did:webvh` and
advertises **how to reach it in that DID document**. Changes to how nodes talk
to each other must keep the document as the source of truth.

- **Advertise messaging transports, not HTTP.** A mediator-configured node's
  DID carries only `TSPTransport` (`#tsp`) and/or `DIDCommMessaging`
  (`#vta-didcomm`) services — **not** a `WebVHHosting` HTTP endpoint. The
  resolution URL is derivable from the `did:webvh` identifier itself, inter-node
  traffic is DIDComm/TSP, and clients reach the REST API by explicit config
  (`webvh_client` takes an explicit `server_url`), so nothing discovers the
  endpoint from the document. Only a **no-mediator (HTTP-only)** node advertises
  `WebVHHosting`, because it has no messaging transport to advertise instead.

- **One builder mints them all.** Every setup path (interactive / recipe /
  online / offline) for server, control, and daemon packages its DID through
  `build_webvh_provision_ask` (a `WebvhDidShape`) in `did-hosting-common`'s
  `server::vta_setup`. Change the `Hosted` template selection there once and it
  applies to all three binaries — don't special-case one. The transport-only
  templates (`did-host-didcomm` / `did-host-tsp`) are still URL-hosted (the
  `URL` var tells the VTA where to publish the log) but emit no `WebVHHosting`
  service. No new vta-sdk template is needed for the mediator-configured shape.

- **Send precedence: document → config → fail.** Outbound trust-task delivery
  picks its binding via `resolve_send_binding` (`server::didcomm_profile`): the
  peer's advertised `TSPTransport` (preferred) or `DIDCommMessaging` wins; if
  the document advertises neither, the node's own configured mediator is the
  fallback (the compatibility bridge for DIDs minted before transports were
  published); if neither yields a binding, the send **fails** as unroutable.
  Do **not** reintroduce a blind-DIDComm default, and do **not** add a REST tier
  — there is no trust-task REST sender or inbound `/api/trust-tasks` route
  *between these services*, and HTTP-only nodes are served by the pull/watcher
  model, not a trust-task push.

- **Nothing gates on `WebVHHosting`.** `resolve_send_binding` reads only the
  messaging services; registration and health use the DIDComm identity; the
  registry's `advertised_services` is display-only; DID resolution is
  identifier-derived. Keep it that way — don't make behaviour depend on the
  hosting service being present.

## Gotchas worth knowing

- **Wire enums are camelCase.** Vault `secretKind` values are `didSelfIssued`,
  `didcommPeer`, `oauthTokens`, … — never kebab-case. The browser extension
  passes a page-supplied `secretKind` verbatim, so an RP page (e.g. the login
  UI) that sends `did-self-issued` fails schema validation at the VTA. Match the
  shared `vault/_shared/*/vault-entry.schema.json` `SecretKind` enum exactly;
  type the outbound filter as a union so a kebab value fails to compile.

- **The `server` code is behind the `server-core` feature.** Tests for
  `did-hosting-common`'s server modules only compile/run with
  `--features server-core` (or `store-fjall`, which enables it). A plain
  `cargo test -p did-hosting-common` silently skips them — and store-backed
  tests need a `store-*` backend feature or they panic on "no storage backend".

- **Versions are bumped by hand.** No release automation. On a release, bump
  every workspace crate's `[package] version` **and** the internal path-dep
  pins (`did-hosting-* = { version = "0.x", path = … }`) — but not external
  crates that happen to share that number (`tower-http`, `tokio-util`) — update
  `did-hosting-ui/package.json`, and add a grouped `CHANGELOG.md` entry.
