# TSP transport

The DID Hosting service speaks two mediator-routed transports:
**DIDComm v2** and **TSP** (the ToIP [Trust Spanning
Protocol](https://trustoverip.org/)). Both carry the same Trust-Task
operations to the same dispatch core; TSP is **preferred** when a peer
advertises it.

## Why two transports

Every wire operation in this workspace is a *Trust Task* — a versioned,
JSON, transport-agnostic description of verifiable work (see
`did-hosting-common/src/server/trust_tasks/`). The dispatch core,
`dispatch_inbound`, is transport-agnostic: each transport authenticates
the sender, builds a small `TransportHandler`, and hands the document to
the *same* handlers. Adding TSP was therefore adding one transport
binding, not a new protocol:

| Transport | Binding handler | Entry point |
|-----------|-----------------|-------------|
| HTTPS | `HttpsHandler` | `POST /api/trust-tasks` |
| DIDComm v2 | `DidcommHandler` | mediator socket envelope |
| **TSP** | **`TspTransportHandler`** | **mediator socket (shared with DIDComm)** |

TSP rides the **same** per-DID mediator websocket as DIDComm (no second
socket): `affinidi-messaging-didcomm-service` unpacks each inbound TSP
frame, authenticates the sender VID, and routes it to
`did_hosting_control::tsp::WebvhTspHandler`, which dispatches through
`dispatch_inbound` and returns a reply the framework seals + routes back.

## The preference rule — "when a DID has a TSPTransport, use that"

A `did:webvh` document minted by the VTA advertises, in this order:

```json
"service": [
  { "id": "…#webvh-hosting", "type": "WebVHHosting",     … },
  { "id": "…#tsp",           "type": "TSPTransport",      "serviceEndpoint": "<mediator-vid>" },
  { "id": "…#vta-didcomm",   "type": "DIDCommMessaging",  … }
]
```

`didcomm_profile::resolve_transport` reads a peer's document and returns
its preferred transport: it scans for `TSPTransport` **first**, falling
back to `DIDCommMessaging`. TSP-capable peers therefore reach each other
over TSP; DIDComm remains the fallback for peers that advertise only it.

## Configuration

`features.tsp` (config `[features] tsp = true`, env `<PREFIX>_FEATURES_TSP`)
toggles the TSP *listener*. It **tracks `features.didcomm` by default**:
whenever a mediator is configured, TSP is enabled alongside DIDComm.

This default is deliberate. The VTA webvh DID templates advertise a
`TSPTransport` service **unconditionally** alongside `DIDCommMessaging`
(both point at the same mediator), and peers prefer TSP — so a
mediator-connected node must listen on TSP to be reachable consistently.
The interactive daemon wizard offers an opt-out, but note that opting the
*listener* out does not remove the advertised service (that is fixed by
the VTA template), so leaving TSP on is recommended.

Nodes with no mediator (HTTP-only) speak neither DIDComm nor TSP over the
mediator; they serve DID resolution and the HTTPS Trust-Task endpoint
only.

## Surfacing transports in the controller UI

Two different facts get displayed, and they are not interchangeable:

- **Enabled** — `features.didcomm` / `features.tsp`. What the operator
  turned on in config; what this process *listens* for.
- **Advertised** — the `service[].type` entries in the node's own DID
  document. What peers *see* when they resolve it, and therefore what
  they will try.

The dashboard's Control Plane card shows both per transport and warns when
they disagree, because each direction is a distinct fault:

- *enabled but not advertised* — peers never discover the transport and
  will never use it;
- *advertised but not enabled* — peers try it and get nothing. This is
  exactly the state the Configuration note above describes when the
  wizard's TSP opt-out is taken against a template that advertises
  `TSPTransport` regardless, and is why leaving TSP on is recommended.

When the control plane's own DID cannot be resolved (or no DID resolver is
configured) the comparison is impossible; the UI reports "unknown" rather
than implying agreement. `GET /api/config` and `GET /api/services/overview`
omit `advertisedServices` entirely in that case — an absent field means
"not known", never "advertises nothing".

Elsewhere the same `service[].type` values render as badges — `Hosting`
(`WebVHHosting`), `TSP`, `DIDComm`, and `Other` for anything else:

- **DID list** — read from `DidRecord.services`, a cache refreshed by every
  write path that touches the DID log, so listing costs no log reads.
  Legacy records are swept at boot by the `M-02` migration on all three
  deployments: server and daemon run the full migration registry, while
  standalone control runs a runner carrying M-02 alone — it has never run
  the others, and switching them on wholesale would fill `domain` from the
  system-default tier as a side effect. The sweep is idempotent and
  marker-gated: one pass over the DID logs on the first boot after upgrade,
  nothing thereafter. `publish_did` self-heals anything the sweep deferred.
- **Servers list** — read from `ServiceInstance.advertised_services`,
  resolved from each instance's DID document at registration and refreshed
  by the registry health-check loop.

There is deliberately **no VTA badge**: no template in `vta-sdk`, and
nothing in `build_did_document`, emits a VTA service type. "VTA" names a
provisioning mode, not a service. The `#vta-didcomm` service *id* has type
`DIDCommMessaging` and so renders as the DIDComm badge.

The spec-implied `#whois` (`LinkedVerifiablePresentation`) and `#files`
(`relativeRef`) services are excluded. A conforming resolver synthesises
both into every document they're absent from (`didwebvh-rs`'s
`resolve::implicit::update_implicit_services`), so they appear on 100% of
*resolved* webvh DIDs and on none of the stored `did.jsonl` logs. Counting
them would put a permanent, contentless `Other` badge on every server while
the DID list showed none — same DID, different badges. Both read paths now
skip them, keyed on the `id` fragment, so a service an operator declares
under their own fragment still earns its badge.

An HTTP-only node — no mediator — advertises `WebVHHosting` alone and shows
a single `Hosting` badge. Absence of `TSP` and `DIDComm` there is the
correct reading: that node is reachable over HTTP only.

## Control ↔ server infrastructure ops

Server registration and health are **trust tasks**, so the binding is chosen
from the peer's DID document rather than hard-coded.

The `MSG_*` constants in `didcomm_types` are already canonical Trust-Task Type
URIs, with the reply being the `#response` fragment of the request:

```text
MSG_SERVER_REGISTER       …/spec/did-management/server/register/0.1
MSG_SERVER_REGISTER_ACK   …/spec/did-management/server/register/0.1#response
MSG_HEALTH_PING           …/spec/did-management/server/health/0.1
MSG_HEALTH_PONG           …/spec/did-management/server/health/0.1#response
```

They are reused verbatim as document Type URIs, so an op has **one identity** on
every wire: as a DIDComm `typ`, inside a trust-task envelope, or as a raw TSP
frame. `TrustTask::respond_with` derives the reply URI instead of restating it.

> The unused `TASK_SERVER_HEALTH_PING_1_0` / `_PONG_1_0` constants in
> `did_hosting_tasks` are **not** these. They sit on a `/did-hosting/` authority
> with no `/spec/` segment, so they do not parse as Type URIs at all, and they
> model the response as a separate URI rather than a fragment. They are
> route-header decorators for the HTTPS surface. Do not promote them into the
> document layer.

Outbound goes through `trust_tasks::send::send_trust_task`, the one place that
answers "how do I reach this peer": TSP when the peer advertises `TSPTransport`
(the document's JSON, sealed), otherwise the document inside a
`trust_tasks_didcomm::ENVELOPE_TYPE` DIDComm message. A TSP send that fails falls
back to DIDComm, and the function returns the transport that *actually* carried
the document. Inbound, both shapes converge on `trust_tasks_infra::dispatch` —
one on the control plane, its mirror on the server. Replies are *returned*, not
sent, so the framework routes them back over the arriving connection: a ping
delivered over TSP is ponged over TSP, with no second resolution.

This is what makes a **TSP-only server** work. Before it, the server had no
trust-task dispatcher at all, registration and health lived only on the DIDComm
router, and a node with `TSPTransport` and DIDComm disabled could never register
or pong — it sat in the dashboard as `Unreachable` forever.

### Two compatibility rules that look like warts

**The server's TSP handler sniffs the payload.** A trust-task document is tried
first, then a serialised DIDComm `Message` (the shape the control plane's outbox
has always used for sync/domain pushes over TSP). The two are unambiguous, but
not for the obvious reason — a `Message` also has top-level `id` and `type`, and
its `type` is itself a canonical Type URI. What separates them is `payload`,
which `TrustTask` requires and `Message` lacks. `didcomm_message_never_parses_as_a_trust_task`
pins that; were it to stop holding, the `owns()` gate would silently swallow
every sync push delivered over TSP.

**Registration's framing follows its transport.** A TSP-only server has no
DIDComm wire on which to send the legacy `MSG_SERVER_REGISTER`, so over TSP it
registers as a trust task. A DIDComm-reachable server keeps sending the legacy
message, because an *older* control plane has no `trust_tasks_infra` arm and
would route a register trust task into `bridge_did_management` — which has never
heard of `server/register` — leaving the server silently unregistered. Once every
control plane in a fleet understands the task, this collapses to
`send_trust_task` unconditionally; `trust-task-discovery/0.1` is the principled
way to detect that, and is deliberately not attempted yet.

Servers declare `trust_task_capable: true` in their registration body. The
control plane records it on `ServiceInstance` and only then sends trust-task
pings; everything else keeps receiving `MSG_HEALTH_PING`. Absent flag → `false`,
so upgrading the control plane first never strands a server. Both legacy `MSG_*`
routes stay registered on both sides and delegate to the same cores as the
trust-task dispatchers, so the two framings cannot drift.

## Unified dispatch

Both TSP and the DIDComm trust-task envelope route inbound
`TrustTask<Value>` documents through one shared entry point,
`messaging::dispatch_trust_task_doc`, which dispatches by Type URI:

- **ACL + discovery** ops → the typed framework §7.2 pipeline
  (`dispatch_inbound`).
- **DID-management** ops (`did/check-name`, `publish`, `register`,
  `delete`, `change-owner`, `info`, `list`, `witness/publish`) →
  `bridge_did_management`, which reuses the transport-agnostic
  `dispatch_did_op` engine and wraps its reply as a Trust Task
  `#response` document.

So **every op is a first-class trust task over TSP and DIDComm** — the
DID-management ops are reachable as trust-task documents, not only via the
legacy `MSG_*` messages (which keep working for back-compat).

`dispatch_did_op` remains the DID-management engine behind this facade:
those ops are bound to the control plane's `AppState` and can't move into
the crate-agnostic framework dispatcher without lifting `AppState` behind
a context abstraction — a larger refactor with no behavioural change.

## Scope

- **Inbound request/response over TSP**: fully supported — the handler's
  reply is sealed and routed back automatically.
- **HTTPS `POST /api/trust-tasks`**: keeps its own dispatch (it maps
  rejections to HTTP status codes, which the value-returning shared router
  would flatten). DID-management over HTTPS remains available via
  `POST /api/didcomm`.
- **Proactive outbound push over TSP** (control→server sync/domain
  updates): supported. The control `outbox` prefers TSP when the target
  server advertises a `TSPTransport` service (`resolve_transport`),
  serialising the DIDComm `Message` and sending it via `send_tsp`; the
  server's `ServerTspHandler` deserialises it and applies it through the
  same `do_*` cores the DIDComm listener uses. Delivery is fire-and-forget
  (the outbox treats a successful send as delivery), so no ack is routed
  back over TSP. Falls back to DIDComm for servers that advertise only it.
- **Step-up authentication is HTTPS-only, by design.** Step-up
  (`auth/step-up/vta/finish`) elevates a *web session's* assurance level
  (aal1 → aal2) and binds the wallet's proof to that session via the
  session id + the JWT-bound session pubkey. TSP has no session and no
  JWT — every TSP message is independently VID-authenticated — so there is
  nothing to "step up". If a future op that is gated on `aal2` must be
  reachable over TSP, define a TSP-native assurance model at that point
  rather than shoehorning the session-based one onto it.
