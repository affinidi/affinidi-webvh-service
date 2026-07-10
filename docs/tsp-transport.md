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
  Legacy records are swept by the `M-02` migration on server/daemon boot,
  and self-heal on their next publish on standalone control.
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
