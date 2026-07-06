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

## Scope

- **Inbound request/response over TSP**: fully supported — the handler's
  reply is sealed and routed back automatically.
- **Proactive outbound push over TSP** (e.g. control→server sync
  updates): out of scope for now; those still use DIDComm. The framework
  has no outbound Trust-Task sender yet — see the `outbox` module.
- **DID-management `MSG_*` ops over TSP**: these light up automatically as
  they migrate from the legacy `dispatch_did_op` onto the framework
  dispatcher (`dispatch_inbound`). ACL + discovery ops work over TSP
  today.
