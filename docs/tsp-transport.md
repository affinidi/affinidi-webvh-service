# TSP transport

> **Status:** current

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

A node's DID document is the source of truth for how to reach it. Every
setup path mints it through `build_webvh_provision_ask`
(`did-hosting-common/src/server/vta_setup/`), and a node with a mediator
advertises its messaging transports only — **no `WebVHHosting` service**:

```json
"service": [
  { "id": "…#tsp",           "type": "TSPTransport",      "serviceEndpoint": "<mediator-vid>" },
  { "id": "…#vta-didcomm",   "type": "DIDCommMessaging",  … }
]
```

(`[identity].transport` picks `tsp`, `didcomm` or both; a self-managed
daemon can also add `TrustTaskHTTPS`.) Only a node with **no** mediator
advertises `WebVHHosting`, because it has no messaging transport to offer
instead.

`didcomm_profile::resolve_send_binding` reads a peer's document and picks
the binding for an outbound Trust Task in this order: `TSPTransport`, then
`DIDCommMessaging`, then `TrustTaskHTTPS` (the same Trust Task `POST`ed to
the peer's `{endpoint}/trust-tasks`, subject to the peer-endpoint egress
policy). If the document advertises none of them, the node's own configured
mediator is the fallback (TSP or DIDComm only — a document-silent peer is
never guessed to speak HTTPS); if nothing yields a binding the send fails
as unroutable. TSP-capable peers therefore reach each other over TSP.

## Configuration

`features.tsp` (config `[features] tsp = true`, env `<PREFIX>_FEATURES_TSP`)
toggles the TSP *listener*. It **tracks `features.didcomm` by default**:
whenever a mediator is configured, TSP is enabled alongside DIDComm.

This default is deliberate. With `[identity].transport = "both"` (the
default) the node's DID advertises `TSPTransport` alongside
`DIDCommMessaging` (both point at the same mediator), and peers prefer
TSP — so a mediator-connected node must listen on TSP to be reachable
consistently. Turning the *listener* off does not remove a service the DID
document already advertises; change the advertised transports at setup
(`transport = "didcomm"`) rather than only the listener.

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
  listener is turned off for a DID that still advertises `TSPTransport`.

When the control plane's own DID cannot be resolved (or no DID resolver is
configured) the comparison is impossible; the UI reports "unknown" rather
than implying agreement. The `server/config` and `registry/list` Trust Task
replies omit `advertisedServices` entirely in that case — an absent field
means "not known", never "advertises nothing".

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
  nothing thereafter. `register_did_atomic` self-heals anything the sweep deferred.
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

Server registration, health, stats sync, DID sync and domain ops are all
**signed Trust Tasks**, so the binding is chosen from the peer's DID document
rather than hard-coded, and each one is authorised on its own proof, never on
the transport that carried it.

The `MSG_*` constants in `didcomm_types` are canonical Trust-Task Type URIs
(checked against the generated `Payload::TYPE_URI`), with the reply being the
`#response` fragment of the request:

```text
MSG_SERVER_REGISTER       …/spec/did-management/server/register/0.2
MSG_SERVER_REGISTER_ACK   …/spec/did-management/server/register/0.2#response
MSG_HEALTH_PING           …/spec/did-management/server/health/0.1
MSG_HEALTH_PONG           …/spec/did-management/server/health/0.1#response
MSG_STATS_SYNC            …/spec/did-management/server/stats-sync/0.1
MSG_STATS_ACK             …/spec/did-management/server/stats-sync/0.1#response
```

An op therefore has **one identity** on every wire: inside a DIDComm
trust-task envelope, as a raw TSP frame, or in an HTTPS body.
`TrustTask::respond_with` derives the reply URI instead of restating it.

Outbound goes through `trust_tasks::send::send_trust_task`, the one place that
answers "how do I reach this peer" (`resolve_send_binding`, above): TSP when the
peer advertises `TSPTransport` (the document's JSON, sealed), the document
inside a `trust_tasks_didcomm::ENVELOPE_TYPE` DIDComm message for
`DIDCommMessaging`, or an HTTPS `POST` for `TrustTaskHTTPS`, whose reply is
verified synchronously. The function returns the transport that *actually*
carried the document. Every outbound privileged document is signed at send
time (`build_signed_request`), so a retry is never refused as stale or as a
replay. Replies to inbound documents are *returned*, not sent, so the framework
routes them back over the arriving connection: a ping delivered over TSP is
ponged over TSP, with no second resolution.

- **Registration.** An edge always registers with a signed
  `server/register/0.2` document (its own hints ride under `ext`, in the
  `com.affinidi.did-hosting` namespace, because the payload is closed). The
  control plane admits it only when the document is signed by the edge's DID
  and that DID holds the `service` role in its ACL. The bare-message form it
  replaced carried no proof and is no longer routed.
- **Stats sync.** An edge sends its periodic deltas as a signed
  `server/stats-sync/0.1` Trust Task over whatever its control plane's DID
  document advertises. (In the daemon, stats are shared in process; nothing is
  sent.)
- **DID sync and domain ops** (control → edge, and control → watcher) are
  queued in the control plane's transactional outbox and delivered as signed
  Trust Tasks; see [Scope](#scope).

### Seeing which transport a server is actually using

The Servers card shows a **Control link** block with the transport that really
carried the last message in each direction — `↓ in` (registration, health pong,
stats sync)
and `↑ out` (health ping). It is recorded, not inferred.

That distinction matters. `advertisedServices` is what a peer *can* speak;
`lastInboundTransport` / `lastOutboundTransport` are what moved. They disagree
whenever a TSP send falls back to DIDComm, or a server registered over DIDComm
before its document advertised a transport. Badging the advertised value as
though it were the transport in use would quietly mislead the operator, which is
why `send_trust_task` returns the transport that actually carried the document
and the health loop persists *that*.

Inbound is tagged from the caller's `TransportHandler::binding_uri()`, matched
against each binding crate's own exported constant — so an unrecognised binding
records nothing rather than being mis-attributed. Outbound is scoped to the
health ping: it is the only outbound path on a timer, so it is the only one
whose observation stays fresh. The outbox's sync/domain pushes also pick a
transport per DID document, but they fire only on mutations and would leave the
value stale for hours.

A server with `trustTaskCapable: false` is always pinged over DIDComm no matter
what it advertises; the card says so rather than leaving the operator to wonder
why a TSP-advertising node never shows TSP.

### Infrastructure payloads

Both payloads follow the pinned specifications (#449): a stats sync is
`instanceId` + `perMnemonic`, its `seq` and latest-event times under
`ext.vnd.affinidi.webvh`; a health ping names the `instanceId` it probes and the
pong answers `instanceId`, `ok`, `observedAt`, with the edge's version and DID
count under the same namespace. `did_hosting_common::server::trust_tasks::infra`
builds and reads them for both ends. A 0.12 control plane still reads the
pre-0.12 sync and pong; a pre-0.12 control plane refuses the new ones, so
**upgrade the control plane before its servers.**

## Unified dispatch

All three transports — HTTPS `POST /api/trust-tasks`, the DIDComm trust-task
envelope and TSP — open their own binding, establish their own authenticated
sender, and then hand the document to one entry point,
`messaging::dispatch_trust_task_doc` (`did-hosting-control/src/messaging/gate.rs`).
What a document *means* is decided once; the source-level test
`did-hosting-control/tests/one_inbound_router.rs` fails if a transport grows a
router of its own.

That entry point runs the proof gate (each row's `ProofRule`) and routes by
Type URI to:

- the control plane's Trust Task table, `control_tasks!`
  (`did-hosting-control/src/control_tasks/mod.rs`) — DID slots, agent names,
  domains, the registry, identity, stats and the sign-in families;
- the ACL and discovery family (`did_hosting_common::server::trust_tasks`,
  the typed SPEC §7.2 pipeline);
- the infrastructure family (`messaging::infra`) — registration, health,
  stats sync, and the edges' acknowledgements.

HTTPS differs only in how a refusal is reported (an HTTP status as well as the
error document) and in being the one transport where a bearer session can add
context; it is the same dispatch. The full list of tasks, with the proof each
requires, is the [Trust Task catalogue](trust-tasks.md).

## Clearing relationship state

Each node persists its half of every TSP relationship (`tsp_relationships`
keyspace, `server::tsp_relationship_store`), so restarting it — or wiping the
mediator, which holds no relationship state at all — changes nothing. To inspect
or clear it, stop the service and use the offline commands on any of the three
binaries:

```
did-hosting-daemon tsp-relationship-list
did-hosting-daemon tsp-relationship-reset  --peer <did>            # our half -> None; next send re-invites
did-hosting-daemon tsp-relationship-delete --peer <did>            # remove the whole record
did-hosting-daemon tsp-relationship-delete --all [--yes]           # every record, half-formed ones too
```

A clean first contact needs both halves gone: the peer has its own equivalent
(`vta tsp-relationships …` on a VTA). Clearing only one side is also a valid
test — the peer's next send is dropped by this node's §7.2.2 gate (logged
`Failed to unpack TSP frame … no relationship`) until the peer's reply-timeout
recovery re-invites.

## Scope

- **Inbound request/response over TSP**: fully supported — the handler's
  reply is sealed and routed back automatically.
- **HTTPS `POST /api/trust-tasks`**: the same dispatch as TSP and DIDComm
  (see [Unified dispatch](#unified-dispatch)); every management operation is
  reachable over all three.
- **Proactive outbound push** (control → edge and control → watcher sync and
  domain ops): supported over every binding. The control plane's outbox
  (`did-hosting-control/src/outbox.rs`) stages each push in the same store
  batch as the mutation, sends it as a freshly signed Trust Task over the
  binding the target's DID document selects, and removes the row only when
  the **target itself** acknowledges it with a signed `#response`. A
  mediator accepting the frame is not delivery. Hard failures retry with
  exponential backoff (2 s doubling to 5 min, up to 50 attempts); a send the
  transport accepted but nobody acknowledged is re-sent on a wait that
  doubles from 1 min to 1 h (up to 24 sends). A row older than 7 days is
  dropped, and the edge's next registration resyncs whatever it missed.
  Recipients are idempotent, and each target's rows are delivered in order.
- **Step-up authentication is a session concept.** `auth/step-up/start` and
  the approver's `auth/step-up/approve-response` raise a *browser session's*
  assurance level (aal1 → aal2). A document sent over TSP or DIDComm carries
  no session — it is authorised by its own proof — so there is nothing to
  step up, and the destructive tasks that require an aal2 session over HTTPS
  are not gated that way when a signer's own key sends them. If an op ever
  needs a second factor over messaging, define a messaging-native assurance
  model then rather than shoehorning the session one onto it.
