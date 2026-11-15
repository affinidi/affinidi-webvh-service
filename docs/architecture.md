# Architecture and trust model

> **Status:** current — the binding rules for contributors are in [CLAUDE.md](../CLAUDE.md); this page explains them for operators and reviewers.

## The pieces

```
           publishes signed did.jsonl                 resolves DIDs (HTTPS GET)
  VTA / owner ─────────────────────────┐        ┌──────────────── anyone
                                       ▼        ▼
                            ┌──────────────────┐   outbox: signed sync,     ┌───────────────────┐
  operator's browser ──────►│  control plane   │── domain and purge ops ──► │ edge (hosting     │
  (console, passkeys,       │ did-hosting-     │   (TSP · DIDComm · HTTPS)  │ server), 1..n     │
   wallet sign-in)          │ control          │◄── register, acks, stats ──│ did-hosting-server│
                            │ authoritative    │                            └───────────────────┘
                            │ store            │── signed webvh/sync/* ───► webvh-watcher (mirror)
                            └──────────────────┘
                                     │ witness requests
                                     ▼
                              webvh-witness (signs witness proofs)
```

- **Control plane** (`did-hosting-control`): the one source of record. It
  stores each DID's record and signed log, the agent-name registry, owner and
  domain assignments, the ACL, and the console. Every write lands here
  first.
- **Edges** (`did-hosting-server`): serve public resolution. Each derives
  what it serves from the logs the control plane sends it, verifies every
  one, and can be wiped and rebuilt from the control plane at any time.
- **Witness** (`webvh-witness`): signs `did:webvh` witness proofs, refusing
  to witness two histories of one DID.
- **Watcher** (`webvh-watcher`): a read-only mirror. Control planes push it
  logs through the same outbox as edges, over whichever transport the
  watcher's DID advertises (TSP, DIDComm or HTTPS).
- **Daemon** (`did-hosting-daemon`): all of the above in one process, on one
  store, coordinating in-process instead of over the network. Recommended
  for a single host.

## Source of record: the control plane is authoritative, edges are caches

The control plane owns all authoritative state. Everything else is
downstream of it:

- **The owner** (normally a VTA) holds a DID's update key and produces its
  signed logs, but it publishes them *into* the control plane, which decides
  what is stored and served. The owner is a source of documents, not of
  record.
- **Edges are lossy.** An edge keeps nothing that a control-plane sync
  cannot rebuild, and its view is never treated as authoritative. When an
  edge misses a change (it was down, an outbox entry was dropped), its
  periodic **reconcile** against the control plane repairs it; past
  `[replication] staleness_bound_secs` without a clean reconcile, its
  health probe fails so a load balancer drains it.

Because nothing can lean on an edge to hold or repair state, every
control-plane write keeps the authoritative state correct by itself. For
example, publishing a DID **reconciles** the agent-name registry against the
signed document: a name the document claims (in `alsoKnownAs`) is
registered, a name it drops is released, and a *parked* name is kept. But
reconciling is not trusting: a name the document claims is still refused if
it is reserved or held by another DID. **A name only ever changes owner
through an explicit `remove` by its current holder**, or the deletion of the
DID that holds it.

## Three roles

| Role | Who | What it does |
| --- | --- | --- |
| **Owner** | A VTA or another external system, never the hosting platform | Holds the DID's keys; authenticates to the control plane and publishes signed logs. The record stores `owner` = the DID that registered it. |
| **Control plane** | `did-hosting-control` (or the daemon) | The registry and the publishing endpoint. Custodian of the DID, not its owner. |
| **Edges** | `did-hosting-server`s | Caches the control plane publishes into. |

### The control plane is never advertised

A hosted DID's document does not name its control plane, and nothing else
makes the control plane discoverable from the DID. Publishing that link in
every managed document would give anyone an enumerable map of the most
sensitive endpoint in the system, for no real benefit: an owner knows its
control plane because it registered with it, and recovering that knowledge
after a loss is operator state (backups, runbooks), not identity data. The
unauthenticated `server/info` task is served by the control plane, not by
edges, so the topology does not leak through an edge either. Keep the
control plane on a hostname of its own and restrict who can reach it where
you can (see [deployment.md](deployment.md#what-to-expose-per-binary)).

## Every privileged message is authorised on its proof

Every message that changes state or discloses more than public data —
control plane to edge and back, DID management, ACL, sign-in — is a
**Trust Task**: a JSON document carrying its own Data Integrity proof. A
service accepts it only when:

- its `issuer` is stated in the document and is exactly the expected peer,
  and the proof's `verificationMethod` belongs to that issuer;
- its `recipient` is this service;
- it is fresh (`issuedAt`) and not a replay of an `(issuer, id)` already
  seen;
- the proof purpose is `authentication`, by a key under the issuer's
  `authentication` relationship. `assertionMethod` is reserved for a human
  approver's decision (consent, step-up), and is checked as such.

The transport is never the authority. A DIDComm `from`, a TSP sender, an
HTTPS bearer session are routing hints that must *agree* with the proof;
nothing is authorised, ACL-checked or replay-keyed on them. So the same
document is accepted identically over TSP, DIDComm and
`POST /api/trust-tasks`, and every successful reply is itself signed by the
service. An edge never answers a document from anyone but its configured
`control_did` — not even with a refusal.

Each control-plane task has a **proof rule** in one table (`control_tasks!`):
most are `Authentication`; a few public reads and sign-in steps are
`Optional`; an approver's decision is `AssertionMethod`; a passkey login is
signed by its session key; wallet sign-in (`auth/oob/*`) uses keys the
exchange itself binds. The generated catalogue is
[trust-tasks.md](trust-tasks.md).

Signers outside the ACL (anyone can mint a `did:key`) are kept away from
what ACL members depend on: they never fill the shared replay cache, and
their proofs are checked under strict resolution and rate bounds.

## How nodes reach each other: the DID document is authoritative

Every node (control plane, edge, witness, watcher, daemon) has its own
`did:webvh` and advertises in it how to reach it:

- A node with a mediator advertises its **messaging** transports —
  `TSPTransport` and/or `DIDCommMessaging` — and not an HTTP hosting
  endpoint. Its resolution URL follows from the DID itself.
- A node with no mediator (HTTP-only) advertises a `WebVHHosting` entry
  instead, having no messaging transport to advertise.
- A node may also advertise a `TrustTaskHTTPS` endpoint, the base its Trust
  Tasks can be `POST`ed to (a control plane or daemon does, so wallets can
  reach its sign-in tasks over HTTPS).

To send a Trust Task to a peer, a node reads the peer's DID document and
picks, in order: **TSP**, then **DIDComm**, then **`TrustTaskHTTPS`** (the
same Trust Task `POST`ed to the peer's `{endpoint}/trust-tasks`, with the
reply verified on the spot). If the document advertises none, the node's own
configured mediator is used for TSP/DIDComm (a bridge for DIDs minted before
transports were published) — never a guessed HTTPS endpoint. If nothing
yields a route, the send fails. A peer-advertised HTTPS endpoint must be
`https` to a public host; private and loopback addresses are treated as
not advertised.

Nothing depends on a `WebVHHosting` entry being present: it is informational.

## How a change flows

1. An owner signs `did/register` (or a later publish) and sends it to the
   control plane over any transport.
2. The control plane verifies the proof and the ACL, verifies the log
   (chain, witness proofs, the slot and domain it names), stores it, and
   reconciles agent names — all under a per-DID lock.
3. In the same transaction it queues an outbox entry for each edge assigned
   that domain and each watcher the log names.
4. The outbox delivers each entry as a signed `webvh/sync/*` Trust Task and
   retries, with backoff, until the target acknowledges it.
5. The edge verifies the document came from its `control_did`, checks that
   the log strictly extends what it holds (its high-water mark), stores it,
   and serves it.

## Identity rotation

Each node can rotate its own keys. A rotation creates a new **generation**;
the old one stays usable for `[identity] rotation_grace_period` so peers
with cached documents still reach it, then it is retired. In the daemon, the
control plane owns rotation for the whole process. See
[identity-rotation-design.md](identity-rotation-design.md) and
[identity-rotation-runbook.md](identity-rotation-runbook.md).

## Further reading

- [glossary.md](glossary.md) — terms.
- [configuration.md](configuration.md), [deployment.md](deployment.md).
- [tsp-transport.md](tsp-transport.md) — the TSP binding.
- [did-webs-hosting.md](did-webs-hosting.md) — how `did:webs` differs.
