# Glossary

> **Status:** current

Terms used across the code, the docs and the console. Where one thing has
several names, the first is the preferred one and the others are listed so
you can recognise them.

**aal2 / step-up** — A console session's assurance level. Destructive tasks
(deleting a DID, retiring an identity, purging a domain) need an `aal2`
session; a wallet session is *stepped up* with `auth/step-up/*`, and a
passkey login is `aal2` from the start. A request with no session (a VTA
signing its own Trust Tasks) is authorised by its proof alone.

**ACL** — The control plane's (and a witness's) access-control list: DIDs
and their **role** — `admin`, `owner`, `service` or `metricsReader`. An edge
and a watcher have no ACL.

**Agent name** — A human-readable name (`/@alice`) bound to a hosted DID.
The DID's signed document must claim it in `alsoKnownAs`; the control
plane's registry decides who holds it. A *parked* name is reserved but not
served. The **community name** is the empty name (`/@`), bound to a domain's
root DID.

**Control plane** (`did-hosting-control`) — The authoritative store and
publishing endpoint for every hosted DID, the console, and the source that
pushes changes to edges. The only source of record. Never advertised in the
DIDs it manages. See [architecture.md](architecture.md).

**`control_did`** — The edge's config key naming the one control plane
whose signed Trust Tasks it applies.

**Daemon** (`did-hosting-daemon`) — The single-binary deployment: control
plane, edge, witness and optionally watcher in one process. The console
calls its backend "the daemon" even when it is a standalone control plane.

**Domain** (hosting domain) — A host name DIDs are hosted under. The control
plane manages domains, marks one the **default**, and **assigns** domains
to edges. Unassigning or disabling a domain schedules its data for removal
after a grace period; the **purge sweep** that removes it runs on edges and
in the daemon.

**Edge** (hosting server, server, `did-hosting-server`) — A node that serves
public DID resolution from logs its control plane syncs to it. Lossy and
ephemeral: a cache that can be wiped and rebuilt from the control plane.
"Server" in code and config usually means the edge; in `server_did` and
`[server]` it means "this node" (below).

**Enrol / enroll** — British spelling (*enrolment*, `control_tasks/enrol.rs`)
in prose and code; the wire Trust Tasks and the config key keep the American
form (`auth/passkey/enroll/*`, `passkey_enrollment_ttl`). They are the same
thing: registering a passkey.

**Generation** — One version of a node's own identity (its keys and DID
document). Rotation creates a new generation; the superseded one stays
usable for `identity.rotation_grace_period`, then is **retired**. See
[identity-rotation-design.md](identity-rotation-design.md).

**High-water mark** — The furthest log entry an edge, watcher or witness
has accepted for a DID. A sync or restore must strictly extend it, so a
replayed or forked history is refused.

**Mediator** — The DIDComm/TSP relay every messaging-capable node connects
to (`mediator_did`). Nodes talk to each other through it.

**Outbox** — The control plane's durable queue of changes for each edge and
watcher. Each entry is retried until its target acknowledges it.

**Owner** — The party a hosted DID belongs to: the DID that registered it
(normally a VTA, never the hosting platform). It holds the DID's update
key and publishes signed logs into the control plane. Also the ACL role
such a party holds.

**Publish / register** — `did/register` creates a slot and stores a DID's
first signed log; later versions are published to the same slot. The
control plane verifies each log before storing it.

**Reconcile** — An edge's periodic check of its store against the control
plane's `did/list`, repairing missed disables and re-registering to fetch
anything else it is missing.

**Replay cache** — Each service's record of the signed documents it has
accepted (`(issuer, id)`), so a captured request cannot be sent again.

**`server_did`** — The config key for **this node's own DID**, whatever the
node is: on the control plane, witness and watcher it is that service's
DID, not an edge's.

**Slot** (mnemonic, path) — The place a DID lives on a domain: the URL path
its log is served from (`https://example.com/{slot}/did.jsonl`), or
`.well-known` for a domain's root DID. Code says `mnemonic` (store keys,
record fields), the CLI accepts both `--path` and `--mnemonic` (each
subcommand takes one and the other as an alias), and the console says
"path". All three are the same thing.

**Trust Task** — A signed, versioned JSON document describing one operation
(`did-management/did/register/0.1`, `acl/grant/0.2`, …), carried unchanged
over TSP, DIDComm or HTTPS (`POST /api/trust-tasks`). Every management
operation is one; it is authorised on its own proof, never on the transport.
Catalogue: [trust-tasks.md](trust-tasks.md).

**TSP / DIDComm** — The two mediator-routed messaging transports. TSP (the
ToIP Trust Spanning Protocol) is preferred when a peer advertises both. See
[tsp-transport.md](tsp-transport.md).

**VTA** (Verifiable Trust Agent) — An external key manager. It provisions a
node's own keys at setup (unless the daemon is self-managed) and, as an
owner, publishes the DIDs it controls into the control plane.

**Watcher** (`webvh-watcher`) — A read-only mirror that control planes push
DID logs to, for redundancy and geographic distribution.

**Witness** (`webvh-witness`) — A service that signs `did:webvh` witness
proofs for log entries, refusing to witness two histories of one DID.

**`did:scid` alias** — The `did:scid:vh:1:<scid>` form of a `did:webvh`,
listed in `alsoKnownAs` (`hosting.scid_also_known_as`).
