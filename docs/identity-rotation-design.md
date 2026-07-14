# Service identity rotation — design

## Status

**Built:** phases 1 and 2, wired into **all four binaries** — the generation
model, `KS_IDENTITY`, `load_identity` (replacing `init_didcomm_auth` and fixing
the kid bug), the `AppState` lift of `DIDCommService` in server and witness, the
daemon consolidation, retirement, the rotation trigger, the expiry sweep, and the
immediate-retire kill switch.

Triggers differ by what each service can observe:

| Service | Publish hook | Sync-update hook | Periodic sweep |
|---|---|---|---|
| control | ✅ `did_ops::publish_did` | — | ✅ |
| server | ✅ `did_ops::publish_did` | ✅ `MSG_SYNC_UPDATE` | ✅ |
| witness | — (hosts no DIDs) | — | ✅ **only trigger** |
| daemon | ✅ via control | — | ✅ in the unified storage task |

The witness has no `dids` keyspace and no publish path — its own DID is published
in another process — so the sweep is not a backstop there but its *only* way to
notice a rotation. A rotation therefore reaches the witness within one sweep
interval (60s) rather than immediately. In daemon mode the embedded server's and
witness's rotation paths are **inert by construction**: neither starts a DIDComm
listener, so their `didcomm_service` slot is never filled and `rebuild_listener`
no-ops. The daemon's control plane owns the identity. Nothing is conditionally
skipped — the no-op falls out of the daemon's existing shape.

### Two sweep cadences, not one

Expiry and re-resolution run on **different timers**, because they cost different
things. Expiry is local — it compares timestamps against the live set and reads
the store — so it runs every **60s** and retires a superseded key promptly.
Re-resolving the DID document is a network fetch, and on control and server it is
only a *backstop* (their publish hooks catch a rotation the instant it happens),
so running it at the expiry cadence would mean ~1,400 pointless self-resolves a
day per service. It runs every **5 minutes** instead — far inside any sane grace
period, and still the witness's only trigger.

### The kill switch has two paths, and only one of them is real

The CLI opens the store directly and the embedded store takes an exclusive lock,
so it cannot run against a live service. That is not just an inconvenience to
route around: **even if the lock allowed it, deleting a record on disk would not
reach into a running process's secrets resolver** — which is where a compromised
key actually still lives. A CLI that wrote to disk while the service kept
decrypting from memory would be a kill switch that looks like it fired and
didn't.

So:

- **Live service** → `POST /api/identity/generations/{id}/retire`, or the
  **Key Generations** panel in the control-plane UI. Runs in-process: the key is
  gone from the secrets resolver and the listener profile before the response is
  written. This is the path that matters for a compromise.
- **Stopped service** → `identity-retire-now --generation <id>` (control, server,
  daemon). Removes the record and the key material from disk so the generation is
  never loaded again.

Both refuse to retire the **current** generation — that would drop the key the
service is actively using and leave it unable to decrypt anything at all.
Publish a new DID document first; that supersedes it, and then it can be retired.

As a backstop for shared-store deployments, the expiry sweep also **reconciles
the in-memory live set against the store**: a generation whose record has been
deleted out of band is dropped from the running process within one sweep
interval, rather than being honoured forever.

### The old-mediator drain is a second listener, NOT an HTTP poll

Planned as a websocket-free `ATM` polling `fetch_messages` over REST. That was
wrong, and the reason is worth recording so nobody re-litigates it.

The HTTP poll can fetch (`send_message` falls back to REST when no websocket is
attached; `profile_add(&p, false)` keeps it that way). It can unpack
(`ATM::unpack` is public). It can even *dispatch*, because `Router` implements
the public `DIDCommHandler` trait and `HandlerContext` has public fields.

**What it cannot do is reply.** A handler returns a `DIDCommResponse`, and
`DIDCommResponse::into_message` — along with every one of its fields — is
`pub(crate)` in `affinidi-messaging-didcomm-service` 0.3.17. There is no public
way to turn one into a sendable `Message`. A drain that received requests and
silently dropped every response would quietly break `MSG_DID_REQUEST`,
`MSG_AUTHENTICATE` and every other request/response protocol — worse than not
draining, because it would look like it was working.

So the drain is a **second `DIDCommService`** bound to the old mediator: the real
listener, the real router, the real response path. It is safe because the
duplicate-DID guard is *per-service-instance* (a stack-local map inside
`start_inner`) and the mediator's own eviction is keyed by DID hash *within one
mediator* — so the same DID on two **different** mediators conflicts at neither
end. Auth tokens are cached under a composite `(profile_did, mediator_did)` key.
The cost is a second TDK stack for the length of the grace window.

Two things hold it together:

- **Order: rebuild, then drain.** The main listener is re-pointed at the new
  mediator *before* the drain attaches to the old one. Otherwise the live
  listener's websocket and its periodic offline sync would race the drain for the
  same queue — and two connections for one DID on one mediator is exactly what
  that mediator evicts.
- **A drain lives exactly as long as its generation.** It polls the live set and
  stops when its generation leaves it, so expiry and the operator kill switch both
  end it with no extra channel to keep in sync. On boot, any live retired
  generation on a different mediator gets its drain restarted — a restart
  mid-window must not abandon the queue, which is the whole reason the generation
  is persisted.

A same-mediator key rotation needs none of this and pays nothing: `needs_drain`
short-circuits, because the old key is already in the main listener's profile.

The one failure an operator must fix by hand: if the DID has been deregistered
from the old mediator, it refuses the connection and the queued messages are
unrecoverable. That is logged plainly rather than retried silently.

### Establishing generation 0 is not a rotation

A service that hosts its own DID **cannot resolve it at boot** — it is the thing
that serves it. So `load_identity` comes up on guessed `#key-0` / `#key-1` kids
and deliberately persists nothing; the first successful resolve, once HTTP is
serving, records generation 0 with the document's real kids
(`ReloadOutcome::Established`).

That distinction is load-bearing. Treating the first resolve as a *rotation*
would retire a generation that never existed — and because our own bootstrap
happens to use `#key-0`/`#key-1`, the guess coincidentally matches and the bug
stays invisible until it meets a DID whose document uses different fragments
(e.g. a VTA-provisioned DID with multibase kids). Then it would fire on the first
boot of a service that has never rotated anything.

The store, not memory, decides which case this is: **no persisted record →
establish; a persisted record that differs → rotate.** Each binary triggers the
resolve the moment its HTTP listener is ready (`rest_ready_rx` /
`http_ready_rx`), *before* the DIDComm listener starts — otherwise the listener's
profile would be built on the guess.

Found by running a daemon, not by any test.

### Known blocker: a root DID at the `.well-known` slot is not resolvable

**Pre-existing, not introduced here, and it prevents rotation entirely on
affected deployments.**

Setup mints a root DID as `did:webvh:<SCID>:<host>:.well-known` — with
`.well-known` *inside* the DID string. Per the did:webvh spec a root DID maps to
`/.well-known/did.jsonl` implicitly, so a conforming resolver strips the suffix
on the round-trip and then rejects the document because its `id` no longer
matches:

```
DID being resolved (did:webvh:Qm…:localhost%3A8534)
does not match the top-level 'id' in any DIDDoc version
```

The document is served correctly (HTTP 200) — it is the *identifier* that does
not round-trip. Hosting the DID at a path instead (`…:<host>:daemon`) resolves
cleanly.

Consequence for this feature: a service whose own DID sits at the `.well-known`
slot can never resolve it, so generation 0 is never established and rotation
cannot function. Left untouched here because commit #72 ("allow registering the
root DID at the .well-known slot") deliberately shaped this area — it needs an
owner's call, not a drive-by fix.

## Verified by running it

Exercised end-to-end against a live daemon (self-managed mode, plaintext secrets,
no mediator):

- identity load, the boot fallback, and `Established` recording generation 0 from
  the real document once HTTP is serving;
- persistence to `KS_IDENTITY`;
- the offline `identity-list` CLI;
- **a restart that loads the stored generation with zero fallback warnings** —
  the durability requirement that motivated the whole design.

Both of the bugs above were found this way, and by nothing else.

**Not verified, and needing a real mediator:** a key rotation end-to-end (no CLI
produces a signed v2 webvh log entry today), the listener rebuild, two-mediator
coexistence, and the drain. Those remain covered by construction and unit tests
only.

### Two decisions that changed during implementation

**Retired key material lives on `ServerSecrets`, not behind new trait methods.**
The plan said to follow the `bootstrap_seed` precedent — separate trait methods,
separate keyring entry. Tracing the actual sequence shows that is wrong.
Keys-then-rotate means the CLI overwrites `ServerSecrets.key_agreement_key` with
the *new* key **before** the DID is published; by the time the publish hook fires
and wants to retire the outgoing generation, the old private key is already gone
from the store. The old key must therefore move into the retired set *in the same
write* that installs the new one — and the secret store has no compare-and-swap,
so two separate writes leave a crash window that loses the old private key
permanently, which is precisely the failure the retirement window exists to
prevent. The right precedent is `vta_credential`: an optional field with
`#[serde(default)]`, which every backend already serialises atomically as one
blob. `bootstrap_seed` was separated because its lifecycle is *independent*;
retired keys' lifecycle is *coupled* to the current keys.

**The interior mutability is inside `ServiceIdentity`, not `AppState`.**
`ThreadedSecretsResolver` exposes `insert` and `remove_secret` on `&self`, and
`DIDCacheClient` is internally `Arc`'d and identical across generations — so a
rotation only needs to replace the *live set*, not the resolvers. A single
`RwLock` around that set lets all four `AppState`s keep a plain
`Option<Arc<ServiceIdentity>>`: no `ArcSwap`, no lock in four state structs, and
no window where a handler sees a half-swapped identity.

## Problem

When the service's own DID (`config.server_did`) is updated — new keys, removed
keys, added or removed services — nothing in the running process notices. A
restart is the only way to pick up the change, and even then the overlap
problem below is unhandled.

Worse, a restart is not sufficient on its own: peers cache DID documents. A peer
that resolved our DID five minutes ago keeps encrypting to the *old*
key-agreement key until its cache expires. Cut over instantly and those messages
are undecryptable. The same applies at the mediator layer: change the mediator
endpoint in the DID document and peers holding a stale doc keep delivering to the
*old* mediator, where the messages queue up and are never collected.

So the requirement is not "reload the DID" — it is "run the old and new identity
concurrently for a grace window, then retire the old one", and to have that
survive a process restart.

## What is frozen at boot today

Three things, in all four binaries:

- **The secrets resolver.** `init_didcomm_auth`
  (`did-hosting-common/src/server/init.rs:48-91`) inserts the signing and
  key-agreement secrets under **hardcoded** kids `{server_did}#key-0` and
  `#key-1`, once, from `ServerSecrets`.
- **The `TDKProfile` inside the listener.** `build_tdk_profile`
  (`did-hosting-common/src/server/didcomm_profile.rs:394-439`) separately
  resolves the *real* verification-method IDs from the DID document
  (`resolve_server_key_ids`, `:31-89`) and bakes them, plus the mediator DID,
  into a profile handed to `DIDCommService`.
- **`config: Arc<AppConfig>`** — `server_did`, `mediator_did` are immutable
  fields.

Nothing re-resolves our own DID after startup. `DIDCacheClient::remove()` exists
(`affinidi-did-resolver-cache-sdk/src/lib.rs:583`) and is called nowhere in the
repo.

### Latent bug to fix on the way through

`init_didcomm_auth` keys the secrets resolver on `#key-0`/`#key-1` while
`build_tdk_profile` keys the listener's profile on the *resolved* VM ids. Those
agree only as long as the DID document happens to use `#key-0`/`#key-1`. Any DID
whose VM ids differ already has a secrets resolver keyed on the wrong kids — the
REST DIDComm auth path (`unpack_signed`) and the listener disagree **today**,
before any rotation. The generation model below fixes this by construction:
there is one source of truth for kids, and it is the resolved document.

## What the TDK actually permits

These findings drive the whole design; they were verified against the pinned
versions (`affinidi-tdk-common 0.6.5`, `affinidi-messaging-didcomm-service
0.3.17`, `affinidi-messaging-sdk 0.18.50`, `affinidi-messaging-mediator
0.16.45`).

1. **Inbound decryption is kid-driven, not document-driven.** `unpack` scans the
   JWE `recipients[].header.kid` and looks each up in the secrets resolver
   (`sdk/src/messages/unpack.rs:117-144`). Our own DID document is never
   consulted for the recipient key. **A message encrypted to an old kid decrypts
   fine as long as the old secret is still in the profile — regardless of what
   the document now advertises.** We do not need to keep the old VM published.

2. **`TDKProfile` holds any number of secrets.** `TDKProfile::new` is a pure
   field-move with no arity or kid-suffix assumption
   (`tdk-common/src/profiles.rs:47-54`); the resolver is a map keyed by kid.
   Four secrets with four distinct kids is fine. Duplicate kids overwrite.

3. **Outbound does not sign.** `pack_encrypted`'s `sign_by` is accepted and
   ignored (`sdk/src/messages/pack.rs:20-28`). Ed25519 signing secrets are inert
   for DIDComm. The only sender key is the *key-agreement* key, chosen from our
   **freshly-resolved document** intersected with the secrets we hold
   (`pack.rs:83-121`). **Outbound therefore self-heals the moment the document
   changes** — no restart, no action. The only lag is the DID resolver cache TTL
   (300s), which we eliminate by calling `remove()` on publish.

4. **Mediator auth is DID-scoped and authcrypt-based**, not a JWS signature
   (`affinidi-did-authentication/src/lib.rs:342-446`). Tokens are cached under a
   composite `(profile_did, mediator_did)` hash
   (`tdk-common/src/tasks/authentication.rs:609-616`). The socket survives a
   document change; the existing JWT stays valid until expiry.

5. **One listener per DID, per `DIDCommService`.** `DIDCommServiceConfig`
   validation rejects two listeners with the same `profile.did`
   (`didcomm-service/src/service/mod.rs:145-161`), keyed on the DID alone,
   ignoring the mediator. The mediator itself also evicts a duplicate socket for
   the same DID (`mediator/src/tasks/websocket_streaming.rs:368-411`) — but that
   registry is *per-mediator*, so two different mediators do not conflict with
   each other.

6. **Individual listeners can be hot-swapped.** `remove_listener` /
   `add_listener` (`service/mod.rs:174-206`) take `&self`, cancel only that
   listener's child token, and leave the rest of the service running. So
   `AppState.didcomm_service: Arc<OnceLock<DIDCommService>>` **does not need to
   change** — we swap listeners inside the service, we never replace the service.

7. **A mediator queue can be drained over plain HTTP.** `ATM::send_message` falls
   back to REST when `ws_channel_tx` is `None`
   (`sdk/src/transports/mod.rs:79-121`), and `profile_add(&p, false)` keeps it
   `None` (`sdk/src/profiles.rs:379-395`). `ATM::fetch_messages` with
   `FetchDeletePolicy::OnReceive` (`sdk/src/messages/fetch.rs:39`) is a
   drain-and-delete loop against `POST /fetch`. `DIDCommService` cannot do this —
   `listener.rs:147` hardcodes `profile_add(.., true)` — so the drain uses the
   raw SDK `ATM`.

8. **`protocols.didcomm` is never read** upstream; only `protocols.tsp` is
   (`listener.rs:258-261`). `TSP_ONLY` is really "TSP, plus DIDComm if it shows
   up". We set the union explicitly anyway rather than depend on this.

9. **Reconnects rebuild the secrets resolver from `config.profile.secrets()`.**
   `ListenerConfig.tdk_config` is consumed via `.take()` on first connect
   (`listener.rs:124-133`), so on every `RestartPolicy::Always` reconnect the
   resolver is re-seeded from the profile's `Vec<Secret>`. **The profile's
   secrets vector is the only durable source of truth** — injecting a secret into
   a shared resolver would silently vanish on the next reconnect.

The consequence of (1)+(2)+(3) is that the "keep the old identity alive"
requirement collapses, for the same-mediator case, to: **leave the old
key-agreement secret in the profile.** There is no second service and no drain.
Only a *mediator change* needs real machinery, and (7) provides it.

## Design

### Generation model

A **generation** is one version of the service identity:

```rust
struct IdentityGeneration {
    id: u64,                        // monotonic
    did: String,
    signing_kid: String,            // resolved from the doc; inert for DIDComm,
                                    // still used for webvh log signing
    ka_kid: String,                 // the load-bearing one
    mediator_did: Option<String>,
    protocols: ProtocolSet,         // { didcomm: bool, tsp: bool }
    created_at: u64,
    retired_at: Option<u64>,
    expires_at: Option<u64>,        // retired_at + rotation_grace_period
}
```

The **live set** is the current generation plus every retired generation whose
`expires_at > now`.

### Runtime topology

One `DIDCommService`. One listener, on the **current** generation's mediator,
with:

- `profile.secrets` = the key-agreement secret of **every live generation**
  (plus their signing secrets, which are harmless and keep the webvh path
  coherent). This is what makes old-kid inbound decrypt.
- `protocols` = the **union** over the live set.

Plus, for each live retired generation whose `mediator_did` differs from the
current one, a **drain task**: a raw `ATM` with `profile_add(&p, false)`, looping
`fetch_messages(limit=100, FetchDeletePolicy::OnReceive)` against the *old*
mediator until it returns empty, then backing off and repeating until the
generation expires. Drained messages are fed into the same transport-agnostic
`dispatch_inbound` core the listener uses.

Your TSP-only-restart case falls straight out: current generation is `TSP_ONLY`,
the retiring one is `DIDCOMM_ONLY`, the union sets `tsp: true` and DIDComm still
dispatches, and at expiry the listener is rebuilt TSP-only.

### Persistence

Split by sensitivity — this is the key decision.

- **Metadata → a new `KS_IDENTITY` keyspace.** `identity:current` → the current
  id; `identity:gen:{id}` → the record above. Adding a keyspace is two lines in
  `store/keyspaces.rs` and needs no migration (keyspaces are created lazily;
  migrations exist only to reshape *existing* data).
- **Private keys → the secret store.** Retired generations' keys must survive a
  restart, but after a rotation `ServerSecrets` holds only the new ones. They do
  **not** go in `KS_IDENTITY`: that is fjall/redis/DynamoDB, so it would write
  private keys in plaintext to the DID store and abandon the keyring/KMS
  protection the current keys enjoy.

  Follow the `bootstrap_seed` precedent exactly — when a second, differently-scoped
  secret was needed, it got its own trait methods, a separate keyring entry
  (`keyring.rs:14`), and a sibling field in the cloud envelope (`StoredSecrets`,
  `mod.rs:103`) so one IAM grant covers both:

  ```rust
  fn get_retired_keys(&self) -> BoxFuture<'_, Result<Vec<RetiredKeys>, AppError>>;
  fn set_retired_keys(&self, keys: &[RetiredKeys]) -> BoxFuture<'_, Result<(), AppError>>;
  ```

  `SecretStore::set()` already works at runtime on all seven backends
  (`secret_store/mod.rs:188`), so this is additive.

  **Caveat:** the secret store has no CAS and `set()` is a whole-blob overwrite.
  All identity mutations must be serialized behind one in-process mutex, and two
  processes sharing a secret store can clobber each other. Document it.

### Boot

Replaces `init_didcomm_auth` with `load_identity()`:

1. Read `identity:current` + all generation records; drop any past `expires_at`.
2. Pull each live generation's keys — current from `ServerSecrets`, retired via
   `get_retired_keys()`.
3. Seed the secrets resolver under the **resolved** kids from the generation
   records (this is what fixes the `#key-0`/`#key-1` bug).
4. Build one profile with the union of secrets and protocols; start the listener.
5. Spawn a drain task per live retired generation on a different mediator.

Boot cannot read `mediator_did` from config alone — config only knows the *new*
mediator. The live set comes from the store.

**Bootstrap:** if `KS_IDENTITY` is empty (existing deployments), synthesise
generation 0 by resolving the current `server_did`, exactly as
`build_tdk_profile` does today. No migration needed.

### Trigger

`reload_service_identity(state)` in `did-hosting-common`:

1. `did_resolver.remove(our_did)` — invalidate, don't wait out the 300s TTL.
2. Re-resolve; extract `(ka_kid, signing_kid, mediator_did, protocols)`.
3. Diff against the current generation. **Unchanged → no-op** (idempotent; this
   is what makes publish bursts safe).
4. Changed → **check we hold a secret for the new `ka_kid`.** If not, *do not
   promote*: keep the current generation, log at error, fail the health check.
   Never half-rotate. (This is the "someone else published a log entry for our
   DID" case — we cannot invent the private key.)
5. Retire the current generation: `retired_at = now`, `expires_at = now + grace`;
   move its keys into `set_retired_keys()`.
6. Install the new generation; rebuild the profile; `remove_listener` +
   `add_listener`.
7. If the mediator changed, spawn a drain task for the retired generation.

Called from:

- `publish_did` (`did-hosting-control/src/did_ops.rs:513`) and the server's
  `publish_did` / `apply_single_update`, gated on `mnemonic == our_mnemonic`
  (`mnemonic_from_did` already exists at `did-hosting-server/src/server.rs:679`;
  no publish path checks this today).
- A **periodic backstop** in the storage task, to catch out-of-band updates.

Debounced behind the identity mutex; concurrent calls coalesce.

### Retirement and the kill switch

New module `identity_sweep.rs`, mirroring `purge_sweep.rs` exactly — a
`run_sweep_once(&Store, ..) -> u64` (directly unit-testable, called from the
daemon's `select!` arm) plus a `run_identity_sweep_loop(..)` wrapper that control
and server `tokio::spawn`. `DEFAULT_SWEEP_INTERVAL: Duration = 60s`.

On expiry: stop the generation's drain task, purge its keys from the secret
store, drop the record, rebuild the profile and hot-swap the listener.

**Expiry is a deadline for the drain, not a severing of it.** A drain task that
has emptied the old mediator's queue exits early; one that hasn't is cut off at
the deadline and the residue is logged.

**Immediate kill** (`identity-retire-now --generation <id>`) runs the same path
early. Semantics to state plainly in the CLI help: old-kid inbound stops
decrypting immediately, and any messages still queued at the old mediator are
abandoned. That is the correct behaviour for **key compromise**, which is the
main reason the lever exists.

### Config

```toml
[identity]
rotation_grace_period = "1h"   # "0" = retire immediately
```

A duration **string**, matching the `unassigned_purge_grace` /
`disable_purge_grace` house style, parsed by the existing `parse_grace_string()`
(`pending_purge.rs:167`). The sweep interval stays a `const` in the module, not
config.

### Operator flow for a key rotation

The order matters, and only one order works:

1. `identity-rotate-keys` generates the new key-agreement (and signing) keys and
   writes them to `ServerSecrets` via `SecretStore::set()`.
2. It builds a new DID document with the new VMs and publishes a new webvh log
   entry.
3. The publish hook fires, sees a new `ka_kid` it *does* hold a secret for, and
   rotates the generation.

Publishing first and writing the secret second would hit step 4's refusal. The
CLI must do both, in that order, or neither.

## Work by crate

**`did-hosting-common`** — new `server::identity` module (generation model, store
access, secret-store extension, `load_identity`, `reload_service_identity`,
`identity_sweep`). Replace `init_didcomm_auth`. Add `KS_IDENTITY`.

**`did-hosting-server`** — **lift `DIDCommService` into `AppState`.** It is
currently a local variable in `run()` (`server.rs:285-296`) and is unreachable at
runtime, so no hot-swap is possible without this. Prerequisite for everything
else.

**`did-hosting-control`** — `AppState` gains the identity state and a
`SecretStore` handle (no binary retains one after startup today; either add it to
`AppState` or reconstruct via `create_secret_store()` at the write site).
`didcomm_service: Arc<OnceLock<..>>` stays as-is — see finding (6).

**`did-hosting-daemon`** — `build_server`, `build_witness` and `build_control`
(`main.rs:1109`, `:1162`, `:1220`) each call `init_didcomm_auth` with the same
`server_did`, producing **three** independent `DIDCacheClient`s and **three**
`ThreadedSecretsResolver`s. A reload must reach all three. Consolidate to one
shared identity state rather than fanning out — this is a cleanup worth doing
regardless.

**`webvh-witness`** — same frozen-at-boot pattern; same treatment.

**CLI** — `recreate-did` / `recover-did` live on daemon and server but **not**
control (`did-hosting-control/src/main.rs:23` has no DID-management commands at
all), and there is no shared clap module — each binary redeclares its variants.
New commands `identity-list` / `identity-rotate-keys` / `identity-retire-now`,
flat (house style has no nested subcommand groups), on all three.

**REST/UI** — `GET /api/identity/generations`, `DELETE
/api/identity/generations/{id}`. A dashboard panel showing live generations and
their expiry is a natural follow-up, not required for correctness.

## Phasing

1. **Foundations, no behaviour change.** `KS_IDENTITY`, the generation model,
   `load_identity` replacing `init_didcomm_auth` (fixing the kid bug), the server
   `AppState` lift, the daemon consolidation. Boot synthesises generation 0 and
   behaves exactly as today.
2. **Rotation, same mediator.** The publish hook, `reload_service_identity`,
   retirement, the reaper, listener hot-swap. Covers key rotation and
   service/protocol changes — the common case.
3. **Mediator change.** The old-mediator HTTP drain task.
4. **Operator surface.** CLI, REST, UI.

## Tests

- Unit: live-set computation, protocol union, generation diffing, grace parsing,
  `identity_sweep::run_sweep_once` (mirroring the `purge_sweep` unit tests).
- Publish an update to our own DID → new generation created, old one retired with
  an expiry, profile carries **both** kids, listener hot-swapped.
- Restart with a live retired generation → profile rebuilt from the store + secret
  store with both kids present. **This is the requirement that motivated the
  durable state; it needs an explicit test.**
- TSP-only current + DIDComm retiring → listener has `tsp: true` and still
  dispatches DIDComm.
- Expiry → old secret dropped, listener rebuilt, old kid no longer decrypts.
- New `ka_kid` with **no matching secret** → no promotion, current generation
  intact, error surfaced. (Guards the half-rotation footgun.)
- Mediator change → drain task started against the old mediator, stopped at
  expiry. Mock `fetch_messages`; a real mediator is out of scope for CI.

## Risks and non-goals

- **Retired keys stay readable in the secret store for the window.** That is the
  point, but it does extend the blast radius of a compromise.
  `identity-retire-now` is the mitigation and must be documented as the
  compromise response.
- **The old-mediator drain needs the DID to still have local ACL at that
  mediator** (`mediator/src/handlers/inbox_fetch.rs:36` returns 403 otherwise).
  If the operator deregistered, the drain 403s — log loudly rather than retry
  silently.
- **Secret-store writes have no CAS.** Serialize behind the identity mutex;
  two processes sharing a store can clobber.
- **Rotating the DID itself** (not its keys) is out of scope. That is two
  distinct DIDs, which the framework supports natively (`DuplicateDid` only fires
  on an identical DID string), but it changes config and the service's whole
  identity — a different problem.
- We do **not** depend on `protocols.didcomm` being ignored upstream, though it
  currently is.
