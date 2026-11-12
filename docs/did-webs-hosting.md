# Hosting `did:webs`

Status: implemented, off by default (`method-webs`)
Extends: `docs/multi-method-hosting-spec.md`

`did:webs` is `did:web` discovery with KERI-verified key state. A DID's last
label is a KERI **AID**, and it publishes two artifacts:

```text
https://{domain}/{path}/{AID}/keri.cesr   the key event log — the authority
https://{domain}/{path}/{AID}/did.json    the document it implies — a cache
```

Only `keri.cesr` carries authority. A conforming resolver derives its own
document from the verified key state and treats a disagreement with the
published `did.json` as an error, not a preference. Everything below follows
from that one fact.

## Enabling it

Off by default on every binary, because it pulls the KERI stack and an operator
hosting no `did:webs` DIDs should not carry it:

```bash
cargo build --locked -p did-hosting-daemon --features method-webs
```

The daemon's `method-webs` turns on **both halves** — the control plane's write
path and the server's resolve routes. Enabling only one gives a deployment that
accepts DIDs it cannot serve, or serves a store nothing can write to.

For standalone deployments, enable `method-webs` on `did-hosting-control` *and*
`did-hosting-server`.

## The two places it does not fit the multi-method spec

Both are deliberate, and both are the interesting part of this work.

### 1. Two artifacts, one `DidMethod`

`DidMethod` is single-artifact: one `content_type()`, one `data_ext()`, one
`apply_update()`. `did:webs` has two files.

Rather than widen the trait — which the spec flags as an "ask first" change, and
which would push a second artifact onto every other method — this service
**stores one blob and derives the other**:

- `keri.cesr` is stored under the existing `content:{mnemonic}:log` key. That is
  this method's log in the same sense the jsonl is webvh's, so sync, backup,
  delete, the content cache and the stats counters all keep working unchanged.
- `did.json` is **derived on every read** from the stored stream.

Storing a derived `did.json` would buy nothing and cost a drift surface. The
only document this service may serve is the one the log implies, so a stored
copy could only ever be right or stale — and "stale" here means serving a
document from *before* a key rotation, which is precisely the attack
pre-rotation exists to defeat. Caching it separately would mean invalidating a
second key at all five sites that invalidate `content_log_key`, where one missed
site is that bug.

The cost is a key-event-log verification per `did.json` request, against bytes
already in the content cache. If that ever shows up in a profile, the safe fix
is a memo keyed by a hash of those bytes, which cannot go stale.

A publisher may still **submit** its own `did.json`; it is cross-checked against
the derivation and rejected on mismatch, then discarded.

### 2. Paths cannot use the shared mnemonic grammar

`validate_custom_path` requires lowercase `[a-z0-9-]` segments. A `did:webs`
slot's last segment **is** the AID — case-sensitive base64url, e.g.
`ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe` — which fails on its first
character. Every `did:webs` DID would be unhostable.

The fix is `validate_webs_mnemonic`, a per-method validator, **not** a loosened
shared rule. The lowercase rule earns its keep for operator-chosen paths: it
makes two slots differing only by case impossible, so a hosted path cannot be
shadowed by a confusable twin. Here the exception is safe for a different
reason — an AID is a high-entropy digest, not a name anyone picks, so a
confusable pair is not something an attacker can arrange. Leading path segments
keep the strict grammar; only the trailing AID is exempt.

There is a regression guard (`the_shared_validator_rejects_every_aid`) asserting
the shared grammar really would have blocked it. If that ever starts failing,
the split can be revisited.

Every operation on an existing slot (`did/info`, `did/log`, `did/set-state`,
`did/change-owner`, `did/delete`, `did/rollback`, `agent-name/*`,
`webvh/witness/publish`) takes the path's grammar from the stored record
(`validate_slot_mnemonic`), never from the request: the AID grammar applies
only to a slot already recorded as `did:webs`.

## What is verified, and where

Verification is what makes this a *host* rather than a file server. It runs
before anything is stored, via `method::publication::verify_publication`:

- every key event's SAID, before any field of it is trusted;
- the prior-event digest chain and sequence ordering;
- controller signatures, against the keys each event type is signed by;
- pre-rotation commitments on every rotation;
- delegation seals, followed, bounded and cycle-checked;
- witness receipts against the threshold the key state declares;
- the designated-aliases attestation — registry inception anchored, issuance
  anchored, signed by the AID's key state, not revoked — which is where
  `alsoKnownAs` comes from.

`affinidi-did-webs` does all of it. This service adds two rules of its own:

- **Slot binding.** The stream must establish exactly the AID the slot's
  identifier ends in. See below for why this is inverted from webvh.
- **Continuation.** An update must strictly extend the hosted log: same AID,
  and every key event the hosted log holds, at the same sequence number with
  the same SAID, followed by zero or more new ones. A shorter log, a different
  event at the hosted tip's sequence number, or a longer log that diverges
  before it is refused. A `did:webs` update republishes the *whole* stream, so
  nothing in the bytes stops a controller, or someone holding a superseded key,
  from publishing a shorter or different log that verifies perfectly well on
  its own. The events are compared by SAID, not as bytes, so republishing the
  same events (re-serialized, or with witness receipts added) is accepted.

An unreadable or unverifiable *stored* stream is deliberately not a reason to
refuse an update: that would wedge a corrupt slot permanently, with no way to
publish the log that repairs it. Every write path verifies a log before it
stores it, so a stored log that does not verify is corrupt, not history.

## Where the identifier comes from — inverted from webvh

For `did:webvh` and `did:web` the identifier is *inside* the content: the log
states its own `state.id`, which is then checked against the slot it was
published to.

A KERI key event log contains no such thing. It establishes an **AID**, and
nothing more — the host and path that turn that AID into a DID are properties of
*where it is published*, not of the log. So the identifier is **constructed**
from the slot:

```text
did:webs:{domain}:{mnemonic}     # mnemonic already ends in the AID
```

and the log is then required to establish exactly that AID. This inverts the
direction of the check but not its strength: a stream for another AID is
refused, and a stream cannot claim a slot by asserting a domain it was not
published under, because it never gets to assert one.

Two consequences:

- **A domain is required.** `register_did_atomic` takes one (the REST handler
  passes the already-resolved domain). Publishing without it would mean
  verifying the stream against an identifier we invented.
- **The record must carry its domain.** Unlike webvh, whose `domain` is a
  convenience backfilled by migration, a `did:webs` record's domain is load
  bearing — the document is re-derived from the identifier on every read.

### The port-separator trap

Callers hold the hosting domain **decoded** (`extract_did_host` percent-decodes,
and the domain registry stores real hostnames). A DID's labels are
colon-separated, so building `did:webs:localhost:8534:{AID}` from a decoded
`localhost:8534` yields host `localhost` with `8534` as a *path segment* — a
different DID, on a host this deployment does not serve. The port separator is
percent-encoded when the identifier is built (`%3A`), idempotently.

Records store the **decoded** form, matching every other record and matching
what an edge derives, so the control plane and its edges agree about the same
DID.

## Managing a `did:webs` slot

A `did:webs` slot is read, suspended, transferred and deleted through the same
Trust Tasks as any other slot. Two do not apply to it:

- **`did/rollback` is refused.** It truncates a `did:webvh` log by line. A key
  event log is not line-delimited, and only its controller moves it on, by
  publishing a longer one; a publish may not rewind it either (see
  *Continuation* above).
- **`webvh/witness/publish` is refused** (`invalidWitness`). A `did:webs`
  slot's witness receipts are part of its key event log.

`did/info` returns no `logSummary`, which is read from a `did:webvh` log line.
`did/log` returns one entry, the document the stored stream implies now
(re-verified, as on resolution), and `raw` returns the stream verbatim.
Earlier establishment events are not listed yet.

## No `.well-known` form

The AID is always the final path segment, so there is always at least one path
element and the root slot never applies. `/.well-known/keri.cesr` is a 400 —
not a 404 — because it is a path a `did:webs` DID can never occupy, which is
worth telling an operator who mis-wired a publish.

Do not add a `.well-known` branch for this method.

## Sharing `/did.json` with `did:web`

Both methods serve that suffix. The dispatcher runs `resolve_webs` **before**
`resolve_web`, and webs claims a `did.json` only when the stored record is
tagged `webs`, falling through otherwise.

Ordering them the other way would let did:web's bridge answer for a did:webs
slot: it would look for a webvh jsonl log where a CESR stream is stored, and
404 a DID that is hosted perfectly well. `keri.cesr` is method-exclusive and
needs no such care.

## Method detection

The management API's body carries content, not a method, and the method must be
known before anything can verify it. `method::detect_method` decides from the
payload's shape rather than a caller-supplied label, so a caller cannot mislabel
a payload into a verifier that would wave it through.

One subtlety is load bearing: **the CESR parser reads a bare JSON object as a
message**, so a `did:webvh` log line "parses" as a stream. What separates them
is that a key event log must carry an **inception** event. Without that check, a
webvh publish would route to the KERI verifier and be rejected. webvh is also
checked first, being the cheapest and most specific test.

A slot's method is fixed at registration — `prepare_republish` refuses a swap,
*before* verification, so a malformed foreign payload is reported as the method
swap it is rather than as a broken log.

## Edges verify for themselves

`control_register::apply_single_update` re-runs the full key-event-log
verification rather than trusting the push. This is stricter than the webvh sync
path, which stays structural-only (the control plane has already walked that
chain, and an edge re-running it would reject logs an older `didwebvh-rs`
accepted).

The asymmetry is deliberate: it is the same reasoning that makes an edge derive
agent names from the signed document instead of from the update. A compromised
or buggy control plane cannot make an edge serve a stream that does not verify.

## Self-registration

A `did:webs` does not exist until a host publishes it, so a node whose own
durable identity is to be a `did:webs` (a VTA or VTC) has nothing to
authenticate as before its first publication — and every other caller here
authenticates as a DID the ACL lists. It does not need anything: a `did:webs`
is self-certifying. Its AID is the digest of its inception event, which names
the keys that control it, so a request signed by a key the submitted key event
log establishes is signed by the identifier's controller.

So a host built with `method-webs` accepts a `did/register/0.1` from a
`did:webs` **outside the ACL**, on a domain whose operator enables it:

```toml
[[hosting.webs_self_register]]
domain = "did.example.com"
path_prefixes = ["nodes"]   # optional; empty = any path on the domain
max_registrations = 100     # optional; the default
```

Opting a domain in opens it to anyone with a key event log, and an AID costs
nothing to mint. `max_registrations` bounds how many self-registered
identifiers the domain holds at once (counted from the owner entries
self-registration grants; deleting one frees its place). A domain at its limit
refuses with `quotaExceeded`. Like the rate limits it is per process, so N
replicas can exceed it by at most N−1.

Off by default: with no entry, an unknown `did:webs` is refused exactly as any
caller outside the ACL is (`permissionDenied`). A host built without
`method-webs` ignores the setting.

The document is held to everything a privileged document is, with the ACL
entry replaced by the key event log (`did-hosting-control/src/webs_self_register.rs`):

1. `issuer` is a `did:webs` the ACL does not list (one it lists takes the
   ordinary path), and the task is `did/register/0.1` — no other task;
2. the payload names an enabled `domain`, a path under one of its
   `path_prefixes`, `method: "webs"` and no `force`. A `did:webvh` is never
   registered this way;
3. `issuer` is exactly the identifier the slot builds,
   `did:webs:{domain}:{path}:{AID}` (`Webs::slot_did`, which the write path
   builds it with too);
4. a per-source rate limit (`webs-self-register-per-source`, 10 a minute: the
   client IP on HTTPS, the sender on TSP and DIDComm), and one bucket shared
   by every source (`webs-self-register-global`, 30 a minute), since a sender
   can be a fresh `did:key` each time; both before any key event log is
   verified;
5. the submitted `keri.cesr` verifies in full and establishes that AID;
6. the proof is sender-bound as every privileged proof is — issuer, transport
   sender, recipient, freshness, `proofPurpose: authentication` — and verifies
   under a key of the document **the submitted log implies**, never one
   resolved over the network: the identifier does not resolve yet, and it is
   that log this service is about to publish. Any of the log's current signing
   keys may sign, as when the published identifier is resolved later.

The registration then holds the domain's self-registration lock, refuses a
domain at its `max_registrations`, and is the ordinary `register_did_atomic`,
as that identifier: it verifies the log again, refuses a slot owned by anyone else
(only an administrator takes one over), and commits. **After** the commit the
identifier is given an `Owner` ACL entry, scoped to its domain and to one slot
(`max_did_count = 1`), so its later publications — key rotations — take the
ordinary owner path, authenticated by resolving the published identifier from
this host. A crash between the two leaves an owned slot and no entry; a retry
is again a self-registration of a slot the identifier already owns, and grants
it then. Each self-registration is logged on the `audit` target
(`did.webs.self_registered`, with the `source` the transport vouched for);
a refusal at the limit as `did.webs.self_register_refused`.

The document is subject to the default 64 KiB Trust Task size limit (the raised
`did/register` limit is for issuers the ACL lists).

In practice a first registration arrives over HTTPS: a DIDComm or TSP sender is
authenticated by resolving its DID, which a `did:webs` that is not yet
published cannot be, and the sender must be the issuer.

## What this service does *not* do

- **It does not create `did:webs` identifiers.** `affinidi-did-webs` is taken
  without its `create` feature. Inception and rotation mean holding the KERI
  signing keys, and the hosting service never does — the controller publishes a
  `keri.cesr` here, exactly as a VTA publishes a signed `did.jsonl` today. This
  keeps `affinidi-keri` and its LMDB store out of the dependency graph.
- **It does not issue the designated-aliases attestation.** That needs TEL/ACDC
  issuance, which is a controller-side capability.
- **Witness and watcher stay webvh-only.** KERI witnesses are a different
  protocol from `webvh-witness` despite the name; `did:webs` witness receipts are
  verified inside the key event log, not by a sidecar service.

## Fixtures

`did-hosting-common/tests/fixtures/` holds the artifacts published by the
`hyperledger-labs/did-webs-resolver` reference implementation, reproduced
unmodified. They are the only bytes in the suite that came from keripy, so they
are the only ones that can catch this service and the wider KERI ecosystem
disagreeing. Tests needing a bad stream derive it from these at runtime.
