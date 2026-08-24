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
cargo build -p did-hosting-daemon --features method-webs
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
- **Continuation.** An update may not rewind or fork the hosted log — same AID,
  and the new sequence number must be ≥ the stored one. A `did:webs` update
  republishes the *whole* stream, so nothing in the bytes stops a controller (or
  an attacker holding a superseded key) from publishing a shorter log that
  verifies perfectly well on its own.

An unreadable *stored* stream is deliberately not a reason to refuse an update —
that would wedge a corrupt slot permanently, with no way to publish the log that
repairs it.

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
