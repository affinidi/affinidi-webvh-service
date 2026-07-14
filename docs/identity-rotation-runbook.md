# Service identity rotation — test runbook

How to exercise runtime DID rotation against a live deployment, and what
"working" looks like at each step.

Design: `docs/identity-rotation-design.md`.

---

## 0. Preflight — do this first, it can save you the whole session

### 0a. Is your service's own DID at the `.well-known` slot?

```bash
grep server_did config.toml
```

If it ends in `:.well-known` — e.g.
`did:webvh:QmAbc…:did.example.com:.well-known` — **stop. Rotation cannot work on
this deployment**, and it is not because of anything in this PR.

A conforming resolver maps a root DID to `/.well-known/did.jsonl` *implicitly*,
so it strips the `.well-known` suffix on the round-trip and then rejects the
document because its `id` no longer matches. The document serves fine (200); the
*identifier* does not round-trip. Confirm with:

```bash
# Should print the establish line. If instead you see the mismatch error, this is it.
grep -E "service identity established|does not match the top-level" <logs>
```

Failure signature:

```
DID being resolved (did:webvh:Qm…:did.example.com)
does not match the top-level 'id' in any DIDDoc version
```

Test against a **path-hosted** DID instead (`…:did.example.com:control`). See the
design doc, "Known blocker".

### 0b. Which secret backend?

```bash
grep -A3 '\[secrets\]' config.toml
```

`keyring` / `aws` / `gcp` / `azure` / `vault` / `k8s` → fine, `import-secrets`
writes to the live backend and the running service reads it back.

`plaintext` → also fine **on this branch** (`get()` now re-reads `config.toml`),
but note the rotation writes new keys into `config.toml` in the clear.

### 0c. Baseline

```bash
# Service running.
curl -sH "Authorization: Bearer $ADMIN_JWT" \
  https://<control>/api/identity/generations | jq
```

Expect exactly one generation, `"current": true`, `expires_at: null`, and
`key_agreement_kid` matching what your DID document actually advertises:

```bash
curl -s https://<host>/<path>/did.jsonl | tail -1 | jq -r '.state.keyAgreement[0]'
```

**Those two must be identical.** If the API shows `#key-1` but the document shows
something else, the identity never established — go back to 0a.

Also confirm in the logs, at boot:

```
INFO service identity established from the DID document  generation=0 ka_kid=…
```

(On a *restart* of an already-established service you get `service identity
loaded … live_generations=1` and **no** "falling back to #key-0/#key-1" warning.
Seeing that warning on a restart means generation 0 never persisted.)

---

## 1. Key rotation, same mediator — the common case

This is the one that must be seamless. Order matters, and only one order works.

### Why the order

`import-secrets` **overwrites** the key-agreement key in the secret store. If you
publish the new DID document *first*, the running service re-resolves, sees a key
it does not hold, and refuses to rotate (loudly, and correctly). If you write the
key *first*, the running service still holds the old key in memory — which is the
only surviving copy once the store is overwritten — and can move it into the
retired set in the same write that installs the new one.

So: **keys, then publish.** Never the reverse.

### Steps

**1. Generate a new X25519 key-agreement key** (and Ed25519 signing key if you are
rotating that too), multibase-encoded.

**2. Write it to the secret store — service still running.**

```bash
did-hosting-daemon --config config.toml import-secrets \
  --signing-key "z6Mk…"  \
  --ka-key      "z6LS…"  \
  --force
```

`import-secrets` does **not** open the DID store, so it is safe against a live
service. Nothing changes yet — the running process still uses the old keys,
because the document still advertises them.

**3. Publish a new DID log entry** advertising the new verification methods
(signed by the current `updateKeys`).

> ⚠️ There is **no CLI for this today**. `recreate-did` mints a *new* DID (new
> SCID), which is not a rotation. You will need to produce a v2 webvh log entry
> with your existing tooling and `PUT` it:
>
> ```bash
> curl -X PUT -H "Authorization: Bearer $ADMIN_JWT" \
>   -H 'Content-Type: text/plain' \
>   --data-binary @did-v2.jsonl \
>   https://<control>/api/dids/<mnemonic>
> ```
>
> Building that entry is the main friction in this runbook and the strongest
> argument for an `identity-rotate-keys` command as a follow-up.

### What to expect

The publish hook fires immediately — no waiting on a poll:

```
INFO our own DID was published — checking for a rotation
INFO service identity rotated — rebuilding listener
     new_generation=1 retired_generation=0 expires_at=…
INFO DIDComm listener rebuilt on the new identity
```

Then:

```bash
curl -sH "Authorization: Bearer $ADMIN_JWT" \
  https://<control>/api/identity/generations | jq
```

- **Two** generations.
- Generation 1: `current: true`, `expires_at: null`, new `key_agreement_kid`.
- Generation 0: `current: false`, `retired_at` set, `expires_at ≈ now + 3600`.

**The behaviour that matters:** a peer whose cached DID document still names the
*old* key can still reach you. Verify by sending from a peer that has not
re-resolved (or whose resolver cache you have not flushed) — it should be
delivered and answered, not dropped.

### Failure signatures

| Log | Means |
|---|---|
| `REFUSED to rotate the service identity: … advertises key-agreement key … but the secret store holds a different private key` | You published before writing the key. Do step 2, then re-publish (or wait for the 5-min backstop). **The service is still running fine on the old identity** — this is the guard working. |
| `service identity unchanged` | The document's kids/mediator/protocols did not actually change. |
| `could not resolve our own DID document` | See preflight 0a. |

---

## 2. Restart mid-window — the durability requirement

**This is the requirement the whole design exists for.** Do it while generation 0
is still inside its grace period (`expires_at` in the future).

```bash
# Restart the service.
```

Expect at boot:

```
INFO service identity loaded  generation=1  live_generations=2
```

`live_generations=2` is the whole point: the retired generation's key material
came back from the secret store, so a peer with a stale document can *still*
reach you after a restart. Confirm:

```bash
curl -sH "Authorization: Bearer $ADMIN_JWT" \
  https://<control>/api/identity/generations | jq '.generations | length'   # 2
```

If you see `live_generations=1` and only one generation, the retired key material
did not survive — that is a bug, and worth capturing the secret store's contents
(redacted) before doing anything else.

---

## 3. Mediator change — the drain

The one case key overlap cannot cover: peers with a stale document keep
delivering to the **old** mediator.

1. Point `mediator_did` at the new mediator in `config.toml`.
2. Publish a DID document whose `DIDCommMessaging` service endpoint names the new
   mediator.
3. Restart (config is read at boot).

Expect:

```
INFO service identity rotated — rebuilding listener
INFO DIDComm listener rebuilt on the new identity
INFO connecting to the old mediator to drain messages from peers with a stale DID document
     generation=0 mediator=did:web:old-mediator…
```

**Verify the thing that actually matters:** have a peer that still holds the old
document send you a message *after* the cutover. It lands at the old mediator, and
the drain should pick it up **and reply**. A reply proves the drain is a real
listener and not a one-way sink.

At expiry (or on kill switch):

```
INFO retired generation is no longer live — stopping its mediator drain
INFO old-mediator drain stopped
```

### Prerequisite the drain cannot fix

Your DID must **still be registered** with the old mediator. If it has been
deregistered, the old mediator refuses the connection and those queued messages
are unrecoverable:

```
WARN could not connect to the old mediator to drain it: … Messages queued there
     by peers holding a stale DID document will not be delivered.
```

So: **do not deregister from the old mediator until the grace period has
elapsed.**

---

## 4. The kill switch

### Live (the one that matters for a compromise)

UI → **Settings → Key Generations → Retire now**, or:

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_JWT" \
  https://<control>/api/identity/generations/0/retire     # 204
```

This runs **in-process**: the key is gone from the running secrets resolver and
the listener profile before the response is written. Verify it actually stopped
being honoured — a peer still encrypting to the old key should now fail, and:

```bash
curl -sH "Authorization: Bearer $ADMIN_JWT" \
  https://<control>/api/identity/generations | jq '.generations | length'   # 1
```

Retiring the **current** generation is refused (it is the key the service is
actively using).

### Offline (stopped service)

```bash
did-hosting-daemon --config config.toml identity-list
did-hosting-daemon --config config.toml identity-retire-now --generation 0
```

The store is exclusively locked, so this needs the service **stopped**. A running
service that shares the store also reconciles within one sweep (60s) and drops the
key.

---

## 5. Expiry

Leave generation 0 alone for `rotation_grace_period` (default `1h`; set
`[identity] rotation_grace_period = "3m"` to test quickly).

Within 60s of expiry:

```
INFO identity generation expired — its key material is no longer honoured  id=0
```

`GET /api/identity/generations` drops to one. A peer still encrypting to the old
key now fails — as intended.

---

## Rollback

Nothing here changes the DID document or the wire protocol; it changes which keys
a process *honours*. To back out, deploy the previous build. `KS_IDENTITY` and
`ServerSecrets.retired` are additive and ignored by older code — the old build
reads `signing_key` / `key_agreement_key` exactly as before.

The one thing that does not roll back: if you have already rotated your DID
document to new keys, the old build will use the guessed `#key-0`/`#key-1` kids
against it, which is the pre-existing bug this PR fixes. Roll the *document* back
too, or stay on the new build.

---

## What I could not verify locally

No mediator was available, so these are covered by unit tests and construction
only — they are the highest-value things for you to watch:

- the listener rebuild against a real mediator (§1);
- two-mediator coexistence and the drain (§3);
- a key rotation end-to-end (§1) — blocked on there being no CLI that emits a
  signed v2 webvh log entry.
