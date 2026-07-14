# Service identity rotation — test runbook

How to exercise runtime DID rotation against a live deployment, and what
"working" looks like at each step.

Design: `docs/identity-rotation-design.md`.

---

## 0. Preflight — do this first, it can save you the whole session

### 0a. Does your service's own DID resolve?

```bash
grep server_did config.toml
```

A **root DID must be pathless** — `did:webvh:<scid>:did.example.com`. That is the
correct and canonical shape; its document is *stored and served* at
`/.well-known/did.jsonl`, but `.well-known` is not part of the identifier.

If your `server_did` **ends in `:.well-known`**, it was minted by a build
predating this PR and **cannot resolve at all** — a conforming resolver strips
the suffix on the round-trip and then rejects the document because the `id`
inside no longer matches:

```
DID being resolved (did:webvh:Qm…:did.example.com)
does not match the top-level 'id' in any DIDDoc version
```

This PR fixes the *minting* (new DIDs come out pathless), but **an existing DID
cannot be corrected in place** — the SCID is derived from the document, so
changing the `id` means a new DID. Affected deployments must recreate theirs. On
boot you will now get an explicit warning saying exactly that, instead of a
resolution error that looks like a network problem.

Confirm the identifier the document actually carries matches the DID you
configured:

```bash
curl -s https://<host>/.well-known/did.jsonl | tail -1 | jq -r '.state.id'
# must equal server_did, and must NOT end in :.well-known
```

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

This is the one that must be seamless, and there is now a single command for it.

```bash
# Service STOPPED (the store is exclusively locked).
did-hosting-daemon --config config.toml identity-rotate-keys --grace 1h
```

It generates a new X25519 key-agreement key, publishes a signed v2 webvh log
entry installing it **on a fresh verification-method fragment**, carries the
outgoing key into the retired set, and records both generations. Then start the
service — it comes back holding *both* keys.

Pass `--ka-key <multibase>` to install a specific key instead of generating one,
and `--grace 0` to retire the old key immediately (a compromise; peers holding a
stale document cannot reach you until their cache expires).

### Why the fresh fragment matters — read this before hand-rolling anything

The new key is published at `#<its own multibase>`, **not** at `#key-1` again.
That is not cosmetic. The secrets resolver is a map keyed by kid, and inbound
JWEs name their recipient by kid — so two keys cannot both answer to `#key-1`.

**A rotation that reuses the fragment has no expressible grace period at all.**
Whichever key you hold, half your peers fail. If you hand-build a v2 entry that
reuses `#key-1`, it will appear to work and will silently cost you the entire
overlap — which is the one thing you are trying to test. The service now detects
this and logs `RotatedWithoutOverlap` at **error** rather than pretending
everything is fine, but the overlap is gone either way.

### Expected output

```
  Rotated the key-agreement key for did:webvh:Qm…:did.example.com
    new key    : did:webvh:Qm…#z6LSd5hAwQ8c…  (generation 1)
    retiring   : did:webvh:Qm…#key-1          (generation 0, honoured for 60m)
    did.jsonl  : now 2 entries
```

Then, on start:

```
INFO service identity loaded  generation=1  live_generations=2
```

**`live_generations=2` is the whole point.** Confirm:

```bash
did-hosting-daemon --config config.toml identity-list      # stopped
# or, live:
curl -sH "Authorization: Bearer $ADMIN_JWT" \
  https://<control>/api/identity/generations | jq
```

- Generation 1: `current`, new fragment.
- Generation 0: `retired_at` set, `expires_at ≈ now + 3600`.

**The behaviour that matters:** a peer whose cached DID document still names the
*old* key can still reach you. Verify by sending from a peer that has not
re-resolved — it should be delivered *and answered*, not dropped.

### Failure signatures

| Log | Means |
|---|---|
| `REFUSED to rotate the service identity: … advertises key-agreement key … but the secret store holds a different private key` | The document and the secret store disagree. `identity-rotate-keys` writes both together, so you only see this if a document was published by other means. **The service is still running fine on the old identity** — this is the guard working. |
| `identity rotated WITHOUT a grace period` | The rotation reused the verification-method fragment. See above — the overlap is gone. |
| `service identity unchanged` | The document's kids/mediator/protocols did not actually change. |
| `no identity generation recorded — start the service once…` | The service has never resolved its own DID. Start it once, then rotate. |

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
- two-mediator coexistence and the drain (§3).
