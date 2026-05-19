# Trust Tasks ACL — client migration guide (v0.7.0 → v0.8.0)

v0.7.0 introduces a new wire surface for ACL administration based on the
[Trust Tasks framework](https://trusttasks.org/). The legacy
`GET/POST /api/acl`, `PUT/DELETE /api/acl/{did}` REST routes are
**deprecated** and will be **removed in v0.8.0**.

This document is the client-facing migration guide. If you operate the
control plane in your own deployment, see
`docs/trust-tasks-registry-gaps.md` for the upstream-spec items not yet
covered by the registry.

## What changed

| Operation        | Old route                       | New: trust-task type URI                                       |
|------------------|---------------------------------|----------------------------------------------------------------|
| List entries     | `GET    /api/acl`               | `https://trusttasks.org/spec/acl/list/0.1`                     |
| Get one entry    | (not exposed)                   | `https://trusttasks.org/spec/acl/show/0.1`                     |
| Add entry        | `POST   /api/acl`               | `https://trusttasks.org/spec/acl/grant/0.1`                    |
| Change role      | `PUT    /api/acl/{did}` (role)  | `https://trusttasks.org/spec/acl/change-role/0.1`              |
| Update metadata  | `PUT    /api/acl/{did}` (other) | `https://trusttasks.org/spec/acl/grant/0.1` (idempotent regrant) |
| Remove entry     | `DELETE /api/acl/{did}`         | `https://trusttasks.org/spec/acl/revoke/0.1`                   |
| Discover what we route | (not exposed)             | `https://trusttasks.org/spec/trust-task-discovery/0.1`         |

All six land on the **single endpoint** `POST /api/trust-tasks` carrying
a typed envelope. The envelope's `type` member identifies which
operation. See
[SPEC.md](https://github.com/trustoverip/dtgwg-trust-tasks-tf/blob/main/SPEC.md)
for the framework-level document shape.

## Behavioural changes vs. v0.7

The new surface is **stricter** by design — these are
maintainer-policy invariants the spec calls for:

- **`acl/grant`** is *idempotent* and *role-preserving*. Re-granting a
  subject with the same role is a no-op. Re-granting with a different
  role is rejected with `permission_denied` + `details.reason =
  "role_change_required"`; use `acl/change-role` instead.
- **`acl/change-role`** is *state-checked*: the request carries
  `fromRole` and `toRole`. The maintainer rejects with
  `acl/change-role:state_mismatch` (retryable) when the subject's
  actual current role does not match `fromRole` — surfaces concurrent
  changes by another admin rather than silently overwriting.
- **`acl/revoke`** has a *last-authority guard*: a revocation that
  would leave the maintainer with zero `Admin` entries is rejected
  with `acl/revoke:last_authority_protected`. The same invariant
  fires on `acl/change-role` demoting the last admin and is reported
  there as `acl/change-role:last_authority_protected` — the slug
  matches the request's `type` so a client dispatching on
  `payload.code` doesn't need to cross spec slugs.
- **`acl/revoke`** supports *scope reduction*: with `payload.scopes`
  present, only the listed scopes are removed. webvh interprets each
  scope item as `domain:<name>` — items in any other shape are
  rejected as `malformed_request`. Reducing the only remaining domain
  fully removes the entry (`entry: null` in the response).

## webvh-specific fields (`ext.vnd.affinidi.webvh.*`)

The spec's canonical `AclEntry` has `subject`, `role`, `scopes`,
`label`, `createdAt`, `createdBy`, `updatedAt`, `updatedBy`,
`expiresAt`, `ext`. webvh-specific fields live under the
`vnd.affinidi.webvh` namespace inside `ext`:

```json
{
  "ext": {
    "vnd.affinidi.webvh": {
      "quota": {
        "maxTotalSize": 1048576,
        "maxDidCount": 50
      },
      "domains": {
        "kind": "allowed_with_default",
        "domains": ["alpha.example", "beta.example"],
        "default": "alpha.example"
      }
    }
  }
}
```

- `quota.maxTotalSize` (bytes), `quota.maxDidCount` — per-account
  ceilings. Both individually optional; omit to inherit the deployment
  default.
- `domains` — per-entry `DomainScope`, tagged enum (`kind` = `"all"` |
  `"allowed"` | `"allowed_with_default"`). **Required** for `Owner`
  entries. `Admin` / `Service` entries default to `{ kind: "all" }`
  when the namespace is absent.

Consumers that don't speak webvh MUST ignore this namespace per
[SPEC.md §4.5.1](https://github.com/trustoverip/dtgwg-trust-tasks-tf/blob/main/SPEC.md#451-the-ext-extension-member).

## Worked example — `acl/grant` over HTTPS

Caller is `did:web:admin.example` (an Admin in the maintainer's ACL).
The grant adds `did:web:alice.example` as a new Owner. `acl/grant`
is a REQUIRED-spec under the framework's
[`IS_PROOF_REQUIRED`](https://github.com/trustoverip/dtgwg-trust-tasks-tf/blob/main/SPEC.md#7-consumer-pipeline)
gate, so the envelope carries a Data Integrity proof signed by the
caller's session keypair (see [Web UI session-key flow](#web-ui-session-key-flow)).

```http
POST /api/trust-tasks HTTP/1.1
Host: control.example
Authorization: Bearer <JWT>
Content-Type: application/json

{
  "id": "urn:uuid:8a91c7b3-2e62-4a91-a3a4-9d61b75e2f01",
  "type": "https://trusttasks.org/spec/acl/grant/0.1",
  "issuedAt": "2026-05-19T10:00:00Z",
  "payload": {
    "entry": {
      "subject": "did:web:alice.example",
      "role": "owner",
      "label": "Alice",
      "ext": {
        "vnd.affinidi.webvh": {
          "domains": { "kind": "all" }
        }
      }
    },
    "reason": "Onboarding new owner"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6Mk…#z6Mk…",
    "created": "2026-05-19T10:00:00Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "z…"
  }
}
```

The `issuer`/`recipient` are omitted in this example because the
bearer JWT pins the caller end-to-end (SPEC.md §4.8.1 falls back to
transport-derived identity when in-band is absent). The proof's
`verificationMethod` references the ephemeral session keypair the
client registered at login — server-side, `dispatch_trust_task`
verifies that the `did:key` matches the JWT-bound session pubkey
before the framework's `AffinidiVerifier` verifies the signature.
On success, the response is routed back to the **caller** (the admin
who issued the grant) — `recipient` is `did:web:admin.example`, not
the grant's subject:

```json
{
  "id": "urn:uuid:9b3c5e2a-1b81-4d3e-9b51-7a3c89e3d1f3",
  "type": "https://trusttasks.org/spec/acl/grant/0.1#response",
  "threadId": "urn:uuid:8a91c7b3-2e62-4a91-a3a4-9d61b75e2f01",
  "issuer": "did:web:control.example",
  "recipient": "did:web:admin.example",
  "issuedAt": "2026-05-19T10:00:01Z",
  "payload": {
    "entry": {
      "subject": "did:web:alice.example",
      "role": "owner",
      "label": "Alice",
      "createdAt": "2026-05-19T10:00:01Z",
      "ext": {
        "vnd.affinidi.webvh": {
          "domains": { "kind": "all" }
        }
      }
    }
  }
}
```

## Worked example — `acl/grant` over DIDComm

The same envelope rides inside a DIDComm v2.1 message whose type is
`https://trusttasks.org/binding/didcomm/0.1/envelope` (see the
[trust-tasks-didcomm](https://github.com/trustoverip/dtgwg-trust-tasks-tf/tree/main/trust-tasks-didcomm)
binding spec). DIDComm carries authcrypt — the verified sender DID
becomes the in-band `issuer` automatically. Response packs back into
the same envelope type.

> **Note**: the `trust-tasks-*` crates are pre-publication at the
> time of v0.7.0. The workspace resolves them via `[patch.crates-io]`
> against an upstream sibling checkout until they land on crates.io
> — see the `[patch.crates-io]` block in the workspace
> [`Cargo.toml`](../Cargo.toml). The links in this document point at
> the upstream GitHub source meanwhile.

## Proof policy (v0.7.0)

The framework spec marks `acl/grant`, `acl/revoke`, and
`acl/change-role` as `proof: REQUIRED`. Under the upstream 0.1.1
framework adoption, that requirement is enforced **authoritatively
per-spec** — proofless documents are rejected with `proof_required`
regardless of consumer policy. The Web UI ships browser-side
Data Integrity signing (`eddsa-jcs-2022` cryptosuite, ephemeral
Ed25519 session keypair) so admin flows work end-to-end.

```toml
[trust_tasks]
enforce_proofs = true   # default in v0.7.0
```

- `true` (default) — [`ProofPolicy::Verify`](../did-hosting-common/src/server/trust_tasks/mod.rs):
  the maintainer verifies a present `proof` against the configured
  verifier (`affinidi-data-integrity` resolving `did:web` /
  `did:webvh` / `did:key`). Failure → `proof_invalid` on the wire.
  An absent `proof` on a REQUIRED spec → `proof_required`. This is
  the framework-correct shape; backend-only callers (CLI,
  service-to-service) that already sign their envelopes work
  out-of-the-box.

- `false` — [`ProofPolicy::RejectIfPresent`](../did-hosting-common/src/server/trust_tasks/mod.rs):
  proof-bearing documents are rejected with `malformed_request`
  (silently dropping a producer-supplied proof would mislead the
  producer about the integrity guarantees of the exchange). Useful
  during migration from v0.6 / legacy clients that have not yet
  rolled out signing. REQUIRED specs remain unreachable without
  flipping back to `true`.

The wire message under `false` + present proof is the framework-
shared sanitised constant `PROOF_NOT_ACCEPTED_BY_POLICY` ("in-band
proof not accepted by consumer policy (SPEC §7.2 item 7)"); the
operator-actionable diagnostic ("flip `enforce_proofs = true`")
lives in a `tracing::warn!` emitted by `dispatch_inbound` so an
unauth probe can't enumerate verifier coverage across a fleet.

## Web UI session-key flow

The Web UI shipped in v0.7.0 emits signed envelopes for REQUIRED
specs using an ephemeral Ed25519 session keypair, bound to the JWT
session at login. The flow:

1. **At `POST /api/auth/passkey/login/finish`:** the browser
   generates a fresh Ed25519 keypair via WebCrypto
   (`crypto.subtle.generateKey({ name: "Ed25519" })`), encodes the
   public key as an Ed25519 multikey (base58btc, `z6Mk…`), and
   sends it in the request body as `session_pubkey_b58btc`. The
   server stores the multikey on the session record
   (`Session.session_pubkey_b58btc`) alongside the JWT's session
   ID and token rotation state. The private key is held as a
   non-extractable `CryptoKey` and never leaves the browser tab.
2. **At `POST /api/trust-tasks` (REQUIRED specs):** the browser
   signs the envelope with the `eddsa-jcs-2022` cryptosuite —
   JCS-canonicalises (RFC 8785) the doc and proof config,
   SHA-256s each, concatenates, signs with the session private
   key, and base58btc-encodes the signature into
   `proof.proofValue`. The proof's `verificationMethod` is the
   `did:key:{multikey}#{multikey}` URL derived from the session
   pubkey.
3. **Server-side `dispatch_trust_task`:** reads
   `session_pubkey_b58btc` from `AuthClaims` (loaded from the
   session record by the JWT auth extractor). If present, asserts
   that the inbound `proof.verificationMethod` equals
   `did:key:{multikey}#{multikey}`; mismatch → `proof_invalid`
   rejection. Backend callers without a session pubkey (the
   `Option<String>` is `None`) skip this pre-check and authenticate
   solely via the proof's verificationMethod resolved against the
   caller's DID document.
4. **Framework verification:** the framework's `AffinidiVerifier`
   (already used to verify other Data Integrity proofs against
   `did:web` / `did:webvh` DID docs) verifies the signature against
   the `did:key` — no DID-doc lookup required for `did:key`, since
   the public key is embedded in the URL itself.

The keypair is persisted to IndexedDB (per-origin, structured-clone
of the `CryptoKey` wrapper — key material remains inside the browser
crypto layer) so it survives page reloads while the JWT is still
valid. Logout (`POST /api/auth/logout` or the UI's logout button)
clears both the JWT and the IndexedDB entry. Clearing site data via
the browser's settings does the same.

Operator implications:
- Make sure `auth.access_token_expiry` and the IDB-persisted keypair
  lifetime are aligned. If the JWT expires but the keypair persists,
  the next REQUIRED-spec request will fail at the bearer-JWT step
  (`401 Unauthorized`), and the UI's existing re-login redirect
  will kick in.
- Operators that run the UI against an older v0.6 server (the
  v0.7.0 → v0.8.0 deprecation overlap) should not set
  `enforce_proofs = true` until they have rolled out v0.7.0+
  to all UI clients — the v0.6 UI emits proofless envelopes.

## Discovery

The control plane advertises its supported types via
`trust-task-discovery/0.1`. To enumerate, POST:

```json
{
  "id": "urn:uuid:...",
  "type": "https://trusttasks.org/spec/trust-task-discovery/0.1",
  "payload": {}
}
```

The response declares `frameworkVersion: "0.1"` and includes the five
`acl/*` types. `acl/grant` and `acl/change-role` carry
`requiredExt: ["vnd.affinidi.webvh"]` so clients know our namespace is
expected. See
[trust-task-discovery/0.1](https://trusttasks.org/spec/trust-task-discovery/0.1)
for the response shape.

## Legacy route deprecation timeline

Every response from the legacy `/api/acl/*` routes now carries:

```
Deprecation: true
Sunset: Mon, 01 Dec 2026 00:00:00 GMT
Link: </api/trust-tasks>; rel="successor-version"
```

Server-side, each call also emits a structured `warn`-level log line
identifying the legacy route, caller DID, and successor URL. Operators
should grep their log stream for `legacy_route=` to find clients that
still need migration before v0.8.0.

## Error code mapping

| Standard code        | HTTP status | When                                                  |
|----------------------|-------------|-------------------------------------------------------|
| `malformed_request`  | 400         | Body did not parse / spec invariant violated          |
| `unsupported_type`   | 400         | Maintainer does not implement this type URI           |
| `permission_denied`  | 403         | Caller not Admin / role-change-attempted-via-grant    |
| `task_failed`        | 422         | Spec-extended condition (default for extension codes) |
| `internal_error`     | 500         | Backend failure                                       |

Spec-extended codes (`acl/grant:role_change_required`,
`acl/revoke:subject_not_present`,
`acl/revoke:last_authority_protected`,
`acl/change-role:state_mismatch`,
`acl/change-role:role_not_recognized`,
`acl/change-role:last_authority_protected`) all map to HTTP **422
Unprocessable Entity** with the extended code carried in
`payload.code` and structured context in `payload.details`. Parse
`payload.code` for application-layer handling; the HTTP status is
informative only.

## Sample client (Rust)

```rust
use trust_tasks_https::HttpsClient;
use trust_tasks_rs::{specs::acl::grant::v0_1 as grant, TrustTask};

let client = HttpsClient::builder()
    .base_url("https://control.example/api/trust-tasks")
    .bearer_token(jwt_token)
    .build()?;

let req = TrustTask::for_payload(
    format!("urn:uuid:{}", uuid::Uuid::new_v4()),
    grant::Payload {
        entry: grant::AclEntry {
            subject: "did:web:alice.example".into(),
            role: "owner".into(),
            // ... ext.vnd.affinidi.webvh.domains required for Owner
        },
        ..Default::default()
    },
);
let resp: TrustTask<grant::Response> = client.send(&req).await?;
```

See the
[trust-tasks-https](https://github.com/trustoverip/dtgwg-trust-tasks-tf/tree/main/trust-tasks-https)
crate docs for the typed client surface (pre-publication; see the
note above).

## Sample client (TypeScript / browser)

The webvh Web UI shipped in v0.7.0 uses the
`api.createAcl/updateAcl/aclShow/deleteAcl/listAcl` methods which now
internally POST trust-task envelopes. Two reference files:
- `did-hosting-ui/lib/api.ts` — typed translator between the wire
  shape and the UI's `AclEntry` type, plus the `trustTask()` helper
  that dispatches envelopes and signs REQUIRED specs.
- `did-hosting-ui/lib/session-key.ts` — `generateSessionKeypair()`,
  `signEnvelope()` (eddsa-jcs-2022), plus the IndexedDB persistence
  layer that survives page reloads. ~370 LOC, no npm deps beyond
  what the UI already pulls in (uses WebCrypto + inline JCS +
  inline base58btc).

Third-party browser clients that talk to `did-hosting-control`
directly (without the Web UI's framework) can lift `session-key.ts`
wholesale — it has no UI-specific dependencies.

## See also

- [SPEC.md](https://github.com/trustoverip/dtgwg-trust-tasks-tf/blob/main/SPEC.md) — Trust Tasks framework
- [acl/* registry entries](https://trusttasks.org/registry) — canonical wire shapes
- [`docs/trust-tasks-registry-gaps.md`](trust-tasks-registry-gaps.md) — webvh ops not yet in the registry
- [CHANGELOG.md](../CHANGELOG.md) — release notes
