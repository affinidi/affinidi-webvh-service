# Trust Tasks ACL — client migration guide (v0.7.1 → v0.8.0)

v0.7.1 introduces a new wire surface for ACL administration based on the
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
  with `acl/revoke:last_authority_protected`. Same guard fires on
  `acl/change-role` demoting the last admin.
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
    "reason": "Onboarding new admin contractor"
  }
}
```

The `issuer`/`recipient` are omitted in this example because the
bearer JWT pins the caller end-to-end (SPEC.md §4.8.1 falls back to
transport-derived identity when in-band is absent). On success, the
response carries:

```json
{
  "id": "urn:uuid:9b3c5e2a-1b81-4d3e-9b51-7a3c89e3d1f3",
  "type": "https://trusttasks.org/spec/acl/grant/0.1#response",
  "threadId": "urn:uuid:8a91c7b3-2e62-4a91-a3a4-9d61b75e2f01",
  "issuer": "did:web:control.example",
  "recipient": "did:web:alice.example",
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
[trust-tasks-didcomm](https://crates.io/crates/trust-tasks-didcomm)
binding spec). DIDComm carries authcrypt — the verified sender DID
becomes the in-band `issuer` automatically. Response packs back into
the same envelope type.

## Proof policy (v0.7.1)

The framework spec marks `acl/grant`, `acl/revoke`, and
`acl/change-role` as `proof: REQUIRED`. v0.7.1 ships a **config flag**
that gates strict enforcement so the Web UI (no in-browser signing
infrastructure today) keeps working:

```toml
[trust_tasks]
enforce_proofs = false   # default in v0.7.1
```

- `false` (default): a present `proof` is ignored; an absent `proof`
  on a non-bearer spec is accepted. Bearer JWT (HTTPS) or authcrypt
  (DIDComm) is the authentication source.
- `true`: the maintainer verifies a present `proof`; an absent
  `proof` on a non-bearer spec is rejected with `proof_required`.

Operators with **backend-only callers** (CLI, service-to-service)
should flip the flag to `true`. v0.8.0 ships either the session-key
protocol that lets the Web UI sign too, or makes the flag mandatory.
Track [the v0.8.0 milestone](../CHANGELOG.md) for the decision.

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
`acl/change-role:role_not_recognized`) all map to HTTP **422
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

See the [trust-tasks-https](https://crates.io/crates/trust-tasks-https)
crate docs for the typed client surface.

## Sample client (TypeScript / browser)

The webvh Web UI shipped in v0.7.1 uses the
`api.createAcl/updateAcl/aclShow/deleteAcl/listAcl` methods which now
internally POST trust-task envelopes. See
`did-hosting-ui/lib/api.ts` for the reference TypeScript translator
between the wire shape and the existing `AclEntry` type.

## See also

- [SPEC.md](https://github.com/trustoverip/dtgwg-trust-tasks-tf/blob/main/SPEC.md) — Trust Tasks framework
- [acl/* registry entries](https://trusttasks.org/registry) — canonical wire shapes
- [`docs/trust-tasks-registry-gaps.md`](trust-tasks-registry-gaps.md) — webvh ops not yet in the registry
- [CHANGELOG.md](../CHANGELOG.md) — release notes
