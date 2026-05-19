# Trust Tasks registry gaps — webvh ops not yet upstream

This document catalogues the wire operations the webvh control plane
emits today that are **not** covered by the public
[Trust Tasks registry](https://trusttasks.org/registry). For each gap
we note the proposed registry slug, the participating parties, the
proof requirement, and a payload sketch. Filing these upstream lets
other implementations interoperate with us; keeping them in our house
namespace (`https://trusttasks.org/did-hosting/...` and
`https://trusttasks.org/webvh/...` per
[multi-method-hosting-spec.md §3](multi-method-hosting-spec.md))
works as a stopgap.

Status legend:

- 🟢 **Reusable**: pattern repeats across DID-hosting ecosystems;
  strong candidate for the public registry.
- 🟡 **Domain-flavoured**: webvh-specific naming but the structure is
  reusable.
- 🔴 **House-namespace**: webvh-specific shape unlikely to interest
  other ecosystems; better kept in `trusttasks.org/did-hosting/...`.

## Group 1 — DID provisioning lifecycle 🟢

The end-to-end "claim a DID slot, write the log, confirm landing"
exchange. Proposed family: `did-provisioning/*`.

| Op                       | Slug                              | Parties                                  | Proof    |
|--------------------------|-----------------------------------|------------------------------------------|----------|
| Request a slot           | `did-provisioning/request/0.1`    | Tenant, Provisioner                      | REQUIRED |
| Offer a slot             | `did-provisioning/offer/0.1`      | Provisioner, Tenant                      | REQUIRED |
| Publish the initial log  | `did-provisioning/publish/0.1`    | Tenant, Provisioner                      | REQUIRED |
| Confirm landing          | `did-provisioning/confirm/0.1`    | Provisioner, Tenant                      | REQUIRED |
| Atomic request + publish | `did-provisioning/register/0.1`   | Tenant, Provisioner                      | REQUIRED |
| Confirm atomic register  | `did-provisioning/register-confirm/0.1` | Provisioner, Tenant                | REQUIRED |
| Query DID info           | `did-provisioning/info-request/0.1`     | Owner, Provisioner                 | RECOMMENDED |
| Return DID info          | `did-provisioning/info/0.1`             | Provisioner, Owner                 | OPTIONAL |
| List owned DIDs          | `did-provisioning/list-request/0.1`     | Owner, Provisioner                 | RECOMMENDED |
| Return DID list          | `did-provisioning/list/0.1`             | Provisioner, Owner                 | OPTIONAL |
| Delete a DID             | `did-provisioning/delete/0.1`           | Owner, Provisioner                 | REQUIRED |
| Confirm deletion         | `did-provisioning/delete-confirm/0.1`   | Provisioner, Owner                 | REQUIRED |
| Change owner             | `did-provisioning/change-owner/0.1`     | Old owner, Provisioner             | REQUIRED |
| Confirm change-owner     | `did-provisioning/change-owner-confirm/0.1` | Provisioner, Old + New owners  | REQUIRED |
| Problem report           | `did-provisioning/problem-report/0.1`   | Provisioner, Initiator             | OPTIONAL |

Payload sketches:

```yaml
# did-provisioning/request/0.1
type: object
required: [path]
properties:
  path: { type: string, description: "Provisioner-relative slot path" }
  method: { type: string, enum: [webvh, web, webs, webplus] }
  ext: { $ref: "framework.schema.json#/$defs/Ext" }
```

```yaml
# did-provisioning/publish/0.1
type: object
required: [didLog]
properties:
  didLog: { type: string, contentMediaType: "application/jsonl" }
  ext: { $ref: "framework.schema.json#/$defs/Ext" }
```

## Group 2 — DID:webvh append-only log specifics 🔴

Genuinely webvh-protocol-specific; stays in `webvh/*` house namespace.
Listing here for completeness so a future implementer can find them.

| Op                  | Current URL                                                     | Note |
|---------------------|-----------------------------------------------------------------|------|
| Witness publish     | `https://trusttasks.org/webvh/did/witness-publish/1.0`          | Witness co-signs a log entry; webvh-specific. |
| Witness confirm     | `https://trusttasks.org/webvh/did/witness-confirm/1.0`          |  |
| Sync update         | `https://trusttasks.org/webvh/did/sync-update/1.0`              | Control plane → server log-tail sync. |
| Sync update ack     | `https://trusttasks.org/webvh/did/sync-update-ack/1.0`          |  |
| Sync delete         | `https://trusttasks.org/webvh/did/sync-delete/1.0`              |  |
| Sync delete ack     | `https://trusttasks.org/webvh/did/sync-delete-ack/1.0`          |  |

## Group 3 — Service mesh 🟢

Service registration + health pinging + stats sync — recurring
patterns in any multi-instance deployment, not webvh-specific.
Proposed family: `service-mesh/*`.

| Op                | Slug                                | Parties              | Proof    |
|-------------------|-------------------------------------|----------------------|----------|
| Register self     | `service-mesh/register/0.1`         | Service, Coordinator | REQUIRED |
| Acknowledge       | `service-mesh/register-ack/0.1`     | Coordinator, Service | REQUIRED |
| Health ping       | `service-mesh/health-ping/0.1`      | Coordinator, Service | OPTIONAL |
| Health pong       | `service-mesh/health-pong/0.1`      | Service, Coordinator | OPTIONAL |
| Stats sync        | `service-mesh/stats-sync/0.1`       | Service, Coordinator | RECOMMENDED |
| Stats ack         | `service-mesh/stats-ack/0.1`        | Coordinator, Service | OPTIONAL |

```yaml
# service-mesh/register/0.1
type: object
required: [serviceType, url]
properties:
  serviceType: { type: string }
  url: { type: string, format: uri }
  protocolVersion: { type: string }
  capabilities: { type: array, items: { type: string } }
  ext: { $ref: "framework.schema.json#/$defs/Ext" }
```

## Group 4 — Tenant admin (domains) 🟢

webvh's multi-domain ops are an instance of the broader
"resource×CRUD with assign/unassign+ack" pattern. Proposed family:
`tenant-admin/*` — or split as `tenant-admin/resource/*` once we know
what else lives there.

| Op                  | Slug                                       | Parties        | Proof    |
|---------------------|--------------------------------------------|----------------|----------|
| List resources      | `tenant-admin/resource/list/0.1`           | Admin, Tenant  | RECOMMENDED |
| Create resource     | `tenant-admin/resource/create/0.1`         | Admin, Tenant  | REQUIRED |
| Update resource     | `tenant-admin/resource/update/0.1`         | Admin, Tenant  | REQUIRED |
| Disable resource    | `tenant-admin/resource/disable/0.1`        | Admin, Tenant  | REQUIRED |
| Set default         | `tenant-admin/resource/set-default/0.1`    | Admin, Tenant  | REQUIRED |
| Purge resource      | `tenant-admin/resource/purge/0.1`          | Admin, Tenant  | REQUIRED |
| Assign to instance  | `tenant-admin/resource/assign/0.1`         | Admin, Instance | REQUIRED |
| Assign ack          | `tenant-admin/resource/assign-ack/0.1`     | Instance, Admin | REQUIRED |
| Unassign            | `tenant-admin/resource/unassign/0.1`       | Admin, Instance | REQUIRED |
| Unassign ack        | `tenant-admin/resource/unassign-ack/0.1`   | Instance, Admin | REQUIRED |
| List my access      | `tenant-admin/me/resources/0.1`            | Caller, Tenant  | RECOMMENDED |

`resource` is a placeholder — the framework could parameterise the
sub-slug (`tenant-admin/<resource-type>/<verb>/<ver>`) to make
domain-vs-tenant-vs-quota a single registered family.

## Group 5 — DID-based session auth + passkey 🟢

The DIDComm-challenge-response + WebAuthn-bootstrap shape is heavily
reusable. Proposed families: `did-auth/*` and (optionally)
`passkey/*`.

| Op                       | Slug                                  | Parties      | Proof    |
|--------------------------|---------------------------------------|--------------|----------|
| Challenge                | `did-auth/challenge/0.1`              | Caller, Issuer | OPTIONAL |
| Authenticate (sign)      | `did-auth/authenticate/0.1`           | Caller, Issuer | REQUIRED |
| Authenticate response    | `did-auth/authenticate-response/0.1`  | Issuer, Caller | REQUIRED |
| Refresh                  | `did-auth/refresh/0.1`                | Caller, Issuer | OPTIONAL |
| Passkey enroll start     | `passkey/enroll-start/0.1`            | Caller, Issuer | OPTIONAL |
| Passkey enroll finish    | `passkey/enroll-finish/0.1`           | Caller, Issuer | REQUIRED (WebAuthn) |
| Passkey login start      | `passkey/login-start/0.1`             | Caller, Issuer | OPTIONAL |
| Passkey login finish     | `passkey/login-finish/0.1`            | Caller, Issuer | REQUIRED (WebAuthn) |
| Passkey invite           | `passkey/invite/0.1`                  | Admin, Inviter | REQUIRED |

```yaml
# did-auth/challenge/0.1
type: object
properties:
  ext: { $ref: "framework.schema.json#/$defs/Ext" }
# Response: { challenge: string<base64url>, expiresAt: string<date-time> }
```

```yaml
# did-auth/authenticate/0.1
type: object
required: [challenge]
properties:
  challenge: { type: string, format: base64url }
  ext: { $ref: "framework.schema.json#/$defs/Ext" }
# Proof binds the challenge → caller DID; response is a session token bundle.
```

The WebAuthn variants would carry the standard `PublicKeyCredentialOptions`
shape as opaque blobs since they are already
[normatively defined elsewhere](https://w3c.github.io/webauthn/).

## Group 6 — Per-DID admin ops 🟡

Method-agnostic-ish (`disable`, `enable`, `rollback`) plus
webvh-flavoured ones (`raw-log`, `log`). Proposed family:
`did-admin/*`.

| Op           | Slug                          | Parties        | Proof    |
|--------------|-------------------------------|----------------|----------|
| Check name   | `did-admin/check-name/0.1`    | Caller, Issuer | OPTIONAL |
| Get log      | `did-admin/log/0.1`           | Owner, Issuer  | RECOMMENDED |
| Disable      | `did-admin/disable/0.1`       | Owner, Issuer  | REQUIRED |
| Enable       | `did-admin/enable/0.1`        | Owner, Issuer  | REQUIRED |
| Rollback     | `did-admin/rollback/0.1`      | Owner, Issuer  | REQUIRED |
| Get raw log  | `did-admin/raw-log/0.1`       | Owner, Issuer  | RECOMMENDED |

Method-specific concerns (webvh's `raw-log` returning the jsonl
verbatim) can live in `ext.vnd.*` namespaces.

## Group 7 — Observability 🔴

Pure house-namespace; numeric APIs unlikely to interest other
ecosystems. Listed for completeness.

| Op                  | Current URL                                            |
|---------------------|--------------------------------------------------------|
| Server stats        | `https://trusttasks.org/did-hosting/stats/server/1.0`  |
| DID stats           | `https://trusttasks.org/did-hosting/stats/did/1.0`     |
| Server time-series  | `https://trusttasks.org/did-hosting/timeseries/server/1.0` |
| DID time-series     | `https://trusttasks.org/did-hosting/timeseries/did/1.0` |
| Services overview   | `https://trusttasks.org/did-hosting/services/overview/1.0` |
| Config              | `https://trusttasks.org/did-hosting/config/1.0`        |

## Group 8 — Registry admin 🔴

Admin's CRUD over the service registry table. House-namespace; could
fold into the `tenant-admin/resource/*` family if we extract the
parameterised resource type.

| Op                | Current URL                                              |
|-------------------|----------------------------------------------------------|
| List              | `https://trusttasks.org/did-hosting/registry/list/1.0`   |
| Get               | `https://trusttasks.org/did-hosting/registry/get/1.0`    |
| Admin-register    | `https://trusttasks.org/did-hosting/registry/admin-register/1.0` |
| Deregister        | `https://trusttasks.org/did-hosting/registry/deregister/1.0` |
| Health            | `https://trusttasks.org/did-hosting/registry/health/1.0` |

## Filing approach

For each Tier 🟢 group:

1. **Open an RFC issue** on
   `trustoverip/dtgwg-trust-tasks-tf` with the family proposal, party
   roles, proof requirements, and a few worked examples. This is the
   pre-PR discussion seam.
2. **Draft `specs/<slug>/0.1/spec.md` + `payload.schema.json`** in a
   feature branch. The `did-provisioning/*` and `service-mesh/*`
   families have the highest reuse value and should land first.
3. **Bump version on `webvh-service` URLs once upstream lands.** The
   `did_hosting_tasks` module's `LazyLock<TrustTask>` constants are
   the single edit point; both the REST + DIDComm dispatch tables
   resolve them by reference.

The Tier 🔴 groups stay in our house namespace indefinitely unless
another ecosystem implementor signals interest.

## See also

- [`docs/trust-tasks-acl-migration.md`](trust-tasks-acl-migration.md) — client-facing migration for the `acl/*` family (already in the registry)
- [`docs/multi-method-hosting-spec.md`](multi-method-hosting-spec.md) — the `webvh/*` vs. `did-hosting/*` URL convention
- [`did-hosting-common/src/did_hosting_tasks.rs`](../did-hosting-common/src/did_hosting_tasks.rs) — the registered URL constants
