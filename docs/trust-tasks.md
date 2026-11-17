# Trust Task catalogue

> **Status:** current — generated from the control plane's routing tables; do not edit by hand.

<!-- Regenerate: UPDATE_TRUST_TASKS=1 cargo test -p did-hosting-control --lib trust_task_catalogue (see did-hosting-control/src/control_tasks/catalogue.rs). -->

Every management operation on a control plane (standalone `did-hosting-control`, or the one inside `did-hosting-daemon`) is a signed Trust Task, sent over TSP, DIDComm or `POST /api/trust-tasks`; all three reach the same dispatch. This page lists every task the control plane serves, the proof the gate requires before the task runs, and the standing its handler then requires of the proven signer. To send one yourself, see [Sending Trust Tasks](sending-trust-tasks.md).

Type URIs are `https://trusttasks.org/spec/<slug>/<version>`; the payload and response schemas are the vendored bundles in [`did-hosting-common/trust-tasks/`](../did-hosting-common/trust-tasks/), pinned by `did-hosting-common/trust-tasks.lock`.

**Proof rules** (`ProofRule`, enforced by the gate before any handler runs):

| Rule | Meaning |
| ---- | ------- |
| `Optional` | May be sent unsigned; a proof that is present must verify. |
| `Authentication` | Signed by the issuer for `authentication`, addressed here, fresh, not a replay. |
| `AssertionMethod` | A human approver's decision: signed for `assertionMethod`. |
| `SessionKey` | Signed by the `did:key` a passkey login ceremony is bound to. |
| `BoundKey(…)` | Wallet sign-in: signed by a fresh key the exchange itself binds; HTTPS only. |

**Standing**: "member" is any ACL entry except `metricsReader`; "admin" is the `admin` role. A destructive task sent with a browser session below `aal2` is refused `step_up_required`; a document authorised by its signer's own key (no session) is not.

## Management, sign-in and the service (`control_tasks!`)

The rows of the control plane's Trust Task table (`did-hosting-control/src/control_tasks/mod.rs`), in table order.

| Task | Version | Proof rule | Standing |
| ---- | ------- | ---------- | -------- |
| `did-management/did/check-name` | 0.1 | `Authentication` | member (a reservation is owned by the caller) |
| `did-management/did/register` | 0.1 | `Authentication` | member; owner or admin to update an existing slot; or a self-registering `did:webs` (`[[hosting.webs_self_register]]`) |
| `did-management/did/info` | 0.1 | `Authentication` | slot owner or admin |
| `did-management/did/list` | 0.2 | `Authentication` | member (own slots); admin to list another owner's |
| `did-management/did/delete` | 0.1 | `Authentication` | slot owner or admin; an `aal2` session over HTTPS when one is presented |
| `did-management/did/change-owner` | 0.1 | `Authentication` | slot owner or admin (the recipient accepts an owner's offer) |
| `did-management/did/set-state` | 0.1 | `Authentication` | slot owner or admin (an administrator's suspension only an administrator lifts) |
| `did-management/did/rollback` | 0.1 | `Authentication` | slot owner or admin |
| `did-management/did/log` | 0.1 | `Authentication` | slot owner or admin |
| `webvh/witness/publish` | 0.1 | `Authentication` | slot owner or admin |
| `did-management/agent-name/update` | 0.1 | `Authentication` | owner of the DID, or admin (with a new signed log) |
| `did-management/agent-name/remove` | 0.1 | `Authentication` | owner of the DID holding the name, or admin (with a new signed log) |
| `did-management/agent-name/list` | 0.1 | `Authentication` | member |
| `did-management/agent-name/check` | 0.1 | `Authentication` | member |
| `did-management/agent-name/resolve` | 0.1 | `Authentication` | member |
| `did-management/me/domains` | 0.1 | `Authentication` | member (the caller's own domains) |
| `did-management/domain/list` | 0.1 | `Authentication` | admin |
| `did-management/domain/create` | 0.1 | `Authentication` | admin |
| `did-management/domain/update` | 0.1 | `Authentication` | admin |
| `did-management/domain/set-state` | 0.1 | `Authentication` | admin |
| `did-management/domain/set-default` | 0.1 | `Authentication` | admin |
| `did-management/domain/purge` | 0.1 | `Authentication` | admin |
| `did-management/domain/assign` | 0.1 | `Authentication` | admin |
| `did-management/domain/unassign` | 0.1 | `Authentication` | admin |
| `did-management/registry/list` | 0.2 | `Authentication` | admin |
| `did-management/registry/get` | 0.2 | `Authentication` | admin |
| `did-management/registry/check` | 0.2 | `Authentication` | admin |
| `did-management/registry/admin-register` | 0.2 | `Authentication` | admin |
| `did-management/registry/deregister` | 0.1 | `Authentication` | admin |
| `did-management/registry/purge-domain` | 0.1 | `Authentication` | admin; an `aal2` session over HTTPS when one is presented |
| `did-management/server/info` | 0.1 | `Optional` | anyone (unsigned allowed) |
| `did-management/server/config` | 0.1 | `Authentication` | admin |
| `did-management/server/metrics` | 0.1 | `Authentication` | admin or `metricsReader` (gauges: admin only) |
| `did-management/stats/get` | 0.1 | `Authentication` | slot owner or admin (whole-service totals: admin) |
| `did-management/stats/set-resolution` | 0.1 | `Authentication` | slot owner (up to `coarse`) or admin |
| `did-management/stats/timeseries` | 0.2 | `Authentication` | slot owner or admin (domain series: admin) |
| `did-management/identity/list` | 0.1 | `Authentication` | admin |
| `did-management/identity/retire` | 0.1 | `Authentication` | admin; an `aal2` session over HTTPS when one is presented |
| `auth/step-up/start` | 0.2 | `Authentication` | the session's subject |
| `auth/step-up/approve-response` | 0.7 | `AssertionMethod` | the approver named in the step-up request (an ACL member) |
| `auth/revoke-session` | 0.2 | `Authentication` | the session's subject |
| `auth/passkey/login/start` | 0.2 | `Optional` | anyone (unsigned allowed) |
| `auth/passkey/login/finish` | 0.2 | `SessionKey` | the `did:key` the login ceremony is bound to; the passkey's subject must be in the ACL |
| `auth/passkey/enroll/invite` | 0.3 | `Authentication` | admin, with an `aal2` session or a request signed by the admin's own DID key |
| `auth/passkey/enroll/redeem/start` | 0.1 | `Optional` | the invite token and claim code (unsigned allowed) |
| `auth/passkey/enroll/redeem/finish` | 0.1 | `Optional` | the invite token and claim code (unsigned allowed) |
| `auth/passkey/enroll/start` | 0.2 | `Authentication` | member, for themselves |
| `auth/passkey/enroll/finish` | 0.2 | `Authentication` | member, for themselves |
| `auth/passkey/enroll/invite/list` | 0.1 | `Authentication` | member (own invites); admin (all) |
| `auth/passkey/enroll/invite/update` | 0.1 | `Authentication` | admin |
| `auth/passkey/enroll/invite/revoke` | 0.1 | `Authentication` | admin |
| `auth/passkey/list` | 0.1 | `Authentication` | member (own passkeys) |
| `auth/passkey/admin-list` | 0.1 | `Authentication` | admin |
| `auth/passkey/revoke/start` | 0.2 | `Authentication` | member (own passkeys); admin (anyone's) |
| `auth/passkey/revoke/finish` | 0.2 | `Authentication` | member (own passkeys); admin (anyone's) |
| `auth/oob/request` | 0.2 | `BoundKey(authentication, assertionMethod)` | the browser's starter key `K_b` (HTTPS only) |
| `auth/oob/claim` | 0.2 | `BoundKey(authentication, assertionMethod)` | the wallet's lock key `K_a` (HTTPS only) |
| `auth/oob/prove` | 0.3 | `BoundKey(authentication, assertionMethod)` | `K_a`, carrying the member's `identify` (HTTPS only) |
| `auth/oob/respond` | 0.3 | `BoundKey(authentication, assertionMethod)` | `K_a`, carrying the member's `grant` (HTTPS only) |
| `auth/oob/redeem` | 0.2 | `BoundKey(authentication, assertionMethod)` | `K_b` (HTTPS only) |
| `auth/oob/cancel` | 0.1 | `BoundKey(authentication, assertionMethod)` | `K_a` or `K_b` (HTTPS only) |

## ACL and discovery

Served by the shared framework pipeline (`did_hosting_common::server::trust_tasks::ACL_TASK_URIS`).

| Task | Version | Proof rule | Standing |
| ---- | ------- | ---------- | -------- |
| `acl/grant` | 0.2 | `Authentication` | admin |
| `acl/revoke` | 0.2 | `Authentication` | admin, or the subject revoking itself |
| `acl/change-role` | 0.2 | `Authentication` | admin |
| `acl/show` | 0.2 | `Authentication` | admin, or the subject looking itself up |
| `acl/list` | 0.3 | `Authentication` | admin |
| `trust-task-discovery` | 0.4 | `Optional` | anyone (unsigned allowed) |

## Console sign-in

The challenge / response sign-in the management UI uses (`did-hosting-control/src/trust_tasks_auth.rs`). Each handler checks its own proof against the challenge it issued.

| Task | Version | Proof rule | Standing |
| ---- | ------- | ---------- | -------- |
| `auth/authenticate` | 0.3 | `Optional` | an ACL member answering its challenge |
| `auth/challenge` | 0.1 | `Optional` | anyone (unsigned allowed) |
| `auth/refresh` | 0.2 | `Optional` | the holder of the session's refresh token and bound key |

## Infrastructure (from edges and watchers)

What an edge or watcher sends the control plane (`did-hosting-control/src/messaging/infra/mod.rs`): its registration, health and stats, and the signed acknowledgements that settle the control plane's outbox rows. Operators never send these.

| Task | Version | Proof rule | Standing |
| ---- | ------- | ---------- | -------- |
| `did-management/server/register` | 0.2 | `Authentication` | an edge with the `service` role |
| `did-management/server/health`#response | 0.1 | `Authentication` | a registered edge (`service`) |
| `did-management/server/stats-sync` | 0.1 | `Authentication` | a registered edge (`service`) |
| `webvh/sync/update`#response | 0.2 | `Authentication` | the edge or watcher the update was sent to |
| `webvh/sync/batch`#response | 0.1 | `Authentication` | the edge or watcher the batch was sent to |
| `webvh/sync/delete`#response | 0.2 | `Authentication` | the edge or watcher the delete was sent to |
| `did-management/replica/domain/assign`#response | 0.1 | `Authentication` | the edge the op was sent to (`service`) |
| `did-management/replica/domain/unassign`#response | 0.1 | `Authentication` | the edge the op was sent to (`service`) |
| `did-management/replica/domain/purge`#response | 0.1 | `Authentication` | the edge the op was sent to (`service`) |
| `did-management/replica/domain/upsert`#response | 0.1 | `Authentication` | the edge the op was sent to (`service`) |
