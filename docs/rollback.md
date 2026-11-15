# Rollback playbook

> **Status:** current — covers the supported releases (N = 0.11, N-1 = 0.10) and the upgrade to 0.12; older paths are in [archive](archive/migrations/v0.6.0-to-v0.7.0.md)

How to step a deployment back to an earlier release, and how to undo an
assignment or purge without changing binaries at all. Read
[backup and upgrade](backup-and-upgrade.md) first: every rollback below that
crosses a minor release starts from a backup taken **before** the upgrade.

Releases are `major.minor`, each on its own `release/<major.minor>` branch
([RELEASES.md](../RELEASES.md)). The newest two GA releases are supported;
patches (`0.11.1`, …) only ever happen on the release branch and never change
the store format.

> Do every step in a maintenance window. Stop every process that reads or
> writes the target store before doing anything destructive — with fjall the
> store is exclusively locked anyway, and a restore into a store another
> process is writing is not supported.

## Which kind of rollback is this?

| From → to | What to do |
|---|---|
| A patch to an earlier patch of the same release (`0.11.2` → `0.11.1`) | [In-place binary swap](#patch-rollback-same-release). |
| N → N-1 (`0.11.x` → `0.10.x`) | [Minor rollback](#minor-rollback-n--n-1): config check, binary swap; restore only if a one-way step below applies. |
| `main` / 0.12 → 0.11 | [Rolling back from 0.12](#rolling-back-from-012): several one-way steps; plan on restoring. |
| Any release to v0.6 | Restore from a v0.6 backup — see the [archived v0.6 → v0.7 guide](archive/migrations/v0.6.0-to-v0.7.0.md). |
| A bad assignment, unassignment or purge | [No binary rollback](#recovering-an-assignment-or-purge). |

## Patch rollback (same release)

Patches do not change the schema, so a binary swap is safe:

1. Stop the service (`systemctl stop did-hosting-daemon`, or your unit).
2. Replace the binary.
3. `did-hosting-daemon --config config.toml health` — it exits non-zero on a
   failed check.
4. Start the service and resolve a known DID:
   `curl -sS https://<host>/<path>/did.jsonl | head -1`.

## Minor rollback (N → N-1)

0.11 changed the wire, not the store layout:

- **Trust Task versions.** 0.11 serves only the latest version of every Trust
  Task. Clients upgraded alongside it (the VTA, the console, other nodes) may
  send versions 0.10 does not serve; roll them back together, or expect
  `unsupportedType` refusals.
- **`trusted_proxies` takes CIDR ranges** in 0.11. Restore the 0.10 config file
  rather than reusing the 0.11 one.
- **`did:scid` aliases.** A DID that `identity-scid-alias list` gave an alias
  keeps it in its log; 0.10 serves the log as it is.

Steps:

1. Take a backup on 0.11 anyway (`backup`, below), and keep the 0.11 store
   directory aside.
2. Stop every node. For a distributed deployment, roll the **control plane**
   back last and start it first, so edges never talk to a newer control plane
   than they understand.
3. Install the 0.10 binaries and the 0.10 config files.
4. `health` each config, then start the services and resolve a known DID.

If 0.10 refuses to start or misbehaves against the 0.11 store, restore the
backup you took on 0.10 before upgrading.

## Rolling back from 0.12

0.12 (in development on `main`) has several one-way steps. If any of these
applied to your deployment, an in-place swap back to 0.11 is not enough —
restore the store from a backup taken on 0.11:

| Change in 0.12 | Effect on a rollback |
|---|---|
| **Cosmos DB single container.** On first start each per-keyspace container is copied once into `store.cosmosdb_container` (default `kv`). | 0.11 reads the old per-keyspace containers, which stopped receiving writes at the upgrade. Restore, or accept losing everything written since. Do not delete the old containers until you no longer need to roll back. |
| **Redis per-keyspace index** (`__index__:<keyspace>`), built once on open and marked done by the `__index_version__` key. | 0.11 ignores the index, so rolling back works, but 0.11 writes rows the index does not list. Before upgrading again, delete `__index_version__` and the `__index__:*` keys so 0.12 rebuilds the index. Never run 0.11 and 0.12 replicas against one database. |
| **Tiered statistics.** Legacy `ts:` rows are folded into the new rows at startup and deleted after 30 days. | 0.11 still reads `ts:` rows, but any deleted after 30 days are gone from its charts. Statistics only; DIDs are unaffected. When you upgrade again, the migration picks up `ts:` rows 0.11 wrote meanwhile. |
| **Refresh tokens stored as SHA-256 digests.** | 0.11 cannot redeem a session issued by 0.12: users sign in again. |
| **Daemon backup format.** `did-hosting-daemon backup` writes a daemon document (both stores and the config verbatim). | 0.11's `did-hosting-daemon restore` cannot read it. Keep a backup taken by 0.11 for a 0.11 restore. |
| **Strict config parsing.** | Nothing to undo; a 0.12 config without new keys loads on 0.11. |
| **Stats-sync and health payloads** follow the pinned specs (#469). | Roll the **edges back first**, then the control plane: a 0.11 control plane refuses a 0.12 edge's sync and pong, while a 0.12 control plane still reads a 0.11 edge's. |
| **DID record indexes** (`domain:` index and `usage:` rows, migration `m03_index_did_records`). | 0.11 ignores them but writes records without updating them. Before upgrading again, delete the `migration:applied:m03_index_did_records` row in the `meta` keyspace so 0.12 rebuilds them (the sweep is idempotent). Never run 0.11 and 0.12 control-plane replicas against one store. |
| **Outbox reference rows.** Queued rows are re-keyed when the 0.12 worker starts. | 0.11 does not understand the new rows. Let the outbox drain before rolling back (`did_hosting_replication_pending` at 0 for every target, in the admin gauges of `server/metrics/0.1`); anything left is re-derived on each edge's next registration. |

Restore with the backup tool of the release you are going back to, into an
empty store; see [backup and upgrade](backup-and-upgrade.md#restore).

## Recovering an assignment or purge

None of these need a binary rollback. Each is a Trust Task; send it from the
console (**Servers** and **Domains** pages) or with
`send-trust-task` (see [sending Trust Tasks](sending-trust-tasks.md); the
payloads are in the [catalogue](trust-tasks.md)). The signing key must be an
`admin` in the control plane's ACL.

### A domain was unassigned by mistake

An unassignment schedules a purge on the edge after
`hosting.unassigned_purge_grace` (default 2 h). Within the grace window,
assign it again — the edge cancels the pending purge:

```bash
did-hosting-control send-trust-task --key admin-key.json \
  --type domain/assign/0.1 \
  --payload '{"instanceId":"<instance-id>","domain":"<domain>"}'
```

Find the instance id with `registry/list/0.2`. A standalone edge runs the purge
sweep itself (every minute), as the daemon does, so once the grace has passed
the DIDs are gone from that edge. They are still on the control plane, which
holds the record: re-assign the domain and the edge is resynced. Only the
control plane's own copy needs a backup to recover.

### "Purge now" hit the wrong domain

`domain/purge/0.1` deletes every DID on the named domain from the control
plane immediately, with no grace (and from the edges, with `purgeServers`).
There is no in-place recovery: restore the control plane's store (or the
daemon's) from backup. Edges are then resynced from it.

`registry/purge-domain/0.1` (`{"instanceId", "domain"}`) purges one domain from
one edge only. The control plane still holds the DIDs: assign the domain to the
edge again to restore them.

### A deleted domain left DIDs behind

Run the purge once more:

```bash
did-hosting-control send-trust-task --key admin-key.json \
  --type registry/purge-domain/0.1 \
  --payload '{"instanceId":"<instance-id>","domain":"<domain>"}'
```

### A restore refuses a DID

A restore never rolls a DID's history back: each restored `did:webvh` (or
`did:webs`) log must verify, match its record, and extend both the backup's
own high-water mark and whatever the target store already holds for that DID.
If a DID changed after the backup was taken, the restore is refused and nothing
is written, not even `config.toml`. Restore into an empty store to start from
the backup's state; on an edge, prefer a resync from the control plane, which
sends each DID's current log. An interrupted restore is safe to run again.

## Audit trail

After any non-trivial rollback or recovery, record:

- the backup file used and the release that wrote it;
- times of stop, restore and start;
- the DIDs and their domains afterwards — the console's DID list, or
  `did/list/0.2`:

  ```bash
  did-hosting-control send-trust-task --key admin-key.json --type did/list/0.2 \
    | jq '.records[] | {mnemonic, domain}'
  ```

- the instances and their served domains (`registry/list/0.2`).

Attach these to the incident record.
