# Backup, restore and upgrade

> **Status:** current

What to back up for each binary, how to restore it, and how to move between
releases. For stepping *back* to an earlier release, see the
[rollback playbook](rollback.md).

## What state each node holds

| Node | Store | Secrets backend | Can it be rebuilt without a backup? |
|---|---|---|---|
| `did-hosting-control` | **Authoritative**: DID records and logs, the agent-name registry, domains and assignments, the ACL, login and step-up passkeys, identity generations, did:scid floors, the registry, the outbound queue, statistics | Its own keys (current and retired generations), VTA credential | **No.** This is the source of record. |
| `did-hosting-daemon` | All of the above in `[store]`, plus the witness's ACL and witness identities in `[witness_store]` | As above | **No.** |
| `did-hosting-server` (edge) | A cache of what its control plane sent it, plus its own DID's slot | Its own keys | **Yes**, the cache is: a fresh edge with the same identity registers and is resynced. Its keys are not. |
| `webvh-witness` | Its ACL and the witness identities it signs with | Its own keys | No — the witness identities' keys are its state. |
| `webvh-watcher` | Mirrored DIDs | Its own keys | Mostly: it is re-fed by its sources. |

Two things are never in a store backup:

- **Service keys.** Every node's signing and key-agreement keys (and the keys of
  retired identity generations still inside their grace period) live in the
  configured secrets backend, not the store. Back them up with that backend's
  own mechanism (version history in AWS / GCP / Azure / Vault, a backed-up
  Kubernetes Secret). The OS keyring is not a backup target; a node whose keys
  live only in a host keyring is lost with the host. To move a node's identity
  to another host, use `export-sealed` on the old host and `import-sealed` on
  the new one (server, control, witness), or `import-secrets` from a VTA bundle.
- **Live sign-in sessions and refresh tokens.** Users sign in again after a
  restore. (Passkey credentials *are* kept.)

## Backup

### Daemon

```bash
did-hosting-daemon --config config.toml backup --output daemon-backup.json
```

A daemon backup carries both stores (every keyspace except the TSP relationship
state, which the next handshake re-establishes) and the configuration file
byte for byte. The tool prints what it left out and why. Since 0.12 this is a
`did-hosting-daemon` document of its own; a daemon backup written by an earlier
release is in the edge's format and is refused by `did-hosting-daemon restore`,
so take a fresh backup after upgrading.

### Edge

```bash
did-hosting-server --config config.toml backup --output edge-backup.json
```

An edge backup (format v3) carries its config and the `dids`, `stats`,
`domains`, `assignments`, `pending_purges`, `registry`, `timeseries`, `meta` and
`witnesses` keyspaces. It is rarely needed: the control plane can resync an
edge from scratch.

Both commands write the file with mode `0600`. It still holds DID logs, the
configuration and (for the daemon) the ACL and passkey credentials unencrypted:
keep it as you keep the service's secrets. `--output -` writes to stdout.

### Control plane, witness, watcher

These binaries have no `backup` command; back up their store directly:

| Backend | Consistent backup |
|---|---|
| fjall (default) | Stop the service (the store is exclusively locked, and a copy of a live directory is not consistent), copy `store.data_dir`, start it again. |
| Redis | RDB snapshot or AOF of the database. |
| DynamoDB | Point-in-time recovery or on-demand backups of every `<table_prefix>_*` table. |
| Firestore | A managed export of the database. |
| Cosmos DB | Continuous or periodic backup of the account; every keyspace is in one container (`store.cosmosdb_container`). |

The control plane is the one store you cannot do without: back it up on a
schedule and before every upgrade.

## Restore

```bash
did-hosting-daemon --config config.toml restore --input daemon-backup.json
did-hosting-server --config config.toml restore --input edge-backup.json
```

- Stop the service first.
- The backup is checked before anything is written, `config.toml` included.
  Each `did:webvh` (or `did:webs`) log must verify, match its record, and extend
  both the backup's own high-water mark and whatever the target store already
  holds for that DID. If any DID fails, nothing is restored.
- So a restore **never rolls a DID's history back** in a store that has moved
  on. To return to the backup's state, restore into an **empty** store.
- The data goes into the store the backup's config names, after the usual
  environment overrides (`DAEMON_STORE_DATA_DIR`, `DID_HOSTING_STORE_DATA_DIR`,
  …). Check it is the store you mean.
- An interrupted restore is safe to run again.
- For an edge, a resync from the control plane is usually better than a
  restore: start it with an empty store and its existing keys, and its first
  registration pulls every DID it should serve.

For the control plane, witness and watcher, restore the store with the backend's
own tool (for fjall, put the copied directory back with the service stopped).

## Upgrade

Releases are `major.minor` ([RELEASES.md](../RELEASES.md)); a patch never
changes the store format, a minor release may. Before a minor upgrade:

1. **Read the release's changelog** for `Breaking` entries.
2. **Back up** every authoritative store (control plane or daemon, witness) and
   keep the previous binaries.
3. **Check every config against the new binary**:
   `<new-binary> --config config.toml health`. Configs are parsed strictly — an
   unknown key stops the service — and `health` names the offending key; it
   exits non-zero on a failed check (`--strict` also fails on warnings).
4. **Upgrade.** For a distributed deployment upgrade the control plane and its
   edges in one window. Store migrations run automatically at startup (M-01,
   M-02, the statistics-tier fold, the outbox re-key, and the per-backend steps
   below); a migration that has to defer records stays pending and retries on
   the next start rather than being marked done.
5. **Verify**: `/api/health` on each node, resolve a known DID, and check the
   console's **Servers** page (or `registry/list/0.2`) shows every edge.

### Upgrading to 0.12

| Change | What to do |
|---|---|
| Strict config parsing; strict boolean env vars | Run `health` with the new binary against each config first. One config file shared by two binaries no longer loads. |
| `features.rest_api` renamed `features.http_listener` | Optional: the old name still works. |
| Default backup file and VTA context renamed (`did-hosting-backup.json`, `did-hosting`) | Pass `--output` / `--context` to keep the old names. |
| Cosmos DB: one container for every keyspace | On first start each old per-keyspace container is copied once into `store.cosmosdb_container` (default `kv`, partition key `/pk`). **Start one upgraded replica alone** so the copy finishes before others write. The old containers are left for you to delete once you no longer need to roll back. The shared logical partition is capped by Cosmos DB at 20 GB. |
| Redis: per-keyspace index | Built once when the store opens. **Upgrade every replica sharing the database together**; an old replica writes rows the index does not list. |
| DynamoDB: new tables are on-demand | Set `store.dynamodb_billing_mode = "provisioned:<r>:<w>"` for provisioned tables, or `store.dynamodb_auto_create = false` if tables are pre-provisioned and the service has no `dynamodb:CreateTable`. |
| Tiered statistics | Automatic: legacy `ts:` rows are folded into the new rows a flush at a time, and deleted after 30 days (`stats-purge-legacy` deletes them at once). |
| Daemon backup format | Take a fresh `did-hosting-daemon backup` after upgrading. |
| Refresh tokens stored hashed | Existing sessions keep working. |
| **Breaking:** stats sync and health pings follow their pinned specs (#469) | **Upgrade the control plane before its edges.** A 0.12 control plane still reads a 0.11 edge's sync and pong (until 0.13); a 0.11 control plane refuses a 0.12 edge's, so its stats go uncounted and it ages to `Unreachable`. |
| DID record indexes (`m03_index_did_records`) | Automatic: the control plane and daemon build the per-domain index and per-owner `usage:` rows at first boot; a control plane that cannot run the migration does not start. **Upgrade control-plane replicas that share a store together**: an old replica writes records without updating these rows. |

### Older upgrades

Upgrading from v0.6 to v0.7 is covered by the
[archived migration guide](archive/migrations/v0.6.0-to-v0.7.0.md). Releases
before 0.10 are end of life: upgrade to a supported release first.

## Which store backends are production-ready

| Backend | Tested in CI | Notes |
|---|---|---|
| fjall | Full unit suite and the store conformance suite, every PR | Default. Single process per data directory; size memory with `[fjall]` ([bootstrap guide](bootstrap_startup.md#fjall-memory-settings-store-fjall-only)). |
| Redis | Conformance suite against a real Redis, every PR | Upgrade all replicas sharing a database together. |
| DynamoDB | Conformance suite against DynamoDB Local, every PR | A batch over DynamoDB's transaction bound is refused, not split. |
| Cosmos DB | Conformance suite against the SDK's in-memory emulator, every PR | One logical partition (20 GB cap). |
| Firestore | Conformance suite against the Firestore emulator, nightly (`store-emulators.yml`) | Built, not tested, on PRs. |

The conformance suite (`server::store::conformance`) covers round trips,
byte-exact prefix scans, paging, atomic batches across keyspaces, `take`,
`incr` and compare-and-swap under contention, and the per-item limit. Only fjall
runs the rest of the test suite, so the cloud backends are exercised by
conformance and by the code paths that share it, not by end-to-end tests.
