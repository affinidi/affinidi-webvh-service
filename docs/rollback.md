# Rollback playbook

Recovery procedure for operators who need to step a deployment
back to an earlier release. The most common scenarios — and what
this doc covers — are:

1. **Roll back v0.7 → v0.6** after the multi-domain migration
   has run. **Forward-migrated stores cannot be downgraded**;
   restore-from-backup is mandatory.
2. **Roll back a future v0.7 point release** (e.g. v0.7.x → v0.7.0).
   In-place binary swap is safe; no migration to undo.
3. **Recover from a failed multi-domain assignment / purge**
   without rolling back the binary at all.

> Run every step under a maintenance window. Stop every daemon
> reading or writing the target data directory before doing
> anything destructive. Multi-process contention on a restore is
> not supported.

## Scenario 1: v0.7 → v0.6 (major rollback)

### Why a restore is mandatory

The v0.7 daemon runs the **M-01 migration** on first boot, which
adds the `domain` field to every `DidRecord`. The v0.6 binary's
`DidRecord` deserialiser doesn't know about that field; serde
will tolerate the unknown key on most platforms but the absence
of the multi-domain enforcement code in v0.6 means resolves
fail in subtle ways. **Don't trust an in-place downgrade — use
the backup.**

### Steps

1. **Stop every v0.7 binary** writing to the data directory:

   ```sh
   systemctl stop did-hosting-daemon          # or your unit name
   ```

2. **Move the v0.7 data directory aside** (don't delete — you
   may need it for forensics):

   ```sh
   mv /var/lib/did-hosting/store /var/lib/did-hosting/store.v0.7
   ```

3. **Restore the most recent v0.6 backup**:

   ```sh
   webvh-server restore --input /var/backups/did-hosting/2026-05-17.json
   # Or, if you took a directory-level snapshot:
   tar -xzf /var/backups/did-hosting/2026-05-17.tar.gz \
       -C /var/lib/did-hosting/
   ```

4. **Install the v0.6 binary** alongside (don't overwrite v0.7
   yet — keep both available until verified):

   ```sh
   cp ./bin/webvh-server-0.6.0 /usr/local/bin/webvh-server
   cp ./bin/webvh-control-0.6.0 /usr/local/bin/webvh-control
   ```

5. **Restore the v0.6 config**. The v0.7 config has new fields
   (`[hosting]`, `server.trusted_proxy_cidrs`) that v0.6's
   parser doesn't recognise. Restore from the pre-upgrade
   config backup or strip the new keys manually.

6. **Start v0.6** and verify:

   ```sh
   systemctl start did-hosting-daemon
   curl -sS "https://example.com/<known-mnemonic>/did.jsonl" | head -5
   ```

7. **Once verified**, archive the v0.7 store directory and
   binaries. Don't delete them — the operations team may need
   them for post-incident review.

### What if you don't have a v0.6 backup

You're stuck on v0.7. The v0.7 daemon is stable on every
verified migration path; if the rollback was triggered by a
specific bug, file an issue and we'll cut a point release.
**Don't attempt to hand-edit DID records back to the v0.6
shape** — the M-01 migration touches every row, and a partial
revert leaves the store in an unanchored state.

## Scenario 2: v0.7.x point rollback

In-place binary swap. No migration to undo (point releases don't
change the schema).

1. Stop the daemon.
2. Replace the binary with the older one.
3. Start the daemon.
4. Verify resolves with `curl`.

The store format is forward-compatible within v0.7.x. v0.7.0
reads later-v0.7.x stored records fine — the only schema
additions within the v0.7 line are `#[serde(default)]` and
deserialise back to defaults.

## Scenario 3: Failed assignment / purge (no binary rollback)

You don't need to roll back the binary for an assignment-layer
mistake. The v0.7 admin surface has direct controls:

### "We accidentally unassigned a domain"

If the grace window hasn't elapsed (default 2h), re-assign:

```sh
curl -sS -X POST \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     "https://control.example.com/api/control/registry/<instance_id>/domains/<domain>/assign"
```

The server-side handler cancels the pending purge atomically;
the audit log records the cancellation.

If the grace has elapsed and the DIDs are gone, restore from
backup (the v0.7 backup format dumps `pending_purges` +
`assignments` keyspaces — those carry the trail of what was
where).

### "An admin Purge Now hit the wrong domain"

The `domain/purge/1.0` Trust Task bypasses the grace and
deletes every DID on the named domain immediately. There is no
in-place recovery. Restore from backup.

### "A domain was deleted but DIDs survived in storage"

This shouldn't happen — `purge_domain_dids` runs every time
either via the sweep or admin trust task. If it does, run the
admin purge once more to clean up:

```sh
curl -sS -X POST \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     "https://control.example.com/api/control/registry/<instance_id>/domains/<domain>/purge"
```

## What gets dumped in a v0.7 backup

The v0.7 backup tool (`webvh-server backup`) dumps every
keyspace:

- `dids` — DID records + their content.
- `acl` — ACL entries (Admin / Owner / Service roles, scopes).
- `stats` — accumulated resolve / update counters.
- `sessions` — durable passkey enrolments (transient session
  state is filtered out).
- `domains` — `DomainEntry` records (multi-domain config).
- `assignments` — which domains this server is authoritative for.
- `pending_purges` — in-flight unassignment purges (preserves the
  audit trail across a restart).
- `registry` — registered service instances + their capabilities.
- `timeseries` — per-DID time-series metrics.
- `meta` — bookkeeping (migration applied-markers, default-domain
  pointer).
- `witnesses` — webvh witness assignments.

v1 backups (pre-v0.7) load against the v0.7 binary; missing
keyspaces default to empty and the first-boot seed re-populates
`domains` + `assignments` from the config.

## Audit trail

After any non-trivial rollback or recovery, capture:

- The exact backup file used.
- Timestamps for stop / restore / start.
- A list of mnemonics + their post-recovery domains
  (`curl /api/dids | jq '.[] | {mnemonic, domain}'`).
- Snapshot of `pending_purges` if any were in flight.

Attach this to the incident record. Future audits will want to
correlate it with the original action that triggered the
rollback.
