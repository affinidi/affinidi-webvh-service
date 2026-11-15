### Breaking — `did-hosting-daemon backup` / `restore` cover the whole daemon, in a format of their own

The daemon used the edge's backup, which loaded the daemon's config file as
an edge config (so with `[store]` omitted it backed up an empty
`data/did-hosting-server` directory), carried only the edge's keyspaces, and
never opened `[witness_store]`. A restore therefore brought DIDs back without
the ACL, login and step-up passkeys, identity generations, did:scid floors or
outbound queue, lost the witness's ACL and keys, and rewrote `config.toml`
through the edge's config type, dropping `[enable]`, `[witness_store]`,
`[registry]`, `[stats_flush]`, `[geoip]` and `did_hosting_url`.

A daemon backup is now a `did-hosting-daemon` document: both stores, with an
explicit keyspace list for each (every keyspace except the TSP relationship
state, which the next handshake re-establishes), and the configuration file
carried and restored byte for byte. DID logs are still checked against their
own history and the target store's before anything is written. A backup an
earlier daemon wrote is in the edge's format and is refused by
`did-hosting-daemon restore`; take a fresh backup after upgrading.

A backup never carries live sign-in sessions or refresh tokens (users sign in
again after a restore), and both binaries now write the backup file readable
by its owner only (`0600`). It still holds the ACL, passkey credentials and
the configuration unencrypted, so keep it as you keep the service's secrets.

### Fixed — a standalone edge runs the purge it acknowledged

An edge answered `replica/domain/unassign` (and a domain disable) with a
scheduled purge time, but only the daemon ran the sweep that carries it out,
so an unassigned domain's DIDs stayed on the edge and kept resolving. The
edge's storage thread now runs the sweep every minute and drops its
resolution cache when it purges anything.

### Fixed — an edge's own DID stays out of the control plane's reach

A self-hosted `did:webvh` edge imports its own DID at setup. It reported that
slot at registration, so the control plane queued a `sync/delete` for it, and
the reconcile counted it as extra for ever, holding `/api/health` at 503. The
edge's own DID is no longer reported, never counts as extra, and a
`sync/delete` of it is refused.

### Fixed — an edge no longer drops an agent name another DID has taken over

When a name moved from one DID to another and the edge applied the new
holder's update first, the old holder's later update (or deletion) removed the
name's index entry anyway, and `/@name` 404'd with nothing to repair it. An
index entry is now removed only while it still names the slot being updated
or deleted, and a re-sync of an unchanged log writes back any of its own
entries that went missing.

### Fixed — migrations that defer records stay pending, and never overwrite a concurrent write

The migration runner marked a migration applied even when it had deferred
records (M-01 without a default domain, M-02 with an unreadable log), so they
were never retried. `Migration::run` now reports `Complete` or
`Deferred(n)`, and only a complete run is marked. M-01 and M-02 also walk the
records in pages and write each one with a compare-and-swap on a fresh read
that changes their one field alone, so a publish another replica commits
during a rolling upgrade is not overwritten with a stale record.

### Fixed — `DAEMON_STORE_*`, `DAEMON_SECRETS_*`, `DAEMON_AUTH_*` and `DAEMON_FEATURES_*` are honoured

The daemon read only a fixed handful of variables, so the store, secret
backend, auth and feature overrides documented for every prefix were ignored
under `DAEMON_`. It now applies the shared overrides, and
`DAEMON_WITNESS_STORE_*` configures `[witness_store]`.
