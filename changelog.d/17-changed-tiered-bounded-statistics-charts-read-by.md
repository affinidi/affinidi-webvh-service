### Changed — tiered, bounded statistics; charts read by key

Every DID now keeps a coarse series (hourly for 7 days, daily for 30) inside
its `stats:` row, and only busy DIDs keep a 5-minute series, in a ring of 288
rows (`t5:{mnemonic}:{slot}`) that is overwritten in place. Nothing grows
without bound and nothing needs a sweep. Charts read rows by key instead of
scanning the time-series keyspace, which on DynamoDB was a full-table Scan
per chart (one per DID for a domain chart). A DID's row is written at most
once per 5 minutes, when its bucket closes, rather than every 10 seconds.

- **`[stats]`** (env `CONTROL_STATS_*`, `DAEMON_STATS_*`): `mode` (`auto`,
  `fine`, `coarse`), `promote_per_hour` (60), `demote_per_hour` (20),
  `max_fine_dids` (1,000).
- **A per-DID override**, `auto`, `fine`, `coarse` or `off`. Only an admin
  may set `fine`; an owner may set the others for their own DID. Set it with
  the new `did-management/stats/set-resolution/0.1` Trust Task, which also
  reports the tier that applies and why, or offline with the new `stats-set`
  command. `stats-show` reports a DID's tier.
- **The chart's `bucketSeconds` now varies**: a DID without 5-minute detail
  is charted hourly (daily over 30 days). The UI uses the value it is sent.
- **Migration is automatic.** At startup the legacy `ts:` rows are folded into
  the new rows, a flush's worth at a time. Only the last 31 days are
  migrated, as no chart shows older, so memory is bounded by a month of
  history rather than the deployment's age. fjall and DynamoDB read them a
  page of 1,000 keys at a time (DynamoDB as a paged `Scan`), and a failed
  read is retried from where it stopped. Redis, Firestore and Cosmos DB read
  them whole, and after a failed read wait 5 minutes before reading again.
  Charts read the legacy rows until it completes. It can run again safely,
  and picks up rows an older version wrote after a rollback. Legacy rows are
  kept for 30 days, then deleted; `stats-purge-legacy` deletes them at once.
- Removing a DID deletes its statistics rows: an explicit delete, and on the
  daemon also the empty-slot cleanup and the domain purge sweep.
- Displayed totals include counts not yet written.
- A flush tick (the paced flush, then the migration step) starts no writes
  after its 10-second interval; under a slow store, what is left waits for
  the next tick instead of delaying it.

See `docs/stats-tiers.md`.
