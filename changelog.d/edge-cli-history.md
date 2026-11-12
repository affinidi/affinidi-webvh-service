### Fixed — a server's own CLI holds a DID log to the history it has served

A synced log must verify and strictly extend every history the server has
served for that DID: the log it holds, and the high-water mark it keeps after
a delete. The server's own subcommands that write a log skipped those checks.
`load-did` and `bootstrap-did --did-log` checked only the log's structure, so
`remove-did` followed by `load-did` could put an older version of a DID back.
`restore` wrote a backup's logs and high-water marks over the store's
unchecked, so restoring an older backup rolled both back.

Every path that writes a log now goes through the same history check and
records the high-water marks: `load-did`, `bootstrap-did` (with or without
`--did-log`), `recreate-did`, and setup's import of the server's own DID, on
both `did-hosting-server` and `did-hosting-daemon`. `load-did` and
`bootstrap-did --did-log` also verify the log's chain and, for a witnessed
DID, its witness proofs. A new DID in a slot is still allowed, as `sync/update`
allows it.

`restore` checks the whole backup before writing anything, `config.toml`
included. It works through the backup's logs, so none is restored unchecked.
Each restored `did:webvh` log, or `did:webs` log in a build with
`method-webs`, must have a record naming the DID the log establishes, must
verify, must extend the backup's own high-water mark, and must extend what the
store holds for that DID and slot. A backup's high-water mark is kept only if
it extends the store's, and a mark the store holds further is left in place.
If any check fails, the restore is refused and nothing is written. The data
goes into the store the backup's config names, after the usual environment
overrides. An interrupted restore can be run again.

`setup`'s replacement of the server's own DID (`--force-reprovision`) now
verifies the new DID before removing the old one, and swaps them in one batch.

Records these commands create are now tagged with the host their identifier
names, as a synced record is, so a purge of that domain selects them. Before,
the domain was empty and a purge skipped them.

Behaviour change (R3.6): no wire changes. `load-did` and `bootstrap-did
--did-log` refuse a log that does not verify, one that lacks the witness
proofs its parameters require, and an older version of a DID the store has
served. `restore` refuses a backup that would roll a DID back, so restore
into an empty data directory to start from a backup's state. It also refuses
an inconsistent backup (a log with no record, a record naming another DID, a
log that does not verify, or a log behind the backup's own high-water mark)
into any store, and no longer writes `config.toml` before that check.
