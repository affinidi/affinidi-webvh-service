### Changed — `did/list` pages from the store, and quota checks stop scanning

`did/list` no longer reads, parses and sorts every record for each page. On
fjall and Redis a page starts at its cursor in the owner index, a new
per-domain index (`domain:{domain}:{mnemonic}`) or the records, and stops
when it is full. On DynamoDB, Cosmos DB and Firestore, whose pages are not in
key order, a page is still one walk of the records, but holds only the page
in memory; the order and the cursor are the same on every backend. Pages stay
in mnemonic order.

The `vnd.affinidi.webvh` request extension of `did/list` takes `search`
(1–200 characters, matched without case against the mnemonic, the DID and its
agent names) and `agentName` (with `domain`: the slot holding that name, from
the name index). A searched page reads at most 5,000 rows and may come back
short, or empty, with a `nextCursor`; keep paging while one is present. An
unknown member of the extension is refused. The same extension's `domain` on
`stats/get` (without `mnemonic`) answers the per-domain aggregate: every slot
on the domain for an administrator, the caller's own slots otherwise.

Each owner's slot count and stored bytes are kept in a `usage:{owner}` row
written in the same batch as the record, so the count and size quotas read one
row instead of every slot the owner holds. Both new kinds of row are built for
an existing store by the `m03_index_did_records` migration, which the control
plane and the daemon run at their first boot after upgrade; a control plane
that cannot run it does not start. Control-plane replicas sharing one store
should be upgraded together: a replica on the previous version writes records
without updating these rows.

### Changed — boot and periodic work no longer hold whole keyspaces in memory

The boot-time integrity check, the session cleanup, the domain purge and the
storage migrations walk the store a page at a time, and the DID counts (the
stats seed and the hourly recount) count keys without reading values. The
stats seed retries a failed store read with backoff and logs it, rather than
silently starting the totals at zero, and the statistics collector no longer
fails every later resolve after a panic while it held its lock.
