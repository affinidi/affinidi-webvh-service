### Breaking — Cosmos DB keeps every keyspace in one container, so a batch is atomic

The `store-cosmosdb` backend kept one container per keyspace and applied a
batch one write at a time, so a failure part-way through left half a change
(a DID record without its log or its name index, a domain re-enabled with its
purge still queued). Every keyspace now lives in one container,
`store.cosmosdb_container` (`<PREFIX>_STORE_COSMOSDB_CONTAINER`, default `kv`,
partitioned on `/pk`), created with its database if missing, and a batch is
one Cosmos DB transactional batch: it lands whole or not at all. A batch over
the transactional batch's bound (100 writes, 2 MB) is refused as a size quota,
writing nothing, as on DynamoDB and Firestore.

On first start, each keyspace still in a container of its own is copied into
the shared container, once. Start one upgraded replica alone so the copy
finishes before others write; the old containers are left for you to delete.
Everything now shares one logical partition, which Cosmos DB caps at 20 GB.

### Fixed — Cosmos DB prefix scans find every key

A prefix scan matched the base64 of the prefix against the base64 of each
key, which only works for prefixes a multiple of 3 bytes long. `did:`,
`acl:` and `session:` scans returned nothing or only part of their rows, so
DID listing, the DID count, domain purges and ACL listing were empty or short
on Cosmos DB.

### Fixed — DynamoDB creates a missing table only when it is missing, and waits for it

A table was created on any `DescribeTable` failure (throttling, `AccessDenied`,
the network), used before it was `ACTIVE`, and never ensured for a keyspace
whose first write was a batch. Now only a missing table is created, a table
someone else is creating counts as created, every table waits until it is
`ACTIVE`, and a batch ensures each table it writes. New tables are on-demand
(`PAY_PER_REQUEST`) instead of 5 provisioned read and write units; set
`store.dynamodb_billing_mode` (`<PREFIX>_STORE_DYNAMODB_BILLING_MODE`) to
`provisioned:<read>:<write>` for provisioned tables, and
`store.dynamodb_auto_create = false`
(`<PREFIX>_STORE_DYNAMODB_AUTO_CREATE=false`) to refuse a missing table
instead of creating it.

### Fixed — Redis prefix scans read only their keyspace, once each

A prefix scan walked every key in the database with `SCAN MATCH`, treated
`*`, `?` and `[` in a prefix as wildcards, could return a row twice, and read
every value in one `MGET`. Each keyspace now keeps a sorted-set index
(`__index__:<keyspace>`), written in the same transaction as its rows, and a
scan, a page or a count reads only that range of it, in chunks. A database
written by an earlier release is indexed once when the store opens. Upgrade
every replica sharing the database together: one still on the old release
writes rows the index does not list.

### Added — store conformance suite, run against every backend

The `KeyspaceOps` contract (round trips, byte-exact prefix scans, paging,
atomic batches across keyspaces, `take`, `incr` and compare-and-swap under
contention, the per-item limit) is one suite every backend runs: fjall in its
unit tests, Redis, DynamoDB Local and Cosmos DB (its SDK's in-memory
emulator) on every PR, and the Firestore emulator nightly. Every backend now
pages prefix scans, lists keys without their values (`prefix_keys_raw`),
counts them (`prefix_count`), and reports its per-item limit
(`Store::max_item_bytes`).
