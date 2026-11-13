### Breaking — the daemon refuses a witness store that reaches the control plane's data

With the witness enabled, `did-hosting-daemon` now refuses to start when
`[witness_store]` reaches the same data as `[store]`. The embedded witness keeps
its ACL in its store, so it would otherwise share the control plane's ACL, and
with `service` entries now allowed to request witness signatures, every
control-plane `service` entry (each registered edge) could have it sign. The
check is made by trying it: at startup the daemon writes a random value under
a reserved key (`store-probe:…`, outside the `acl:` entries) in `[store]`'s ACL
keyspace, looks for it through `[witness_store]`, and removes it. Any spelling
of the same Redis server and database, DynamoDB table prefix and region,
Firestore database or Cosmos DB database is therefore caught. On DynamoDB both
prefixes default to `webvh`, so a `[witness_store]` without its own
`dynamodb_table_prefix` is refused. The default layout (separate fjall
directories) is unaffected.

To move a deployment that shares one store, keeping its witness identities
(and, with sealed witness keys, the recorded key-encryption key and the sealed
keys, which live in the same keyspace):

1. Stop the daemon and run `did-hosting-daemon backup -o witness.json`. The
   backup includes the `witnesses` keyspace; it does not include the ACL.
2. Give `[witness_store]` its own location (for example
   `dynamodb_table_prefix = "webvh-witness"`).
3. Restore into it: run `did-hosting-daemon restore -i witness.json` with a
   copy of the config whose `[store]` section is the new `[witness_store]`.
   This also writes the backup's other keyspaces there; the witness does not
   read them.
4. Re-create the witness's ACL with `did-hosting-daemon add-acl --witness
   --did <DID> --role admin|service`, giving `service` to callers that only
   request signatures.

If that is not possible, the fallback is to create new witness identities in
the new store and have DIDs that list the old identities move to them.

### Changed — a witness caller can be allowed to request signatures and nothing else

On a witness, `webvh/witness/sign` required an `admin` ACL entry, and an
`admin` can also create and delete witness identities and administer the
witness's ACL. So a control plane, VTA or edge that only needs proofs had to
hold a credential that could delete every witness identity and grant access
to others. `webvh/witness/sign` now also accepts a `service` entry, and
nothing else on the witness does: `key/create`, `key/list` and `key/delete`
still require `admin`, and the ACL tasks still require `admin` (any member
may show or revoke its own entry, as before). An `owner` or `metricsReader`
entry still can do nothing on a witness.

Existing entries and how they move:

- An `admin` entry keeps every permission it had; nothing stops working.
  To narrow a caller that only requests signatures, change its role to
  `service`: `acl/change-role` (`fromRole: admin`, `toRole: service`) from
  another admin, or `webvh-witness remove-acl --did <DID>` then
  `webvh-witness add-acl --did <DID> --role service`. The last `admin`
  cannot be demoted.
- An existing `service` entry on a witness, which could do nothing there
  before, can now request signatures.
- On a witness, a `service` entry now states `keys: {"scope": "all"}` in
  `acl/show` and `acl/list`, since it may have the witness sign with any of
  its identities. An `acl/grant` of a `service` entry to a witness must say
  `keys: {"scope": "all"}`; one saying `none` is refused (`taskFailed`,
  `details.reason: notSupportedByMaintainer`).
  Other services are unchanged: they sign nothing for their members.
- `webvh-witness add-acl` now requires `--role`, and accepts only `admin`
  or `service`. It defaulted to `owner`, which can do nothing on a witness.
- `did-hosting-daemon add-acl --witness` and `list-acl --witness` write and
  read the embedded witness's ACL, which had no CLI before.
