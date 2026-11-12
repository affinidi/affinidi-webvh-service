### Fixed — witness signing keys are sealed, with the key in the secret store

A witness identity's Ed25519 private key was serialised in clear into its
record in the data store (`witness:{id}` in the `witnesses` keyspace), so
anyone able to read that store, a backup of it, or a disk snapshot could sign
witness proofs as that identity. The record now holds the key only sealed
(HPKE, the envelope already used for VTA bootstrap bundles) to a witness
key-encryption key, and the additional authenticated data names the
identity, so a sealed key moved onto another record does not open. The
key-encryption key is held in the configured secret store in an entry of its
own (`<name>-witness-kek`, or the keyring account
`witness_key_encryption_key`; see `webvh-witness/README.md`). It is written
once, when the witness first starts, and never rewritten, so no release that
writes the service's own entry can drop it, and nothing reads, modifies and
writes back a shared secret. Its creation is claimed through the data
store's atomic counter, so two witnesses starting together on one store make
one key. The data store records its public half; a witness whose secret store
holds no key or another key, while its identities are sealed to the recorded
one, refuses to start and names the entry to restore.

The key-encryption key is read when the witness starts (bounded at 15 s) and
held in memory, so signing reads nothing from the secret store. The signer
checks that the key it opens is the one the identity's id names.

On the first start after upgrading, the witness (standalone, or embedded in
the daemon) seals every key still held in clear in a record, re-reading each
record just before rewriting it, 50 at a time. It logs the witness ids
sealed, never key material. Startup is refused, naming the identity and
changing nothing, if a record's key does not belong to it. Keys are not
changed, so no DID's witness list needs updating. Identities whose key
cannot be opened are named in a startup warning.

The service's own secret-store entry also now keeps any member this release
does not know when it rewrites the entry, instead of dropping it.

Behaviour changes:

- The witness needs permission to create and read a second secret-store
  entry on the cloud, Vault and Kubernetes backends.
- A backup of the data store (including the server's `backup` command)
  holds no usable witness key; back up the key-encryption key's entry too.
  `setup` re-run with another backend, and `export-sealed` /
  `import-sealed`, do not carry it.
- New CLI commands `webvh-witness reset-witness-kek-claim` and
  `did-hosting-daemon reset-witness-kek-claim`, for a first start that
  stopped part-way. A first write the secret store refuses releases the
  claim itself.
- In a rolling upgrade, replicas still on an earlier release cannot sign for
  identities the upgraded ones have sealed until they are upgraded too.
- Moving back to an earlier release after the upgrade does not work: it
  cannot read a sealed record. Nothing is lost; upgrading again works.

Records written before this change remain in earlier backups, snapshots,
and any history the storage backend keeps (point-in-time recovery, for
example), with the keys in clear, and restoring one brings them back until
the witness next starts. Where those copies may have been readable by
others, consider creating new witness identities and having DID controllers
move their witness lists to them; that cannot be done by the service alone.
