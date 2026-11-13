### Fixed — a rollback keeps the agent-name registry in step with the document it restores

`did/rollback` rewrote the log, the DID, its services and version count but
left the agent-name registry as it was, so the registry could list names the
restored document no longer claims, or miss names it does. A rollback now
reconciles the registry exactly as a publish does: names the restored entry
claims are registered, names it no longer claims are released, parked names
stay parked.

Behaviour change (R3.6): a rollback to an entry that claims a name another DID
now holds, or a reserved name, is refused (`agent-name` taken / reserved) and
changes nothing. A name changes holder only through an explicit `remove` by
its holder.

### Changed — refresh tokens are stored as SHA-256 digests

The session row and the refresh index key held each refresh token as issued.
They now hold `sha256:` and the token's SHA-256, so reading the sessions
keyspace (a Redis, DynamoDB or Cosmos backend, or a backup) does not yield a
token that redeems. The settlement marker a refresh checks is keyed the same
way.

Sessions written by an earlier release keep working: a token of the shape
those releases issued is also looked up under its old key, and a stored digest
is never accepted in place of a token. The session sweep now also removes
refresh index entries no session issues any more (the session has gone, or a
later sign-in replaced the token without retiring it).

### Changed — service keys are wiped from memory when dropped

`ServerSecrets`, `RetiredKeys` and `StoredSecrets` are zeroized on drop, as is
the serialised envelope, the JWT key's DER encoding and a key a rotation
replaces. Signing a Trust Task copies only the signing key rather than every
live key.

### Breaking — unused items removed from `did-hosting-common` and `did-hosting-control`

Rust callers:

- `ServerSecrets`, `RetiredKeys` and `StoredSecrets` implement `Drop`
  (`ZeroizeOnDrop`), so a field can no longer be moved out of one; use
  `clone()` or `std::mem::take`.
- `did-hosting-control`'s `AppState::signing_key_bytes` is removed. It was a
  second, unused copy of the signing seed; sign with
  `signing::control_signing_secret`.
- `didcomm_unpack::{unpack_signed, require_addressed_to, REPLAY_WINDOW_SECS}`
  are removed. Nothing called them since the REST sign-in path was retired.
- `server::acl::{CreateAclRequest, UpdateAclRequest, AclEntryResponse,
  AclListResponse}` are removed, left over from the retired ACL REST routes.
- `SpecAclEntry::into_local` takes the creation time to record, and ignores
  an inbound `createdAt`, as it already did for the other provenance members.
- New: `ServiceIdentity::secret(kid)`,
  `auth::session::{refresh_token_digest, refresh_hash_of_stored}`.
