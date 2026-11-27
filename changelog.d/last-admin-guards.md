### Fixed — removing the last administrator from the console can no longer delete its DIDs first

The ACL page's remove dialog deletes an account's DIDs before removing its
entry. For the last administrator the control plane refuses the removal
(`acl/revoke` answers `lastAuthorityProtected`), but only after the DIDs had
already been deleted. The dialog now says the account is the last
administrator and offers nothing, and before deleting any DID it checks again
against a fresh ACL, so a stale page cannot lose them either. The refusal is
also worded for the operator instead of shown raw.

### Changed — `remove-acl` refuses to remove the last admin without `--force`

`did-hosting-control`, `did-hosting-daemon` and `webvh-witness`
`remove-acl` work on the store directly, so they never had the last-admin
guard `acl/revoke` enforces. They now refuse to remove the last `admin`
entry unless `--force` is given. An operator can still recover a service
with no admin with `invite --did <DID> --role admin`.
