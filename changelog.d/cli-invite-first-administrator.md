### Fixed — an operator's CLI invite enrolls the first administrator again

Since invites began to be honored only while their issuer is still an
administrator, an invite made with the operator's `invite` subcommand was
refused at the last step of enrollment with "the administrator who issued this
invite no longer holds that standing": its recorded issuer is the operator, not
an ACL entry, so the lookup never found one. A fresh deployment could not enroll
its first administrator's passkey. A CLI invite carries the operator's
authority, which is store access rather than an ACL entry, so its redemption no
longer looks the operator up in the ACL. This applies to every CLI invite,
whatever its role, not only the first administrator's. Invites issued by an
administrator are checked as before. A refused invite is spent; issue a new one
after upgrading.

### Fixed — an administrator who changes an invite is answerable for it

An administrator who changes an outstanding invite's role or expiry
(`auth/passkey/enroll/invite/update`) is now recorded on the invite. From then
on the invite is honored only while that administrator, as well as its issuer,
is still an administrator, and it is withdrawn when their ACL entry is removed.
Before, a change left no record, so an administrator could raise an operator's
CLI invite to `admin` and the invite stayed redeemable after they were removed.
It also stayed redeemable if they changed an invite another administrator issued.

### Changed — an invite that would be refused is refused before the passkey is made

`auth/passkey/enroll/redeem/start` now refuses an invite whose issuer or
amending administrator has lost administrator standing, and one that would pair
a passkey with a metrics reader, with `permissionDenied`. Before, these were
refused only at `redeem/finish`, after the invitee had created a passkey on
their authenticator, and the invite was spent. A start refused this way leaves
the invite in place. The finish still checks both. It now reads the role to
grant from the invite as it stands at the finish, not as it was when the
ceremony opened.

### Fixed — the CLI no longer issues an invite that cannot be redeemed

The `invite` subcommand refuses `--role metricsReader`, as
`auth/passkey/enroll/invite` already did. Before, it printed an invite that was
always refused at the finish. `remove-acl --did <did>` now also withdraws the
invites issued for a DID that has no ACL entry, so an operator can take back a
CLI invite.

### Breaking — `did-hosting-common` invite issuer type

Rust callers of `did-hosting-common` must update for the changes below:

- `passkey::invite::Invite::issued_by`, `passkey::invite::InviteRequest::issued_by`
  and `passkey::store::CeremonyOrigin::Invite::issued_by` are now
  `passkey::invite::Issuer` instead of `String`. Build one with
  `Issuer::administrator(did)`, which refuses anything that is not a DID, or
  `Issuer::operator()`. The stored form is unchanged, so invites and ceremonies
  already on disk still read.
- `passkey::invite::Invite` has a new public field, `amended_by: Vec<String>`.
- `passkey::issue_cli_invite` is new. It is the validating half of
  `run_cli_invite` and returns the issued invite instead of printing it.
