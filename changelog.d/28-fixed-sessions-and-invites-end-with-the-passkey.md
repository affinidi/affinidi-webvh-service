### Fixed — sessions and invites end with the passkey or ACL entry they rest on

Revoking a passkey left the sessions it had signed in, and the elevation
it had granted, in place until they expired. Removing a subject's ACL
entry (`acl/revoke` with `revocation.kind: entry`) left its sessions, and
the enrolment invites issued for it, in place, and redeeming such an
invite recreated the entry. Now:

- `auth/passkey/revoke/finish` ends the subject's sessions a login passkey
  signed in (when the revoked passkey is a login passkey) and returns
  sessions a passkey elevated to `aal1`. A session does not record which
  passkey established it, so this covers every such session of the
  subject, except that a passkey session the revocation was made from is
  kept (an elevation on it is still dropped).
- Removing an ACL entry, by `acl/revoke` or by the operator's
  `acl remove`, ends every session of its subject and withdraws the
  invites issued for it or by it. Narrowing an entry's act scope does
  neither. An invite redemption waits for a removal in progress, so it
  cannot recreate the entry in between. The subject's passkeys are kept:
  login checks the ACL, so they work again only if the subject is granted
  an entry again, and then they do. `acl remove` from the command line
  does not take the running control plane's removal lock, so on a store a
  running control plane shares (DynamoDB, Redis and the other networked
  backends) prefer `acl/revoke`.
- A refresh in flight while its session is ended or demoted does not undo
  that: the refresh re-applies it to the rotated session (an ended
  session's refresh is refused).
- `auth/passkey/enroll/redeem/finish` refuses (`permissionDenied`) an
  invite whose issuer no longer holds administrator standing, checked
  under the ACL write lock; the invite is spent.

Behaviour change: a subject signed in with a passkey is signed out when
one of its login passkeys is revoked from another session, and a removed
member is signed out at once rather than when its session expires.
