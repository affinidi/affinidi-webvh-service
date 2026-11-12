### Changed — a passkey login start discloses no subject and leaves no rows behind

`auth/passkey/login/start/0.2` is answered to anyone, unsigned. With no
`subject` it read every login passkey enrolled here, returned all their
credential ids as `allowCredentials`, and stored a snapshot of them under the
new `authId`. Those rows were never removed unless the login finished, and
the start answered `subjectNotRecognized` and `noCredentials` differently, so
it also said which DIDs had a passkey.

- **No subject named:** the start opens a discoverable-credential ceremony
  with no `allowCredentials`; the browser offers the passkeys it holds for
  this service. Finish looks the credential up by id, requires the returned
  user handle to be that credential's user (an assertion without one is
  `assertionInvalid`), and verifies against that one subject's credentials.
  The ceremony row holds only its challenge, whatever the number of passkeys.
- **A subject named:** the start lists that subject's credentials, as
  before, so a passkey enrolled as non-discoverable keeps signing in. For a
  subject with no login passkey it lists decoy credential ids instead of
  answering `subjectNotRecognized` / `noCredentials`: one or two ids derived
  from a service key (made on first use, kept as `pk_login_decoy_key`) and
  the subject, the same on every start for that subject and shaped as the
  console's own enrolments are. Nothing answers them.
- A login that named its subject fails in exactly one way at finish
  (`assertionInvalid`, "the assertion did not verify"), whether the
  credential is unknown, not listed, another subject's, or a decoy list's,
  or the assertion does not verify, so its outcome does not say whether the
  subject is enrolled. An unnamed login still says `credentialUnknown`.
- The counter update after a successful login is made under the subject's
  credentials guard on a fresh read, so a login racing a revocation or an
  enrolment neither restores the revoked credential nor drops the new one.
- Only a request carrying the named subject's own bearer session is told
  `subjectNotRecognized` or `noCredentials`.
- Each source may open 30 login ceremonies a minute: the client address on
  HTTPS (refused as `unavailable` with `retryAfter`), the authenticated
  sender on DIDComm and TSP (refused as `rateLimited`). A DIDComm or TSP
  start with no authenticated sender is refused (`permissionDenied`). A
  messaging sender can mint a fresh `did:key` per request, so there the limit
  is per identity rather than per party; what each start leaves is one small,
  swept row.
- The session sweep now removes expired login ceremonies (`pk_task_meta:`
  and any `pk_auth:` state row an older build wrote), passkey revocation
  ceremonies (`pk_revoke:`), step-up challenges (`stepup-task:`) and DID
  ownership offers (`did_xfer:`). A login ceremony opened by the previous
  build can still be finished.
- New login passkeys are requested with `residentKey: preferred`, so an
  authenticator that can store a discoverable credential does. Step-up
  passkeys are unchanged.
- The console's passkey sign-in takes an optional DID; naming it lists that
  DID's credentials, for a security key the browser does not offer by itself.
- `webauthn-rs` gains its `conditional-ui` feature (no new dependency).
- Behaviour changes (R3.6):
  - An anonymous login start never answers `noCredentials` or
    `subjectNotRecognized`. Unnamed, it opens a ceremony with no list;
    naming an unknown subject, it lists decoys.
  - A passkey enrolled as non-discoverable (some hardware security keys,
    registered under the earlier `residentKey: discouraged`) signs in only
    when the start names its subject — in the console, by entering the DID
    beside "Login with Passkey".
  - A discoverable-flow assertion with no user handle is refused.
  - A named login's failures are all `assertionInvalid` (a named login with
    an unknown credential used to be `credentialUnknown`).
  - Residual signal: decoys are always one or two ids of 16, 20 or 32 bytes.
    A named subject whose real list has three or more credentials, ids of
    other lengths, or `transports` (recorded when a browser reports them at
    enrolment) is distinguishable from an unknown one. Real lists cannot be
    trimmed without breaking those credentials' sign-in, so this is left as
    is; a subject's count and id lengths are what they disclose.
  - The 31st login start a minute from one source is refused, and a
    DIDComm/TSP start with no sender is refused.
  - Checked consumers: the console's `passkeyLoginStart` (updated here to
    pass an optional subject) handles options with or without
    `allowCredentials`. No client in verifiable-trust-infrastructure calls
    this service's passkey login (its own `vta-service` and `vtc-service`
    have their own).
