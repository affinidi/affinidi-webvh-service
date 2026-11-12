### Changed — enrolling a passkey that grants `aal2` needs a stepped-up session or the caller's own key

A passkey login is minted at `aal2`. `auth/passkey/enroll/{start,finish}/0.2`
let any authenticated subject add a login passkey, and asked for user
verification only when one was already held, so a session at `aal1` (signed
by its browser session key) could enrol a first passkey and sign in again at
`aal2`. An administrator's session at `aal1` could do the same through an
invite (`auth/passkey/enroll/invite/0.3`) naming itself. And enrolment
accepted a credential id already bound to another subject, repointing that
credential's index so its holder could no longer sign in with it.

- Enrolling a subject's first login passkey needs a session already at
  `aal2`, or a request signed by the subject's own DID key (the factor a
  `didSigned` step-up rests on). The check runs at start and again at finish,
  against the credentials held then.
- Issuing any enrolment invite needs the same of the administrator: an `aal2`
  session or its own DID key's signature, whoever the invite names.
- Both refusals are `permissionDenied` with message `step_up_required`. The
  console treats that, like a declared `stepUpRequired`, as a request to step
  up and retry, for invites and for domain purges.
- Every enrolment finish (redeem, self-enrolment, either purpose) refuses a
  credential id already bound to any subject in either credential store
  (`attestationInvalid`), as WebAuthn §7.1 requires; enrolments of the same id
  are serialised.
- Adding a further passkey is unchanged (user verification over an existing
  one).
- Behaviour changes (R3.6):
  - A session at `aal1` signed by its session key can no longer start or
    finish a first login passkey enrolment, or issue an invite. A passkey
    session is `aal2` already; a wallet session steps up first.
  - Re-enrolling a credential already bound anywhere is refused.
  - Checked consumers: the console enrols through invites (it steps up when
    asked); no client in verifiable-trust-infrastructure calls this service's
    `enroll/*` tasks.
