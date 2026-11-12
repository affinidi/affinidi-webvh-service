### Fixed — a `mandateCredential` is checked as a decision and must name its own end

A proxied `auth/authenticate/0.3` backed by `delegationEvidence` of kind
`mandateCredential` verified the mandate's proof with the general proof
check, which does not refuse a principal whose `did:webvh` is
deactivated, and accepted a mandate with no `expiresAt`, which then let the
delegate sign in as the principal with no end. The mandate is now verified
as every other decision is (`TransportBoundVerifier::verify_approval`: an
`assertionMethod` proof by a key under the principal's own
`assertionMethod`, never a session delegate, from a principal that has not
deactivated its DID). It must carry `issuedAt` (not in the future) and
`expiresAt` (after it, and not past), at most 30 days apart, and the
session it backs, and that session's refresh token, end no later than the
mandate's `expiresAt`. So does its first access token, and the session
row's `not_after` is set to the mandate's end, which `auth/refresh` clamps
to and the bearer check now refuses past.

Behaviour change: a mandate without `issuedAt` or `expiresAt`, or valid for
more than 30 days, is refused (`delegationNotRecognized`). A session whose
mandate ends before its refresh token would is not refreshed; the delegate
signs in again with its mandate. A bearer session past its `not_after`
is refused (`unauthorized`); only these mandate-backed sessions set it.
`siopIdToken` evidence is unchanged.
