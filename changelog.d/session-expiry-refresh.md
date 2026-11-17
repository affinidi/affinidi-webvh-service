### Fixed — the console stops renewing a session the control plane has ended

When `auth/refresh` was refused for good (the session reached its absolute
lifetime, idled out, or was revoked or unknown), the console swallowed the
refusal and sent the same refresh token again on every request, background
polls included, until the access token ran out. It now ends the session on the
first such refusal: the tokens and session key are cleared, the other tabs
holding the session are told, and the "Session expired — sign in again" prompt
shows. Network errors, 5xx responses and `unavailable` are still retried, with
a backoff that doubles up to a minute.

The control plane now answers a store failure during the refresh pre-checks as
retryable `unavailable`, not `permissionDenied`, so a non-retryable refusal
always means the session is over. The idle-timeout refusal is still
`permissionDenied`; nothing else changes on the wire.

### Fixed — normal session expiry is no longer logged as a warning

A refresh refused because the session reached its absolute lifetime or idled
out, and a bearer request refused because its session reached its end, are
now logged at `info`, and an idle refusal is logged once, not twice. WARN is
kept for refusals worth an operator's attention, such as a wrong or missing
session-key proof or an unknown, replayed or superseded refresh token.
