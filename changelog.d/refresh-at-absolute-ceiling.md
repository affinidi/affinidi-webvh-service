### Fixed — a session refreshes until its absolute lifetime, not until its refresh deadline reaches it

`auth/refresh` refused a session as `sessionLifetimeExceeded` as soon as its
refresh deadline sat *at* its absolute ceiling, rather than once the clock
reached the ceiling. A trigger-link (`auth/oob/*`) sign-in starts in exactly
that state whenever its grant is shorter than the refresh-token expiry (the
wallet grants 12 hours), so its first renewal was refused and the console
signed out — a step-up, which renews the session the moment it is approved,
failed with "Your session has ended" seconds after sign-in. Mandate-backed
sessions, and any session a refresh had clamped to its ceiling, ended the same
way, one access-token lifetime later instead of at `absoluteExpiresAt`.

A refresh is now refused only once the ceiling has passed, and every token it
mints is capped at the ceiling: the refresh deadline, as before, and now the
access token too, so a renewal near the end cannot outlive it.
