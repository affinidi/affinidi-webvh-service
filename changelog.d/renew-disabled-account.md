### Fixed — a self-registered account disabled for inactivity can renew again

`did-management/account/renew/0.1` restores a disabled account, but its
proof was verified by resolving the holder's DID, and disabling the account
is exactly what makes that DID stop resolving (404). The renewal was refused
as `unavailable`, so a disabled account could never be restored, and
`account/status` (how an offline holder learns its state) failed the same
way. Both tasks from a self-registered account are now verified against the
host's own stored log for its DID, as the registration was against the
submitted one. A deactivated DID is refused.
