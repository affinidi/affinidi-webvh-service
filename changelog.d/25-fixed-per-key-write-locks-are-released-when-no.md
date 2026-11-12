### Fixed — per-key write locks are released when no longer in use

`PathLocks` (the per-slot, per-name and ACL write locks) kept one entry for
every key ever locked, for the life of the process, including keys that named
no stored record. An entry is now removed as soon as no task holds or waits
for its key, so the lock table stays as small as the set of keys in use.
Same-key callers still serialise exactly as before.
