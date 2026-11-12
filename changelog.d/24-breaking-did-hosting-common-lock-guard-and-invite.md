### Breaking — `did-hosting-common` lock-guard and invite signatures

Rust callers of `did-hosting-common` must update for the two changes below:

- `PathLocks::guard` returns `did_hosting_common::server::path_locks::PathGuard`
  instead of `tokio::sync::OwnedMutexGuard<()>`. Code that only holds the
  guard and drops it needs no change; code that names the type does.
- `passkey::invite::issue`, `passkey::invite::redeem` and
  `passkey::run_cli_invite` take a final `std::time::Duration` argument, the
  longest wait for a claim-code hashing slot. Pass
  `config.auth.claim_code_hash_wait()`.

This change is for the next release and will not be backported.
