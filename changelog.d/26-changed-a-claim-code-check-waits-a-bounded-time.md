### Changed — a claim-code check waits a bounded time for a hashing slot

Passkey invite claim codes are checked with Argon2 in a small fixed number of
concurrent slots. A check that found every slot busy used to wait for as long
as it took. It now waits at most `auth.claim_code_hash_wait_ms` (default
5000 ms, at most 60000; env `*_AUTH_CLAIM_CODE_HASH_WAIT_MS`) and is then
answered `unavailable` with a retry time (`RateLimited`, limiter
`claim-code-hashing`). The same bound applies to a redemption waiting behind
another attempt on the same invite. A refused check counts no wrong code
against the invite. A slot is now held until its hash finishes, even if the
caller has gone away; before this, a cancelled request freed its slot while
its hash was still running. Issuing an invite has its own two slots, so
redemption attempts cannot hold up an administrator issuing one. A config
file with a wait above 60000 ms is refused at load.
