### Fixed — secrets envelope writes in one process no longer overwrite each other

Writing the service keys (`set`, as a rotation does), writing the offline
bootstrap seed and clearing it each read the whole secrets envelope, changed
one member and wrote it back, with nothing ordering them. Two of them at
once could write back an envelope read before the other's change. A rotation
could then be undone by a seed write that started earlier, leaving the
service unable to sign as its published DID.

Updates of one envelope entry in a process now take turns, wherever the
store was built. Each backend read and write an update makes is bounded at
20 s. An update that waits more than 60 s for its turn fails rather than
queueing indefinitely. Nothing is written after a failed or timed-out read.

Behaviour change (R3.6): a secrets write against a backend that does not
answer now fails after 20 s (a wait for a turn after 60 s) instead of waiting
on it indefinitely. The backends offer no compare-and-swap, so writers in
separate processes (the setup CLI and a running service on one entry) are
still not ordered against each other.

### Breaking — proof-verification failures carry their kind as a value

Whether a refused proof was a signer that could not be resolved (retryable),
a deactivated signer or a bad proof was decided by searching the error message
for fixed phrases. That message includes the signer's DID, which the sender
chooses. The verifier now reports the kind as a value, taken from where it was
decided, and nothing decides it from text.

Rust callers of `did-hosting-common`:

- `trust_tasks::is_unreachable` and `trust_tasks::unreachable_error` are
  removed. Use `TransportBoundVerifier::check_operational` /
  `check_approval`, which return a `VerifyFailure { kind, error }`
  (`VerifyFailureKind::{Unreachable, Deactivated, Invalid}`), and
  `BoundError::unreachable(detail)` to report a signer you gave up waiting on.
- `BoundError` has a new `Unreachable(VerificationError)` variant, which is
  what `is_transient` now reports. An unreachable signer is no longer a
  `BoundError::Proof`, and its message reads "proof could not be checked: …".
- `verify_operational`, `verify_approval` and `ProofVerifier::verify` keep
  their signatures.
- A caller-supplied resolver (`TransportBoundVerifier::with_resolver`)
  cannot report a kind, so its failures count as bad proofs, whatever their
  message says.

No wire shapes change. Which failures are retryable is unchanged for the
service's own verifier.
