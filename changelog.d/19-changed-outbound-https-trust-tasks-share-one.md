### Changed — outbound HTTPS Trust Tasks share one client and one verifier

An HTTPS send built a new HTTP client, and a new reply verifier, for every
request. Each service now verifies HTTPS replies with the verifier it checks
inbound documents with, so DID-status verdicts are reused and forced
re-resolutions of a peer's DID are rate-limited across calls (at most one per
DID per 30 s) on these paths too. Replies get a forced-refresh allowance of
their own (`TransportBoundVerifier::for_replies`), so inbound documents cannot
use up the re-resolution a just-rotated peer's reply needs. `WitnessClient` and `WebVHClient` build
their verifier once per client. HTTP clients are built once per process, so
connections are reused.

- **API:** `send_trust_task` and `send_trust_task_with_retry` take a
  `send::Peers` (DID cache and verifier) in place of `Option<&DIDCacheClient>`.
  `post_trust_task_https` still builds a verifier per call and is meant for
  one-off callers; long-lived callers use `post_trust_task_https_verified`.
