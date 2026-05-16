# Changelog — webvh-witness

See the [workspace CHANGELOG](../CHANGELOG.md) for cross-crate release notes.

## 0.6.0 (2026-05-05)

### Breaking

- **`WitnessSigner` is now async.** The trait's `sign_proof` method returns
  a `BoxFuture<Result<DataIntegrityProof, AppError>>` so it can be implemented
  by remote-signing backends (HSM, KMS, VTA-based key managers). External
  implementations of `WitnessSigner` must update their signatures and adopt
  the boxed-future return type.
- **`sign_proof` REST endpoint now requires Admin role.** The handler used to
  accept any authenticated user and sign for any `witness_id`; it now refuses
  unless the caller's JWT has Admin role and emits an audit log line on every
  signed proof. Operators that issue Owner-role JWTs to non-admin users will
  see those callers receive 403 Forbidden on this endpoint.
- **`WitnessRecord::Debug` no longer prints the private key.** Manually
  implemented to redact `private_key_multibase`. Any consumer that depended
  on the derived `Debug` will see `<redacted>` in place of key material — a
  feature, not a regression.

### Added

- **DIDComm REST endpoint returns `501 Not Implemented`.** The Phase 4 stub
  at `/api/didcomm` previously returned 500. The mediator-driven inbound
  DIDComm path is the supported transport for v0.6; the REST endpoint will
  be revived in a follow-up release.

### Security

- The witness now runs the shared `security_headers` middleware (CSP,
  X-Frame-Options, Referrer-Policy, HSTS, X-Content-Type-Options,
  Cache-Control) on every response. Aligns with control plane and server.
- DIDComm authentication asserts that the JWS signer's DID matches the
  message's `from` field. Same fix as the rest of the workspace; covers a
  potential auth-bypass on the witness's REST `/api/auth/` surface.

### Dependencies

- See workspace CHANGELOG for the full dep-bump matrix (affinidi-tdk
  0.5 → 0.7, affinidi-data-integrity 0.3 → 0.6, vta-sdk 0.4 → 0.5,
  azure_*, redis, jsonwebtoken, etc.).
