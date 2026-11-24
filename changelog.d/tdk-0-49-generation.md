### Changed — the workspace moves to the affinidi-tdk 0.49 generation, and `didwebvh-rs` is no longer pinned exactly

Every crate moves to the Affinidi TDK generation built on
`affinidi-data-integrity` 0.9 and `affinidi-secrets-resolver` 0.6, together:
`affinidi-tdk` 0.49, `affinidi-did-common` 0.5,
`affinidi-did-resolver-cache-sdk` 0.9, `affinidi-did-webs` 0.14,
`affinidi-messaging-sdk` 0.50, `affinidi-messaging-didcomm-service` 0.38,
`affinidi-tsp` 0.5, `vta-sdk` 0.92, `vti-common` 0.68, `vti-secrets` 0.41,
the `trust-tasks-*` crates 0.41 and `agent-names` 0.2 (#486).

- `didwebvh-rs` is required as `0.8.3` instead of exactly `=0.8.2`. The exact
  pin was a stopgap: 0.8.3 accepts the newer generation, so an unlocked build
  (`cargo install` without `--locked`) of 0.12 gave it different
  `affinidi-data-integrity` and `affinidi-secrets-resolver` copies from the
  rest of the service and did not compile. Now the whole workspace is on
  that generation.
- `jsonwebtoken` moves from 10 to 12, the version `trust-tasks-https` and
  `vti-common` now use, so the service ships one copy instead of two. It is
  built with the `aws_lc_rs` backend, as they build it, instead of
  `rust_crypto`. Session tokens are still EdDSA, signed and verified only by
  this service. The `rsa` and `crypto-bigint` 0.5 advisories that
  jsonwebtoken 10 brought in no longer apply, and their `deny.toml` ignores
  are gone.
- `did-hosting-control` and `did-hosting-server` no longer declare the storage
  and cloud-secret backend crates themselves. Their `store-*` and `*-secrets`
  features turn on the same `did-hosting-common` features as before, which
  bring those crates in. No feature was renamed or removed.

The `acl/*` Trust Task versions do not change: `acl/{grant,show,change-role,revoke}`
stay at 0.2 and `acl/list` at 0.3. The next versions make a per-entry
`purposes` scope required, which this service does not implement yet.

No configuration, stored data or wire format changes.
