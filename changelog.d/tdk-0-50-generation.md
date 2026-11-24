### Changed — the workspace moves to the affinidi-tdk 0.50 generation, and the graph holds one trust-tasks copy

Every Affinidi / VTI crate moves together: `affinidi-tdk` 0.50,
`affinidi-messaging-sdk` 0.51, `affinidi-messaging-didcomm-service` 0.39,
`vta-sdk` 0.94, `vti-common` 0.70, `vti-secrets` 0.43, the `trust-tasks-*`
crates 0.41.2, `trust-tasks-build` 0.2.2 and the test mediator 0.56 (dev).
No source change was needed.

- The messaging stack is now on trust-tasks 0.41, so `trust-tasks-rs` and
  `trust-tasks-proof` 0.40 leave the dependency graph. `cargo tree -d` lists
  no duplicate `affinidi-*`, `trust-tasks-*`, `vta-*` or `vti-*` crate, and
  the `deny.toml` skips for the 0.40 copies, `trust-tasks-build` 0.1 and
  `pem` are gone.
- `fuzz/Cargo.lock` is refreshed the same way.

No configuration, stored data or wire format changes.
