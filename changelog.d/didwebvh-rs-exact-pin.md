### Fixed — `cargo install` builds again: didwebvh-rs is pinned to 0.8.2

`didwebvh-rs` 0.8.3 accepts `affinidi-data-integrity` 0.9 and
`affinidi-secrets-resolver` 0.6, so a fresh resolve (`cargo install`, which
ignores `Cargo.lock`) gave it that generation while the rest of the stack
stayed on 0.8 / 0.5, and the binaries failed to compile. The workspace now
requires `didwebvh-rs = "=0.8.2"` until `vta-sdk` and `vti-common` ship on the
new generation and the whole family can move together (#486). Locked builds
are unchanged.
