### Changed — `did-hosting-control` refuses to build with no storage backend, or with more than one

Its build script used to print a warning and carry on, leaving a binary that
could not open a store (none selected) or picked one by accident of cfg
ordering (several). It now fails the build with the same message as
`did-hosting-server`, `webvh-witness` and `webvh-watcher`: enable exactly one
of `store-fjall`, `store-redis`, `store-dynamodb`, `store-firestore` or
`store-cosmosdb`.

### Changed — release builds use one codegen unit and strip symbols

`[profile.release]` adds `codegen-units = 1` and `strip = "symbols"`
alongside the existing `opt-level = "s"` and `lto = true`. Release binaries
are smaller and a little faster to run, slower to build, and a panic
backtrace from one shows addresses rather than function names; build with
`CARGO_PROFILE_RELEASE_STRIP=none` when you need them. `opt-level` stays at
`"s"`: `3` measured no faster on webvh log verification and made the binary
about 27% larger.

### Fixed — `did-hosting-daemon` builds without the `ui` feature

`cargo build -p did-hosting-daemon --no-default-features --features
<store>,did-methods` failed to compile (a missing `IntoResponse` import on the
no-UI fallback route). CI now builds the daemon once per storage backend
without default features, so a broken feature passthrough is caught.
