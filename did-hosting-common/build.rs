// Generates the Trust Task types this workspace speaks from the versions
// pinned in `trust-tasks.lock` (vendored bundles under `trust-tasks/`), so no
// crate here compiles `trust-tasks-rs`'s prebuilt spec modules. Change a pin
// with the `trust-tasks` CLI (`cargo install trust-tasks-cli`), run from this
// directory, and commit the toml, the lock and the bundles together.
//
// Only `server-core` builds use Trust Tasks; other builds skip generation.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_FEATURE_SERVER_CORE").is_none() {
        return;
    }
    #[cfg(feature = "server-core")]
    if let Err(e) = trust_tasks_build::Config::new().compile() {
        panic!("trust-tasks-build: {e}");
    }
}
