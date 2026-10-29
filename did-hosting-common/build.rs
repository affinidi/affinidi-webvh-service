// Generates the Trust Task types this workspace speaks from the versions
// pinned in `trust-tasks.lock` (vendored bundles under `trust-tasks/`), so no
// crate here compiles `trust-tasks-rs`'s prebuilt spec modules. Change a pin
// with the `trust-tasks` CLI (`cargo install trust-tasks-cli`), run from this
// directory, and commit the toml, the lock and the bundles together.
//
// Only `server-core` builds use Trust Tasks; other builds skip generation.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_FEATURE_SERVER_CORE").is_none() {
        return Ok(());
    }
    #[cfg(feature = "server-core")]
    {
        let generated = trust_tasks_build::Config::new()
            .compile()
            .map_err(|e| format!("trust-tasks-build: {e}"))?;
        write_schema_index(&generated)?;
    }
    Ok(())
}

/// Writes `trust_tasks_schema_index.rs` next to the generated types: a
/// `schema_for(type_uri)` over every pinned request and `#response` Type URI,
/// the same shape as `trust_tasks_rs::schema_index::schema_for` but for the
/// versions this workspace pins rather than the runtime's prebuilt specs.
///
/// The entries come from `trust-tasks.lock` and its bundles — the same inputs
/// the types were generated from (`compile()` has already verified each
/// bundle against its locked digest). Each one names the generated type's
/// `PAYLOAD_SCHEMA`, so a module path that does not exist fails the build.
#[cfg(feature = "server-core")]
fn write_schema_index(generated: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::fmt::Write as _;

    let lock = trust_tasks_build::Lockfile::read("trust-tasks.lock")
        .map_err(|e| format!("trust-tasks.lock: {e}"))?;
    let bundle_dir = std::path::Path::new("trust-tasks");
    let mut arms = String::new();
    for task in &lock.tasks {
        if task.source.is_some() {
            return Err(format!(
                "{}: third-party sources are not indexed; extend build.rs first",
                task.display_id()
            )
            .into());
        }
        let bundle = task
            .read_bundle(bundle_dir)
            .map_err(|e| format!("{}: {e}", task.display_id()))?;
        // `acl/change-role` 0.2 → `acl::change_role::v0_2`, the generator's
        // module layout.
        let module = format!(
            "self::{}::v{}",
            task.slug.replace('-', "_").replace('/', "::"),
            task.version.replace('.', "_")
        );
        let uri = &task.type_uri;
        writeln!(
            arms,
            "        {uri:?} => <{module}::Payload as ::trust_tasks_rs::Payload>::PAYLOAD_SCHEMA,"
        )?;
        if bundle.response_schema.is_some() {
            let response = format!("{uri}#response");
            writeln!(
                arms,
                "        {response:?} => <{module}::Response as ::trust_tasks_rs::Payload>::PAYLOAD_SCHEMA,"
            )?;
        }
    }
    let out = format!(
        "/// The payload schema for a pinned Type URI (bare for the request,\n\
         /// suffixed `#response` for the response), or `None` if this workspace\n\
         /// pins no such version.\n\
         pub fn schema_for(type_uri: &str) -> Option<&'static str> {{\n\
         \x20   match type_uri {{\n{arms}        _ => None,\n    }}\n}}\n"
    );
    let dest = generated.with_file_name("trust_tasks_schema_index.rs");
    std::fs::write(&dest, out).map_err(|e| format!("{}: {e}", dest.display()))?;
    Ok(())
}
