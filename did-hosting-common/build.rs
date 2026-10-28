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
    {
        let generated = match trust_tasks_build::Config::new().compile() {
            Ok(path) => path,
            Err(e) => panic!("trust-tasks-build: {e}"),
        };
        write_schema_index(&generated);
    }
}

/// Writes `trust_tasks_schema_index.rs` next to the generated types: a
/// `schema_for(type_uri)` over every pinned request and `#response` Type URI,
/// the same shape as `trust_tasks_rs::schema_index::schema_for` but for the
/// versions this workspace pins rather than the runtime's prebuilt specs.
///
/// The Type URIs are read from the generated `impl Payload` blocks, and each
/// one's module path follows from the URI (`acl/change-role/0.2` →
/// `acl::change_role::v0_2`). A path that does not exist fails the build.
#[cfg(feature = "server-core")]
fn write_schema_index(generated: &std::path::Path) {
    const PREFIX: &str = "https://trusttasks.org/spec/";
    let src = std::fs::read_to_string(generated).expect("read generated trust tasks");
    let mut arms = String::new();
    let mut lines = src.lines();
    while let Some(line) = lines.next() {
        let ty = match line.trim() {
            "impl ::trust_tasks_rs::Payload for Payload {" => "Payload",
            "impl ::trust_tasks_rs::Payload for Response {" => "Response",
            _ => continue,
        };
        let uri = lines
            .next()
            .and_then(|l| l.trim().strip_prefix("const TYPE_URI: &'static str = \""))
            .and_then(|l| l.strip_suffix("\";"))
            .expect("a generated Payload impl starts with its TYPE_URI");
        let bare = uri.strip_suffix("#response").unwrap_or(uri);
        let Some(rest) = bare.strip_prefix(PREFIX) else {
            continue;
        };
        let (slug, version) = rest.rsplit_once('/').expect("Type URI ends in /M.N");
        let module: Vec<String> = slug.split('/').map(|s| s.replace('-', "_")).collect();
        let path = format!(
            "self::{}::v{}::{ty}",
            module.join("::"),
            version.replace('.', "_")
        );
        arms.push_str(&format!(
            "        {uri:?} => <{path} as ::trust_tasks_rs::Payload>::PAYLOAD_SCHEMA,\n"
        ));
    }
    let out = format!(
        "/// The payload schema for a pinned Type URI (bare for the request,\n\
         /// suffixed `#response` for the response), or `None` if this workspace\n\
         /// pins no such version.\n\
         pub fn schema_for(type_uri: &str) -> Option<&'static str> {{\n\
         \x20   match type_uri {{\n{arms}        _ => None,\n    }}\n}}\n"
    );
    let dest = generated.with_file_name("trust_tasks_schema_index.rs");
    std::fs::write(dest, out).expect("write schema index");
}
