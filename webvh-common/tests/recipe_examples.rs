//! Smoke tests: every shipped recipe in `examples/` must parse + validate.
//!
//! Gated on `server-core` since the recipe module lives under
//! `affinidi_webvh_common::server::*`. Run with:
//!
//!   cargo test -p affinidi-webvh-common --features server-core --test recipe_examples
//!
//! CI builds with the server-core feature on as a matter of course.

#![cfg(feature = "server-core")]

//!
//! These tests run in CI to catch regressions where the schema and an
//! example drift apart. They don't exercise the apply paths — those
//! touch the secret store and live filesystem — but the parse-and-
//! validate gate is what most operator-facing typos hit.
//!
//! The recipes ship at the workspace root (`<workspace>/examples/`).
//! `CARGO_MANIFEST_DIR` is `<workspace>/webvh-common` when these tests
//! run, so we climb one directory level.

use std::path::PathBuf;

use affinidi_webvh_common::server::setup_recipe::{ServiceKind, load_recipe};

fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("examples")
}

fn load_example(name: &str, expected: ServiceKind) {
    let path = examples_dir().join(name);
    let recipe = load_recipe(&path).unwrap_or_else(|e| {
        panic!("example {name} failed to load + validate: {e}");
    });
    assert_eq!(
        recipe.deployment.service, expected,
        "example {name} targeted wrong service"
    );
}

#[test]
fn daemon_example_parses() {
    load_example("webvh-daemon-build.toml", ServiceKind::Daemon);
}

#[test]
fn server_example_parses() {
    load_example("webvh-server-build.toml", ServiceKind::Server);
}

#[test]
fn control_example_parses() {
    load_example("webvh-control-build.toml", ServiceKind::Control);
}

#[test]
fn witness_example_parses() {
    load_example("webvh-witness-build.toml", ServiceKind::Witness);
}

#[test]
fn watcher_example_parses() {
    load_example("webvh-watcher-build.toml", ServiceKind::Watcher);
}
