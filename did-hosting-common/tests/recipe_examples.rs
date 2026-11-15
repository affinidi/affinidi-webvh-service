//! Smoke tests: every shipped recipe in `examples/` must parse + validate.
//!
//! Gated on `server-core` since the recipe module lives under
//! `did_hosting_common::server::*`. Run with:
//!
//!   cargo test -p did-hosting-common --features server-core --test recipe_examples
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
//! `CARGO_MANIFEST_DIR` is `<workspace>/did-hosting-common` when these tests
//! run, so we climb one directory level.

use std::path::PathBuf;

use did_hosting_common::server::setup_recipe::{ServiceKind, load_recipe};

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
    load_example("did-hosting-daemon-build.toml", ServiceKind::Daemon);
}

#[test]
fn server_example_parses() {
    load_example("did-hosting-server-build.toml", ServiceKind::Server);
}

#[test]
fn control_example_parses() {
    load_example("did-hosting-control-build.toml", ServiceKind::Control);
}

#[test]
fn witness_example_parses() {
    load_example("webvh-witness-build.toml", ServiceKind::Witness);
}

#[test]
fn watcher_example_parses() {
    load_example("webvh-watcher-build.toml", ServiceKind::Watcher);
}

#[test]
fn daemon_self_managed_example_parses() {
    load_example("did-hosting-daemon-self-managed.toml", ServiceKind::Daemon);
    let recipe =
        load_recipe(&examples_dir().join("did-hosting-daemon-self-managed.toml")).expect("loads");
    assert_eq!(
        recipe.deployment.vta_mode,
        did_hosting_common::server::setup_recipe::VtaMode::SelfManaged,
        "the self-managed example must not need a VTA"
    );
}

/// Every `*.toml` in `examples/` is a recipe the docs tell operators to run,
/// so each one must have a test above. A new example without one fails here.
#[test]
fn every_example_is_covered() {
    let covered = [
        "did-hosting-daemon-build.toml",
        "did-hosting-daemon-self-managed.toml",
        "did-hosting-server-build.toml",
        "did-hosting-control-build.toml",
        "webvh-witness-build.toml",
        "webvh-watcher-build.toml",
    ];
    for entry in std::fs::read_dir(examples_dir()).expect("examples dir") {
        let name = entry.expect("dir entry").file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".toml") {
            assert!(
                covered.contains(&name.as_ref()),
                "examples/{name} has no parse + validate test in recipe_examples.rs"
            );
        }
    }
}
