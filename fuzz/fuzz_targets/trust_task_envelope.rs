#![no_main]
//! Fuzz the first reads an inbound Trust Task gets on every transport, in the
//! order the listeners run them: the TSP binding envelope
//! (`tsp_binding::open`), the size gate before parsing (`size::check`), then
//! the `TrustTask<Value>` document parse. Built with `--features server-core`.
//! Must never panic.

use did_hosting_common::server::trust_tasks::size;
use did_hosting_common::server::tsp_binding;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use trust_tasks_rs::TrustTask;

/// Type URIs the size gate is told are served: one with a raised limit and an
/// ordinary one, so both branches of the per-type lookup are reachable.
const SERVED: &[&str] = &[
    "https://trusttasks.org/spec/did/register/0.1",
    "https://trusttasks.org/spec/messaging/ping/0.1",
];

fuzz_target!(|data: &[u8]| {
    let (document, _carriage) = tsp_binding::open(data);
    if size::check(&document, SERVED).is_err() {
        return;
    }
    let _ = serde_json::from_slice::<TrustTask<Value>>(&document);
});
