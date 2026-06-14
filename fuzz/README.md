# Fuzzing `did_ops`

Coverage-guided fuzzing for the pure validators in
`did_hosting_common::did_ops` (issue #47).

This is a **detached crate** — it declares its own empty `[workspace]`, so the
root `cargo build`/`cargo test` never compile it and the nightly-only
libfuzzer toolchain stays out of normal CI. The scheduled
`.github/workflows/fuzz.yml` job runs it on a cron.

## Targets

| target | input | what it exercises |
|---|---|---|
| `validate_did_jsonl` | `&str` | per-line parse + the did:webvh latest-entry gate |
| `verify_did_log_proofs` | `&str` | SCID / entry-hash chain walk + proof gate (seeded by valid chains) |
| `verify_did_log_proofs_structured` | `Vec<LogEntry>` | structure-aware chains via didwebvh-rs `arbitrary` → JSONL → verifier |
| `validate_did_id_matches_request` | `(String, String, String)` | did:webvh URL parse + host/path impersonation guard |

The property under test for every target: the validator returns `Ok`/`Err` and
**never panics** on hostile input.

## Running

Requires a nightly toolchain and cargo-fuzz:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz

# from the repo root:
cargo +nightly fuzz run verify_did_log_proofs -- -max_total_time=60
cargo +nightly fuzz run verify_did_log_proofs_structured -- -max_total_time=60
cargo +nightly fuzz list          # list all targets
```

## Seed corpus

`corpus/<target>/` holds committed seeds. Regenerate the `did.jsonl` seeds with
the generator (which self-checks each fixture against the real validators):

```sh
cargo run -p did-hosting-common --example gen_corpus -- fuzz/corpus
```
