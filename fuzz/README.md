# Fuzzing `did_ops`

Coverage-guided fuzzing for the pure validators in
`did_hosting_common::did_ops` (issue #47).

This is a **detached crate** — it declares its own empty `[workspace]`, so the
root `cargo build`/`cargo test` never compile it and the nightly-only
libfuzzer toolchain stays out of normal CI. `.github/workflows/fuzz.yml` runs
every target for 300s on a cron, and for 60s on a pull request that touches
`did-hosting-common/` or `fuzz/`.

## Targets

| target | input | what it exercises |
|---|---|---|
| `validate_did_jsonl` | `&str` | per-line parse + the did:webvh latest-entry gate |
| `verify_did_log_proofs` | `&str` | SCID / entry-hash chain walk + proof gate (seeded by valid chains) |
| `verify_did_log_proofs_structured` | `Vec<LogEntry>` | structure-aware chains via didwebvh-rs `arbitrary` → JSONL → verifier |
| `validate_did_id_matches_request` | `(String, String, String)` | did:webvh URL parse + host/path impersonation guard |
| `verify_log_for_witnessing` | `versionId` line, witness DID line, log | the check a witness runs before signing: chain walk, deactivation index, last-entry and witness-list checks |
| `verify_did_log_with_witness_proofs` | count byte, log, optional NUL + `did-witness.json` | `verify_did_log_and_witness_proofs`, `verify_did_log_for_publish`, `servable_did_log` |
| `verify_log_extends` | previous log, NUL, next log | the append-only (rollback / fork / post-deactivation) check |
| `log_metadata` | `&str` | the unverified `did.jsonl` readers (`extract_*`, `parse_log_entries`) |
| `trust_task_envelope` ¹ | `&[u8]` | `tsp_binding::open` → `trust_tasks::size::check` → `TrustTask<Value>` parse |
| `mnemonic` ¹ | `&str` | `validate_mnemonic`, `validate_webs_mnemonic` |
| `witness_proof_for_version` ¹ | `versionId` line, proof JSON line, log | `verify_witness_proof_for_version` (witness proofs taken from the wire) |

¹ Server-only code: build with `--features server-core`, which enables
`did-hosting-common/server-core`.

The property under test for every target: the validator returns `Ok`/`Err` and
**never panics** on hostile input.

## Running

Requires a nightly toolchain and cargo-fuzz:

```sh
rustup toolchain install nightly
cargo install --locked cargo-fuzz

# from the repo root:
cargo +nightly fuzz run verify_did_log_proofs -- -max_total_time=60
cargo +nightly fuzz run verify_did_log_proofs_structured -- -max_total_time=60
cargo +nightly fuzz run --features server-core trust_task_envelope -- -max_total_time=60
cargo +nightly fuzz list          # list all targets
```

## Seed corpus

The seeds for the newer targets (`verify_log_for_witnessing`,
`verify_did_log_with_witness_proofs`, `verify_log_extends`, `log_metadata`,
`witness_proof_for_version`) are the committed chains in the input layout each
target expects; their witness proofs and Trust Task proofs are placeholders,
there to get past the parsers, not to verify.

`corpus/<target>/` holds committed seeds. Regenerate the `did.jsonl` seeds with
the generator (which self-checks each fixture against the real validators):

```sh
cargo run -p did-hosting-common --example gen_corpus -- fuzz/corpus
```
