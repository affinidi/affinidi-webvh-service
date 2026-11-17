//! did:webvh log parsing and verification: [`parse_log`],
//! [`validate_did_jsonl`], the chain and witness verifiers, the
//! log-extension check and the request-path identifier check.

use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};
use didwebvh_rs::log_entry_state::{LogEntryState, LogEntryValidationStatus};
use didwebvh_rs::parameters::Parameters;

// ---------------------------------------------------------------------------
// JSONL validation & extraction
// ---------------------------------------------------------------------------

/// Upper bound on the number of log entries (versions) a single `did.jsonl`
/// may carry. This is a denial-of-service guard on the per-entry proof
/// verification, not a protocol limit — a webvh DID realistically accrues at
/// most tens to low-hundreds of versions over its lifetime, so this ceiling is
/// only ever reached by a degenerate or deliberately-inflated chain. Bump it if
/// a legitimate deployment ever genuinely needs more.
pub const MAX_LOG_ENTRIES: usize = 10_000;

/// Validate that every line in the JSONL body is a well-formed did:webvh log entry.
///
/// In addition to structural shape, the *last* entry's `state.id` must start
/// with `did:webvh:`. This rules out leaked-push-token attackers republishing
/// arbitrary JSON that happens to deserialise into the LogEntry shape but
/// targets a different DID method.
///
/// Returns an error string on failure (caller wraps in their own error type).
/// This is [`parse_log`] with the parsed entries discarded; a caller that goes
/// on to verify the log should call the verifier alone, which parses once.
pub fn validate_did_jsonl(content: &str) -> Result<(), String> {
    parse_log(content).map(|_| ())
}

/// Parse a `did.jsonl` into unverified log entries — the one parse every
/// did:webvh read path shares ([`validate_did_jsonl`], the chain verifiers,
/// [`servable_did_log`] and [`verify_log_for_witnessing`]), so a structural
/// rule lands in all of them at once.
///
/// Refuses: empty content; more than [`MAX_LOG_ENTRIES`] entries (counted
/// before any per-entry work); a line that is not a log entry (each line is
/// parsed under the method version of the entry before it, as the chain
/// itself is); an entry whose `versionId` is malformed; and a log whose last
/// entry's `state.id` is not a `did:webvh:` identifier, which stops a
/// leaked-push-token republish of arbitrary JSON that merely deserialises
/// into the entry shape. Blank lines are skipped; line numbers in errors
/// count them.
///
/// Nothing is verified: every entry comes back `NotValidated` with default
/// parameters, for the caller's own verifier to walk.
pub fn parse_log(content: &str) -> Result<DIDWebVHState, String> {
    if content.is_empty() {
        return Err("did.jsonl content cannot be empty".into());
    }

    // Bound the entry count up front, before any O(n) per-entry work (the
    // deserialize loop below, and every verifier's per-entry Ed25519 proof
    // check). The 10 MB request limit alone would still admit thousands of
    // versions and let a slot owner amplify CPU by republishing a max-length
    // multi-version log. `MAX_LOG_ENTRIES` is far above any realistic webvh
    // history, so it only ever refuses a degenerate/abusive chain.
    let entry_count = content.lines().filter(|l| !l.trim().is_empty()).count();
    if entry_count == 0 {
        return Err("did.jsonl content has no entries".into());
    }
    if entry_count > MAX_LOG_ENTRIES {
        return Err(format!(
            "did.jsonl has too many log entries (limit {MAX_LOG_ENTRIES})"
        ));
    }

    let mut state = DIDWebVHState::default();
    let mut version = None;
    for (idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry = LogEntry::deserialize_string(line, version)
            .map_err(|e| format!("invalid log entry at line {}: {e}", idx + 1))?;
        version = Some(entry.get_webvh_version());
        let version_number = entry
            .get_version_id_fields()
            .map_err(|e| format!("invalid versionId at line {}: {e}", idx + 1))?
            .0;
        state.log_entries_mut().push(LogEntryState {
            log_entry: entry,
            version_number,
            validation_status: LogEntryValidationStatus::NotValidated,
            validated_parameters: Parameters::default(),
        });
    }

    // Must encode a did:webvh identifier on the latest entry.
    let is_webvh = state.log_entries().last().is_some_and(|last| {
        last.log_entry
            .get_state()
            .get("id")
            .and_then(|id| id.as_str())
            .is_some_and(|id| id.starts_with("did:webvh:"))
    });
    if !is_webvh {
        return Err("did.jsonl latest entry has no resolvable state.id".into());
    }
    Ok(state)
}

// The did:webvh verifiers. All of them start from [`parse_log`]; where they
// differ, they differ on purpose:
//
// - [`verify_did_log_proofs`] / [`verify_did_log_and_witness_proofs`]
//   (via `verify_did_log_chain`): the upstream `DIDWebVHState::validate` plus
//   `assert_complete`, witness threshold included — a log served as-is must be
//   whole. Used where a node accepts a log it did not author.
// - [`verify_did_log_for_publish`] and [`verify_witness_proof_for_version`]
//   (via `parse_and_verify_chain`): per-entry `verify_log_entry`, then the
//   witness threshold only for entries already published, because a new
//   version's witness proofs arrive after it is registered.
// - [`servable_did_log`]: the same per-entry walk, but it fails open — content
//   it cannot parse or whose chain does not verify is served verbatim (the
//   write paths gate on those), and an unmet witness threshold truncates
//   rather than refuses.
// - [`verify_log_for_witnessing`]: verifies only through the entry that first
//   deactivates the DID, so it can name the more specific `deactivated`
//   refusal, and never checks the entry's own witness proofs (it is producing
//   them).

/// Verify the cryptographic proofs on every log entry in a `did.jsonl`
/// chain.
///
/// This is the semantic-correctness gate for the DID method —
/// `validate_did_jsonl` is structural-only (it parses each line and
/// confirms the latest `state.id` is `did:webvh:`) but does not check
/// that the embedded `proof` actually verifies against
/// `parameters.updateKeys`. An authenticated owner (or admin via
/// force) could otherwise publish a `did.jsonl` whose proof is invalid
/// or signed with an unknown key — clients resolving the DID would
/// then encounter a chain that doesn't verify and produce inscrutable
/// downstream failures.
///
/// Wraps the upstream `didwebvh-rs::DIDWebVHState::validate` —
/// signature verification, parameter-transition rules, hash-chain,
/// pre-rotation key authorisation, and post-deactivation tamper
/// detection are all enforced. Witness proofs are NOT validated here
/// (they're optional and uploaded separately via
/// `webvh/witness/publish/0.1`); use `assert_complete()` if you need to
/// reject any partial-chain truncation.
///
/// Returns the structural-validation message verbatim on parse-time
/// failures and a "proof verification failed: ..." prefix on the
/// upstream verifier's report.
pub fn verify_did_log_proofs(content: &str) -> Result<(), String> {
    verify_did_log_chain(content, None).map(|_| ())
}

/// [`verify_did_log_proofs`] plus the DID's witness proofs.
///
/// For a hosting node that serves a log it did not author: when the log
/// configures witnesses, the published witness proofs must be supplied and must
/// meet the threshold — a witnessed DID is refused outright without them rather
/// than served unwitnessed.
pub fn verify_did_log_and_witness_proofs(
    content: &str,
    witness_content: Option<&str>,
) -> Result<(), String> {
    let witnessed = verify_did_log_chain(content, witness_content)?;
    if witnessed && witness_content.is_none_or(|w| w.trim().is_empty()) {
        return Err(
            "the DID log configures witnesses but no witness proofs were supplied; refusing to \
             serve it unwitnessed"
                .into(),
        );
    }
    Ok(())
}

/// Parse `content` into log entries and run the full chain check every
/// caller of it needs: signature against the authorised updateKeys,
/// parameter transitions, the hash chain, pre-rotation, and (via
/// `Parameters::validate`) refusing any entry after a deactivation. Witness
/// proofs are deliberately not part of this — callers that need them layer
/// their own check on top, using each entry's now-populated
/// `validated_parameters.active_witness`.
fn parse_and_verify_chain(content: &str) -> Result<DIDWebVHState, String> {
    let mut state = parse_log(content)?;

    {
        let entries = state.log_entries_mut();
        for idx in 0..entries.len() {
            let (before, rest) = entries.split_at_mut(idx);
            rest[0].verify_log_entry(before.last()).map_err(|e| {
                format!(
                    "proof verification failed: entry {} does not verify: {e}",
                    rest[0].get_version_id()
                )
            })?;
        }
    }

    Ok(state)
}

/// Verify one incoming witness proof against this DID's own stored log,
/// before the control plane persists it to the witness-proof store
/// (`webvh/witness/publish`).
///
/// This is deliberately *not* the threshold check [`verify_did_log_for_publish`]
/// and [`servable_did_log`] do — threshold is a property of the whole set of
/// stored proofs, and partial proofs must be allowed to accumulate one at a
/// time, so it stays a resolve-time concern. What belongs at write time is
/// authenticity: the proof must cryptographically verify over the
/// `versionId` it names, *and* the key that signed it must actually be one
/// of the witnesses this exact log entry's parameters configure. The second
/// check is the one that matters — a `did:key` proof is self-certifying (the
/// public key travels inside `verificationMethod`), so a bare signature
/// check alone would "verify" a proof from any key an attacker just
/// generated, trusted by no one.
///
/// `content` is this DID's currently stored did:webvh log
/// (`content_log_key`); `version_id` and `proof_value` are the two fields
/// `webvh/witness/publish` accepted from the wire.
///
/// Gated on `server-core`: `affinidi_data_integrity` is an optional
/// dependency of this crate, pulled in only by that feature (this module
/// itself is not — a client-only build must still compile without it).
#[cfg(feature = "server-core")]
pub fn verify_witness_proof_for_version(
    content: &str,
    version_id: &str,
    proof_value: &serde_json::Value,
) -> Result<(), String> {
    use affinidi_data_integrity::DataIntegrityProof;

    let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone())
        .map_err(|e| format!("invalid witness proof shape: {e}"))?;

    let state = parse_and_verify_chain(content)?;
    let entry = state
        .log_entries()
        .iter()
        .find(|e| e.get_version_id() == version_id)
        .ok_or_else(|| {
            format!(
                "witness proof names versionId {version_id:?}, which is not in this DID's \
                 published log"
            )
        })?;

    let witnesses = entry
        .validated_parameters
        .active_witness
        .as_ref()
        .and_then(|w| w.witnesses())
        .ok_or_else(|| format!("versionId {version_id:?} does not configure an active witness"))?;

    if !witnesses
        .iter()
        .any(|w| w.as_did_key() == proof.verification_method)
    {
        return Err(format!(
            "witness proof's verificationMethod ({}) does not name a witness configured for \
             versionId {version_id:?}",
            proof.verification_method
        ));
    }

    let options = didwebvh_rs::witness::WitnessVerifyOptions::new();
    entry
        .log_entry
        .validate_witness_proof(&proof, &options)
        .map_err(|e| format!("witness proof failed verification: {e}"))?;

    Ok(())
}

/// Verify a submitted did:webvh log for `did/register` or a publish.
///
/// Every entry's own proof and the hash/parameter chain is checked in full,
/// for the whole log — but the witness threshold is enforced only on
/// entries that were already part of the DID's published log before this
/// call.
///
/// `didwebvh_rs::DIDWebVHState::validate` enforces the witness threshold
/// unconditionally, on every entry including the log's last one. That is
/// right for a resolver — which only ever sees an already-published log,
/// witnessed or not — but wrong for register/publish: a version's witness
/// proofs arrive *after* it is published, via `webvh/witness/publish`, so no
/// proof can exist yet for the version this call is adding. Enforcing the
/// threshold on it here would make the first witnessed version, and every
/// later republish (register/publish re-verifies the whole log each time),
/// permanently unregistrable — see `verify_did_log_proofs`, which is what
/// this function replaces on that path.
///
/// `previously_published` is the number of entries the currently stored log
/// already has (`0` for a brand-new registration) — the caller computes it
/// from its own storage, never from the request, so a submitter cannot
/// widen or shrink which entries this check applies to. Entries before that
/// index must still meet their witness threshold, using `witness_content`
/// (the DID's currently stored witness-proof file, if any); entries at or
/// after it are the new, not-yet-witnessed tail and are exempt from the
/// threshold check outright — their own chain/signature proof is still
/// verified in full, exactly like every other entry.
pub fn verify_did_log_for_publish(
    content: &str,
    witness_content: Option<&str>,
    previously_published: usize,
) -> Result<(), String> {
    let mut state = parse_and_verify_chain(content)?;

    let previously_published = previously_published.min(state.log_entries().len());

    if previously_published == 0 {
        // Nothing has been published yet — every entry here is new tail,
        // exempt from the witness threshold outright.
        return Ok(());
    }

    // Nothing to check if none of the already-published entries are
    // themselves witnessed — skip parsing `witness_content` at all. A slot
    // can hold stale or unrelated bytes at its witness-content key (e.g. an
    // admin takeover, which republishes under a new identity and clears the
    // prior owner's witness file in the same commit this call's caller is
    // about to make); an unwitnessed republish must not fail over content
    // that was never going to be consulted.
    let needs_witness = state.log_entries()[..previously_published].iter().any(|e| {
        e.validated_parameters
            .active_witness
            .as_ref()
            .is_some_and(|w| w.witnesses().is_some())
    });
    if !needs_witness {
        return Ok(());
    }

    // Witness threshold, only for the entries already published. Scoped to
    // that range's highest version so a proof cannot be misapplied to a
    // later entry it does not cover — mirrors `DIDWebVHState::validate`'s
    // own steps 3/4, just capped short of the new tail instead of the whole
    // log.
    let highest_already_published = state.log_entries()[previously_published - 1].version_number;

    let mut proofs = match witness_content.filter(|w| !w.trim().is_empty()) {
        Some(raw) => DIDWebVHState::parse_witness_proofs(raw)
            .map_err(|e| format!("invalid witness proofs: {e}"))?,
        None => didwebvh_rs::witness::proofs::WitnessProofCollection::default(),
    };
    proofs
        .generate_proof_state(highest_already_published)
        .map_err(|e| format!("invalid witness proofs: {e}"))?;

    let options = didwebvh_rs::witness::WitnessVerifyOptions::new();
    for entry in state
        .log_entries_mut()
        .iter_mut()
        .take(previously_published)
    {
        proofs
            .validate_log_entry(entry, highest_already_published, &options)
            .map_err(|e| format!("proof verification failed: {e}"))?;
    }

    Ok(())
}

/// What a resolver may serve for a stored did:webvh log, honouring the
/// witness threshold at every entry that configures one.
///
/// Walks the chain in order — full signature and parameter-transition
/// verification, exactly like [`verify_did_log_proofs`] — and, for each
/// entry that configures an active witness, checks it against
/// `witness_content` (the DID's current witness-proof file, if any). The
/// first entry that fails its witness threshold ends what is servable: every
/// entry before it still resolves. This is did:webvh's own truncation
/// semantics (a resolver serves up to the last version it can fully verify,
/// not "all or nothing"), applied to the witness threshold — so a DID with a
/// satisfied genesis and an unwitnessed republish still resolves to its last
/// witnessed version, rather than going dark the moment a new,
/// not-yet-witnessed version is registered.
///
/// A chain/signature failure is a different matter: register and publish
/// already gate on it, so stored content should never have one, and this
/// function's job is only the witness threshold — not re-litigating chain
/// integrity on every resolve. If an entry fails to verify structurally,
/// this returns `content` unchanged rather than guessing at a truncation
/// point; the same goes for content that plainly isn't a did:webvh log at
/// all (a caller with unrelated content at this key, or an integration
/// test's simplified fixture, must not be gated on witnessing it never
/// declared).
///
/// Unparseable `witness_content` is treated the same as none — a corrupt or
/// legacy blob at the witness-content key must not make an otherwise-good,
/// already-witnessed log stop resolving; it just means nothing further is
/// witnessed than the stored file can actually attest.
///
/// Returns `None` only when a *witness* check fails on the first (genesis)
/// entry — nothing at all is servable then; `Some(jsonl)` otherwise (either
/// `content` verbatim, or its servable prefix, verbatim by entry).
pub fn servable_did_log(content: &str, witness_content: Option<&str>) -> Option<String> {
    // Not a did:webvh log this function can read: served verbatim (see above).
    let Ok(mut state) = parse_log(content) else {
        return Some(content.to_string());
    };

    let highest_version_number = state
        .log_entries()
        .last()
        .map(|e| e.version_number)
        .unwrap_or(0);

    // An unparseable witness file is "no proofs available", not a hard
    // error — see the doc comment above.
    let mut proofs = witness_content
        .filter(|w| !w.trim().is_empty())
        .and_then(|raw| DIDWebVHState::parse_witness_proofs(raw).ok())
        .unwrap_or_default();
    let _ = proofs.generate_proof_state(highest_version_number);

    let options = didwebvh_rs::witness::WitnessVerifyOptions::new();
    let total = state.log_entries().len();
    let mut servable = 0usize;
    {
        let entries = state.log_entries_mut();
        for idx in 0..entries.len() {
            let (before, rest) = entries.split_at_mut(idx);
            let entry = &mut rest[0];
            if entry.verify_log_entry(before.last()).is_err() {
                // Chain/signature failure — not this function's call to
                // make; see the doc comment.
                return Some(content.to_string());
            }
            let witnessed_here = entry
                .validated_parameters
                .active_witness
                .as_ref()
                .is_some_and(|w| w.witnesses().is_some());
            if witnessed_here
                && proofs
                    .validate_log_entry(entry, highest_version_number, &options)
                    .is_err()
            {
                break;
            }
            servable = idx + 1;
        }
    }

    if servable == total {
        return Some(content.to_string());
    }
    if servable == 0 {
        return None;
    }

    let lines: Vec<String> = state.log_entries()[..servable]
        .iter()
        .filter_map(|e| serde_json::to_string(&e.log_entry).ok())
        .collect();
    Some(lines.join("\n"))
}

/// Walk and validate the chain; returns whether the (current) parameters
/// configure witnesses.
fn verify_did_log_chain(content: &str, witness_content: Option<&str>) -> Result<bool, String> {
    let mut state = parse_log(content)?;

    if let Some(raw) = witness_content.filter(|w| !w.trim().is_empty()) {
        let proofs = DIDWebVHState::parse_witness_proofs(raw)
            .map_err(|e| format!("invalid witness proofs: {e}"))?;
        state.set_witness_proofs(proofs);
    }

    let report = state
        .validate()
        .map_err(|e| format!("proof verification failed: {e}"))?;

    // assert_complete rejects truncation — any entry that failed
    // verification or any post-deactivation tampering surfaces here.
    report
        .assert_complete()
        .map_err(|e| format!("proof verification failed (chain incomplete): {e}"))?;

    let witnessed = state.log_entries().last().is_some_and(|e| {
        e.validated_parameters
            .witness
            .as_ref()
            .and_then(|w| serde_json::to_value(w).ok())
            .and_then(|v| v.get("threshold").and_then(|t| t.as_u64()))
            .is_some_and(|t| t > 0)
    });
    Ok(witnessed)
}

/// Why a witness refuses to witness an entry — the refusals
/// `webvh/witness/sign/0.1` declares, in the order it checks them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessLogRefusal {
    /// The log does not verify as a did:webvh log (`invalidLog`).
    InvalidLog(String),
    /// The versionId asked for is not the log's last entry (`versionNotLast`).
    VersionNotLast { last: String },
    /// An entry *before* the one asked for already deactivated the DID
    /// (`deactivated`). The entry that itself first deactivates the DID is
    /// not refused by this rule — did:webvh witnessing applies to it like
    /// any other entry; only an entry after it is.
    Deactivated,
    /// The witness parameter in force for the entry does not name this
    /// witness (`notListed`).
    NotListed,
}

/// What [`verify_log_for_witnessing`] established about a log it accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessedLog {
    /// The DID's SCID: its identity across every host it moves to.
    pub scid: String,
    /// Every entry's versionId, in log order (`version_ids[n - 1]` is entry
    /// `n`'s). The hash chain makes a matching versionId at position `n` a
    /// match of the whole log up to it.
    pub version_ids: Vec<String>,
}

/// Verify a did:webvh log a witness has been asked to witness, *before* it
/// signs anything: the chain up to and including the entry (every entry's
/// proof against its authorised `updateKeys`, the hash chain, pre-rotation and
/// the parameter transitions), that `version_id` is the last entry, that no
/// entry *before* it already deactivated the DID, and that the witness
/// parameter in force for that entry names `witness_did`.
///
/// A DID's deactivating entry — the first to set `parameters.deactivated:
/// true` — is not refused by the deactivation check: did:webvh does not
/// exempt it from witnessing. While a witness set is active, a threshold of
/// it MUST provide valid proofs for every log entry, with no carve-out for
/// the entry that happens to deactivate the DID (did:webvh "DID Witnesses" >
/// "Witness Lists": "while there are active witnesses, a threshold of the
/// active witnesses must provide valid proofs associated with each DID log
/// entry before the DID log entry can be published"). A witness that refused
/// to sign a deactivating entry *as such* would make a DID that ever had
/// witnesses undeactivatable. Only an entry *after* the deactivating one is
/// refused, since nothing is witnessed once a DID is deactivated.
///
/// The entry's own witness proofs are not checked — they are what is being
/// produced. Every other rule of [`verify_did_log_proofs`] applies.
pub fn verify_log_for_witnessing(
    content: &str,
    version_id: &str,
    witness_did: &str,
) -> Result<WitnessedLog, WitnessLogRefusal> {
    let mut state = parse_log(content).map_err(WitnessLogRefusal::InvalidLog)?;
    let entries = state.log_entries_mut();

    // did:webvh deactivation is itself a log entry, and did:webvh does not
    // exempt it from witnessing (see this function's doc comment) — so the
    // entry that *first* sets `deactivated: true` is witnessed like any
    // other, and only an entry *after* it is refused.
    //
    // didwebvh-rs's own per-entry parameter validation already refuses (as a
    // generic, structural error) any entry whose predecessor deactivated the
    // DID — deactivation is terminal for it, not merely un-witnessable. A raw
    // (unverified) look at each entry's own declared `parameters.deactivated`
    // finds that entry *before* full verification reaches — and reports on —
    // it, so the more specific `deactivated` refusal is used instead of the
    // less specific `invalidLog`. This is safe to read unverified: the
    // outcome below is refusal either way, never a signature, and entries up
    // to and including the deactivating one are still fully verified.
    let deactivating_index = entries
        .iter()
        .position(|e| e.log_entry.get_parameters().deactivated == Some(true));
    let last_index = entries.len().checked_sub(1);
    let past_deactivation =
        matches!((deactivating_index, last_index), (Some(d), Some(last)) if d < last);
    let verify_through = deactivating_index.map_or(entries.len(), |d| d + 1);

    for idx in 0..verify_through {
        let (before, rest) = entries.split_at_mut(idx);
        let entry = &mut rest[0];
        entry.verify_log_entry(before.last()).map_err(|e| {
            WitnessLogRefusal::InvalidLog(format!(
                "entry {} does not verify: {e}",
                entry.get_version_id()
            ))
        })?;
    }

    // `get_version_id` reads the raw entry, so this check does not need
    // `last` to have been in the verified range above.
    let last = entries
        .last()
        .ok_or_else(|| WitnessLogRefusal::InvalidLog("the log has no entries".into()))?;
    if last.get_version_id() != version_id {
        return Err(WitnessLogRefusal::VersionNotLast {
            last: last.get_version_id().to_string(),
        });
    }
    if past_deactivation {
        return Err(WitnessLogRefusal::Deactivated);
    }
    let listed = last
        .validated_parameters
        .active_witness
        .as_deref()
        .and_then(|w| w.witnesses())
        .is_some_and(|ws| {
            ws.iter().any(|w| {
                let id = w.id.to_string();
                id == witness_did || format!("did:key:{id}") == witness_did
            })
        });
    if !listed {
        return Err(WitnessLogRefusal::NotListed);
    }
    let scid = last
        .validated_parameters
        .scid
        .as_deref()
        .map(|s| s.to_string())
        .ok_or_else(|| WitnessLogRefusal::InvalidLog("the log establishes no SCID".into()))?;
    Ok(WitnessedLog {
        scid,
        version_ids: entries
            .iter()
            .map(|e| e.get_version_id().to_string())
            .collect(),
    })
}

/// Why [`verify_log_extends`] refused a log: a typed reason, so a caller
/// picks its wire code without reading the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LogExtendError {
    /// The log is shorter than the one held, or diverges from it: a rollback
    /// or a fork.
    #[error(
        "did.jsonl is not an extension of the hosted log ({held} entries held, {received} \
         received, or the shared history differs); refusing a rollback or fork"
    )]
    HistoryRewrite { held: usize, received: usize },
    /// The held log already deactivated the DID, and this one appends to it.
    #[error("the hosted DID is deactivated; refusing entries appended after deactivation")]
    Deactivated,
}

/// Check that `next` is an acceptable successor of the `did.jsonl` a host
/// already holds (`previous`), independent of who sent it.
///
/// A webvh log is append-only: every version commits to the one before it, so
/// the only legitimate way for a hosted log to change is to gain entries at the
/// end. This refuses:
///
/// - **rollback / fork** — a `next` that is not `previous` with zero or more
///   entries appended (shorter, or diverging anywhere in the shared prefix).
///   Serving an older log would resurrect keys the controller has rotated out,
///   or a document it has since changed;
/// - **resurrection** — any change at all to a log whose history already
///   contains a deactivation. A deactivated DID stays deactivated.
///
/// Resending the identical log is accepted (idempotent sync). This is a
/// history check only; pair it with [`verify_did_log_proofs`] for the chain's
/// own validity.
pub fn verify_log_extends(previous: Option<&str>, next: &str) -> Result<(), LogExtendError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    let entries = |log: &str| -> Vec<String> {
        log.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    };
    let old = entries(previous);
    let new = entries(next);
    if new.len() < old.len() || new[..old.len()] != old[..] {
        return Err(LogExtendError::HistoryRewrite {
            held: old.len(),
            received: new.len(),
        });
    }
    let deactivated = old.iter().any(|line| {
        serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|v| v.get("parameters")?.get("deactivated")?.as_bool())
            .unwrap_or(false)
    });
    if deactivated && new.len() != old.len() {
        return Err(LogExtendError::Deactivated);
    }
    Ok(())
}

/// Verify that a `did:webvh:...` identifier names the host described
/// by `server_base_url` and resolves at the slot named by `request_path`.
///
/// Used by atomic claim-and-publish flows where the caller asserts a
/// pre-built `did.jsonl`. Without this check, anyone with write
/// access to a slot could upload content claiming a different host
/// (impersonation) or a different path on this host (claim-jumping).
///
/// `server_base_url` is the URL the server publishes DIDs at — i.e.
/// the resulting hosting URL is `<server_base_url>/<request_path>/did.jsonl`.
/// Trailing slashes on `server_base_url` are tolerated.
pub fn validate_did_id_matches_request(
    did_id: &str,
    request_path: &str,
    server_base_url: &str,
) -> Result<(), String> {
    use didwebvh_rs::url::WebVHURL;
    use url::Url;

    let id_parsed = WebVHURL::parse_did_url(did_id)
        .map_err(|e| format!("did_log's DID identifier {did_id} is not a valid did:webvh: {e}"))?;

    let expected_str = format!(
        "{}/{request_path}/did.jsonl",
        server_base_url.trim_end_matches('/')
    );
    let expected_url = Url::parse(&expected_str).map_err(|e| {
        format!(
            "internal: server_base_url {server_base_url} cannot form a valid URL when combined \
             with the requested path: {e}"
        )
    })?;
    let expected_parsed = WebVHURL::parse_url(&expected_url).map_err(|e| {
        format!(
            "internal: the URL this server would publish at ({expected_str}) cannot be expressed \
             as a webvh URL: {e}"
        )
    })?;

    if id_parsed.domain != expected_parsed.domain || id_parsed.port != expected_parsed.port {
        return Err(format!(
            "did_log's DID host (domain={}, port={:?}) does not match this server's host \
             (domain={}, port={:?})",
            id_parsed.domain, id_parsed.port, expected_parsed.domain, expected_parsed.port,
        ));
    }
    if id_parsed.path != expected_parsed.path {
        return Err(format!(
            "did_log's DID path '{}' does not resolve at the requested path '{}' on this server \
             (server would publish at '{}')",
            id_parsed.path.trim_matches('/'),
            request_path,
            expected_parsed.path.trim_matches('/'),
        ));
    }

    Ok(())
}

#[cfg(test)]
#[path = "log_extension_tests.rs"]
mod log_extension_tests;

/// Tests for [`verify_did_log_for_publish`] — the register/publish witness
/// split: full chain verification for every entry, but the witness
/// threshold enforced only on already-published ones.
#[cfg(test)]
#[path = "verify_for_publish_tests.rs"]
mod verify_for_publish_tests;
