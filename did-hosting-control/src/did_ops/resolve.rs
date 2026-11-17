//! Agent name to DID and DID to agent names, against the authoritative
//! registry: the write-time name resolution the ACL and owner-change inputs
//! use, and the batch reverse lookup the UI displays.

use did_hosting_common::did_ops::{DidRecord, agent_name_key, did_key};
use did_hosting_common::server::acl::validate_did_format;
use did_hosting_common::server::identity::mnemonic_from_did;

use crate::auth::AuthClaims;
use crate::server::AppState;
use did_hosting_common::server::error::AppError;

/// The most DIDs one resolve call will answer for.
///
/// Sized for the display surfaces that drive it — a settings page holds three
/// DIDs, a servers list a handful — not for bulk export. Each entry is a store
/// read, so an uncapped list would turn one request into unbounded I/O.
pub const MAX_RESOLVE_DIDS: usize = 64;

/// Turn what an operator typed into the DID an authorization record is keyed on.
///
/// Shared by the ACL routes and `change_did_owner`.
///
/// Accepts either a DID, or an **agent name** (`webvh.storm.ws/@alice`) which
/// is resolved to the DID that currently holds it. Names are far easier to type
/// correctly than a `did:webvh:Qm…` string, and a mistyped ACL subject is a
/// silent failure — the entry simply never matches anyone.
///
/// # Resolution happens here, and *only* here
///
/// The value stored is always the DID. Nothing downstream ever resolves a name
/// again, and that is a security property rather than an optimisation:
///
/// - A name can be released by its holder and claimed by someone else. If
///   authorization resolved names at **check** time, the new holder would
///   inherit the old holder's role the moment they claimed it — no write to the
///   ACL, no audit trail, nothing to notice.
/// - `check_acl` is an exact lookup on the authenticated DID, and the principal
///   arriving at every authorization decision is a DID. A name stored as a key
///   could never match one, so late resolution is not merely unsafe, it does
///   not work.
///
/// So an agent name here is *input convenience*. The binding it creates is to
/// the DID the name pointed at when the operator pressed the button, and it
/// stays pointed there. The UI shows the DID's current name by looking it up
/// (the `agent-name/resolve` Trust Task), so the display stays live without the stored
/// authorization data depending on a mutable label.
///
/// Only names this deployment actually serves resolve — the same gates the
/// public `/@name` redirect applies. A name that resolves to nothing is a
/// validation error naming the name, never a silently-created entry keyed on
/// something that cannot authenticate.
pub async fn resolve_did_or_agent_name(state: &AppState, input: &str) -> Result<String, AppError> {
    let trimmed = input.trim();
    if !agent_names::AgentName::looks_like_agent_name(trimmed) {
        return validate_did_format(trimmed);
    }
    // Canonicalise through the shared parser so the authority and local part are
    // split exactly as the resolver and the registry would split them.
    let name = agent_names::AgentName::parse(trimmed)
        .map_err(|e| AppError::invalid(format!("'{trimmed}' is not a valid agent name: {e}")))?;
    match resolve_agent_name_to_did(state, name.authority(), name.local_name()).await? {
        Some(did) => Ok(did),
        None => Err(AppError::invalid(format!(
            "agent name '{}' does not resolve to a DID hosted here — bind it first, \
             or use the DID directly",
            name.without_scheme()
        ))),
    }
}

/// The DID an agent name currently resolves to, or `None` if it resolves to
/// nothing here.
///
/// The `/@name` redirect the edge serves, done in-process against the
/// authoritative registry. Applies the same gates the edge does — the name must
/// be `enabled`, and the slot must be neither disabled nor deleted — so this
/// can never hand back a DID that the public redirect would refuse to serve.
///
/// # This is a *write-time* helper, and that is the whole point
///
/// Resolving a name to a DID is only safe at the moment an operator types it.
/// A name is not a stable identifier: its holder may release it (`remove`) and
/// somebody else may then claim it. Anything that resolves a name **at decision
/// time** therefore hands the new holder whatever the old holder had — silently,
/// with no write to the thing being protected and nothing in an audit log to
/// show for it. Resolve once, store the DID, and a later re-claim changes
/// nothing.
pub async fn resolve_agent_name_to_did(
    state: &AppState,
    domain: &str,
    name: &str,
) -> Result<Option<String>, AppError> {
    if !state.config.features.agent_names {
        return Ok(None);
    }
    let bare = name.strip_prefix('@').unwrap_or(name);
    let Some(mnemonic) = state
        .dids_ks
        .get_raw(agent_name_key(domain, bare))
        .await?
        .and_then(|b| String::from_utf8(b).ok())
    else {
        return Ok(None);
    };
    let Some(record) = state.dids_ks.get::<DidRecord>(did_key(&mnemonic)).await? else {
        return Ok(None);
    };
    if record.disabled || record.deleted_at.is_some() {
        return Ok(None);
    }
    if !record
        .agent_names
        .iter()
        .any(|e| e.name == bare && e.enabled)
    {
        return Ok(None);
    }
    Ok(record.did_id)
}

/// DID → its served agent names, for a batch of DIDs. The reverse of the
/// `/@name` redirect.
///
/// # Why this is not an index lookup
///
/// The registry indexes `name → mnemonic`; nothing maps a DID identifier back
/// to its record. It does not need to: for `did:webvh` the mnemonic *is*
/// derivable from the identifier ([`mnemonic_from_did`]), so this is a direct
/// read per DID rather than a scan. That is also why the result is not
/// authoritative for foreign DIDs — a DID hosted elsewhere simply has no local
/// record, and is reported as having no names rather than resolved over the
/// network. Callers rendering a foreign DID get the DID, which is correct: this
/// service can only vouch for names it serves.
///
/// # What is returned
///
/// Only **served** (`enabled`) names, and only from a record whose `did_id` is
/// the DID asked about. Parked names are registry-private — they resolve to
/// nothing, so publishing them here would advertise a handle that 404s and
/// would leak a reservation its holder deliberately took out of service.
///
/// DIDs with no names are omitted from the map entirely; a caller reads a
/// missing key and an empty list the same way, and the common case is that most
/// DIDs have none.
///
/// # Disclosure
///
/// Every name returned is already in that DID's `alsoKnownAs` and already
/// served as a public redirect by the edge, so this reveals nothing new about a
/// DID the caller already holds. It is authenticated regardless — it answers
/// questions about arbitrary DIDs, and an unauthenticated batch endpoint is an
/// enumeration surface even when each individual answer is public.
///
/// Answers only for DIDs `reader` may read — its own, or any for an
/// administrator — so a DID not hosted here, one the reader may not read and
/// one serving no name are indistinguishable, and the call cannot be used to
/// test whether a DID is hosted.
pub async fn resolve_agent_names(
    state: &AppState,
    reader: &AuthClaims,
    dids: &[String],
) -> Result<std::collections::HashMap<String, Vec<String>>, AppError> {
    use std::collections::HashMap;

    if !state.config.features.agent_names {
        return Ok(HashMap::new());
    }
    if dids.len() > MAX_RESOLVE_DIDS {
        return Err(AppError::invalid(format!(
            "at most {MAX_RESOLVE_DIDS} DIDs per resolve request, got {}",
            dids.len()
        )));
    }

    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for did in dids {
        // Already answered — a caller may repeat a DID (the same instance
        // appearing twice in a list), and one read is enough.
        if out.contains_key(did) {
            continue;
        }
        let Some(mnemonic) = mnemonic_from_did(did) else {
            continue;
        };
        // A failed read is reported, not taken for "no names": a throttled
        // store would otherwise answer success with the names missing.
        let Some(record) = state.dids_ks.get::<DidRecord>(did_key(&mnemonic)).await? else {
            continue;
        };
        // The slot must hold *this* DID. `mnemonic_from_did` yields the slot a
        // DID *would* occupy, and for a pathless DID that is the single global
        // `.well-known` — so without this, asking about any foreign root DID
        // would return the local root DID's names.
        if record.did_id.as_deref() != Some(did.as_str())
            || record.disabled
            || record.deleted_at.is_some()
        {
            continue;
        }
        if reader.role != did_hosting_common::server::acl::Role::Admin && record.owner != reader.did
        {
            continue;
        }
        let names: Vec<String> = record
            .agent_names
            .iter()
            .filter(|e| e.enabled)
            .map(|e| e.name.clone())
            .collect();
        if !names.is_empty() {
            out.insert(did.clone(), names);
        }
    }
    Ok(out)
}
