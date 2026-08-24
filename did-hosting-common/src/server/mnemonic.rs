use super::error::{AgentNameError, AppError, ValidationKind};

/// Names that conflict with server routes and must not be used as the
/// **first segment** of a custom path.
const RESERVED_NAMES: &[&str] = &[
    ".well-known",
    "api",
    "auth",
    "dids",
    "stats",
    "acl",
    "health",
];

/// Construct an `InvalidPath`-tagged validation error.
///
/// Tagging at construction lets `AppError::didcomm_code()` return
/// `e.p.did.path-invalid` deterministically — no substring sniffing on
/// the message wording, so renaming the literal here doesn't silently
/// re-route the protocol code.
fn path_err(msg: impl Into<String>) -> AppError {
    AppError::validation(ValidationKind::InvalidPath, msg)
}

/// Validate a single path segment: 2–63 chars, `[a-z0-9-]`, must start
/// and end with an alphanumeric character.
fn validate_segment(segment: &str) -> Result<(), AppError> {
    if segment.len() < 2 || segment.len() > 63 {
        return Err(path_err(
            "each path segment must be between 2 and 63 characters",
        ));
    }

    if !segment
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(path_err(
            "path segments must contain only lowercase letters, digits, and hyphens",
        ));
    }

    let first = segment.as_bytes()[0];
    let last = segment.as_bytes()[segment.len() - 1];
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return Err(path_err(
            "each path segment must start and end with an alphanumeric character",
        ));
    }

    Ok(())
}

/// Validate that a custom path meets the naming rules.
///
/// Rules:
/// - No empty segments, no leading or trailing `/`
/// - Total path length ≤ 255 characters
/// - Each segment: 2–63 chars, `[a-z0-9-]`, starts/ends alphanumeric
/// - First segment must not be a reserved name
pub fn validate_custom_path(path: &str) -> Result<(), AppError> {
    if path.is_empty() {
        return Err(path_err("path must not be empty"));
    }

    if path.len() > 255 {
        return Err(path_err("path must be at most 255 characters"));
    }

    if path.starts_with('/') || path.ends_with('/') {
        return Err(path_err("path must not start or end with '/'"));
    }

    for (i, segment) in path.split('/').enumerate() {
        if segment.is_empty() {
            return Err(path_err(
                "path must not contain empty segments (double slashes)",
            ));
        }
        validate_segment(segment)?;

        if i == 0 && RESERVED_NAMES.contains(&segment) {
            return Err(path_err(format!(
                "'{segment}' is a reserved name and cannot be used as the first path segment",
            )));
        }
    }

    Ok(())
}

/// Validate a mnemonic extracted from a URL path parameter.
///
/// Accepts either `.well-known` (the root DID) or any path that passes
/// [`validate_custom_path`].
pub fn validate_mnemonic(mnemonic: &str) -> Result<(), AppError> {
    if mnemonic == ".well-known" {
        return Ok(());
    }
    validate_custom_path(mnemonic)
}

/// Validate a `did:webs` mnemonic — path segments plus a trailing AID.
///
/// `did:webs` cannot use [`validate_custom_path`], and the reason is not
/// cosmetic. A `did:webs` slot's last segment **is** the identifier's KERI
/// AID: it is the self-certifying value the key event log establishes, it is
/// case-sensitive base64url, and the service does not get to choose it. A
/// typical AID —
/// `ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe` — fails the shared
/// lowercase-only segment rule on its first character, so *every* `did:webs`
/// DID would be unhostable under it.
///
/// The fix is a per-method validator rather than a loosened shared one. The
/// lowercase rule earns its keep for operator-chosen paths: it makes two slots
/// that differ only by case impossible, so a hosted path cannot be shadowed by
/// a confusable twin. Relaxing it globally would give that up for `did:web`
/// and `did:webvh` paths, which have no reason to need it. Here the exception
/// is safe for a different reason — an AID is a high-entropy digest, not a
/// name anyone picks, so a confusable pair is not something an attacker can
/// arrange.
///
/// Rules:
/// - Leading segments (if any): the ordinary [`validate_custom_path`] grammar,
///   reserved-first-segment check included.
/// - Final segment: 4–63 characters from the CESR base64url alphabet
///   (`A–Z`, `a–z`, `0–9`, `-`, `_`), case preserved.
///
/// This is a *syntactic* check. That the trailing segment is the AID of the
/// key event log actually published here is enforced on the write path, where
/// the stream is in hand — see `method::webs::Webs::verify_artifacts`.
pub fn validate_webs_mnemonic(mnemonic: &str) -> Result<(), AppError> {
    if mnemonic.is_empty() {
        return Err(path_err("path must not be empty"));
    }
    if mnemonic.len() > 255 {
        return Err(path_err("path must be at most 255 characters"));
    }
    if mnemonic.starts_with('/') || mnemonic.ends_with('/') {
        return Err(path_err("path must not start or end with '/'"));
    }
    // `did:webs` has no root form: the AID is always the final path
    // segment, so there is never a `.well-known` slot to fall back to.
    if mnemonic == ROOT_DID_MNEMONIC {
        return Err(path_err(
            "did:webs has no root slot — the AID is always the final path segment",
        ));
    }

    let segments: Vec<&str> = mnemonic.split('/').collect();
    let (aid, leading) = segments
        .split_last()
        .expect("split on a non-empty string yields at least one segment");

    for (i, segment) in leading.iter().enumerate() {
        if segment.is_empty() {
            return Err(path_err(
                "path must not contain empty segments (double slashes)",
            ));
        }
        validate_segment(segment)?;
        if i == 0 && RESERVED_NAMES.contains(segment) {
            return Err(path_err(format!(
                "'{segment}' is a reserved name and cannot be used as the first path segment",
            )));
        }
    }

    validate_aid_segment(aid)?;

    // A single-segment mnemonic is the AID alone, and it is also the
    // first segment — so it has to clear the reserved-name check too.
    if leading.is_empty() && RESERVED_NAMES.contains(aid) {
        return Err(path_err(format!(
            "'{aid}' is a reserved name and cannot be used as the first path segment",
        )));
    }

    Ok(())
}

/// Validate the trailing AID segment of a `did:webs` mnemonic.
///
/// Matches the syntactic AID check `affinidi-did-webs` applies when parsing an
/// identifier, so a DID that crate accepts is one this service can host, and
/// one it rejects never reaches storage.
fn validate_aid_segment(aid: &str) -> Result<(), AppError> {
    if aid.len() < 4 || aid.len() > 63 {
        return Err(path_err(
            "the final path segment of a did:webs path is its AID, and must be \
             between 4 and 63 characters",
        ));
    }
    if !aid
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(path_err(
            "the final path segment of a did:webs path is its AID, and must contain \
             only characters from the base64url alphabet (A-Z, a-z, 0-9, '-', '_')",
        ));
    }
    Ok(())
}

/// Agent names nobody may claim.
///
/// Distinct from [`RESERVED_NAMES`], which protects *route* prefixes. These
/// protect **trust**: `@support`, `@security` and `@admin` are what a victim
/// would expect to belong to the operator, so letting a tenant register them
/// hands over a ready-made phishing primitive. `@well-known` is reserved
/// because it looks like infrastructure.
const RESERVED_AGENT_NAMES: &[&str] = &[
    "abuse",
    "admin",
    "administrator",
    "api",
    "help",
    "hostmaster",
    "info",
    "postmaster",
    "root",
    "security",
    "support",
    "sysadmin",
    "webmaster",
    "well-known",
];

/// The mnemonic of the root DID — the slot whose document resolves at
/// `https://{domain}/.well-known/did.jsonl`, and which *is* the domain's own
/// identity. Registering it is admin-only (see `register_did_atomic`).
pub const ROOT_DID_MNEMONIC: &str = ".well-known";

/// Validate an agent name's local part — the `alice` in `/@alice`.
///
/// Deliberately the same grammar as a path segment (2–63 chars, `[a-z0-9-]`,
/// alphanumeric at both ends) so a name can never be ambiguous with, or
/// confusable against, a hosted DID's mnemonic.
///
/// Note the charset makes collision with a mnemonic route structurally
/// impossible in the other direction too: `@` is not a legal mnemonic
/// character, so `/@alice` can never shadow a hosted DID path.
///
/// # The community name
///
/// An **empty** local part is the community name — `webvh.storm.ws/@`, which
/// the agent name FAQ defines as the name of the verifiable trust community
/// owning the domain. It is well-formed, so this returns `Ok` for it, but
/// being well-formed is not permission to *bind* it: that is
/// [`validate_agent_name_binding`]'s job, and every binding site must go
/// through it. This function answers "may this be served / looked up", which
/// is why the edge's resolve route and the availability probe use it directly.
pub fn validate_agent_name(name: &str) -> Result<(), AppError> {
    let name = name.strip_prefix('@').unwrap_or(name);

    // The community name has no local part to check against the grammar, and
    // an empty string is not a reserved *word* — the protection it needs is
    // the binding rule, not this list.
    if name.is_empty() {
        return Ok(());
    }

    validate_segment(name)?;

    if RESERVED_AGENT_NAMES.contains(&name) {
        // A typed error, not `path_err`: the provisioning surfaces map this to
        // the `name_reserved` spec code, distinct from a malformed name.
        return Err(AppError::AgentName(AgentNameError::Reserved));
    }

    Ok(())
}

/// May `mnemonic` bind `name` on this host?
///
/// The grammar check of [`validate_agent_name`], plus the one rule that a
/// grammar cannot express: **the community name (`/@`) belongs to the root DID
/// and to nothing else.**
///
/// That rule is structural rather than role-based, and deliberately so. The
/// community name is the domain's own identity — the strongest phishing
/// primitive the host has, one step beyond the `@support` / `@security` names
/// [`RESERVED_AGENT_NAMES`] already withholds. An admin-only gate would still
/// let an operator bind it to a tenant's DID by mistake; tying it to the
/// `.well-known` slot means the only DID that can ever answer for
/// `{domain}/@` is the one already serving as `{domain}`'s root, which is
/// exactly what a resolver following the name expects to find.
///
/// Call this from **every** site that writes the name index — the explicit
/// `agent-name/*` verbs *and* the publish-path reconciliation, which derives
/// claims from a document's `alsoKnownAs` and so is equally a binding site.
/// Reconciling is not trusting: a tenant that puts `{domain}/@` in its own
/// `alsoKnownAs` is refused here rather than silently registered.
pub fn validate_agent_name_binding(name: &str, mnemonic: &str) -> Result<(), AppError> {
    validate_agent_name(name)?;

    let bare = name.strip_prefix('@').unwrap_or(name);
    if bare.is_empty() && mnemonic != ROOT_DID_MNEMONIC {
        // `Reserved` rather than a new variant: to every caller this is the
        // same answer the reserved list gives — a well-formed name the host
        // keeps for itself — and it already carries the `name_reserved` spec
        // code and a 409.
        return Err(AppError::AgentName(AgentNameError::Reserved));
    }

    Ok(())
}

#[cfg(test)]
mod webs_mnemonic_tests {
    use super::*;

    /// A real AID, from the `did:webs` conformance vectors.
    const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";

    #[test]
    fn the_shared_validator_rejects_every_aid() {
        // The reason `validate_webs_mnemonic` exists. If this ever
        // starts passing, the per-method split can be revisited — but
        // until then, hosting did:webs through the shared grammar is
        // not merely awkward, it is impossible.
        assert!(
            validate_custom_path(AID).is_err(),
            "an AID is mixed-case, so the lowercase-only segment rule rejects it",
        );
    }

    #[test]
    fn accepts_a_bare_aid() {
        validate_webs_mnemonic(AID).expect("an AID alone is the common did:webs slot");
    }

    #[test]
    fn accepts_path_segments_before_the_aid() {
        validate_webs_mnemonic(&format!("tenants/acme/{AID}")).expect("leading path is allowed");
    }

    #[test]
    fn rejects_uppercase_in_leading_segments() {
        // Only the AID gets the case exemption; operator-chosen path
        // segments keep the confusable-proof lowercase rule.
        assert!(validate_webs_mnemonic(&format!("Tenants/{AID}")).is_err());
    }

    #[test]
    fn rejects_a_reserved_first_segment() {
        assert!(validate_webs_mnemonic(&format!("api/{AID}")).is_err());
        // Including when the AID is itself the first segment.
        assert!(validate_webs_mnemonic("api").is_err());
    }

    #[test]
    fn rejects_an_aid_outside_base64url() {
        assert!(validate_webs_mnemonic("not.an.aid").is_err());
        assert!(validate_webs_mnemonic("has spaces").is_err());
    }

    #[test]
    fn rejects_a_too_short_aid() {
        assert!(validate_webs_mnemonic("abc").is_err());
    }

    #[test]
    fn rejects_the_root_slot() {
        // did:webs always has the AID as its last path segment, so the
        // `.well-known` root form never applies.
        assert!(validate_webs_mnemonic(ROOT_DID_MNEMONIC).is_err());
    }

    #[test]
    fn rejects_empty_and_slash_edges() {
        assert!(validate_webs_mnemonic("").is_err());
        assert!(validate_webs_mnemonic(&format!("/{AID}")).is_err());
        assert!(validate_webs_mnemonic(&format!("{AID}/")).is_err());
        assert!(validate_webs_mnemonic(&format!("tenants//{AID}")).is_err());
    }

    #[test]
    fn accepts_the_base64url_specials() {
        // `-` and `_` are in the CESR alphabet and appear in real AIDs.
        validate_webs_mnemonic("EAbc-def_ghi").expect("`-` and `_` are legal in an AID");
    }
}
