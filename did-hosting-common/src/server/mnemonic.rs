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

/// Validate an agent name's local part — the `alice` in `/@alice`.
///
/// Deliberately the same grammar as a path segment (2–63 chars, `[a-z0-9-]`,
/// alphanumeric at both ends) so a name can never be ambiguous with, or
/// confusable against, a hosted DID's mnemonic.
///
/// Note the charset makes collision with a mnemonic route structurally
/// impossible in the other direction too: `@` is not a legal mnemonic
/// character, so `/@alice` can never shadow a hosted DID path.
pub fn validate_agent_name(name: &str) -> Result<(), AppError> {
    let name = name.strip_prefix('@').unwrap_or(name);

    validate_segment(name)?;

    if RESERVED_AGENT_NAMES.contains(&name) {
        // A typed error, not `path_err`: the provisioning surfaces map this to
        // the `name_reserved` spec code, distinct from a malformed name.
        return Err(AppError::AgentName(AgentNameError::Reserved));
    }

    Ok(())
}
