use super::error::{AppError, ValidationKind};

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
