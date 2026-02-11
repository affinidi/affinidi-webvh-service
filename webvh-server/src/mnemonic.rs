use crate::error::AppError;
use crate::store::KeyspaceHandle;
use bip39::Language;
use rand::random_range;

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

/// Generate a random 2-word BIP-39 mnemonic (e.g., "apple-banana").
fn random_mnemonic() -> String {
    let wordlist = Language::English.word_list();
    let w1 = wordlist[random_range(0..wordlist.len())];
    let w2 = wordlist[random_range(0..wordlist.len())];
    format!("{w1}-{w2}")
}

/// Generate a unique 2-word BIP-39 mnemonic that doesn't collide with
/// existing entries in the store. Retries up to 100 times.
pub async fn generate_unique_mnemonic(dids_ks: &KeyspaceHandle) -> Result<String, AppError> {
    for _ in 0..100 {
        let mnemonic = random_mnemonic();
        let key = format!("did:{mnemonic}");
        if !dids_ks.contains_key(key).await? {
            return Ok(mnemonic);
        }
    }

    Err(AppError::Internal(
        "failed to generate unique mnemonic after 100 attempts".into(),
    ))
}

/// Validate a single path segment: 2–63 chars, `[a-z0-9-]`, must start
/// and end with an alphanumeric character.
fn validate_segment(segment: &str) -> Result<(), AppError> {
    if segment.len() < 2 || segment.len() > 63 {
        return Err(AppError::Validation(
            "each path segment must be between 2 and 63 characters".into(),
        ));
    }

    if !segment
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(AppError::Validation(
            "path segments must contain only lowercase letters, digits, and hyphens".into(),
        ));
    }

    let first = segment.as_bytes()[0];
    let last = segment.as_bytes()[segment.len() - 1];
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return Err(AppError::Validation(
            "each path segment must start and end with an alphanumeric character".into(),
        ));
    }

    Ok(())
}

/// Validate that a custom path meets the naming rules.
///
/// Paths may contain `/` separators for hierarchical folder-style paths
/// (e.g. `people/staff/glenn`). Each segment is validated individually.
/// The **first segment** is checked against reserved route names to prevent
/// collisions with `/api`, `/.well-known`, etc.
///
/// Rules:
/// - No empty segments, no leading or trailing `/`
/// - Total path length ≤ 255 characters
/// - Each segment: 2–63 chars, `[a-z0-9-]`, starts/ends alphanumeric
/// - First segment must not be a reserved name
pub fn validate_custom_path(path: &str) -> Result<(), AppError> {
    if path.is_empty() {
        return Err(AppError::Validation("path must not be empty".into()));
    }

    if path.len() > 255 {
        return Err(AppError::Validation(
            "path must be at most 255 characters".into(),
        ));
    }

    if path.starts_with('/') || path.ends_with('/') {
        return Err(AppError::Validation(
            "path must not start or end with '/'".into(),
        ));
    }

    let segments: Vec<&str> = path.split('/').collect();

    for segment in &segments {
        if segment.is_empty() {
            return Err(AppError::Validation(
                "path must not contain empty segments (double slashes)".into(),
            ));
        }
        validate_segment(segment)?;
    }

    // Only check the first segment against reserved names
    if let Some(&first) = segments.first()
        && RESERVED_NAMES.contains(&first)
    {
        return Err(AppError::Validation(format!(
            "'{first}' is a reserved name and cannot be used as the first path segment",
        )));
    }

    Ok(())
}

/// Check whether a path is available (not already taken) in the store.
pub async fn is_path_available(dids_ks: &KeyspaceHandle, path: &str) -> Result<bool, AppError> {
    Ok(!dids_ks.contains_key(format!("did:{path}")).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Valid paths ----

    #[test]
    fn valid_simple_path() {
        assert!(validate_custom_path("hello-world").is_ok());
    }

    #[test]
    fn valid_nested_path() {
        assert!(validate_custom_path("people/staff/glenn").is_ok());
    }

    #[test]
    fn valid_numeric_segment() {
        assert!(validate_custom_path("org123").is_ok());
    }

    #[test]
    fn valid_min_segment_length() {
        assert!(validate_custom_path("ab").is_ok());
    }

    #[test]
    fn valid_max_segment_length() {
        let seg = "a".repeat(63);
        assert!(validate_custom_path(&seg).is_ok());
    }

    #[test]
    fn valid_reserved_name_in_non_first_segment() {
        assert!(validate_custom_path("myorg/api").is_ok());
    }

    // ---- Invalid paths ----

    #[test]
    fn invalid_empty() {
        assert!(validate_custom_path("").is_err());
    }

    #[test]
    fn invalid_too_long() {
        let path = "a".repeat(256);
        assert!(validate_custom_path(&path).is_err());
    }

    #[test]
    fn invalid_leading_slash() {
        assert!(validate_custom_path("/hello").is_err());
    }

    #[test]
    fn invalid_trailing_slash() {
        assert!(validate_custom_path("hello/").is_err());
    }

    #[test]
    fn invalid_double_slash() {
        assert!(validate_custom_path("hello//world").is_err());
    }

    #[test]
    fn invalid_segment_too_short() {
        assert!(validate_custom_path("a").is_err());
    }

    #[test]
    fn invalid_segment_too_long() {
        let seg = "a".repeat(64);
        assert!(validate_custom_path(&seg).is_err());
    }

    #[test]
    fn invalid_uppercase() {
        assert!(validate_custom_path("Hello").is_err());
    }

    #[test]
    fn invalid_special_chars() {
        assert!(validate_custom_path("hello_world").is_err());
    }

    #[test]
    fn invalid_leading_hyphen() {
        assert!(validate_custom_path("-hello").is_err());
    }

    #[test]
    fn invalid_trailing_hyphen() {
        assert!(validate_custom_path("hello-").is_err());
    }

    #[test]
    fn invalid_reserved_api() {
        assert!(validate_custom_path("api").is_err());
    }

    #[test]
    fn invalid_reserved_well_known() {
        assert!(validate_custom_path(".well-known").is_err());
    }

    #[test]
    fn invalid_reserved_dids() {
        assert!(validate_custom_path("dids").is_err());
    }

    #[test]
    fn invalid_reserved_stats() {
        assert!(validate_custom_path("stats").is_err());
    }

    #[test]
    fn invalid_reserved_acl() {
        assert!(validate_custom_path("acl").is_err());
    }

    #[test]
    fn invalid_reserved_health() {
        assert!(validate_custom_path("health").is_err());
    }

    #[test]
    fn invalid_reserved_auth() {
        assert!(validate_custom_path("auth").is_err());
    }

    #[test]
    fn valid_255_chars() {
        // 63-char segments separated by `/` — 4 segments = 4*63 + 3 = 255
        let seg = "a".repeat(63);
        let path = format!("{seg}/{seg}/{seg}/{seg}");
        assert_eq!(path.len(), 255);
        assert!(validate_custom_path(&path).is_ok());
    }
}
