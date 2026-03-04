use crate::error::AppError;
use crate::store::KeyspaceHandle;
use bip39::Language;
use rand::random_range;

// Re-export validation from common crate
pub use affinidi_webvh_common::server::mnemonic::{validate_custom_path, validate_mnemonic};

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
