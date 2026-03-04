pub mod extractor;
pub mod jwt;
pub mod session;

pub use extractor::{AdminAuth, AuthClaims};

/// Constant-time byte comparison to prevent timing side-channel attacks.
///
/// Used for challenge values, bearer tokens, and other security-sensitive
/// string comparisons. The length check is not constant-time, but the values
/// being compared (challenges, tokens) have publicly known fixed lengths.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
