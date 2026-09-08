use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum WebVHError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("not authenticated — call authenticate() first")]
    NotAuthenticated,

    #[error("server error ({status}): {message}")]
    Server { status: u16, message: String },

    #[error("DIDComm error: {0}")]
    DIDComm(String),

    #[error("resolver error: {0}")]
    Resolver(String),
}

pub type Result<T> = std::result::Result<T, WebVHError>;

/// Helper to display WebVHError variants without the enum prefix.
impl WebVHError {
    /// Return a short label for the error category.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Http(_) => "http",
            Self::Json(_) => "json",
            Self::NotAuthenticated => "not_authenticated",
            Self::Server { .. } => "server",
            Self::DIDComm(_) => "didcomm",
            Self::Resolver(_) => "resolver",
        }
    }
}

/// Server error response shape: `{"error": "..."}`.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ServerErrorBody {
    pub error: String,
}

impl fmt::Display for ServerErrorBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.error)
    }
}

/// Bound and sanitize a server-supplied error string before it is surfaced to the
/// SDK caller (CWE-209): collapse control characters/whitespace and cap length, so
/// a verbose or input-echoing server body can't leak detail or inject control
/// characters through the client's error.
pub(crate) fn redact_server_message(raw: &str) -> String {
    const MAX_LEN: usize = 200;
    let despaced: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let normalized = despaced.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return "unspecified server error".to_string();
    }
    if normalized.chars().count() <= MAX_LEN {
        return normalized;
    }
    // Mark the cut. Without it a truncated message is indistinguishable from a
    // complete one, so an operator reading a clipped multi-part rejection sees
    // what looks like a malformed server response rather than a long one.
    let mut capped: String = normalized.chars().take(MAX_LEN - 1).collect();
    capped.push('\u{2026}');
    capped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_server_message_bounds_and_sanitizes() {
        assert_eq!(redact_server_message("bad request"), "bad request");
        // A control char (newline) becomes a space; whitespace is normalized.
        let raw = format!("line1{}line2", char::from(10u8));
        assert_eq!(redact_server_message(&raw), "line1 line2");
        // Over-long input is capped, and the cut is marked.
        let long = redact_server_message(&"x".repeat(500));
        assert_eq!(long.chars().count(), 200);
        assert!(
            long.ends_with('\u{2026}'),
            "truncated message must be marked"
        );
        // A message exactly at the cap is returned whole, with no marker.
        let exact = redact_server_message(&"y".repeat(200));
        assert_eq!(exact, "y".repeat(200));
        // One over the cap is the first truncation case.
        assert!(redact_server_message(&"z".repeat(201)).ends_with('\u{2026}'));
        // Empty/blank → a fixed placeholder, never an empty message.
        assert_eq!(redact_server_message("   "), "unspecified server error");
    }
}
