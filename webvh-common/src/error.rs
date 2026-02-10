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
#[derive(serde::Deserialize)]
pub(crate) struct ServerErrorBody {
    pub error: String,
}

impl fmt::Display for ServerErrorBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.error)
    }
}
