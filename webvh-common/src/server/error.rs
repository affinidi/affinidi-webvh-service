use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tracing::{debug, warn};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("store error: {0}")]
    Store(String),

    #[error("secret store error: {0}")]
    SecretStore(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("authentication error: {0}")]
    Authentication(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),
}

/// Semantic tags for finer-grained error classification without string matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationKind {
    InvalidLog,
    InvalidPath,
    InvalidWitness,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaKind {
    Size,
    Count,
}

impl AppError {
    /// Create a tagged validation error.
    pub fn validation(kind: ValidationKind, msg: impl Into<String>) -> Self {
        let mut s = msg.into();
        // Embed a machine-readable tag prefix for structured matching
        let tag = match kind {
            ValidationKind::InvalidLog => "[log]",
            ValidationKind::InvalidPath => "[path]",
            ValidationKind::InvalidWitness => "[witness]",
            ValidationKind::Other => "",
        };
        if !tag.is_empty() {
            s = format!("{tag} {s}");
        }
        AppError::Validation(s)
    }

    /// Classify a Validation error's kind by its tag prefix.
    pub fn validation_kind(&self) -> ValidationKind {
        match self {
            AppError::Validation(msg) => {
                if msg.starts_with("[log]") {
                    ValidationKind::InvalidLog
                } else if msg.starts_with("[path]") {
                    ValidationKind::InvalidPath
                } else if msg.starts_with("[witness]") {
                    ValidationKind::InvalidWitness
                } else {
                    ValidationKind::Other
                }
            }
            _ => ValidationKind::Other,
        }
    }

    /// Classify a QuotaExceeded error's kind by its content.
    pub fn quota_kind(&self) -> QuotaKind {
        match self {
            AppError::QuotaExceeded(msg) if msg.contains("size") => QuotaKind::Size,
            _ => QuotaKind::Count,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::SecretStore(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Serialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Authentication(_) => StatusCode::UNAUTHORIZED,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::Validation(_) => StatusCode::BAD_REQUEST,
            AppError::QuotaExceeded(_) => StatusCode::FORBIDDEN,
        };

        if status.is_server_error() {
            warn!(status = %status.as_u16(), error = %self, "server error");
        } else {
            debug!(status = %status.as_u16(), error = %self, "client error");
        }

        let body = serde_json::json!({ "error": self.to_string() });
        (status, axum::Json(body)).into_response()
    }
}
