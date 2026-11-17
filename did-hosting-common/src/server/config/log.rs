//! `[log]`: level and format, and the global tracing subscriber.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
}

/// Initialize the global tracing subscriber based on config.
///
/// Uses `try_init` so that callers embedded inside a host process that has
/// already installed a global subscriber (e.g. when this crate is consumed
/// as a library, or when a test harness has set one up) get a no-op rather
/// than a panic. The first installer wins; later attempts log a debug line
/// and continue. Most production callers run as the daemon binary and are
/// the first installer; the no-op path is for embedded use cases.
pub fn init_tracing(log: &LogConfig) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log.level));

    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);

    let result = match log.format {
        LogFormat::Json => subscriber.json().try_init(),
        LogFormat::Text => subscriber.try_init(),
    };
    if let Err(e) = result {
        // Best-effort message — we may have no subscriber to deliver it. Print
        // to stderr as a fallback so the operator at least sees a hint when
        // the embedding host's subscriber is silent.
        eprintln!("tracing subscriber already initialised; continuing ({e})");
    }
}
