//! `[fjall]`: optional fjall memory settings, byte-size parsing, and the
//! `STORAGE_FJALL_*` environment overrides.

use crate::server::error::AppError;
use serde::{Deserialize, Serialize};

/// Optional Fjall memory settings, shared by every service that opens a
/// local fjall store (did-hosting-control, did-hosting-server,
/// webvh-witness, webvh-watcher, and did-hosting-daemon, which opens two).
/// Exists so a pod's Kubernetes memory limit can be kept clear of fjall's
/// block cache, buffered writes and startup journal replay — all three
/// grow with the data set and, left at fjall's defaults, are sized for a
/// workstation rather than a constrained pod.
///
/// Deliberately **not** a field of [`StoreConfig`](super::StoreConfig): that type is
/// constructed as a bare struct literal (`StoreConfig { data_dir: .. }`)
/// at hundreds of call sites across the workspace, mostly tests opening
/// an ad hoc store, and adding a field there would force every one of
/// them to change. Instead this is a sibling value each service loads
/// separately (a `[fjall]` config-file table, see below) and threads
/// explicitly into [`crate::server::store::Store::open_with`] alongside
/// the `StoreConfig` it already had. [`crate::server::store::Store::open`]
/// — what every existing call site still uses — is `open_with` with
/// [`FjallTuning::default()`], so nothing already opening a store needed
/// to change to keep behaving exactly as before.
///
/// Every field is optional and defaults to `None`: unset, byte for byte,
/// leaves fjall's own defaults (and this codebase's behaviour before this
/// type existed) unchanged. Settable in a service's config file under
/// `[fjall]` (a bare integer byte count, or a string like `"64MiB"` /
/// `"512MB"` / `"1GiB"`), and overridable per field by the environment
/// variables named on each field below — the env var wins when both are
/// set. The **same** three env var names are used for every consumer
/// (there is deliberately no per-service prefix): this is a pod-level
/// Kubernetes memory-limit knob, not a per-service setting.
///
/// Validated before use ([`FjallTuning::validate`]): zero, a value fjall
/// itself would refuse (its own `Builder` asserts under 1 MiB for the
/// write buffer and under 64 MiB for the journal — panics this type
/// exists to turn into an ordinary startup error instead), or anything
/// that fails to parse is refused with a message naming the setting,
/// never silently ignored or clamped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FjallTuning {
    /// fjall's shared block cache size, in bytes
    /// (`fjall::Database::builder(..).cache_size(..)`). fjall's own
    /// default is 32 MiB. Env override: `STORAGE_FJALL_BLOCK_CACHE`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_block_cache"
    )]
    pub block_cache: Option<u64>,
    /// Maximum unflushed bytes held in memory across every keyspace this
    /// process opens. fjall 3.1 stores but does not enforce its own
    /// `max_write_buffer_size`, so the fjall store's background flusher
    /// (`store::flusher`) enforces this value; unset, it uses
    /// `store::flusher::DEFAULT_WRITE_BUFFER_LIMIT` (8 MiB).
    /// Env override: `STORAGE_FJALL_WRITE_BUFFER`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_write_buffer"
    )]
    pub write_buffer: Option<u64>,
    /// Maximum size of all journals — the write-ahead log fjall replays
    /// on startup — in bytes
    /// (`fjall::Database::builder(..).max_journaling_size(..)`). fjall's
    /// own default is 512 MiB. fjall only checks it while flushing, which
    /// the store's background flusher now makes happen regularly. Env
    /// override: `STORAGE_FJALL_MAX_JOURNAL`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_max_journal"
    )]
    pub max_journal: Option<u64>,
}

/// Floor for [`FjallTuning::block_cache`]. fjall places no lower bound on
/// its cache size itself, but a cache below this buys nothing meaningful
/// and is far more likely to be a fat-fingered value (bytes typed where
/// mebibytes were meant) than an intentional setting.
pub const MIN_BLOCK_CACHE_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Floor for [`FjallTuning::write_buffer`] — mirrors fjall's own
/// `Builder::max_write_buffer_size`, which panics below this.
pub const MIN_WRITE_BUFFER_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Floor for [`FjallTuning::max_journal`] — mirrors fjall's own
/// `Builder::max_journaling_size`, which panics below this.
pub const MIN_MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

/// Byte-size suffixes this module accepts, longest first so e.g. `"MiB"`
/// is tried before the bare `"B"` it also ends with. IEC (binary, 1024-based)
/// before SI (decimal, 1000-based) is an arbitrary but fixed tie-break —
/// there is no overlap between the two suffix spellings, so it never
/// actually matters which list comes first.
const BYTE_SIZE_SUFFIXES: &[(&str, u64)] = &[
    ("TiB", 1024 * 1024 * 1024 * 1024),
    ("GiB", 1024 * 1024 * 1024),
    ("MiB", 1024 * 1024),
    ("KiB", 1024),
    ("TB", 1_000_000_000_000),
    ("GB", 1_000_000_000),
    ("MB", 1_000_000),
    ("KB", 1_000),
    ("B", 1),
];

/// Parse a byte-size value: a plain byte count (`"67108864"`), or a
/// number followed by a binary (`KiB`/`MiB`/`GiB`/`TiB`) or decimal
/// (`KB`/`MB`/`GB`/`TB`/`B`) suffix, case-insensitively. Never validates
/// range — callers combine this with a minimum (see
/// [`parse_and_validate_fjall_bytes`]).
pub fn parse_byte_size(raw: &str) -> Result<u64, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("value is empty".to_string());
    }
    if trimmed.starts_with('-') {
        return Err(format!(
            "{trimmed:?} is negative; a byte size cannot be negative"
        ));
    }
    for (suffix, multiplier) in BYTE_SIZE_SUFFIXES {
        if trimmed.len() > suffix.len()
            && trimmed[trimmed.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        {
            let number_part = trimmed[..trimmed.len() - suffix.len()].trim();
            let value: f64 = number_part.parse().map_err(|_| {
                format!(
                    "{trimmed:?} is not a valid byte size (expected a number before the {suffix:?} suffix)"
                )
            })?;
            if !value.is_finite() || value < 0.0 {
                return Err(format!("{trimmed:?} is not a valid byte size"));
            }
            return Ok((value * (*multiplier as f64)).round() as u64);
        }
    }
    trimmed.parse::<u64>().map_err(|_| {
        format!(
            "{trimmed:?} is not a valid byte size (expected a plain byte count, or a number with \
             a B/KB/MB/GB/TB or KiB/MiB/GiB/TiB suffix)"
        )
    })
}

/// Render a byte count the way this module's error messages and startup
/// log line do: the most natural binary unit, two decimal places.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: &[(&str, u64)] = &[
        ("TiB", 1024 * 1024 * 1024 * 1024),
        ("GiB", 1024 * 1024 * 1024),
        ("MiB", 1024 * 1024),
        ("KiB", 1024),
    ];
    for (unit, size) in UNITS {
        if bytes >= *size {
            return format!("{:.2} {unit}", bytes as f64 / *size as f64);
        }
    }
    format!("{bytes} B")
}

/// Parse then range-check a byte-size value against `minimum`, producing
/// an error that names `field` (an env var name or a config key path) —
/// used identically by the config-file deserializer and the env var
/// overrides so a bad value is refused wherever it came from, with the
/// same message shape.
pub fn parse_and_validate_fjall_bytes(field: &str, raw: &str, minimum: u64) -> Result<u64, String> {
    let bytes = parse_byte_size(raw).map_err(|e| format!("invalid {field} value {raw:?}: {e}"))?;
    validate_fjall_bytes(field, bytes, minimum, raw)
}

fn validate_fjall_bytes(
    field: &str,
    bytes: u64,
    minimum: u64,
    raw_display: &str,
) -> Result<u64, String> {
    if bytes == 0 {
        return Err(format!(
            "{field} must not be zero (got {raw_display:?}); fjall needs a positive size here"
        ));
    }
    if bytes < minimum {
        return Err(format!(
            "{field} value {raw_display:?} ({bytes} bytes) is too small; must be at least \
             {minimum} bytes ({})",
            human_bytes(minimum)
        ));
    }
    Ok(bytes)
}

/// A `[fjall]` field is either a bare integer byte count or a suffixed
/// string — accept both.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawByteSize {
    Number(u64),
    Text(String),
}

fn deserialize_optional_fjall_byte_size<'de, D>(
    deserializer: D,
    field: &str,
    minimum: u64,
) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<RawByteSize>::deserialize(deserializer)? {
        None => Ok(None),
        Some(RawByteSize::Number(n)) => validate_fjall_bytes(field, n, minimum, &n.to_string())
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(RawByteSize::Text(s)) => {
            let bytes = parse_byte_size(&s).map_err(|e| {
                serde::de::Error::custom(format!("invalid {field} value {s:?}: {e}"))
            })?;
            validate_fjall_bytes(field, bytes, minimum, &s)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
    }
}

fn deserialize_block_cache<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_fjall_byte_size(deserializer, "fjall.block_cache", MIN_BLOCK_CACHE_BYTES)
}

fn deserialize_write_buffer<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_fjall_byte_size(deserializer, "fjall.write_buffer", MIN_WRITE_BUFFER_BYTES)
}

fn deserialize_max_journal<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_fjall_byte_size(deserializer, "fjall.max_journal", MIN_MAX_JOURNAL_BYTES)
}

impl FjallTuning {
    /// Re-check every set field against its floor. Called from
    /// [`crate::server::store::Store::open_with`] right before the values
    /// are handed to fjall's builder, so a `FjallTuning` built any other
    /// way than through the deserializer or [`apply_fjall_env_overrides`]
    /// (a test fixture, a future caller) still can never reach fjall's
    /// own asserting `Builder` methods with a value that would panic.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(bytes) = self.block_cache {
            validate_fjall_bytes(
                "fjall.block_cache",
                bytes,
                MIN_BLOCK_CACHE_BYTES,
                &bytes.to_string(),
            )?;
        }
        if let Some(bytes) = self.write_buffer {
            validate_fjall_bytes(
                "fjall.write_buffer",
                bytes,
                MIN_WRITE_BUFFER_BYTES,
                &bytes.to_string(),
            )?;
        }
        if let Some(bytes) = self.max_journal {
            validate_fjall_bytes(
                "fjall.max_journal",
                bytes,
                MIN_MAX_JOURNAL_BYTES,
                &bytes.to_string(),
            )?;
        }
        Ok(())
    }
}

/// Apply `STORAGE_FJALL_BLOCK_CACHE` / `STORAGE_FJALL_WRITE_BUFFER` /
/// `STORAGE_FJALL_MAX_JOURNAL` onto `config`, one field at a time, if set.
/// The **same** three env var names for every consumer (did-hosting-control,
/// did-hosting-server, webvh-witness, webvh-watcher, did-hosting-daemon, and
/// any future one) — this is a pod-level Kubernetes memory-limit knob, not a
/// per-service setting, so there is deliberately no service-specific prefix.
/// Called by each service's own config loader, after the config file is
/// parsed, so an env var overrides the file — an unset var leaves whatever
/// the file (or the type's `None` default) already set untouched.
pub fn apply_fjall_env_overrides(config: &mut FjallTuning) -> Result<(), AppError> {
    if let Ok(raw) = std::env::var("STORAGE_FJALL_BLOCK_CACHE") {
        config.block_cache = Some(
            parse_and_validate_fjall_bytes(
                "STORAGE_FJALL_BLOCK_CACHE",
                &raw,
                MIN_BLOCK_CACHE_BYTES,
            )
            .map_err(AppError::Config)?,
        );
    }
    if let Ok(raw) = std::env::var("STORAGE_FJALL_WRITE_BUFFER") {
        config.write_buffer = Some(
            parse_and_validate_fjall_bytes(
                "STORAGE_FJALL_WRITE_BUFFER",
                &raw,
                MIN_WRITE_BUFFER_BYTES,
            )
            .map_err(AppError::Config)?,
        );
    }
    if let Ok(raw) = std::env::var("STORAGE_FJALL_MAX_JOURNAL") {
        config.max_journal = Some(
            parse_and_validate_fjall_bytes(
                "STORAGE_FJALL_MAX_JOURNAL",
                &raw,
                MIN_MAX_JOURNAL_BYTES,
            )
            .map_err(AppError::Config)?,
        );
    }
    Ok(())
}
