//! Unit tests for `[fjall]` byte-size parsing, validation and env overrides.

use super::*;
use std::sync::Mutex;

// `apply_fjall_env_overrides` reads process-wide env vars; `cargo test`
// runs test functions concurrently within one process, so every test
// here that sets/removes `STORAGE_FJALL_*` serializes on this lock.
static ENV_LOCK: Mutex<()> = Mutex::new(());

const FJALL_ENV_VARS: [&str; 3] = [
    "STORAGE_FJALL_BLOCK_CACHE",
    "STORAGE_FJALL_WRITE_BUFFER",
    "STORAGE_FJALL_MAX_JOURNAL",
];

fn clear_fjall_env() {
    // SAFETY: guarded by `ENV_LOCK`, held by every test in this module
    // that touches these vars — no other test in this crate reads or
    // writes the `STORAGE_FJALL_*` names.
    unsafe {
        for var in FJALL_ENV_VARS {
            std::env::remove_var(var);
        }
    }
}

// -----------------------------------------------------------------
// parse_byte_size: every suffix, plus the error cases
// -----------------------------------------------------------------

#[test]
fn parse_byte_size_accepts_a_plain_byte_count() {
    assert_eq!(parse_byte_size("67108864").unwrap(), 67_108_864);
    assert_eq!(parse_byte_size("0").unwrap(), 0);
    assert_eq!(
        parse_byte_size("  1024  ").unwrap(),
        1024,
        "whitespace is trimmed"
    );
}

#[test]
fn parse_byte_size_accepts_every_binary_suffix() {
    assert_eq!(parse_byte_size("1KiB").unwrap(), 1024);
    assert_eq!(parse_byte_size("64MiB").unwrap(), 64 * 1024 * 1024);
    assert_eq!(parse_byte_size("1GiB").unwrap(), 1024 * 1024 * 1024);
    assert_eq!(
        parse_byte_size("2TiB").unwrap(),
        2 * 1024 * 1024 * 1024 * 1024
    );
}

#[test]
fn parse_byte_size_accepts_every_decimal_suffix() {
    assert_eq!(parse_byte_size("512B").unwrap(), 512);
    assert_eq!(parse_byte_size("1KB").unwrap(), 1_000);
    assert_eq!(parse_byte_size("512MB").unwrap(), 512_000_000);
    assert_eq!(parse_byte_size("1GB").unwrap(), 1_000_000_000);
    assert_eq!(parse_byte_size("1TB").unwrap(), 1_000_000_000_000);
}

#[test]
fn parse_byte_size_is_case_insensitive_and_accepts_fractions() {
    assert_eq!(parse_byte_size("64mib").unwrap(), 64 * 1024 * 1024);
    assert_eq!(
        parse_byte_size("1.5GiB").unwrap(),
        (1.5 * 1024.0 * 1024.0 * 1024.0) as u64
    );
}

#[test]
fn parse_byte_size_rejects_garbage_and_unknown_suffixes() {
    assert!(parse_byte_size("").is_err(), "empty");
    assert!(parse_byte_size("   ").is_err(), "whitespace only");
    assert!(parse_byte_size("not-a-size").is_err(), "non-numeric");
    assert!(parse_byte_size("64XiB").is_err(), "unrecognised suffix");
    assert!(parse_byte_size("-64MiB").is_err(), "negative");
    assert!(parse_byte_size("-1").is_err(), "negative, no suffix");
    assert!(parse_byte_size("MiB").is_err(), "suffix with no number");
}

// -----------------------------------------------------------------
// Range validation
// -----------------------------------------------------------------

#[test]
fn parse_and_validate_rejects_zero_naming_the_field() {
    let err =
        parse_and_validate_fjall_bytes("STORAGE_FJALL_BLOCK_CACHE", "0", MIN_BLOCK_CACHE_BYTES)
            .unwrap_err();
    assert!(err.contains("STORAGE_FJALL_BLOCK_CACHE"), "got: {err}");
    assert!(err.contains("zero"), "got: {err}");
}

#[test]
fn parse_and_validate_rejects_an_absurdly_small_value_naming_the_field() {
    let err =
        parse_and_validate_fjall_bytes("STORAGE_FJALL_MAX_JOURNAL", "1KiB", MIN_MAX_JOURNAL_BYTES)
            .unwrap_err();
    assert!(err.contains("STORAGE_FJALL_MAX_JOURNAL"), "got: {err}");
    assert!(err.contains("too small"), "got: {err}");
}

#[test]
fn parse_and_validate_rejects_an_unparseable_value_naming_the_field() {
    let err = parse_and_validate_fjall_bytes(
        "STORAGE_FJALL_WRITE_BUFFER",
        "garbage",
        MIN_WRITE_BUFFER_BYTES,
    )
    .unwrap_err();
    assert!(err.contains("STORAGE_FJALL_WRITE_BUFFER"), "got: {err}");
}

#[test]
fn parse_and_validate_accepts_a_value_at_exactly_the_floor() {
    assert_eq!(
        parse_and_validate_fjall_bytes("STORAGE_FJALL_MAX_JOURNAL", "64MiB", MIN_MAX_JOURNAL_BYTES)
            .unwrap(),
        MIN_MAX_JOURNAL_BYTES
    );
}

#[test]
fn fjall_tuning_validate_passes_when_every_field_is_unset() {
    assert!(FjallTuning::default().validate().is_ok());
}

#[test]
fn fjall_tuning_validate_reports_a_below_floor_field() {
    let cfg = FjallTuning {
        block_cache: None,
        write_buffer: Some(1024),
        max_journal: None,
    };
    let err = cfg.validate().unwrap_err();
    assert!(err.contains("fjall.write_buffer"), "got: {err}");
}

// -----------------------------------------------------------------
// Config-file (de)serialization: `[fjall]`, plain int or suffixed string
// -----------------------------------------------------------------

#[test]
fn an_absent_fjall_table_defaults_every_field_to_unset() {
    let cfg: FjallTuning = toml::from_str("").expect("loads");
    assert_eq!(cfg, FjallTuning::default());
}

#[test]
fn fjall_table_accepts_suffixed_strings_and_plain_integers() {
    let cfg: FjallTuning = toml::from_str(
        r#"
            block_cache = "64MiB"
            write_buffer = "16MiB"
            max_journal = 134217728
            "#,
    )
    .expect("loads");
    assert_eq!(cfg.block_cache, Some(64 * 1024 * 1024));
    assert_eq!(cfg.write_buffer, Some(16 * 1024 * 1024));
    assert_eq!(cfg.max_journal, Some(134_217_728));
}

#[test]
fn fjall_table_refuses_a_below_floor_value_at_parse_time() {
    let err = toml::from_str::<FjallTuning>(r#"block_cache = "1B""#)
        .expect_err("a below-floor block_cache must be refused when the file is parsed");
    let msg = err.to_string();
    assert!(msg.contains("fjall.block_cache"), "got: {msg}");
}

#[test]
fn fjall_table_refuses_an_unknown_suffix_at_parse_time() {
    let err = toml::from_str::<FjallTuning>(r#"max_journal = "64XiB""#)
        .expect_err("an unparseable size must be refused when the file is parsed");
    assert!(err.to_string().contains("fjall.max_journal"));
}

// -----------------------------------------------------------------
// Env overrides the file
// -----------------------------------------------------------------

#[test]
fn env_override_wins_over_the_file_value() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_fjall_env();

    let mut cfg = FjallTuning {
        block_cache: Some(32 * 1024 * 1024),
        write_buffer: None,
        max_journal: None,
    };
    // SAFETY: serialized by `ENV_LOCK`.
    unsafe {
        std::env::set_var("STORAGE_FJALL_BLOCK_CACHE", "8MiB");
    }
    apply_fjall_env_overrides(&mut cfg).expect("valid override applies");
    assert_eq!(
        cfg.block_cache,
        Some(8 * 1024 * 1024),
        "the env var must win over whatever the file set"
    );

    clear_fjall_env();
}

#[test]
fn an_unset_env_var_leaves_the_file_value_untouched() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_fjall_env();

    let mut cfg = FjallTuning {
        block_cache: Some(32 * 1024 * 1024),
        write_buffer: Some(MIN_WRITE_BUFFER_BYTES),
        max_journal: None,
    };
    let before = cfg;
    apply_fjall_env_overrides(&mut cfg).expect("no env vars set: nothing to apply");
    assert_eq!(
        cfg, before,
        "with no STORAGE_FJALL_* vars set, nothing changes"
    );
}

#[test]
fn env_override_refuses_an_invalid_value_naming_the_var() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_fjall_env();

    // SAFETY: serialized by `ENV_LOCK`.
    unsafe {
        std::env::set_var("STORAGE_FJALL_MAX_JOURNAL", "1KiB");
    }
    let err = apply_fjall_env_overrides(&mut FjallTuning::default())
        .expect_err("a below-floor journal size must be refused");
    assert!(
        err.to_string().contains("STORAGE_FJALL_MAX_JOURNAL"),
        "got: {err}"
    );

    clear_fjall_env();
}

#[test]
fn human_bytes_renders_the_natural_unit() {
    assert_eq!(human_bytes(512), "512 B");
    assert_eq!(human_bytes(64 * 1024 * 1024), "64.00 MiB");
    assert_eq!(human_bytes(1024 * 1024 * 1024), "1.00 GiB");
}
