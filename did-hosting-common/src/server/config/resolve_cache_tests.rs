//! Unit tests for `[server.resolve_cache]` and its env overrides.

use super::*;

#[test]
fn default_is_five_minutes_public() {
    let c = ResolveCacheConfig::default();
    assert_eq!(c.header_value(), "public, max-age=300");
}

#[test]
fn optional_directives_are_appended() {
    let c = ResolveCacheConfig {
        max_age_secs: 60,
        shared_max_age_secs: Some(600),
        stale_while_revalidate_secs: Some(30),
    };
    assert_eq!(
        c.header_value(),
        "public, max-age=60, s-maxage=600, stale-while-revalidate=30"
    );
}

#[test]
fn zero_max_age_means_no_cache() {
    let c = ResolveCacheConfig {
        max_age_secs: 0,
        ..Default::default()
    };
    assert_eq!(c.header_value(), "no-cache");
    // A CDN-only policy still caches at the edge, not in clients.
    let c = ResolveCacheConfig {
        max_age_secs: 0,
        shared_max_age_secs: Some(120),
        stale_while_revalidate_secs: None,
    };
    assert_eq!(c.header_value(), "public, max-age=0, s-maxage=120");
}

#[test]
fn durations_past_a_year_are_refused() {
    let c = ResolveCacheConfig {
        stale_while_revalidate_secs: Some(RESOLVE_CACHE_MAX_SECS + 1),
        ..Default::default()
    };
    assert!(c.validate().is_err());
    let c = ResolveCacheConfig {
        max_age_secs: RESOLVE_CACHE_MAX_SECS,
        ..Default::default()
    };
    assert!(c.validate().is_ok());
}

#[test]
fn toml_table_parses_and_defaults_when_absent() {
    let s: ServerConfig = toml::from_str("host = \"0.0.0.0\"").unwrap();
    assert_eq!(s.resolve_cache, ResolveCacheConfig::default());

    let s: ServerConfig =
        toml::from_str("[resolve_cache]\nmax_age_secs = 30\nstale_while_revalidate_secs = 60\n")
            .unwrap();
    assert_eq!(s.resolve_cache.max_age_secs, 30);
    assert_eq!(s.resolve_cache.stale_while_revalidate_secs, Some(60));
    assert_eq!(s.resolve_cache.shared_max_age_secs, None);

    // A typo is an error, not a silently ignored setting.
    assert!(toml::from_str::<ServerConfig>("[resolve_cache]\nmax_age = 30\n").is_err());
}

#[test]
fn env_overrides_set_clear_and_validate() {
    // A prefix no other test uses, so this test owns these vars.
    const MAX: &str = "RCTEST_SERVER_RESOLVE_CACHE_MAX_AGE_SECS";
    const SHARED: &str = "RCTEST_SERVER_RESOLVE_CACHE_SHARED_MAX_AGE_SECS";
    const SWR: &str = "RCTEST_SERVER_RESOLVE_CACHE_STALE_WHILE_REVALIDATE_SECS";
    // SAFETY: only this test reads or writes the `RCTEST_*` names.
    unsafe {
        std::env::set_var(MAX, "45");
        std::env::set_var(SHARED, "900");
        std::env::set_var(SWR, "");
    }
    let mut c = ResolveCacheConfig {
        stale_while_revalidate_secs: Some(10),
        ..Default::default()
    };
    c.apply_env_overrides("RCTEST").unwrap();
    assert_eq!(c.max_age_secs, 45);
    assert_eq!(c.shared_max_age_secs, Some(900));
    assert_eq!(c.stale_while_revalidate_secs, None, "empty clears");

    unsafe { std::env::set_var(MAX, "soon") };
    assert!(c.apply_env_overrides("RCTEST").is_err());
    unsafe { std::env::set_var(MAX, "99999999") };
    assert!(c.apply_env_overrides("RCTEST").is_err(), "past a year");

    unsafe {
        std::env::remove_var(MAX);
        std::env::remove_var(SHARED);
        std::env::remove_var(SWR);
    }
}
