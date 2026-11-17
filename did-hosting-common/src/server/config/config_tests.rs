//! Unit tests for the shared config sections and their env overrides.

use super::*;
use ipnetwork::IpNetwork;

/// The claim-code hashing wait is finite by default and the operator's
/// to set.
#[test]
fn claim_code_hash_wait_has_a_finite_default_and_is_configurable() {
    let auth: AuthConfig = toml::from_str("").unwrap();
    assert_eq!(auth.claim_code_hash_wait_ms, 5000);
    assert_eq!(
        auth.claim_code_hash_wait(),
        std::time::Duration::from_secs(5)
    );
    assert_eq!(AuthConfig::default().claim_code_hash_wait_ms, 5000);
    let auth: AuthConfig = toml::from_str("claim_code_hash_wait_ms = 250").unwrap();
    assert_eq!(
        auth.claim_code_hash_wait(),
        std::time::Duration::from_millis(250)
    );
    assert!(AuthConfig::default().validate().is_ok());
    let at_cap = AuthConfig {
        claim_code_hash_wait_ms: MAX_CLAIM_CODE_HASH_WAIT_MS,
        ..AuthConfig::default()
    };
    assert!(at_cap.validate().is_ok());
    let over = AuthConfig {
        claim_code_hash_wait_ms: MAX_CLAIM_CODE_HASH_WAIT_MS + 1,
        ..AuthConfig::default()
    };
    assert!(over.validate().is_err());
}

/// `did:webs` self-registration is off unless a domain opts in, and a
/// domain's prefixes match whole leading segments only.
#[test]
fn webs_self_register_is_off_by_default_and_matches_whole_segments() {
    let hosting: HostingConfig = toml::from_str("").unwrap();
    assert!(hosting.webs_self_register.is_empty());

    let hosting: HostingConfig = toml::from_str(
        "[[webs_self_register]]\ndomain = \"did.example.com\"\n\
             [[webs_self_register]]\ndomain = \"b.example\"\npath_prefixes = [\"nodes\", \"x/y\"]",
    )
    .unwrap();
    let [any, scoped] = hosting.webs_self_register.as_slice() else {
        panic!("two domains");
    };
    assert!(any.admits_path("EAID"));
    assert!(any.admits_path("a/EAID"));
    assert!(scoped.admits_path("nodes/EAID"));
    assert!(scoped.admits_path("nodes/eu/EAID"));
    assert!(scoped.admits_path("x/y/EAID"));
    assert!(!scoped.admits_path("EAID"));
    assert!(!scoped.admits_path("nodesx/EAID"));
    assert!(!scoped.admits_path("nodes/"));
    assert!(!scoped.admits_path("x/EAID"));
    // Capped by default, and the cap is the operator's to set.
    assert_eq!(any.max_registrations, DEFAULT_WEBS_SELF_REGISTER_MAX);
    let hosting: HostingConfig =
        toml::from_str("[[webs_self_register]]\ndomain = \"a\"\nmax_registrations = 3").unwrap();
    assert_eq!(hosting.webs_self_register[0].max_registrations, 3);

    // Each self-registered identifier holds its own slot only by default; the
    // operator may let it hold more, never none.
    assert_eq!(any.max_dids_per_identifier.get(), 1);
    let hosting: HostingConfig =
        toml::from_str("[[webs_self_register]]\ndomain = \"a\"\nmax_dids_per_identifier = 50")
            .unwrap();
    assert_eq!(
        hosting.webs_self_register[0].max_dids_per_identifier.get(),
        50
    );
    assert!(
        toml::from_str::<HostingConfig>(
            "[[webs_self_register]]\ndomain = \"a\"\nmax_dids_per_identifier = 0"
        )
        .is_err()
    );

    // An unknown member is refused, not ignored.
    assert!(
        toml::from_str::<HostingConfig>(
            "[[webs_self_register]]\ndomain = \"a\"\nprefixes = [\"n\"]"
        )
        .is_err()
    );
}

/// An absent `[replay]` table keeps today's bounds; a set one replaces
/// them, and an inconsistent one is refused.
#[test]
fn replay_bounds_parse_and_validate() {
    let parsed: ReplayConfig = toml::from_str("").unwrap();
    assert_eq!(parsed, ReplayConfig::default());
    assert_eq!(parsed.max_entries, 1_000_000);
    assert_eq!(parsed.max_entries_per_signer, 250_000);
    assert!(parsed.is_default());

    // A partial table takes the default for the other bound.
    let parsed: ReplayConfig = toml::from_str("max_entries = 2000000").unwrap();
    parsed.validate().unwrap();
    assert_eq!(parsed.max_entries_per_signer, 250_000);
    assert!(!parsed.is_default());

    let parsed: ReplayConfig =
        toml::from_str("max_entries = 200000\nmax_entries_per_signer = 50000").unwrap();
    parsed.validate().unwrap();
    assert_eq!(parsed.max_entries_per_signer, 50_000);

    assert!(toml::from_str::<ReplayConfig>("max_entrys = 1").is_err());
    for (max_entries, max_entries_per_signer) in [(0, 0), (10, 0), (10, 20), (20_000_000, 1)] {
        let config = ReplayConfig {
            max_entries,
            max_entries_per_signer,
        };
        assert!(config.validate().is_err(), "{config:?} should be refused");
    }
}

/// `{prefix}_REPLAY_*` replace the file's bounds, and the result is
/// validated; an unparseable or inconsistent value is refused.
#[test]
fn replay_env_overrides_replace_and_validate() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |var: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == var)
                .map(|(_, v)| v.to_string())
        }
    };

    let mut config = ReplayConfig::default();
    config
        .apply_overrides(
            &["DAEMON"],
            env(&[
                ("DAEMON_REPLAY_MAX_ENTRIES", "200000"),
                ("DAEMON_REPLAY_MAX_ENTRIES_PER_SIGNER", " 50000 "),
                ("CONTROL_REPLAY_MAX_ENTRIES", "1"),
            ]),
        )
        .unwrap();
    assert_eq!(
        (config.max_entries, config.max_entries_per_signer),
        (200_000, 50_000)
    );

    // A deprecated prefix still applies; the current one wins, and the
    // pair is validated only once both are in.
    let mut config = ReplayConfig::default();
    config
        .apply_overrides(
            &["WEBVH", "DID_HOSTING"],
            env(&[
                ("WEBVH_REPLAY_MAX_ENTRIES_PER_SIGNER", "3000000"),
                ("WEBVH_REPLAY_MAX_ENTRIES", "1"),
                ("DID_HOSTING_REPLAY_MAX_ENTRIES", "5000000"),
            ]),
        )
        .unwrap();
    assert_eq!(
        (config.max_entries, config.max_entries_per_signer),
        (5_000_000, 3_000_000)
    );

    let mut config = ReplayConfig::default();
    config.apply_overrides(&["DAEMON"], env(&[])).unwrap();
    assert_eq!(config, ReplayConfig::default());

    for pairs in [
        &[("DAEMON_REPLAY_MAX_ENTRIES", "lots")][..],
        &[("DAEMON_REPLAY_MAX_ENTRIES_PER_SIGNER", "2000000")][..],
    ] {
        let mut config = ReplayConfig::default();
        assert!(
            config.apply_overrides(&["DAEMON"], env(pairs)).is_err(),
            "{pairs:?} should be refused"
        );
    }
}

/// `{prefix}_SERVER_TRUSTED_PROXIES` takes addresses and CIDR ranges,
/// an empty value clears the list, and anything else is refused.
#[test]
fn trusted_proxies_env_override_takes_addresses_and_ranges() {
    let mut server: ServerConfig = toml::from_str("trusted_proxies = [\"10.0.0.1\"]").unwrap();
    server
        .apply_trusted_proxies_override("DAEMON", |var| {
            (var == "DAEMON_SERVER_TRUSTED_PROXIES").then(|| " 10.0.0.0/20, 2001:db8::/32 ,".into())
        })
        .unwrap();
    assert_eq!(
        server.trusted_proxies,
        [
            "10.0.0.0/20".parse::<IpNetwork>().unwrap(),
            "2001:db8::/32".parse().unwrap()
        ]
    );

    server
        .apply_trusted_proxies_override("DAEMON", |_| Some(String::new()))
        .unwrap();
    assert!(
        server.trusted_proxies.is_empty(),
        "an empty value clears the list"
    );

    for bad in ["load-balancer", "10.0.0.0/33", "0.0.0.0/0", "::/0"] {
        let result = server.apply_trusted_proxies_override("DAEMON", |_| Some(bad.into()));
        assert!(result.is_err(), "{bad} should be refused");
    }
}

/// A range trusting every peer is refused in the file too, not only in
/// the environment.
#[test]
fn trusted_proxies_refuse_a_catch_all_range() {
    let error = toml::from_str::<ServerConfig>("trusted_proxies = [\"0.0.0.0/0\"]")
        .unwrap_err()
        .to_string();
    assert!(error.contains("covers every address"), "{error}");
}

/// An absent `[server.resolve_rate_limit]` means no limit; a set one is
/// read from the file and the env, and a zero limit or window is refused.
#[test]
fn resolve_rate_limit_parses_overrides_and_validates() {
    let parsed: ResolveRateLimitConfig = toml::from_str("").unwrap();
    assert_eq!(parsed, ResolveRateLimitConfig::default());
    assert_eq!(parsed.max_per_window, None);

    let parsed: ResolveRateLimitConfig =
        toml::from_str("max_per_window = 500\nwindow_secs = 60").unwrap();
    parsed.validate().unwrap();
    assert_eq!((parsed.max_per_window, parsed.window_secs), (Some(500), 60));
    assert!(toml::from_str::<ResolveRateLimitConfig>("max_per_windw = 1").is_err());

    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |var: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == var)
                .map(|(_, v)| v.to_string())
        }
    };
    let mut config = ResolveRateLimitConfig::default();
    config
        .apply_overrides(
            "DAEMON",
            env(&[
                ("DAEMON_SERVER_RESOLVE_RATE_LIMIT_MAX_PER_WINDOW", " 200 "),
                ("DAEMON_SERVER_RESOLVE_RATE_LIMIT_WINDOW_SECS", "5"),
            ]),
        )
        .unwrap();
    assert_eq!((config.max_per_window, config.window_secs), (Some(200), 5));
    config
        .apply_overrides(
            "DAEMON",
            env(&[("DAEMON_SERVER_RESOLVE_RATE_LIMIT_MAX_PER_WINDOW", "")]),
        )
        .unwrap();
    assert_eq!(
        config.max_per_window, None,
        "an empty value clears the limit"
    );
    config
        .apply_overrides(
            "DAEMON",
            env(&[("DAEMON_SERVER_RESOLVE_RATE_LIMIT_WINDOW_SECS", " ")]),
        )
        .unwrap();
    assert_eq!(
        config.window_secs,
        default_resolve_rate_limit_window_secs(),
        "an empty value restores the default window"
    );

    for pairs in [
        &[("DAEMON_SERVER_RESOLVE_RATE_LIMIT_MAX_PER_WINDOW", "0")][..],
        &[("DAEMON_SERVER_RESOLVE_RATE_LIMIT_WINDOW_SECS", "0")][..],
        &[("DAEMON_SERVER_RESOLVE_RATE_LIMIT_WINDOW_SECS", "3601")][..],
        &[("DAEMON_SERVER_RESOLVE_RATE_LIMIT_MAX_PER_WINDOW", "many")][..],
    ] {
        let mut config = ResolveRateLimitConfig::default();
        assert!(
            config.apply_overrides("DAEMON", env(pairs)).is_err(),
            "{pairs:?} should be refused"
        );
    }
}

/// The did:scid alias is listed unless an operator turns it off; a config
/// written before the setting existed reads as on.
#[test]
fn hosting_lists_the_scid_alias_by_default() {
    assert!(HostingConfig::default().scid_also_known_as);
    let parsed: HostingConfig = toml::from_str("bootstrap_domains = []").unwrap();
    assert!(parsed.scid_also_known_as);
    let parsed: HostingConfig = toml::from_str("scid_also_known_as = false").unwrap();
    assert!(!parsed.scid_also_known_as);
}

#[test]
fn agent_names_default_on_for_absent_and_empty_config() {
    // An operator who never heard of the flag serves `/@name`.
    assert!(FeaturesConfig::default().agent_names);
    let cfg: FeaturesConfig = toml::from_str("").unwrap();
    assert!(cfg.agent_names);
    // Sibling flags stay opt-in — this changes one default, not all of them.
    assert!(!cfg.didcomm);
    assert!(!cfg.tsp);
    assert!(!cfg.http_listener);
}

#[test]
fn agent_names_can_still_be_switched_off() {
    let cfg: FeaturesConfig = toml::from_str("agent_names = false").unwrap();
    assert!(!cfg.agent_names);
}

/// The `[hosting]` grace periods are parsed at load: a bad one is refused
/// naming the key and the accepted units, and a good one round-trips as
/// the text it was written as.
#[test]
fn hosting_grace_periods_are_parsed_at_load() {
    let hosting: HostingConfig = toml::from_str("").unwrap();
    assert_eq!(hosting.unassigned_purge_grace.as_secs(), 2 * 3600);
    assert_eq!(hosting.disable_purge_grace.as_secs(), 30 * 86_400);

    let hosting: HostingConfig =
        toml::from_str("unassigned_purge_grace = \"90m\"\ndisable_purge_grace = \"7d\"").unwrap();
    assert_eq!(hosting.unassigned_purge_grace.as_secs(), 90 * 60);
    assert_eq!(hosting.disable_purge_grace.as_secs(), 7 * 86_400);
    let written = toml::to_string(&hosting).unwrap();
    assert!(
        written.contains("unassigned_purge_grace = \"90m\""),
        "{written}"
    );
    assert_eq!(toml::from_str::<HostingConfig>(&written).unwrap(), hosting);

    for (key, value) in [
        ("unassigned_purge_grace", "1w"),
        ("disable_purge_grace", "soon"),
        ("disable_purge_grace", ""),
    ] {
        let err = toml::from_str::<HostingConfig>(&format!("{key} = \"{value}\""))
            .unwrap_err()
            .to_string();
        assert!(err.contains(key), "{key}: {err}");
        assert!(err.contains("s, m, h or d"), "{key}: {err}");
    }
}

/// `[identity] rotation_grace_period` is parsed at load like the
/// `[hosting]` periods: a bad value is refused naming the key, not
/// quietly read as an hour.
#[test]
fn rotation_grace_period_is_parsed_at_load() {
    let identity: IdentityConfig = toml::from_str("").unwrap();
    assert_eq!(identity.rotation_grace_secs(), 3600, "default is 1h");

    let identity: IdentityConfig = toml::from_str("rotation_grace_period = \"30m\"").unwrap();
    assert_eq!(identity.rotation_grace_secs(), 1800);
    let written = toml::to_string(&identity).unwrap();
    assert!(
        written.contains("rotation_grace_period = \"30m\""),
        "{written}"
    );
    assert_eq!(
        toml::from_str::<IdentityConfig>(&written).unwrap(),
        identity
    );

    let identity: IdentityConfig = toml::from_str("rotation_grace_period = \"0\"").unwrap();
    assert_eq!(identity.rotation_grace_secs(), 0, "0 retires immediately");

    for value in ["1 fortnight", "soon", ""] {
        let err = toml::from_str::<IdentityConfig>(&format!("rotation_grace_period = \"{value}\""))
            .unwrap_err()
            .to_string();
        assert!(err.contains("[identity] rotation_grace_period"), "{err}");
        assert!(err.contains("s, m, h or d"), "{err}");
    }
}

/// `[server] trusted_proxy_cidrs` is parsed at load: an entry that is not
/// an address or a CIDR range is refused naming the key and the entry,
/// not dropped with a warning.
#[test]
fn trusted_proxy_cidrs_are_parsed_at_load() {
    let server: ServerConfig = toml::from_str(
        "trusted_proxy_cidrs = [\"10.0.0.0/8\", \" 2001:db8::/32 \", \"192.0.2.7\"]",
    )
    .unwrap();
    assert_eq!(server.trusted_proxy_cidrs.len(), 3);
    let written = toml::to_string(&server).unwrap();
    let reread: ServerConfig = toml::from_str(&written).unwrap();
    assert_eq!(reread.trusted_proxy_cidrs, server.trusted_proxy_cidrs);

    for entry in ["10.0.0.0/33", "proxy.internal", "", "0.0.0.0/0"] {
        let err = toml::from_str::<ServerConfig>(&format!(
            "trusted_proxy_cidrs = [\"10.0.0.1\", \"{entry}\"]"
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("[server] trusted_proxy_cidrs"),
            "{entry}: {err}"
        );
        assert!(err.contains(&format!("`{entry}`")), "{entry}: {err}");
    }
}

/// Every `[store]` key, the backend ones added for DynamoDB and Cosmos DB
/// included, is a known field under the strict parser and round-trips.
#[test]
fn every_store_key_is_a_known_field_and_round_trips() {
    let toml_text = r#"
data_dir = "data/x"
redis_url = "redis://localhost:6379"
dynamodb_table_prefix = "tbl"
dynamodb_region = "eu-west-1"
dynamodb_billing_mode = "provisioned"
dynamodb_auto_create = false
firestore_project = "proj"
firestore_database = "db"
cosmosdb_connection_string = "AccountEndpoint=x"
cosmosdb_database = "webvh"
cosmosdb_container = "kv2"
cosmosdb_region = "eastus"
"#;
    let store: StoreConfig = toml::from_str(toml_text).expect("every key is known");
    assert_eq!(store.dynamodb_billing_mode.as_deref(), Some("provisioned"));
    assert_eq!(store.dynamodb_auto_create, Some(false));
    assert_eq!(store.cosmosdb_container.as_deref(), Some("kv2"));
    let again: StoreConfig = toml::from_str(&toml::to_string(&store).unwrap()).unwrap();
    assert_eq!(again.dynamodb_auto_create, Some(false));
    assert_eq!(again.cosmosdb_container.as_deref(), Some("kv2"));
    assert!(toml::from_str::<StoreConfig>("cosmosdb_contianer = \"x\"").is_err());
    assert!(toml::from_str::<StoreConfig>("dynamodb_auto_create = \"maybe\"").is_err());
}

/// `_STORE_DYNAMODB_AUTO_CREATE` is read as strictly as the other booleans.
#[test]
fn store_auto_create_env_is_strict() {
    let apply = |store: &mut StoreConfig| {
        apply_env_overrides(
            "AUTOCREATETEST",
            &mut FeaturesConfig::default(),
            &mut ServerConfig::default(),
            &mut LogConfig::default(),
            store,
            &mut AuthConfig::default(),
            &mut SecretsConfig::default(),
        )
    };
    let mut store = StoreConfig::default();
    // SAFETY: test-only; the name is unique to this test.
    unsafe { std::env::set_var("AUTOCREATETEST_STORE_DYNAMODB_AUTO_CREATE", "no") };
    apply(&mut store).unwrap();
    assert_eq!(store.dynamodb_auto_create, Some(false));
    unsafe { std::env::set_var("AUTOCREATETEST_STORE_DYNAMODB_AUTO_CREATE", "sometimes") };
    assert!(apply(&mut store).is_err());
    unsafe { std::env::remove_var("AUTOCREATETEST_STORE_DYNAMODB_AUTO_CREATE") };
}

/// A misspelt key in a core section is refused, not silently dropped.
#[test]
fn core_sections_refuse_unknown_keys() {
    assert!(toml::from_str::<StoreConfig>("redis_ur = \"redis://x\"").is_err());
    assert!(toml::from_str::<AuthConfig>("acess_token_expiry = 300").is_err());
    assert!(toml::from_str::<ServerConfig>("prot = 1").is_err());
    assert!(toml::from_str::<LogConfig>("levle = \"debug\"").is_err());
    assert!(toml::from_str::<FeaturesConfig>("didcom = true").is_err());
    assert!(toml::from_str::<HostingConfig>("bootstrap_domain = []").is_err());
    assert!(toml::from_str::<SecretsConfig>("aws_secret = \"x\"").is_err());
    assert!(toml::from_str::<IdentityConfig>("mod = \"vta\"").is_err());
    assert!(toml::from_str::<VtaConfig>("ulr = \"x\"").is_err());
    assert!(toml::from_str::<FjallTuning>("block_cach = 1").is_err());
}

/// `http_listener` was `rest_api`; the old name still loads.
#[test]
fn http_listener_accepts_its_former_name() {
    let cfg: FeaturesConfig = toml::from_str("rest_api = true").unwrap();
    assert!(cfg.http_listener);
    let cfg: FeaturesConfig = toml::from_str("http_listener = true").unwrap();
    assert!(cfg.http_listener);
    let written = toml::to_string(&cfg).unwrap();
    assert!(written.contains("http_listener = true"), "{written}");
}

/// `deployment_mode` takes the two values it always had, and nothing else.
#[test]
fn deployment_mode_is_an_enum_of_the_existing_values() {
    let cfg: FeaturesConfig = toml::from_str("deployment_mode = \"daemon\"").unwrap();
    assert_eq!(cfg.deployment_mode, DeploymentMode::Daemon);
    let cfg: FeaturesConfig = toml::from_str("deployment_mode = \"standalone\"").unwrap();
    assert_eq!(cfg.deployment_mode, DeploymentMode::Standalone);
    assert!(toml::from_str::<FeaturesConfig>("deployment_mode = \"cluster\"").is_err());
    assert_eq!(DeploymentMode::Daemon.as_str(), "daemon");
}

#[test]
fn boolean_env_values_are_read_strictly() {
    for v in ["1", "true", "TRUE", "yes", "On", " on "] {
        assert!(parse_env_bool("X", v).unwrap(), "{v}");
    }
    for v in ["0", "false", "No", "off"] {
        assert!(!parse_env_bool("X", v).unwrap(), "{v}");
    }
    for v in ["", "maybe", "2", "enabled"] {
        let err = parse_env_bool("X_FEATURES_DIDCOMM", v)
            .unwrap_err()
            .to_string();
        assert!(err.contains("X_FEATURES_DIDCOMM"), "{err}");
    }
}

/// An unrecognised boolean stops the load instead of reading as false,
/// and `_FEATURES_HTTP_LISTENER` wins over its former name.
#[test]
fn boolean_env_overrides_refuse_unrecognised_values() {
    // A prefix no other test uses, so these variables race nothing.
    let mut features = FeaturesConfig::default();
    let apply = |features: &mut FeaturesConfig| {
        apply_env_overrides(
            "ENVBOOLTEST",
            features,
            &mut ServerConfig::default(),
            &mut LogConfig::default(),
            &mut StoreConfig::default(),
            &mut AuthConfig::default(),
            &mut SecretsConfig::default(),
        )
    };
    // SAFETY: test-only; the names are unique to this test.
    unsafe {
        std::env::set_var("ENVBOOLTEST_FEATURES_DIDCOMM", "yes");
        std::env::set_var("ENVBOOLTEST_FEATURES_REST_API", "on");
        std::env::set_var("ENVBOOLTEST_FEATURES_HTTP_LISTENER", "off");
    }
    apply(&mut features).unwrap();
    assert!(features.didcomm);
    assert!(!features.http_listener, "the current name wins");

    unsafe { std::env::set_var("ENVBOOLTEST_FEATURES_DIDCOMM", "maybe") };
    let err = apply(&mut features).unwrap_err().to_string();
    assert!(err.contains("ENVBOOLTEST_FEATURES_DIDCOMM"), "{err}");

    unsafe {
        std::env::remove_var("ENVBOOLTEST_FEATURES_DIDCOMM");
        std::env::remove_var("ENVBOOLTEST_FEATURES_REST_API");
        std::env::remove_var("ENVBOOLTEST_FEATURES_HTTP_LISTENER");
    }
}

#[test]
fn features_default_matches_toml_round_trip() {
    // The hand-written `Default` and the serde defaults must not drift:
    // `..Default::default()` in the setup wizards has to produce the same
    // config an operator gets from an empty `[features]` table.
    let from_toml: FeaturesConfig = toml::from_str("").unwrap();
    let from_default = FeaturesConfig::default();
    assert_eq!(from_toml.agent_names, from_default.agent_names);
    assert_eq!(from_toml.deployment_mode, from_default.deployment_mode);
    assert_eq!(from_default.deployment_mode, DeploymentMode::Standalone);
}

#[test]
fn identity_mode_default_is_vta() {
    assert_eq!(IdentityMode::default(), IdentityMode::Vta);
    assert_eq!(IdentityConfig::default().mode, IdentityMode::Vta);
}

#[test]
fn identity_mode_serializes_kebab_case() {
    let toml_str = toml::to_string(&IdentityConfig {
        mode: IdentityMode::SelfManaged,
        ..Default::default()
    })
    .unwrap();
    assert!(
        toml_str.contains(r#"mode = "self-managed""#),
        "expected kebab-case `self-managed`, got: {toml_str}"
    );

    let toml_str = toml::to_string(&IdentityConfig {
        mode: IdentityMode::Vta,
        ..Default::default()
    })
    .unwrap();
    assert!(
        toml_str.contains(r#"mode = "vta""#),
        "expected `vta`, got: {toml_str}"
    );
}

#[test]
fn identity_config_deserializes_self_managed() {
    let cfg: IdentityConfig = toml::from_str(r#"mode = "self-managed""#).unwrap();
    assert_eq!(cfg.mode, IdentityMode::SelfManaged);
}

#[test]
fn identity_config_deserializes_vta() {
    let cfg: IdentityConfig = toml::from_str(r#"mode = "vta""#).unwrap();
    assert_eq!(cfg.mode, IdentityMode::Vta);
}

#[test]
fn identity_config_round_trips() {
    let original = IdentityConfig {
        mode: IdentityMode::SelfManaged,
        ..Default::default()
    };
    let serialized = toml::to_string(&original).unwrap();
    let deserialized: IdentityConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(original, deserialized);
}

#[test]
fn identity_config_missing_mode_defaults_to_vta() {
    // An empty `[identity]` table (no `mode = ...`) should default to Vta
    // — this is the back-compat path for existing VTA-mode configs that
    // grow an `[identity]` section but don't yet set `mode`.
    let cfg: IdentityConfig = toml::from_str("").unwrap();
    assert_eq!(cfg.mode, IdentityMode::Vta);
}

#[test]
fn identity_config_unknown_mode_rejected() {
    let result: Result<IdentityConfig, _> = toml::from_str(r#"mode = "bogus""#);
    assert!(
        result.is_err(),
        "expected unknown mode to be rejected, got: {result:?}"
    );
}

#[test]
fn transport_selection_flags() {
    assert_eq!(TransportSelection::Didcomm.as_flags(), (true, false));
    assert_eq!(TransportSelection::Tsp.as_flags(), (false, true));
    assert_eq!(TransportSelection::Both.as_flags(), (true, true));
}

#[test]
fn transport_selection_parse_accepts_known_values() {
    assert_eq!(
        TransportSelection::parse("didcomm").unwrap(),
        TransportSelection::Didcomm
    );
    assert_eq!(
        TransportSelection::parse("TSP").unwrap(),
        TransportSelection::Tsp
    );
    assert_eq!(
        TransportSelection::parse(" Both ").unwrap(),
        TransportSelection::Both
    );
    assert_eq!(
        TransportSelection::parse("didcomm+tsp").unwrap(),
        TransportSelection::Both
    );
}

#[test]
fn transport_selection_parse_rejects_unknown() {
    assert!(TransportSelection::parse("carrier-pigeon").is_err());
}

#[test]
fn transport_selection_from_flags() {
    assert_eq!(
        TransportSelection::from_flags(true, true),
        Some(TransportSelection::Both)
    );
    assert_eq!(
        TransportSelection::from_flags(true, false),
        Some(TransportSelection::Didcomm)
    );
    assert_eq!(
        TransportSelection::from_flags(false, true),
        Some(TransportSelection::Tsp)
    );
    assert_eq!(TransportSelection::from_flags(false, false), None);
}

#[test]
fn transport_selection_flags_round_trip() {
    for sel in [
        TransportSelection::Didcomm,
        TransportSelection::Tsp,
        TransportSelection::Both,
    ] {
        let (d, t) = sel.as_flags();
        assert_eq!(TransportSelection::from_flags(d, t), Some(sel));
    }
}

#[test]
fn transport_selection_str_round_trips() {
    for sel in [
        TransportSelection::Didcomm,
        TransportSelection::Tsp,
        TransportSelection::Both,
    ] {
        assert_eq!(TransportSelection::parse(sel.as_str()).unwrap(), sel);
    }
}
