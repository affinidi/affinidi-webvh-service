//! TOML schema for a non-interactive setup recipe.
//!
//! One file works for any webvh service — `[deployment].service` is the
//! discriminator and per-service validation lives in [`SetupRecipe::validate`].

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level recipe. Every section except `[deployment]` and `[output]`
/// is optional and falls back to sensible defaults per service.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetupRecipe {
    pub deployment: DeploymentSection,
    pub output: OutputSection,
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub identity: IdentitySection,
    #[serde(default)]
    pub vta: VtaSection,
    #[serde(default)]
    pub secrets: SecretsSection,
    #[serde(default)]
    pub admin: AdminSection,
    #[serde(default)]
    pub reprovision: ReprovisionSection,
    /// Only consulted when `deployment.service = "watcher"`.
    #[serde(default)]
    pub watcher: WatcherSection,
    /// Only consulted when `deployment.service = "daemon"`.
    #[serde(default)]
    pub daemon: DaemonSection,
}

/// Top-level discriminator + VTA mode.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentSection {
    pub service: ServiceKind,
    /// How this service obtains its DID identity. Defaults to `online` —
    /// the most common case (VTA reachable, ephemeral did:key enrolled).
    #[serde(default = "default_vta_mode")]
    pub vta_mode: VtaMode,
}

fn default_vta_mode() -> VtaMode {
    VtaMode::Online
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceKind {
    Daemon,
    Server,
    Control,
    Witness,
    Watcher,
}

impl ServiceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daemon => "did-hosting-daemon",
            Self::Server => "did-hosting-server",
            Self::Control => "did-hosting-control",
            Self::Witness => "webvh-witness",
            Self::Watcher => "webvh-watcher",
        }
    }
}

impl std::fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VtaMode {
    /// VTA is reachable from this host. Operator has already run
    /// `--setup-key-out` and enrolled the ephemeral did:key; the recipe
    /// path now expects `--setup-key-file <path>` to drive Phase 2.
    Online,
    /// Phase 1 of the offline (air-gapped VTA) flow — writes a sealed
    /// bootstrap request to ferry to the VTA admin.
    OfflinePrepare,
    /// Phase 2 of the offline flow — opens the VTA admin's sealed reply.
    /// Requires `[vta].bundle_path` + `[vta].expect_digest` + the state
    /// file from phase 1.
    OfflineComplete,
    /// Daemon-only. The daemon generates its own keys and self-hosts a
    /// `did:webvh` — no VTA involved.
    SelfManaged,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSection {
    /// Where to write the generated `config.toml`.
    pub config_path: PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// `host:port` is the binary's listen address. Defaults match the
    /// interactive wizard per service: 8530 (server), 8532 (control),
    /// 8533 (watcher), 8534 (daemon/witness).
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub log_format: Option<LogFormatStr>,
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
}

/// String enum so `log_format = "json"` reads naturally in TOML. Maps to
/// `did_hosting_common::server::config::LogFormat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormatStr {
    Text,
    Json,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySection {
    /// Public URL this service is reachable at. For `did-hosting-server` /
    /// `did-hosting-daemon` (self-managed) it drives the service's own
    /// `did:webvh` identifier. For `did-hosting-control` it's the WebAuthn
    /// rp_id origin (NOT the same as `did_hosting_url`).
    #[serde(default)]
    pub public_url: Option<String>,
    /// Where did-hosting-server hosts DID documents publicly. Used by
    /// `did-hosting-control` / `webvh-witness` whose DIDs live on a separate
    /// hosting server. Defaults match interactive prompts.
    #[serde(default)]
    pub did_hosting_url: Option<String>,
    /// DID path on the hosting server. `services/control` for control,
    /// `services/witness` for witness. Server/daemon derive their path
    /// from `public_url`'s path component (`.well-known` when empty).
    #[serde(default)]
    pub did_path: Option<String>,
    /// DIDComm mediator DID. When set, the service's DID document
    /// advertises a `DIDCommMessaging` service entry pointing at this
    /// mediator. Required for daemon hosting external tenant DIDs.
    #[serde(default)]
    pub mediator_did: Option<String>,
    /// Which messaging transport(s) the node advertises and its mediator
    /// listener carries: `didcomm`, `tsp`, or `both`. Only meaningful when
    /// `mediator_did` is set (both ride the mediator socket). Absent /
    /// empty defaults to `both`.
    #[serde(default)]
    pub transport: Option<String>,
    /// Server-only: the control plane's DID, for DIDComm sync auth.
    #[serde(default)]
    pub control_did: Option<String>,
    /// Server-only: the control plane's HTTP URL (optional — sync uses
    /// DIDComm; this is only consulted by tooling that pokes the API).
    #[serde(default)]
    pub control_url: Option<String>,
}

impl IdentitySection {
    /// Transport feature flags `(didcomm, tsp)` implied by this identity.
    /// Both transports ride the mediator socket, so with no `mediator_did`
    /// the node is HTTP-only and both are false. Otherwise the `transport`
    /// field (default `both`) selects which are enabled.
    pub fn transport_flags(&self) -> Result<(bool, bool), crate::server::error::AppError> {
        use crate::server::config::TransportSelection;
        if self.mediator_did.is_none() {
            return Ok((false, false));
        }
        Ok(TransportSelection::parse(self.transport.as_deref().unwrap_or("both"))?.as_flags())
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VtaSection {
    /// VTA DID the integration is provisioned against. Required for
    /// `vta_mode = "online"`.
    #[serde(default)]
    pub did: Option<String>,
    /// VTA context the integration will live in. Defaults to `"webvh"`.
    #[serde(default)]
    pub context_id: Option<String>,
    /// Phase 1 offline output: path for the bootstrap request JSON.
    #[serde(default)]
    pub request_path: Option<PathBuf>,
    /// Phase 1 + Phase 2 offline state file (plain TOML, no secrets).
    #[serde(default)]
    pub state_path: Option<PathBuf>,
    /// Phase 2 offline input: the sealed bundle from the VTA admin.
    #[serde(default)]
    pub bundle_path: Option<PathBuf>,
    /// Phase 2 offline input: SHA-256 digest the VTA admin printed
    /// out-of-band. Required for offline-complete.
    #[serde(default)]
    pub expect_digest: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsSection {
    /// Backend kind. One of: `keyring`, `aws`, `gcp`, `azure`, `vault`,
    /// `k8s`, `plaintext`. Defaults to `keyring`. The wizard refuses
    /// `plaintext` unless `confirm_plaintext = true` is also set — a
    /// defence against shipping CI recipes into production by mistake.
    #[serde(default)]
    pub backend: Option<SecretsBackend>,
    #[serde(default)]
    pub keyring_service: Option<String>,
    #[serde(default)]
    pub aws_region: Option<String>,
    #[serde(default)]
    pub aws_secret_name: Option<String>,
    #[serde(default)]
    pub gcp_project: Option<String>,
    #[serde(default)]
    pub gcp_secret_name: Option<String>,
    #[serde(default)]
    pub azure_vault_url: Option<String>,
    #[serde(default)]
    pub azure_secret_name: Option<String>,
    // HashiCorp Vault (backend = "vault"). Only `vault_addr` is required;
    // `vault_secret_path` defaults to the service's secret name, and the
    // mount/auth defaults match the runtime `SecretsConfig`.
    #[serde(default)]
    pub vault_addr: Option<String>,
    #[serde(default)]
    pub vault_kv_mount: Option<String>,
    #[serde(default)]
    pub vault_secret_path: Option<String>,
    #[serde(default)]
    pub vault_secret_key: Option<String>,
    #[serde(default)]
    pub vault_namespace: Option<String>,
    #[serde(default)]
    pub vault_auth_method: Option<String>,
    #[serde(default)]
    pub vault_k8s_role: Option<String>,
    #[serde(default)]
    pub vault_k8s_mount: Option<String>,
    #[serde(default)]
    pub vault_k8s_jwt_path: Option<String>,
    #[serde(default)]
    pub vault_token: Option<String>,
    #[serde(default)]
    pub vault_approle_role_id: Option<String>,
    #[serde(default)]
    pub vault_approle_secret_id: Option<String>,
    #[serde(default)]
    pub vault_approle_mount: Option<String>,
    #[serde(default)]
    pub vault_skip_verify: Option<bool>,
    // Native Kubernetes Secret (backend = "k8s"). `k8s_secret_name`
    // defaults to the service's secret name; namespace defaults to the
    // pod's namespace at runtime.
    #[serde(default)]
    pub k8s_secret_name: Option<String>,
    #[serde(default)]
    pub k8s_namespace: Option<String>,
    #[serde(default)]
    pub k8s_secret_key: Option<String>,
    /// Required when `backend = "plaintext"`. Acknowledges the recipe
    /// will produce a config file containing private keys in clear text.
    #[serde(default)]
    pub confirm_plaintext: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretsBackend {
    Keyring,
    Aws,
    Gcp,
    Azure,
    /// HashiCorp Vault (KV v2), authenticating via Kubernetes SA JWT
    /// (default), a static token, or AppRole.
    Vault,
    /// Native Kubernetes `Secret` resource.
    #[serde(rename = "k8s", alias = "kubernetes")]
    K8s,
    /// Stores key material directly in `config.toml`. Dev only.
    Plaintext,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminSection {
    #[serde(default)]
    pub mode: AdminMode,
    /// Required when `mode = "did"` — the operator-supplied DID gets
    /// inserted into the ACL with role admin.
    #[serde(default)]
    pub did: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdminMode {
    /// Insert the operator-supplied DID (`[admin].did`) into the ACL.
    Did,
    /// Generate a fresh did:key and print the private half to stderr
    /// once. The DID is inserted into the ACL.
    Generate,
    /// Don't seed the ACL. Admin enrolment happens later (via
    /// `did-hosting-daemon invite` for self-managed, or `add-acl` manually).
    #[default]
    Skip,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReprovisionSection {
    /// Allow the wizard to run when an existing config + provisioned
    /// backend is detected. Without this, the wizard refuses with exit
    /// code 4 to protect issued JWTs and active VTA sessions.
    #[serde(default)]
    pub force: bool,
}

/// Daemon-specific settings. Other services ignore this section.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonSection {
    /// Which embedded services the daemon runs. Defaults match the
    /// interactive wizard: control + server + witness on, watcher off.
    #[serde(default)]
    pub enable_control: Option<bool>,
    #[serde(default)]
    pub enable_server: Option<bool>,
    #[serde(default)]
    pub enable_witness: Option<bool>,
    #[serde(default)]
    pub enable_watcher: Option<bool>,
}

/// Watcher-specific settings. Other services ignore this section.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherSection {
    /// Bearer tokens that source servers must present when pushing.
    /// Empty disables auth (only safe on a trusted private network).
    #[serde(default)]
    pub push_tokens: Vec<String>,
    #[serde(default)]
    pub sources: Vec<WatcherSourceConfig>,
    /// Reconcile interval in seconds. 0 disables outbound reconcile.
    #[serde(default)]
    pub reconcile_interval: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherSourceConfig {
    pub url: String,
    #[serde(default)]
    pub token: Option<String>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Errors a recipe can produce before any side effects. Maps to
/// [`crate::server::setup_recipe::EXIT_RECIPE_INVALID`].
#[derive(Debug, thiserror::Error)]
pub enum RecipeError {
    #[error("missing required field for {service}: {field}")]
    MissingField {
        service: ServiceKind,
        field: &'static str,
    },
    #[error("field {field} is not valid for {service}: {reason}")]
    InvalidField {
        service: ServiceKind,
        field: &'static str,
        reason: String,
    },
    #[error("service {service:?} cannot use vta_mode = {mode:?}: {reason}")]
    UnsupportedMode {
        service: ServiceKind,
        mode: VtaMode,
        reason: &'static str,
    },
    #[error(
        "secrets.backend = \"plaintext\" but secrets.confirm_plaintext is false. \
         Plaintext writes private keys directly into config.toml — set \
         confirm_plaintext = true to acknowledge, or pick a real backend."
    )]
    PlaintextNotConfirmed,
    #[error("failed to parse recipe TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("failed to read recipe file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl SetupRecipe {
    /// Per-service required-field validation. Run before any side effects.
    pub fn validate(&self) -> Result<(), RecipeError> {
        use ServiceKind::*;
        use VtaMode::*;

        let service = self.deployment.service;
        let mode = self.deployment.vta_mode;

        // Self-managed is daemon-only — same rule the interactive wizards
        // enforce via `SELF_MANAGED_DAEMON_ONLY`.
        if mode == SelfManaged && service != Daemon {
            return Err(RecipeError::UnsupportedMode {
                service,
                mode,
                reason: "self-managed mode is daemon-only; use did-hosting-daemon",
            });
        }

        // The watcher has no VTA / DID identity — only `online` makes
        // sense (and even then it skips the VTA path entirely; we accept
        // the value but warn nothing).
        if service == Watcher && mode != Online {
            return Err(RecipeError::UnsupportedMode {
                service,
                mode,
                reason: "watcher has no VTA integration; only vta_mode = \"online\" is accepted",
            });
        }

        // Plaintext confirmation gate — defends CI recipes from leaking
        // into prod.
        if matches!(self.secrets.backend, Some(SecretsBackend::Plaintext))
            && !self.secrets.confirm_plaintext
        {
            return Err(RecipeError::PlaintextNotConfirmed);
        }

        // Vault needs a server address; the KV path defaults to the
        // service's secret name and auth-method-specific fields are
        // validated at connect time by the backend itself.
        if matches!(self.secrets.backend, Some(SecretsBackend::Vault))
            && self.secrets.vault_addr.is_none()
        {
            return Err(RecipeError::MissingField {
                service,
                field: "secrets.vault_addr (required for backend = \"vault\")",
            });
        }

        // VTA section — required for any mode that talks to the VTA.
        match (service, mode) {
            (Watcher, _) | (_, SelfManaged) => {}
            (_, Online) => {
                if self.vta.did.is_none() {
                    return Err(RecipeError::MissingField {
                        service,
                        field: "vta.did (required for vta_mode = \"online\")",
                    });
                }
            }
            (_, OfflinePrepare) => {
                // The VTA DID isn't required here — phase 1 only writes
                // a request; the VTA's identity gets pinned when phase
                // 2 opens the sealed response.
                if self.vta.request_path.is_none() {
                    return Err(RecipeError::MissingField {
                        service,
                        field: "vta.request_path (required for vta_mode = \"offline-prepare\")",
                    });
                }
            }
            (_, OfflineComplete) => {
                if self.vta.bundle_path.is_none() {
                    return Err(RecipeError::MissingField {
                        service,
                        field: "vta.bundle_path (required for vta_mode = \"offline-complete\")",
                    });
                }
                if self.vta.expect_digest.is_none() {
                    return Err(RecipeError::MissingField {
                        service,
                        field: "vta.expect_digest (required for vta_mode = \"offline-complete\")",
                    });
                }
                // state_path is intentionally NOT required: the recipe
                // is the state. Operators re-run with the SAME recipe
                // file (vta_mode flipped + bundle_path/expect_digest
                // filled in) and the bootstrap seed comes back out of
                // the configured secret store keyed by the same backend.
            }
        }

        // Service-specific identity fields.
        match service {
            Daemon | Server => {
                if mode != OfflineComplete && self.identity.public_url.is_none() {
                    return Err(RecipeError::MissingField {
                        service,
                        field: "identity.public_url",
                    });
                }
            }
            Control => {
                if mode != OfflineComplete && self.identity.did_hosting_url.is_none() {
                    return Err(RecipeError::MissingField {
                        service,
                        field: "identity.did_hosting_url",
                    });
                }
                if mode != OfflineComplete && self.identity.public_url.is_none() {
                    return Err(RecipeError::MissingField {
                        service,
                        field: "identity.public_url (control plane's WebAuthn origin)",
                    });
                }
            }
            Witness => {
                if mode != OfflineComplete && self.identity.did_hosting_url.is_none() {
                    return Err(RecipeError::MissingField {
                        service,
                        field: "identity.did_hosting_url",
                    });
                }
            }
            Watcher => {}
        }

        // Admin DID required when mode = "did".
        if self.admin.mode == AdminMode::Did && self.admin.did.is_none() {
            return Err(RecipeError::MissingField {
                service,
                field: "admin.did (required when admin.mode = \"did\")",
            });
        }

        Ok(())
    }

    /// Best-effort default port for a service when not specified.
    pub fn default_port(service: ServiceKind) -> u16 {
        match service {
            ServiceKind::Server => 8530,
            ServiceKind::Control => 8532,
            ServiceKind::Watcher => 8533,
            // Daemon and witness both default to 8534 in their wizards;
            // operators usually pick one or the other on a host.
            ServiceKind::Daemon | ServiceKind::Witness => 8534,
        }
    }

    /// Best-effort default data dir for a service when not specified.
    pub fn default_data_dir(service: ServiceKind) -> PathBuf {
        match service {
            ServiceKind::Daemon => PathBuf::from("data/daemon"),
            ServiceKind::Server => PathBuf::from("data/did-hosting-server"),
            ServiceKind::Control => PathBuf::from("data/did-hosting-control"),
            ServiceKind::Witness => PathBuf::from("data/webvh-witness"),
            ServiceKind::Watcher => PathBuf::from("data/webvh-watcher"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal(service: ServiceKind) -> SetupRecipe {
        SetupRecipe {
            deployment: DeploymentSection {
                service,
                vta_mode: VtaMode::Online,
            },
            output: OutputSection {
                config_path: PathBuf::from("config.toml"),
            },
            server: ServerSection::default(),
            identity: IdentitySection {
                public_url: Some("https://example.com".into()),
                did_hosting_url: Some("https://example.com".into()),
                ..Default::default()
            },
            vta: VtaSection {
                did: Some("did:webvh:vta.example.com".into()),
                ..Default::default()
            },
            secrets: SecretsSection::default(),
            admin: AdminSection::default(),
            reprovision: ReprovisionSection::default(),
            watcher: WatcherSection::default(),
            daemon: DaemonSection::default(),
        }
    }

    #[test]
    fn self_managed_rejected_outside_daemon() {
        for service in [
            ServiceKind::Server,
            ServiceKind::Control,
            ServiceKind::Witness,
            ServiceKind::Watcher,
        ] {
            let mut r = minimal(service);
            r.deployment.vta_mode = VtaMode::SelfManaged;
            let err = r.validate().unwrap_err();
            assert!(matches!(err, RecipeError::UnsupportedMode { .. }));
        }
    }

    #[test]
    fn self_managed_accepted_for_daemon() {
        let mut r = minimal(ServiceKind::Daemon);
        r.deployment.vta_mode = VtaMode::SelfManaged;
        // Self-managed daemon doesn't need vta.did.
        r.vta = VtaSection::default();
        r.validate().expect("self-managed daemon is valid");
    }

    #[test]
    fn watcher_only_accepts_online_mode() {
        let mut r = minimal(ServiceKind::Watcher);
        r.deployment.vta_mode = VtaMode::OfflinePrepare;
        assert!(matches!(
            r.validate().unwrap_err(),
            RecipeError::UnsupportedMode { .. }
        ));
        r.deployment.vta_mode = VtaMode::Online;
        r.validate().unwrap();
    }

    #[test]
    fn online_requires_vta_did() {
        let mut r = minimal(ServiceKind::Server);
        r.vta.did = None;
        assert!(matches!(
            r.validate().unwrap_err(),
            RecipeError::MissingField { field, .. } if field.starts_with("vta.did")
        ));
    }

    #[test]
    fn offline_complete_requires_bundle_and_digest() {
        let mut r = minimal(ServiceKind::Server);
        r.deployment.vta_mode = VtaMode::OfflineComplete;
        // public_url not required in offline-complete (the sealed reply carries the DID).
        r.identity.public_url = None;
        // Missing bundle_path → bundle_path complaint wins.
        let err = r.validate().unwrap_err();
        assert!(
            matches!(err, RecipeError::MissingField { field, .. } if field.contains("bundle_path"))
        );
        r.vta.bundle_path = Some(PathBuf::from("b.txt"));
        // Now expect_digest is the next required field.
        let err = r.validate().unwrap_err();
        assert!(
            matches!(err, RecipeError::MissingField { field, .. } if field.contains("expect_digest"))
        );
        r.vta.expect_digest = Some("deadbeef".into());
        // state_path is intentionally NOT required — recipe is the state.
        r.validate().unwrap();
    }

    #[test]
    fn offline_prepare_requires_request_path() {
        let mut r = minimal(ServiceKind::Server);
        r.deployment.vta_mode = VtaMode::OfflinePrepare;
        // Default fixture has no request_path → first check fires.
        let err = r.validate().unwrap_err();
        assert!(
            matches!(err, RecipeError::MissingField { field, .. } if field.contains("request_path"))
        );
        r.vta.request_path = Some(PathBuf::from("bootstrap-request.json"));
        r.validate().unwrap();
    }

    #[test]
    fn plaintext_requires_confirmation() {
        let mut r = minimal(ServiceKind::Server);
        r.secrets.backend = Some(SecretsBackend::Plaintext);
        assert!(matches!(
            r.validate().unwrap_err(),
            RecipeError::PlaintextNotConfirmed
        ));
        r.secrets.confirm_plaintext = true;
        r.validate().unwrap();
    }

    #[test]
    fn admin_did_required_when_mode_is_did() {
        let mut r = minimal(ServiceKind::Server);
        r.admin.mode = AdminMode::Did;
        assert!(matches!(
            r.validate().unwrap_err(),
            RecipeError::MissingField { field, .. } if field.starts_with("admin.did")
        ));
        r.admin.did = Some("did:key:z6Mk...".into());
        r.validate().unwrap();
    }

    #[test]
    fn control_requires_did_hosting_url() {
        let mut r = minimal(ServiceKind::Control);
        r.identity.did_hosting_url = None;
        assert!(matches!(
            r.validate().unwrap_err(),
            RecipeError::MissingField { field, .. } if field.starts_with("identity.did_hosting_url")
        ));
    }

    #[test]
    fn deny_unknown_fields_rejects_typos() {
        // Catch operator typos at parse time rather than silently ignoring.
        let bad = r#"
            [deployment]
            service = "server"
            vta_mode = "online"

            [output]
            config_path = "config.toml"

            [identity]
            public_url = "https://example.com"
            unkown_field = "oops"
        "#;
        let err = toml::from_str::<SetupRecipe>(bad).unwrap_err();
        assert!(err.to_string().contains("unkown_field"));
    }

    #[test]
    fn round_trip_minimal_daemon_recipe() {
        let r = minimal(ServiceKind::Daemon);
        let s = toml::to_string_pretty(&r).unwrap();
        let r2: SetupRecipe = toml::from_str(&s).unwrap();
        assert_eq!(r2.deployment.service, ServiceKind::Daemon);
    }
}
