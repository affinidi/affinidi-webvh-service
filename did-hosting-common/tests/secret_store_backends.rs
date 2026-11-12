//! Live get/set/bootstrap-seed round-trip smoke tests for the HashiCorp
//! Vault and native Kubernetes `Secret` backends.
//!
//! These exercise the real backends against real infrastructure, so they
//! are **opt-in**: each test no-ops (prints a skip line and returns) unless
//! the corresponding `WEBVH_TEST_*` env vars are set. This keeps the
//! default `cargo test` green on machines with no Vault/cluster while still
//! giving CI (or a developer with infra) a real round-trip check.
//!
//! ## Vault
//!
//! Spin up a dev server (root token, KV v2 mounted at `secret`):
//!
//! ```sh
//! docker run --rm -d -p 8200:8200 \
//!   -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault
//! WEBVH_TEST_VAULT_ADDR=http://127.0.0.1:8200 \
//! WEBVH_TEST_VAULT_TOKEN=root \
//!   cargo test -p did-hosting-common \
//!   --features vault-secrets,k8s-secrets,store-fjall \
//!   --test secret_store_backends vault -- --nocapture
//! ```
//!
//! ## Kubernetes
//!
//! Point at any cluster your kubeconfig can reach (kind/minikube/etc.):
//!
//! ```sh
//! WEBVH_TEST_K8S=1 WEBVH_TEST_K8S_NAMESPACE=default \
//!   cargo test -p did-hosting-common \
//!   --features vault-secrets,k8s-secrets,store-fjall \
//!   --test secret_store_backends k8s -- --nocapture
//! ```

#![cfg(all(feature = "vault-secrets", feature = "k8s-secrets"))]

use did_hosting_common::server::config::SecretsConfig;
use did_hosting_common::server::secret_store::{
    ServerSecrets, create_secret_store, create_witness_kek_store,
};

fn sample_secrets() -> ServerSecrets {
    ServerSecrets {
        signing_key: "z6MkSigningKeyMultibasePlaceholder".into(),
        key_agreement_key: "z6LSKeyAgreementMultibasePlaceholder".into(),
        jwt_signing_key: "z6MkJwtSigningKeyMultibasePlaceholder".into(),
        vta_credential: Some("dGVzdC1jcmVkZW50aWFs".into()),
        retired: Vec::new(),
    }
}

/// Run the full `SecretStore` contract against a freshly-constructed store:
/// empty → set → get → bootstrap-seed set/get/clear.
async fn assert_round_trip(store: &dyn did_hosting_common::server::secret_store::SecretStore) {
    // Fresh path: nothing stored yet.
    assert!(
        store.get().await.expect("get empty").is_none(),
        "expected no secrets at a fresh path"
    );
    assert!(
        store
            .get_bootstrap_seed()
            .await
            .expect("get empty seed")
            .is_none(),
        "expected no bootstrap seed at a fresh path"
    );

    // Store and read back the server secrets.
    let secrets = sample_secrets();
    store.set(&secrets).await.expect("set secrets");
    let loaded = store
        .get()
        .await
        .expect("get secrets")
        .expect("secrets present");
    assert_eq!(loaded.signing_key, secrets.signing_key);
    assert_eq!(loaded.key_agreement_key, secrets.key_agreement_key);
    assert_eq!(loaded.jwt_signing_key, secrets.jwt_signing_key);
    assert_eq!(loaded.vta_credential, secrets.vta_credential);

    // Bootstrap seed shares the same envelope and must not disturb secrets.
    let seed = [7u8; 32];
    store.set_bootstrap_seed(&seed).await.expect("set seed");
    assert_eq!(
        store.get_bootstrap_seed().await.expect("get seed"),
        Some(seed)
    );
    assert!(
        store
            .get()
            .await
            .expect("secrets survive seed write")
            .is_some(),
        "storing the bootstrap seed must not clobber the server secrets"
    );

    // Clearing the seed leaves the secrets intact.
    store.clear_bootstrap_seed().await.expect("clear seed");
    assert!(
        store
            .get_bootstrap_seed()
            .await
            .expect("get cleared seed")
            .is_none(),
        "bootstrap seed should be gone after clear"
    );
    assert!(
        store.get().await.expect("secrets after clear").is_some(),
        "clearing the seed must not clobber the server secrets"
    );
}

/// The witness key-encryption key round-trips in its own entry, and the
/// service envelope at `cfg` is not changed by it, nor it by the envelope.
async fn assert_witness_kek_round_trip(cfg: &SecretsConfig) {
    let path = std::path::Path::new("config.toml");
    let kek_store = create_witness_kek_store(cfg, path).expect("build witness kek store");
    assert!(kek_store.get().await.expect("get empty").is_none());
    let kek = affinidi_secrets_resolver::secrets::Secret::generate_x25519(None, None).unwrap();
    kek_store.set(&kek).await.expect("set kek");

    let envelope = create_secret_store(cfg, path).expect("build store");
    let before = envelope
        .get()
        .await
        .expect("get secrets")
        .map(|s| s.signing_key);
    envelope
        .set(&sample_secrets())
        .await
        .expect("rewrite envelope");
    assert_eq!(
        before.as_deref(),
        Some(sample_secrets().signing_key.as_str()),
        "writing the key-encryption key must not touch the envelope"
    );

    let read = kek_store
        .get()
        .await
        .expect("get kek")
        .expect("kek present");
    assert_eq!(read.get_public_bytes(), kek.get_public_bytes());
    eprintln!("witness key-encryption key: OK in {}", kek_store.location());
}

#[tokio::test]
async fn vault_round_trip() {
    let (Ok(addr), Ok(token)) = (
        std::env::var("WEBVH_TEST_VAULT_ADDR"),
        std::env::var("WEBVH_TEST_VAULT_TOKEN"),
    ) else {
        eprintln!(
            "skipping vault_round_trip: set WEBVH_TEST_VAULT_ADDR + WEBVH_TEST_VAULT_TOKEN to run"
        );
        return;
    };

    // Unique path per run so repeated runs against a persistent Vault start
    // clean. `std::process::id()` avoids needing a random source.
    let path = format!("webvh-test/secret-store-{}", std::process::id());

    let cfg = SecretsConfig {
        vault_addr: Some(addr),
        vault_secret_path: Some(path.clone()),
        vault_auth_method: "token".into(),
        vault_token: Some(token),
        ..SecretsConfig::default()
    };

    let store =
        create_secret_store(&cfg, std::path::Path::new("config.toml")).expect("build vault store");
    assert_round_trip(store.as_ref()).await;
    assert_witness_kek_round_trip(&cfg).await;
    eprintln!("vault_round_trip: OK against path {path}");
}

#[tokio::test]
async fn k8s_round_trip() {
    if std::env::var("WEBVH_TEST_K8S").is_err() {
        eprintln!(
            "skipping k8s_round_trip: set WEBVH_TEST_K8S=1 (with a reachable kubeconfig) to run"
        );
        return;
    }

    let name = format!("webvh-test-secret-store-{}", std::process::id());
    let cfg = SecretsConfig {
        k8s_secret_name: Some(name.clone()),
        k8s_namespace: std::env::var("WEBVH_TEST_K8S_NAMESPACE").ok(),
        ..SecretsConfig::default()
    };

    let store =
        create_secret_store(&cfg, std::path::Path::new("config.toml")).expect("build k8s store");
    assert_round_trip(store.as_ref()).await;
    assert_witness_kek_round_trip(&cfg).await;
    eprintln!(
        "k8s_round_trip: OK against Secrets {name} and {name}-witness-kek (remember to delete them)"
    );
}
