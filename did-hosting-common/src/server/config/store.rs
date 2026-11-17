//! `[store]`: the storage backend selection and its environment overrides.

use crate::server::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::env::parse_env_bool;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Redis connection URL (e.g. `redis://localhost:6379`). Used by `store-redis` backend.
    pub redis_url: Option<String>,
    /// DynamoDB table name prefix (default: `"webvh"`). Used by `store-dynamodb` backend.
    pub dynamodb_table_prefix: Option<String>,
    /// AWS region for DynamoDB. Used by `store-dynamodb` backend.
    pub dynamodb_region: Option<String>,
    /// How a table the `store-dynamodb` backend creates is billed:
    /// `pay_per_request` (the default, on-demand) or
    /// `provisioned:<read units>:<write units>`. Tables that already exist
    /// are left as they are.
    pub dynamodb_billing_mode: Option<String>,
    /// Whether the `store-dynamodb` backend creates a missing table (the
    /// default) or refuses to start using it. Set `false` where tables are
    /// provisioned ahead (Terraform, CloudFormation) and the service's role
    /// has no `dynamodb:CreateTable`.
    pub dynamodb_auto_create: Option<bool>,
    /// GCP project ID for Firestore. Used by `store-firestore` backend.
    pub firestore_project: Option<String>,
    /// Firestore database name (default: `"(default)"`). Used by `store-firestore` backend.
    pub firestore_database: Option<String>,
    /// Azure Cosmos DB connection string. Used by `store-cosmosdb` backend.
    pub cosmosdb_connection_string: Option<String>,
    /// Cosmos DB database name (default: `"webvh"`). Used by `store-cosmosdb` backend.
    pub cosmosdb_database: Option<String>,
    /// Cosmos DB container holding every keyspace (default: `"kv"`), so a
    /// batch can be one transactional batch. Created, partitioned on `/pk`,
    /// if missing. Used by `store-cosmosdb` backend.
    pub cosmosdb_container: Option<String>,
    /// Azure region name for Cosmos DB routing (e.g. `"eastus"`, `"westeurope"`,
    /// or display form `"West US 2"`). Defaults to `"eastus"` when unset. The
    /// SDK normalizes the name; see `azure_data_cosmos::Region` for the list
    /// of well-known regions.
    pub cosmosdb_region: Option<String>,
}

// `redis_url` and `cosmosdb_connection_string` can carry credentials; the
// other backend fields are non-sensitive identifiers. Manual Debug keeps
// startup-config logging from leaking the credential-bearing URLs.
impl std::fmt::Debug for StoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreConfig")
            .field("data_dir", &self.data_dir)
            .field("redis_url", &self.redis_url.as_ref().map(|_| "<redacted>"))
            .field("dynamodb_table_prefix", &self.dynamodb_table_prefix)
            .field("dynamodb_region", &self.dynamodb_region)
            .field("dynamodb_billing_mode", &self.dynamodb_billing_mode)
            .field("dynamodb_auto_create", &self.dynamodb_auto_create)
            .field("firestore_project", &self.firestore_project)
            .field("firestore_database", &self.firestore_database)
            .field(
                "cosmosdb_connection_string",
                &self
                    .cosmosdb_connection_string
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("cosmosdb_database", &self.cosmosdb_database)
            .field("cosmosdb_container", &self.cosmosdb_container)
            .field("cosmosdb_region", &self.cosmosdb_region)
            .finish()
    }
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("data/did-hosting-server")
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            redis_url: None,
            dynamodb_table_prefix: None,
            dynamodb_region: None,
            dynamodb_billing_mode: None,
            dynamodb_auto_create: None,
            firestore_project: None,
            firestore_database: None,
            cosmosdb_connection_string: None,
            cosmosdb_database: None,
            cosmosdb_container: None,
            cosmosdb_region: None,
        }
    }
}

/// Apply the `{prefix}_*` store overrides (`_DATA_DIR`, `_REDIS_URL`,
/// `_DYNAMODB_TABLE_PREFIX`, …) to one [`StoreConfig`].
///
/// [`apply_env_overrides`](super::apply_env_overrides) calls it with `{PREFIX}_STORE`; a binary with a
/// second store calls it once more with that store's own prefix (the daemon's
/// `[witness_store]` reads `DAEMON_WITNESS_STORE_*`).
pub fn apply_store_env_overrides(prefix: &str, store: &mut StoreConfig) -> Result<(), AppError> {
    macro_rules! env_opt {
        ($var:expr, $field:expr) => {
            if let Ok(v) = std::env::var($var) {
                $field = Some(v);
            }
        };
    }
    let store_data_dir_var = format!("{prefix}_DATA_DIR");
    if let Ok(data_dir) = std::env::var(&store_data_dir_var) {
        store.data_dir = PathBuf::from(data_dir);
    }
    env_opt!(&format!("{prefix}_REDIS_URL"), store.redis_url);
    env_opt!(
        &format!("{prefix}_DYNAMODB_TABLE_PREFIX"),
        store.dynamodb_table_prefix
    );
    env_opt!(&format!("{prefix}_DYNAMODB_REGION"), store.dynamodb_region);
    env_opt!(
        &format!("{prefix}_DYNAMODB_BILLING_MODE"),
        store.dynamodb_billing_mode
    );
    let auto_create_var = format!("{prefix}_DYNAMODB_AUTO_CREATE");
    if let Ok(v) = std::env::var(&auto_create_var) {
        store.dynamodb_auto_create = Some(parse_env_bool(&auto_create_var, &v)?);
    }
    env_opt!(
        &format!("{prefix}_FIRESTORE_PROJECT"),
        store.firestore_project
    );
    env_opt!(
        &format!("{prefix}_FIRESTORE_DATABASE"),
        store.firestore_database
    );
    env_opt!(
        &format!("{prefix}_COSMOSDB_CONNECTION_STRING"),
        store.cosmosdb_connection_string
    );
    env_opt!(
        &format!("{prefix}_COSMOSDB_DATABASE"),
        store.cosmosdb_database
    );
    env_opt!(
        &format!("{prefix}_COSMOSDB_CONTAINER"),
        store.cosmosdb_container
    );
    env_opt!(&format!("{prefix}_COSMOSDB_REGION"), store.cosmosdb_region);
    Ok(())
}
