fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Ensure exactly one storage backend is selected at compile time.
    let store_features = [
        std::env::var("CARGO_FEATURE_STORE_FJALL").is_ok(),
        std::env::var("CARGO_FEATURE_STORE_REDIS").is_ok(),
        std::env::var("CARGO_FEATURE_STORE_DYNAMODB").is_ok(),
        std::env::var("CARGO_FEATURE_STORE_FIRESTORE").is_ok(),
        std::env::var("CARGO_FEATURE_STORE_COSMOSDB").is_ok(),
    ];
    let count: usize = store_features.iter().filter(|&&v| v).count();
    if count == 0 {
        panic!(
            "No storage backend selected. Enable exactly one: \
             store-fjall, store-redis, store-dynamodb, store-firestore, or store-cosmosdb"
        );
    }
    if count > 1 {
        panic!(
            "Multiple storage backends selected. Enable exactly one: \
             store-fjall, store-redis, store-dynamodb, store-firestore, or store-cosmosdb"
        );
    }
}
