use std::path::Path;

fn main() {
    // ---- Storage backend feature-gate validation ----
    let store_features = [
        cfg!(feature = "store-fjall"),
        cfg!(feature = "store-redis"),
        cfg!(feature = "store-dynamodb"),
        cfg!(feature = "store-firestore"),
        cfg!(feature = "store-cosmosdb"),
    ];
    let enabled_count = store_features.iter().filter(|&&f| f).count();

    if enabled_count == 0 {
        println!(
            "cargo:warning=No storage backend feature enabled! Enable one of: store-fjall, store-redis, store-dynamodb, store-firestore, store-cosmosdb"
        );
    }
    if enabled_count > 1 {
        println!(
            "cargo:warning=Multiple storage backend features enabled — only one will be used at runtime."
        );
    }

    // ---- Secret store feature-gate validation ----
    let secret_features = [
        cfg!(feature = "keyring"),
        cfg!(feature = "aws-secrets"),
        cfg!(feature = "gcp-secrets"),
    ];
    let secret_count = secret_features.iter().filter(|&&f| f).count();
    if secret_count > 1 {
        println!(
            "cargo:warning=Multiple secret store features enabled — only one will be used at runtime."
        );
    }

    // ---- UI build (when ui feature is enabled) ----
    #[cfg(feature = "ui")]
    build_ui();
}

#[cfg(feature = "ui")]
fn build_ui() {
    let ui_dir = Path::new("../webvh-ui");
    let dist_dir = ui_dir.join("dist");

    // Track UI source files for rebuild detection
    for dir in &["app", "components", "lib"] {
        let path = ui_dir.join(dir);
        if path.is_dir() {
            track_dir_recursive(&path);
        }
    }
    for file in &[
        "package.json",
        "package-lock.json",
        "tsconfig.json",
        "app.json",
        "App.tsx",
        "index.ts",
    ] {
        let path = ui_dir.join(file);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    // Rebuild if dist is missing or stale (any tracked source file is newer)
    let needs_build = if let Ok(dist_meta) = std::fs::metadata(dist_dir.join("index.html")) {
        let dist_mtime = dist_meta
            .modified()
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        any_source_newer(ui_dir, dist_mtime)
    } else {
        true // dist doesn't exist
    };

    if !needs_build {
        return;
    }

    // Install deps if needed
    if !ui_dir.join("node_modules").exists() {
        run_npm(ui_dir, &["install", "--prefer-offline"]);
    }

    // Build
    run_npm(ui_dir, &["run", "build:web"]);
}

#[cfg(feature = "ui")]
fn run_npm(cwd: &Path, args: &[&str]) {
    let status = std::process::Command::new("npm")
        .current_dir(cwd)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to run npm {}: {e}", args.join(" ")));
    if !status.success() {
        panic!("npm {} failed with {status}", args.join(" "));
    }
}

/// Returns true if any source file under the UI dirs is newer than `threshold`.
#[cfg(feature = "ui")]
fn any_source_newer(ui_dir: &Path, threshold: std::time::SystemTime) -> bool {
    for dir_name in &["app", "components", "lib"] {
        let path = ui_dir.join(dir_name);
        if path.is_dir() && dir_has_newer(&path, threshold) {
            return true;
        }
    }
    for file in &["package.json", "tsconfig.json", "app.json"] {
        let path = ui_dir.join(file);
        if let Ok(meta) = std::fs::metadata(&path)
            && let Ok(mtime) = meta.modified()
            && mtime > threshold
        {
            return true;
        }
    }
    false
}

#[cfg(feature = "ui")]
fn dir_has_newer(dir: &Path, threshold: std::time::SystemTime) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name.starts_with('.') || name == "node_modules" {
                continue;
            }
            if dir_has_newer(&path, threshold) {
                return true;
            }
        } else if let Ok(meta) = std::fs::metadata(&path)
            && let Ok(mtime) = meta.modified()
            && mtime > threshold
        {
            return true;
        }
    }
    false
}

#[cfg(feature = "ui")]
fn track_dir_recursive(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Skip node_modules and hidden dirs
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if name.starts_with('.') || name == "node_modules" {
                    continue;
                }
                track_dir_recursive(&path);
            } else {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}
