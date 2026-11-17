#[cfg(feature = "ui")]
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

    // Exactly one, as did-hosting-server, webvh-witness and webvh-watcher
    // require: a control plane with no store cannot start, and with several
    // the one it picks is an accident of cfg ordering.
    if enabled_count == 0 {
        panic!(
            "No storage backend selected. Enable exactly one: \
             store-fjall, store-redis, store-dynamodb, store-firestore, or store-cosmosdb"
        );
    }
    if enabled_count > 1 {
        panic!(
            "Multiple storage backends selected. Enable exactly one: \
             store-fjall, store-redis, store-dynamodb, store-firestore, or store-cosmosdb"
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

/// The Node.js floor is `engines.node` in `did-hosting-ui/package.json` — the
/// one place it is stated. This build script reads it from there (it only
/// checks Node when that workspace is present), so the two cannot drift.
#[cfg(feature = "ui")]
fn node_floor(ui_dir: &Path) -> (u32, u32, u32) {
    let path = ui_dir.join("package.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    parse_engines_node(&text).unwrap_or_else(|| {
        panic!(
            "{} must declare `engines.node` as \">=MAJOR.MINOR.PATCH\"",
            path.display()
        )
    })
}

/// `">=24.3.0"` (the value of `"node"` inside `"engines"`) → `(24, 3, 0)`.
/// A deliberately small reader: the build script has no JSON dependency, and
/// the shape is ours.
#[cfg(feature = "ui")]
fn parse_engines_node(package_json: &str) -> Option<(u32, u32, u32)> {
    let engines = &package_json[package_json.find("\"engines\"")?..];
    let node = &engines[engines.find("\"node\"")? + "\"node\"".len()..];
    let open = node.find('"')? + 1;
    let close = open + node[open..].find('"')?;
    parse_version(node[open..close].trim().strip_prefix(">=")?.trim())
}

#[cfg(feature = "ui")]
fn parse_version(v: &str) -> Option<(u32, u32, u32)> {
    let mut parts = v.trim_start_matches('v').split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().map_or(Some(0), |p| p.parse().ok())?;
    let patch = parts
        .next()
        .map_or(Some(0), |p| p.split(['-', '+']).next()?.parse().ok())?;
    Some((major, minor, patch))
}

#[cfg(feature = "ui")]
fn mtime(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

#[cfg(feature = "ui")]
fn build_ui() {
    let ui_dir = Path::new("../did-hosting-ui");
    // The embedded bundle lives inside this crate (`ui-dist/`) so it is carried
    // by the published tarball; `npm run build:web` writes straight into it.
    // See the `include` list in Cargo.toml and `frontend.rs`.
    let dist_dir = Path::new("ui-dist");

    // No UI workspace — we are building from the published `.crate` (or any
    // checkout of this crate alone), where `ui-dist` is pre-bundled. Nothing to
    // build, and crucially neither Node nor npm is required.
    if !ui_dir.is_dir() {
        if !dist_dir.join("index.html").exists() {
            // rust-embed's derive fails outright on a missing folder, so leave
            // an empty one behind: the binary builds and `static_handler`
            // already answers 404 when `index.html` is absent.
            std::fs::create_dir_all(dist_dir)
                .unwrap_or_else(|e| panic!("failed to create {}: {e}", dist_dir.display()));
            println!(
                "cargo:warning=No management UI bundle found in did-hosting-control/ui-dist and \
                 the ../did-hosting-ui workspace is absent — UI routes will return 404. Build \
                 from the workspace checkout, or disable the `ui` feature."
            );
        }
        return;
    }

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

    // Only now that a bundler run is actually due does Node become a hard
    // requirement — a fresh `ui-dist` builds fine without it.
    check_node_version(ui_dir);

    // Install deps when `node_modules` is missing OR out of sync with the
    // lockfile. npm writes `node_modules/.package-lock.json` on a successful
    // install; if the committed `package-lock.json` is newer (e.g. a
    // dependency bump just landed via `git pull`), the existing tree is stale
    // and must be resynced before building — otherwise `expo export` runs
    // against the old packages. Installing only on a missing `node_modules`
    // silently used stale deps despite the `rerun-if-changed` on the lockfile.
    let node_modules = ui_dir.join("node_modules");
    let needs_install = !node_modules.exists()
        || match (
            mtime(&ui_dir.join("package-lock.json")),
            mtime(&node_modules.join(".package-lock.json")),
        ) {
            (Some(lock), Some(installed)) => lock > installed,
            // No install marker (older npm) but node_modules exists: assume
            // in sync rather than reinstalling on every build.
            _ => false,
        };
    if needs_install {
        run_npm(ui_dir, &["install", "--prefer-offline"]);
    }

    // Build. `expo export` refuses to write into a non-empty output directory,
    // so clear the previous bundle first — a failed build fails the crate build
    // too, so there is nothing to preserve.
    let _ = std::fs::remove_dir_all(dist_dir);
    run_npm(ui_dir, &["run", "build:web"]);
}

/// Fail fast with a clear error if `node` is missing or older than the Metro
/// / Expo floor. Otherwise a bundler failure deep in `expo export` surfaces as
/// `TypeError: configs.toReversed is not a function` — a known ES2023 symptom
/// of an old Node. The floor is `engines.node` in `did-hosting-ui/package.json`
/// ([`node_floor`]).
#[cfg(feature = "ui")]
fn check_node_version(ui_dir: &Path) {
    let (fmaj, fmin, fpat) = node_floor(ui_dir);
    let floor = format!("{fmaj}.{fmin}.{fpat}");
    let output = match std::process::Command::new("node").arg("--version").output() {
        Ok(o) => o,
        Err(e) => panic!(
            "failed to invoke `node --version`: {e}. The `ui` feature requires \
             Node.js >= {floor} (engines.node in did-hosting-ui/package.json) to \
             build the management UI. Install it (e.g. via nvm) or build without \
             the `ui` feature (see the crate README)."
        ),
    };
    if !output.status.success() {
        panic!(
            "`node --version` exited non-zero. Install Node.js >= {floor} or build \
             without the `ui` feature."
        );
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let found = parse_version(raw.trim()).unwrap_or_else(|| {
        panic!("could not parse Node.js version from `node --version` output: {raw:?}")
    });
    if found < (fmaj, fmin, fpat) {
        panic!(
            "Node.js {} detected; the `ui` feature requires Node.js >= {floor} \
             (engines.node in did-hosting-ui/package.json). Upgrade Node — e.g. \
             `nvm install {fmaj} && nvm use {fmaj}` — or build without the `ui` \
             feature (see the crate README).",
            raw.trim()
        );
    }
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
