use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_FEATURE_UI").is_err() {
        return;
    }

    let ui_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../webvh-ui");

    // Track source files so cargo only re-runs the build when they change
    let tracked_dirs = ["app", "components", "lib"];
    let tracked_files = ["package.json", "app.json", "tsconfig.json", "index.ts"];

    for dir in &tracked_dirs {
        track_dir_recursive(&ui_dir.join(dir));
    }
    for file in &tracked_files {
        let p = ui_dir.join(file);
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }

    // Install deps if node_modules is missing
    if !ui_dir.join("node_modules").exists() {
        run_npm(&ui_dir, &["install", "--prefer-offline"]);
    }

    // Build the UI
    run_npm(&ui_dir, &["run", "build:web"]);
}

fn run_npm(cwd: &Path, args: &[&str]) {
    let status = Command::new("npm")
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "Failed to run `npm {}` in {}: {}\n\
                 Hint: ensure npm is installed and on your PATH.",
                args.join(" "),
                cwd.display(),
                e
            );
        });

    if !status.success() {
        panic!(
            "`npm {}` exited with status {} in {}",
            args.join(" "),
            status,
            cwd.display()
        );
    }
}

fn track_dir_recursive(dir: &Path) {
    if !dir.is_dir() {
        return;
    }
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            track_dir_recursive(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}
