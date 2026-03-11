use std::process::Command;

fn main() {
    // Re-run only when build.rs itself changes or a new commit is made.
    // We intentionally do NOT watch .git/HEAD or refs — packed refs may not
    // exist as files (git packs them into .git/packed-refs), and cargo treats
    // a missing rerun-if-changed path as "always dirty", causing recompilation
    // on every single build. Instead, we only watch build.rs. The git hash
    // and build date change rarely enough that a `cargo clean` or touching
    // build.rs is acceptable when they need to update.
    println!("cargo:rerun-if-changed=build.rs");

    // Git short hash for version info.
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=OAIE_GIT_HASH={git_hash}");

    // Build date (ISO 8601 date only).
    let build_date = Command::new("date")
        .args(["+%Y-%m-%d"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=OAIE_BUILD_DATE={build_date}");

    // Target triple.
    if let Ok(target) = std::env::var("TARGET") {
        println!("cargo:rustc-env=OAIE_TARGET={target}");
    }
}
