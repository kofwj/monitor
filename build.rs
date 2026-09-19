//! Puts the pinned default theme where `rust-embed` will find it.
//!
//! The hub embeds a built theme, which `scripts/theme.sh` fetches. Running it
//! here lets a plain `cargo build` proceed without a setup step, taking its
//! input from `web-theme.pin` rather than a hand-maintained directory.

use std::process::Command;

fn main() {
    // Cargo reruns this only when one of these changes. The stamp is listed as
    // well, so deleting `target/theme` triggers a refetch rather than a later
    // failure inside rust-embed.
    println!("cargo:rerun-if-changed=web-theme.pin");
    println!("cargo:rerun-if-changed=target/theme/.pin");
    println!("cargo:rerun-if-changed=scripts/theme.sh");

    // Exits rather than panics: a panicking build script prints Rust's own
    // formatting, which reads like a bug in the hub, while this failure belongs
    // to the download that `scripts/theme.sh` performs. The exit status stays in
    // the message because it is the part the script's own output may not state.
    match Command::new("sh").arg("scripts/theme.sh").status() {
        Ok(status) if status.success() => {}
        Ok(status) => {
            eprintln!("scripts/theme.sh failed ({status}); see the message above");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("could not run scripts/theme.sh: {e}");
            std::process::exit(1);
        }
    }
}
