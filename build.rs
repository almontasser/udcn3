use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Set build-time environment variables
    println!("cargo:rustc-env=BUILD_TIME={}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
    
    // Get git information if available
    if let Ok(output) = std::process::Command::new("git")
        .args(&["rev-parse", "HEAD"])
        .output()
    {
        if output.status.success() {
            let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("cargo:rustc-env=GIT_HASH={}", git_hash);
        }
    }
    
    // Get git branch if available
    if let Ok(output) = std::process::Command::new("git")
        .args(&["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
    {
        if output.status.success() {
            let git_branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("cargo:rustc-env=GIT_BRANCH={}", git_branch);
        }
    }
    
    // Check for eBPF toolchain requirements
    if env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default() == "bpf" {
        println!("cargo:rustc-link-arg=-z");
        println!("cargo:rustc-link-arg=noexecstack");
    }
    
    // Rerun build script if git state changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
}