fn main() {
    // Needed at runtime to locate the sidecar during `tauri dev`, where the core
    // still carries its target-triple suffix.
    println!(
        "cargo:rustc-env=TARGET_TRIPLE={}",
        std::env::var("TARGET").unwrap_or_default()
    );
    tauri_build::build()
}
