fn main() {
    // Tell Cargo to rebuild if build.rs changes
    println!("cargo:rerun-if-changed=build.rs");

    // For wasm-bindgen CLI optimization (if available)
    // This enables -Os optimization when running wasm-bindgen
    println!("cargo:rustc-env=WASM_BINDGEN_CFG_DISABLE_ASSERTIONS=1");
}
