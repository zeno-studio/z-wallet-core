//! WASM Tests
//!
//! This file contains unit tests for the WASM bindings.
//! These tests are compiled and run when the "wasm" feature is enabled.
//!
//! Note: These tests require the wasm32 target and wasm-bindgen to run properly.
//! They can be run with: cargo test --features wasm --target wasm32-unknown-unknown
//!
//! Or using wasm-bindgen-test: cargo test --features wasm
//!
//! IMPORTANT: These tests cannot run on native targets because they use js_sys and wasm_bindgen.
//! To run these tests, you need to use wasm32 target:
//!   rustup target add wasm32-unknown-unknown
//!   cargo test --features wasm --target wasm32-unknown-unknown

#![cfg(all(feature = "wasm", target_arch = "wasm32"))]

extern crate alloc;

// Import from wasm module (which re-exports the functions)
use yami_wallet_core::wasm::{
    validate_mnemonic, generate_mnemonic,
    WalletCoreJs,
};

#[test]
fn test_validate_mnemonic() {
    // Valid mnemonic (12 words for 128 bits)
    let valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(validate_mnemonic(valid_mnemonic));
    
    // Invalid mnemonic (empty)
    assert!(!validate_mnemonic(""));
    
    // Invalid mnemonic (wrong number of words)
    let invalid_mnemonic = "word1 word2 word3";
    assert!(!validate_mnemonic(invalid_mnemonic));
}

#[test]
fn test_generate_mnemonic() {
    // Generate 128-bit mnemonic
    let result = generate_mnemonic(128);
    assert!(result.is_ok());
    
    let mnemonic = result.expect("Failed to generate mnemonic");
    assert!(!mnemonic.is_empty());
    
    // Check it's a valid 12-word mnemonic
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 12);
    
    // Generate 256-bit mnemonic
    let result = generate_mnemonic(256);
    assert!(result.is_ok());
    
    let mnemonic = result.expect("Failed to generate mnemonic");
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 24);
}

#[test]
fn test_wallet_core_js_new() {
    let wallet = WalletCoreJs::new();
    // Just test that it can be created
    // The internal state will be tested through other methods
    assert!(wallet.get_cache_duration() > 0);
}

#[test]
fn test_wallet_core_js_create_vault() {
    let mut wallet = WalletCoreJs::new();
    let password = "test_password_123";
    let entropy_bits = 128;
    let cache_duration = 3600;
    let now = 1000000;
    
    let result = wallet.create_vault(password, entropy_bits, cache_duration, now);
    assert!(result.is_ok());
    
    let js_value = result.expect("Failed to create vault");
    // The result should be a JS object with vault, address, path
    // We can't directly test JS objects in Rust, but we can verify the method doesn't panic
}

#[test]
fn test_wallet_core_js_load_vault() {
    // First create a vault
    let mut wallet_create = WalletCoreJs::new();
    let password = "test_password_123";
    let entropy_bits = 128;
    let cache_duration = 3600;
    let now = 1000000;
    
    let create_result = wallet_create.create_vault(password, entropy_bits, cache_duration, now);
    assert!(create_result.is_ok());
    
    let vault_string = wallet_create.get_vault_string().expect("Failed to get vault string");
    assert!(!vault_string.is_empty());
    
    // Now load it into a new wallet
    let mut wallet_load = WalletCoreJs::new();
    let load_result = wallet_load.load_vault(&vault_string);
    assert!(load_result.is_ok());
}

#[test]
fn test_wallet_core_js_import_vault() {
    // First create a vault
    let mut wallet_create = WalletCoreJs::new();
    let password = "test_password_123";
    let entropy_bits = 128;
    let cache_duration = 3600;
    let now = 1000000;
    
    let create_result = wallet_create.create_vault(password, entropy_bits, cache_duration, now);
    assert!(create_result.is_ok());
    
    let vault_string = wallet_create.get_vault_string().expect("Failed to get vault string");
    
    // Import it into a new wallet
    let mut wallet_import = WalletCoreJs::new();
    let import_result = wallet_import.import_vault(password, &vault_string, cache_duration, now);
    assert!(import_result.is_ok());
}

#[test]
fn test_wallet_core_js_verify_password() {
    // Create a vault
    let mut wallet_create = WalletCoreJs::new();
    let password = "test_password_123";
    let entropy_bits = 128;
    let cache_duration = 3600;
    let now = 1000000;
    
    let create_result = wallet_create.create_vault(password, entropy_bits, cache_duration, now);
    assert!(create_result.is_ok());
    
    let vault_string = wallet_create.get_vault_string().expect("Failed to get vault string");
    
    // Verify correct password
    let mut wallet_verify = WalletCoreJs::new();
    let verify_result = wallet_verify.load_vault(&vault_string);
    assert!(verify_result.is_ok());
    
    let valid = wallet_verify.verify_password(password, now + 100).expect("Failed to verify password");
    assert!(valid);
}

#[test]
fn test_wallet_core_js_derive_account() {
    // Create a vault
    let mut wallet_create = WalletCoreJs::new();
    let password = "test_password_123";
    let entropy_bits = 128;
    let cache_duration = 3600;
    let now = 1000000;
    
    let create_result = wallet_create.create_vault(password, entropy_bits, cache_duration, now);
    assert!(create_result.is_ok());
    
    let vault_string = wallet_create.get_vault_string().expect("Failed to get vault string");
    
    // Derive account
    let mut wallet = WalletCoreJs::new();
    let load_result = wallet.load_vault(&vault_string);
    assert!(load_result.is_ok());
    
    let derive_result = wallet.derive_account(password, 0, now + 100);
    assert!(derive_result.is_ok());
}

#[test]
fn test_wallet_core_js_get_address() {
    // Create a vault
    let mut wallet_create = WalletCoreJs::new();
    let password = "test_password_123";
    let entropy_bits = 128;
    let cache_duration = 3600;
    let now = 1000000;
    
    let create_result = wallet_create.create_vault(password, entropy_bits, cache_duration, now);
    assert!(create_result.is_ok());
    
    let vault_string = wallet_create.get_vault_string().expect("Failed to get vault string");
    
    // Get address
    let mut wallet = WalletCoreJs::new();
    let load_result = wallet.load_vault(&vault_string);
    assert!(load_result.is_ok());
    
    let address_result = wallet.get_address(Some(password.to_string()), 0, now + 100);
    assert!(address_result.is_ok());
    
    let address = address_result.expect("Failed to get address");
    assert!(!address.is_empty());
    // Address should be 40 hex characters (20 bytes)
    assert_eq!(address.len(), 40);
}

#[test]
fn test_wallet_core_js_sign_hash() {
    // Create a vault
    let mut wallet_create = WalletCoreJs::new();
    let password = "test_password_123";
    let entropy_bits = 128;
    let cache_duration = 3600;
    let now = 1000000;
    
    let create_result = wallet_create.create_vault(password, entropy_bits, cache_duration, now);
    assert!(create_result.is_ok());
    
    let vault_string = wallet_create.get_vault_string().expect("Failed to get vault string");
    
    // Sign hash
    let mut wallet = WalletCoreJs::new();
    let load_result = wallet.load_vault(&vault_string);
    assert!(load_result.is_ok());
    
    // A sample 32-byte hash (64 hex characters)
    let hash_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    let sign_result = wallet.sign_hash(password, 0, hash_hex, now + 100);
    assert!(sign_result.is_ok());
    
    let signature = sign_result.expect("Failed to sign hash");
    // Signature should be 130 hex characters (65 bytes)
    assert_eq!(signature.len(), 130);
}

#[test]
fn test_wallet_core_js_sign_hash_components() {
    // Create a vault
    let mut wallet_create = WalletCoreJs::new();
    let password = "test_password_123";
    let entropy_bits = 128;
    let cache_duration = 3600;
    let now = 1000000;
    
    let create_result = wallet_create.create_vault(password, entropy_bits, cache_duration, now);
    assert!(create_result.is_ok());
    
    let vault_string = wallet_create.get_vault_string().expect("Failed to get vault string");
    
    // Sign hash and get components
    let mut wallet = WalletCoreJs::new();
    let load_result = wallet.load_vault(&vault_string);
    assert!(load_result.is_ok());
    
    let hash_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    let sign_result = wallet.sign_hash_components(password, 0, hash_hex, now + 100);
    assert!(sign_result.is_ok());
    // Returns JS object, can't verify contents in Rust test
}

#[test]
fn test_wallet_core_js_change_password() {
    // Create a vault
    let mut wallet_create = WalletCoreJs::new();
    let password = "test_password_123";
    let new_password = "new_password_456";
    let entropy_bits = 128;
    let cache_duration = 3600;
    let now = 1000000;
    
    let create_result = wallet_create.create_vault(password, entropy_bits, cache_duration, now);
    assert!(create_result.is_ok());
    
    let vault_string = wallet_create.get_vault_string().expect("Failed to get vault string");
    
    // Change password
    let mut wallet = WalletCoreJs::new();
    let load_result = wallet.load_vault(&vault_string);
    assert!(load_result.is_ok());
    
    let change_result = wallet.change_password(password, new_password, now + 100);
    assert!(change_result.is_ok());
    
    // Get new vault string
    let new_vault_string = wallet.get_vault_string().expect("Failed to get new vault string");
    assert_ne!(vault_string, new_vault_string);
}

#[test]
fn test_wallet_core_js_get_vault_info() {
    // Create a vault
    let mut wallet = WalletCoreJs::new();
    let password = "test_password_123";
    let entropy_bits = 128;
    let cache_duration = 3600;
    let now = 1000000;
    
    let create_result = wallet.create_vault(password, entropy_bits, cache_duration, now);
    assert!(create_result.is_ok());
    
    let info_result = wallet.get_vault_info();
    assert!(info_result.is_ok());
    // Returns JS object, can't verify contents in Rust test
}
