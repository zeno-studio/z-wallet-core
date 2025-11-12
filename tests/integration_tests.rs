//! Integration Tests
//!
//! This file contains integration tests for the wallet core functionality.
//!
//! Tests cover:
//! - Wallet creation and vault generation
//! - Password verification
//! - Account derivation
//! - Password change functionality
//! - Airgap feature testing (import/export mnemonic)

extern crate alloc;

use z_wallet_core::{WalletCore};
use z_wallet_core::constants::{
    ENTROPY_128, ARGON2_SALT_LEN, XCHACHA_XNONCE_LEN
};

#[test]
fn test_wallet_core_create_vault() {
    let mut wallet = WalletCore::new();
    let password = "test_password";
    let entropy_bits = ENTROPY_128;
    let duration = 3600u64;
    let now = 1000u64;
    
    let result = wallet.create_vault(password, entropy_bits, duration, now);
    if let Err(e) = &result {
        eprintln!("Error creating vault: {:?}", e);
    }
    assert!(result.is_ok());
    
    let (vault, address) = result.unwrap();
    assert!(!vault.ciphertext.is_empty());
    assert_eq!(vault.salt.len(), ARGON2_SALT_LEN);
    assert_eq!(vault.nonce.len(), XCHACHA_XNONCE_LEN);
    // Address is now an alloy_primitives::Address, which doesn't have is_zero()
    // We'll just check that it's not the zero address
    assert!(!address.is_zero());
    
    // Check that wallet state is updated through public methods
    assert!(wallet.get_ciphertext().is_ok());
    assert!(wallet.has_derived_key());
    assert!(wallet.get_salt().is_ok());
    assert!(wallet.get_nonce().is_ok());
    assert_eq!(wallet.get_cache_duration(), duration);
    assert_eq!(wallet.get_entropy_bits(), entropy_bits);
}

#[test]
fn test_wallet_core_verify_password() {
    let mut wallet = WalletCore::new();
    let password = "test_password";
    let entropy_bits = ENTROPY_128;
    let duration = 3600u64;
    let now = 1000u64;
    
    // First create a vault
    let create_result = wallet.create_vault(password, entropy_bits, duration, now);
    assert!(create_result.is_ok());
    
    // Now verify the password
    let verify_result = wallet.verify_password(password, now);
    assert!(verify_result.is_ok());
    assert_eq!(verify_result.unwrap(), true);
    
    // Verify with wrong password
    let wrong_verify_result = wallet.verify_password("wrong_password", now);
    assert!(wrong_verify_result.is_ok());
    assert_eq!(wrong_verify_result.unwrap(), false);
}

#[test]
fn test_wallet_core_derive_account() {
    let mut wallet = WalletCore::new();
    let password = "test_password";
    let entropy_bits = ENTROPY_128;
    let duration = 3600u64;
    let now = 1000u64;
    let index = 0u32;
    
    // First create a vault
    let create_result = wallet.create_vault(password, entropy_bits, duration, now);
    assert!(create_result.is_ok());
    
    // Now derive an account
    let derive_result = wallet.derive_account(password, index, now);
    assert!(derive_result.is_ok());
    
    let address = derive_result.unwrap();
    assert!(!address.is_empty());
    assert!(address.starts_with("0x"));
}

#[test]
fn test_wallet_core_change_password() {
    let mut wallet = WalletCore::new();
    let old_password = "old_password";
    let new_password = "new_password";
    let entropy_bits = ENTROPY_128;
    let duration = 3600u64;
    let now = 1000u64;
    
    // First create a vault
    let create_result = wallet.create_vault(old_password, entropy_bits, duration, now);
    assert!(create_result.is_ok());
    
    // Change the password
    let change_result = wallet.change_ciphertext_password(old_password, new_password, now);
    assert!(change_result.is_ok());
    assert_eq!(change_result.unwrap(), true);
    
    // Verify with new password should work
    let verify_result = wallet.verify_password(new_password, now);
    assert!(verify_result.is_ok());
    assert_eq!(verify_result.unwrap(), true);
    
    // Verify with old password should fail
    let old_verify_result = wallet.verify_password(old_password, now);
    assert!(old_verify_result.is_ok());
    assert_eq!(old_verify_result.unwrap(), false);
}

#[cfg(feature = "airgap")]
#[test]
fn test_wallet_core_import_export_mnemonic() {
    let mut wallet = WalletCore::new();
    let password = "test_password";
    let entropy_bits = ENTROPY_128;
    let duration = 3600u64;
    let now = 1000u64;
    
    // First create a vault
    let create_result = wallet.create_vault(password, entropy_bits, duration, now);
    assert!(create_result.is_ok());
    
    // Export mnemonic
    let export_result = wallet.export_to_mnemonic(Some(password), now);
    assert!(export_result.is_ok());
    
    let mnemonic = export_result.unwrap();
    assert!(!mnemonic.is_empty());
    
    // Import from mnemonic (this would be a separate wallet instance in real usage)
    let mut new_wallet = WalletCore::new();
    let import_result = new_wallet.import_from_mnemonic(&mnemonic, password, duration, now);
    assert!(import_result.is_ok());
    
    let (imported_vault, _) = import_result.unwrap();
    assert!(!imported_vault.ciphertext.is_empty());
}

#[cfg(feature = "airgap")]
#[test]
fn test_create_vault_and_export_mnemonic() {
    let mut wallet = WalletCore::new();
    let password = "test_password";
    let entropy_bits = ENTROPY_128;
    let duration = 3600u64;
    let now = 1000u64;
    
    // First create a vault
    let create_result = wallet.create_vault(password, entropy_bits, duration, now);
    assert!(create_result.is_ok());
    
    // Export mnemonic
    let export_result = wallet.export_to_mnemonic(Some(password), now);
    assert!(export_result.is_ok());
    
    let mnemonic = export_result.unwrap();
    assert!(!mnemonic.is_empty());
    
    // Print the mnemonic for verification
    println!("Generated mnemonic: {}", mnemonic);
    
    // Verify it's a valid BIP39 mnemonic (12 words)
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 12);
    
    // Verify each word is not empty
    for word in words {
        assert!(!word.is_empty());
    }
}
