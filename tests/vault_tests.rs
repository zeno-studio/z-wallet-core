//! Vault Tests
//!
//! This file contains unit tests for the Vault functionality.
//!
//! Tests cover:
//! - Vault creation
//! - Vault serialization to keystore string
//! - Vault deserialization from keystore string
//! - Vault validation with empty fields
//! - Vault version validation

extern crate alloc;

use alloc::vec::Vec;
use z_wallet_core::{Vault, CoreError};
use z_wallet_core::constants::{
    ARGON2_SALT_LEN, XCHACHA_XNONCE_LEN, VERSION_TAG_1, VERSION_TAG_LEN
};

#[test]
fn test_vault_creation() {
    let version = VERSION_TAG_1.as_bytes().try_into().unwrap();
    let salt = [1u8; ARGON2_SALT_LEN];
    let nonce = [2u8; XCHACHA_XNONCE_LEN];
    let ciphertext = vec![3u8; 32];
    
    let vault = Vault {
        version,
        salt,
        nonce,
        ciphertext: ciphertext.clone(),
    };
    
    assert_eq!(vault.version, version);
    assert_eq!(vault.salt, salt);
    assert_eq!(vault.nonce, nonce);
    assert_eq!(vault.ciphertext, ciphertext);
}

#[test]
fn test_vault_to_keystore_string() {
    let version = VERSION_TAG_1.as_bytes().try_into().unwrap();
    let salt = [1u8; ARGON2_SALT_LEN];
    let nonce = [2u8; XCHACHA_XNONCE_LEN];
    let ciphertext = vec![3u8; 32];
    
    let mut vault = Vault {
        version,
        salt,
        nonce,
        ciphertext: ciphertext.clone(),
    };
    
    let keystore_result = vault.to_keystore_string();
    assert!(keystore_result.is_ok());
    
    let keystore_string = keystore_result.unwrap();
    assert!(!keystore_string.is_empty());
}

#[test]
fn test_vault_from_keystore_string() {
    // Create a valid keystore string first
    let version = VERSION_TAG_1.as_bytes().try_into().unwrap();
    let salt = [1u8; ARGON2_SALT_LEN];
    let nonce = [2u8; XCHACHA_XNONCE_LEN];
    let ciphertext = vec![3u8; 32];
    
    let mut vault = Vault {
        version,
        salt,
        nonce,
        ciphertext: ciphertext.clone(),
    };
    
    let keystore_string = vault.to_keystore_string().unwrap();
    
    // Now test parsing it back
    let parsed_vault_result = Vault::from_keystore_string(&keystore_string);
    assert!(parsed_vault_result.is_ok());
    
    let parsed_vault = parsed_vault_result.unwrap();
    assert_eq!(parsed_vault.version, version);
    assert_eq!(parsed_vault.salt, salt);
    assert_eq!(parsed_vault.nonce, nonce);
    assert_eq!(parsed_vault.ciphertext, ciphertext);
}

#[test]
fn test_vault_from_keystore_string_invalid_version() {
    // Create a keystore string with invalid version
    let version = [0u8; VERSION_TAG_LEN]; // Invalid version
    let salt = [1u8; ARGON2_SALT_LEN];
    let nonce = [2u8; XCHACHA_XNONCE_LEN];
    let ciphertext = vec![3u8; 32];
    
    let vault = Vault {
        version,
        salt,
        nonce,
        ciphertext,
    };
    
    // We need to manually create the keystore string since to_keystore_string 
    // will correct the version
    let mut bytes = Vec::with_capacity(VERSION_TAG_LEN + ARGON2_SALT_LEN + XCHACHA_XNONCE_LEN + 32);
    bytes.extend_from_slice(&vault.version);
    bytes.extend_from_slice(&vault.salt);
    bytes.extend_from_slice(&vault.nonce);
    bytes.extend_from_slice(&vault.ciphertext);
    
    let keystore_string = bs58::encode(bytes).into_string();
    
    let parsed_vault_result = Vault::from_keystore_string(&keystore_string);
    assert!(parsed_vault_result.is_err());
    
    // Should be VaultInvalidVersion error
    match parsed_vault_result.unwrap_err() {
        CoreError::VaultInvalidVersion { .. } => {}, // Expected
        _ => panic!("Expected VaultInvalidVersion error"),
    }
}

#[test]
fn test_vault_from_keystore_string_invalid_length() {
    // Create an invalid keystore string (too short)
    let short_bytes = vec![1u8; 10]; // Too short
    let invalid_keystore_string = bs58::encode(short_bytes).into_string();
    
    let parsed_vault_result = Vault::from_keystore_string(&invalid_keystore_string);
    assert!(parsed_vault_result.is_err());
    
    // Should be VaultParseError
    match parsed_vault_result.unwrap_err() {
        CoreError::VaultParseError => {}, // Expected
        _ => panic!("Expected VaultParseError"),
    }
}

#[test]
fn test_vault_to_keystore_string_empty_fields() {
    let version = VERSION_TAG_1.as_bytes().try_into().unwrap();
    let salt = [0u8; ARGON2_SALT_LEN]; // Empty salt
    let nonce = [0u8; XCHACHA_XNONCE_LEN]; // Empty nonce
    let ciphertext = vec![]; // Empty ciphertext
    
    let mut vault = Vault {
        version,
        salt,
        nonce,
        ciphertext,
    };
    
    let keystore_result = vault.to_keystore_string();
    assert!(keystore_result.is_err());
    
    // Should be InvalidVault error
    match keystore_result.unwrap_err() {
        CoreError::InvalidVault => {}, // Expected
        _ => panic!("Expected InvalidVault error"),
    }
}