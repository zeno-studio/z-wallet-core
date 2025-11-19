//! Wallet Core Tests
//!
//! This file contains unit tests for the wallet core functionality.
//!
//! Tests cover:
//! - WalletCore struct initialization
//! - Password validation
//! - Entropy validation
//! - Key derivation with Argon2
//! - Encryption/decryption with XChaCha20Poly1305
//! - Entropy generation and mnemonic conversion
//! - Salt and nonce validation

extern crate alloc;

use z_wallet_core::{
    WalletCore,
    entropy_to_mnemonic, generate_entropy_bits,
    password_kdf_argon2, encrypt_xchacha, decrypt_xchacha,
};
use z_wallet_core::error::CoreError;
use z_wallet_core::constants::{
    DEFAULT_CACHE_DURATION, DEFAULT_ENTROPY_BITS, ENTROPY_128, ENTROPY_256,
    ARGON2_SALT_LEN, ARGON2_OUTPUT_LEN, XCHACHA_XNONCE_LEN
};
use z_wallet_core::validate::{
    validate_password, validate_entropy, validate_salt, validate_nonce,
    validate_mnemonic
};

#[test]
fn test_wallet_core_new() {
    let wallet = WalletCore::new();
    // We can't directly access private fields, so we'll test through public methods
    assert!(wallet.get_ciphertext().is_err()); // Should error because ciphertext is None
    assert_eq!(wallet.get_cache_duration(), DEFAULT_CACHE_DURATION);
    assert_eq!(wallet.get_entropy_bits(), DEFAULT_ENTROPY_BITS);
    assert!(!wallet.has_derived_key());
}

#[test]
fn test_validate_password() {
    // Test valid password
    assert!(validate_password("valid_password").is_ok());
    
    // Test empty password
    assert!(matches!(validate_password(""), Err(CoreError::EmptyPassword)));
}

#[test]
fn test_validate_entropy() {
    // Test valid entropy bits
    assert!(validate_entropy(ENTROPY_128).is_ok());
    assert!(validate_entropy(ENTROPY_256).is_ok());
    
    // Test invalid entropy bits
    assert!(matches!(validate_entropy(64), Err(CoreError::InvalidEntropyBits)));
    assert!(matches!(validate_entropy(192), Err(CoreError::InvalidEntropyBits)));
}

#[test]
fn test_password_kdf_argon2() {
    let password = "test_password";
    let salt = [1u8; ARGON2_SALT_LEN];
    
    let result = password_kdf_argon2(password, &salt);
    assert!(result.is_ok());
    
    let dkey = result.expect("Failed to derive key with Argon2");
    assert_eq!(dkey.len(), ARGON2_OUTPUT_LEN);
}

#[test]
fn test_encrypt_decrypt_xchacha() {
    let phrase = "test_phrase";
    let password = "test_password";
    let salt = [1u8; ARGON2_SALT_LEN];
    let nonce = [2u8; XCHACHA_XNONCE_LEN];
    
    let dkey_result = password_kdf_argon2(password, &salt);
    assert!(dkey_result.is_ok());
    
    let dkey = dkey_result.expect("Failed to derive key with Argon2");
    let encrypt_result = encrypt_xchacha(phrase, &dkey, &nonce);
    assert!(encrypt_result.is_ok());
    
    let ciphertext = encrypt_result.expect("Failed to encrypt phrase");
    let decrypt_result = decrypt_xchacha(&ciphertext, &dkey, &nonce);
    assert!(decrypt_result.is_ok());
    
    let decrypted_phrase = decrypt_result.expect("Failed to decrypt ciphertext");
    assert_eq!(decrypted_phrase.as_str(), phrase);
}

#[test]
fn test_generate_entropy_bits() {
    let entropy_result = generate_entropy_bits(ENTROPY_128);
    assert!(entropy_result.is_ok());
    
    let entropy = entropy_result.expect("Failed to generate entropy bits");
    assert_eq!(entropy.len(), (ENTROPY_128 / 8) as usize);
}

#[test]
fn test_entropy_to_mnemonic() {
    // Generate 128-bit entropy
    let entropy_result = generate_entropy_bits(ENTROPY_128);
    assert!(entropy_result.is_ok());
    
    let entropy = entropy_result.expect("Failed to generate entropy bits");
    let mnemonic_result = entropy_to_mnemonic(&entropy);
    assert!(mnemonic_result.is_ok());
    
    let mnemonic = mnemonic_result.expect("Failed to convert entropy to mnemonic");
    assert!(!mnemonic.is_empty());
}

#[test]
fn test_validate_mnemonic() {
    // Valid mnemonic (12 words for 128 bits)
    let valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(validate_mnemonic(valid_mnemonic).is_ok());
    
    // Invalid mnemonic (empty)
    assert!(matches!(validate_mnemonic(""), Err(CoreError::MnemonicGenerationFailed)));
    
    // Invalid mnemonic (wrong number of words)
    let invalid_mnemonic = "word1 word2 word3";
    assert!(matches!(validate_mnemonic(invalid_mnemonic), Err(CoreError::MnemonicGenerationFailed)));
}

#[test]
fn test_validate_salt() {
    // Valid salt (non-zero)
    let valid_salt = [1u8; ARGON2_SALT_LEN];
    assert!(validate_salt(valid_salt).is_ok());
    
    // Invalid salt (all zeros)
    let invalid_salt = [0u8; ARGON2_SALT_LEN];
    assert!(matches!(validate_salt(invalid_salt), Err(CoreError::EmptySalt)));
}

#[test]
fn test_validate_nonce() {
    // Valid nonce (non-zero)
    let valid_nonce = [1u8; XCHACHA_XNONCE_LEN];
    assert!(validate_nonce(valid_nonce).is_ok());
    
    // Invalid nonce (all zeros)
    let invalid_nonce = [0u8; XCHACHA_XNONCE_LEN];
    assert!(matches!(validate_nonce(invalid_nonce), Err(CoreError::EmptyNonce)));
}