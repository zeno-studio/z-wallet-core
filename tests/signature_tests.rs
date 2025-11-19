//! Signature Tests
//!
//! This file contains tests for the signature functionality:
//! - Hash signing
//! - EIP-7702 authorization signing
//! - EIP-7702 transaction signing

extern crate alloc;

use z_wallet_core::WalletCore;
use z_wallet_core::constants::ENTROPY_128;
use alloy_primitives::{B256, Address, U256, Bytes};

#[test]
fn test_sign_hash() {
    let mut wallet = WalletCore::new();
    let password = "test_password";
    let entropy_bits = ENTROPY_128;
    let duration = Some(3600u64);
    let now = 1000u64;
    let index = 0u32;
    
    // First create a vault
    let create_result = wallet.create_vault(password, entropy_bits, duration, now);
    assert!(create_result.is_ok());
    
    // Create a hash to sign
    let hash = B256::from([1u8; 32]);
    
    // Sign the hash
    let sign_result = wallet.sign_hash(password, index, now, &hash);
    assert!(sign_result.is_ok());
    
    let signature = sign_result.expect("Failed to sign hash");
    assert!(!signature.as_bytes().is_empty());
}

#[test]
fn test_sign_authorization() {
    let mut wallet = WalletCore::new();
    let password = "test_password";
    let entropy_bits = ENTROPY_128;
    let duration = Some(3600u64);
    let now = 1000u64;
    let index = 0u32;
    
    // First create a vault
    let create_result = wallet.create_vault(password, entropy_bits, duration, now);
    assert!(create_result.is_ok());
    
    // Create authorizations to sign
    let auth1 = alloy_eip7702::Authorization {
        chain_id: U256::from(1u64),
        address: Address::from([2u8; 20]),
        nonce: 0u64,
    };
    
    let auth2 = alloy_eip7702::Authorization {
        chain_id: U256::from(1u64),
        address: Address::from([3u8; 20]),
        nonce: 1u64,
    };
    
    let auths = vec![auth1, auth2];
    
    // Sign the authorizations
    let sign_result = wallet.sign_authorization(password, index, now, &auths);
    assert!(sign_result.is_ok());
    
    let signed_auths = sign_result.expect("Failed to sign authorizations");
    assert_eq!(signed_auths.len(), 2);
    
    // Verify the signatures are not empty
    for signed_auth in signed_auths {
        let signature = signed_auth.signature();
        assert!(signature.is_ok());
        assert!(!signature.expect("Failed to get signature").as_bytes().is_empty());
    }
}

#[test]
fn test_sign_empty_authorizations() {
    let mut wallet = WalletCore::new();
    let password = "test_password";
    let entropy_bits = ENTROPY_128;
    let duration = Some(3600u64);
    let now = 1000u64;
    let index = 0u32;
    
    // First create a vault
    let create_result = wallet.create_vault(password, entropy_bits, duration, now);
    assert!(create_result.is_ok());
    
    // Sign empty authorizations vector
    let auths = vec![];
    let sign_result = wallet.sign_authorization(password, index, now, &auths);
    assert!(sign_result.is_ok());
    
    let signed_auths = sign_result.expect("Failed to sign empty authorizations");
    assert!(signed_auths.is_empty());
}

#[test]
fn test_sign_7702_with_auths() {
    let mut wallet = WalletCore::new();
    let password = "test_password";
    let entropy_bits = ENTROPY_128;
    let duration = Some(3600u64);
    let now = 1000u64;
    let index = 0u32;
    
    // First create a vault
    let create_result = wallet.create_vault(password, entropy_bits, duration, now);
    assert!(create_result.is_ok());
    
    // Create authorizations to sign
    let auth1 = alloy_eip7702::Authorization {
        chain_id: U256::from(1u64),
        address: Address::from([2u8; 20]),
        nonce: 0u64,
    };
    
    let auths = vec![auth1];
    
    // Create an EIP-7702 transaction
    let tx = alloy_consensus::TxEip7702 {
        chain_id: 1,
        nonce: 0,
        gas_limit: 21000,
        max_fee_per_gas: 20_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: Address::from([4u8; 20]),
        value: U256::from(1000000000000000000u64), // 1 ETH
        access_list: Default::default(),
        authorization_list: vec![], // This will be filled by sign_7702
        input: Bytes::from(vec![]),
    };
    
    // Sign the EIP-7702 transaction with authorizations
    let sign_result = wallet.sign_7702(password, index, now, tx, Some(&auths));
    assert!(sign_result.is_ok());
    
    let signed_tx = sign_result.expect("Failed to sign EIP-7702 transaction with auths");
    assert!(!signed_tx.is_empty());
    assert!(signed_tx.starts_with("0x"));
}

#[test]
fn test_sign_7702_without_auths() {
    let mut wallet = WalletCore::new();
    let password = "test_password";
    let entropy_bits = ENTROPY_128;
    let duration = Some(3600u64);
    let now = 1000u64;
    let index = 0u32;
    
    // First create a vault
    let create_result = wallet.create_vault(password, entropy_bits, duration, now);
    assert!(create_result.is_ok());
    
    // Create an EIP-7702 transaction without authorizations
    let tx = alloy_consensus::TxEip7702 {
        chain_id: 1,
        nonce: 0,
        gas_limit: 21000,
        max_fee_per_gas: 20_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: Address::from([4u8; 20]),
        value: U256::from(1000000000000000000u64), // 1 ETH
        access_list: Default::default(),
        authorization_list: vec![],
        input: Bytes::from(vec![]),
    };
    
    // Sign the EIP-7702 transaction without authorizations
    let sign_result = wallet.sign_7702(password, index, now, tx, None);
    assert!(sign_result.is_ok());
    
    let signed_tx = sign_result.expect("Failed to sign EIP-7702 transaction without auths");
    assert!(!signed_tx.is_empty());
    assert!(signed_tx.starts_with("0x"));
}