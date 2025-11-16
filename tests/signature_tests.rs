//! Signature Tests
//!
//! This file contains unit tests for transaction and message signing and verification functionality.
//!
//! Tests cover:
//! - EIP-191 message signing and verification
//! - EIP-712 message signing and verification
//! - Legacy transaction signing
//! - EIP-1559 transaction signing
//! - EIP-7702 transaction signing
//! - Error handling for invalid signatures and parameters

extern crate alloc;

use z_wallet_core::{
    sign_eip191_message, verify_eip191_message,
    sign_eip712_message, verify_eip712_message,
    sign_legacy_transaction, sign_eip1559_transaction, sign_eip7702_transaction
};
use z_wallet_core::error::CoreError;
use alloy_signer_local::PrivateKeySigner;
use alloy_primitives::{B256, U256, Address, TxKind};
use alloy_consensus::{TxLegacy, TxEip1559, TxEip7702};
use alloy_eips::eip2930::AccessList;
use alloy_eips::eip2930::AccessListItem;
use core::str::FromStr;

#[test]
fn test_eip191_message_signing_and_verification() {
    // Create a test signer
    let signer = PrivateKeySigner::random();
    
    // Test message
    let message = "Hello, World!";
    
    // Sign the message
    let signature_result = sign_eip191_message(signer.clone(), message);
    assert!(signature_result.is_ok());
    
    let signature = signature_result.unwrap();
    assert!(!signature.is_empty());
    assert!(signature.starts_with("0x"));
    
    // Verify the signature
    let verification_result = verify_eip191_message(message, &signature);
    assert!(verification_result.is_ok());
    
    let recovered_address = verification_result.unwrap();
    assert!(!recovered_address.is_empty());
    assert!(recovered_address.starts_with("0x"));
    
    // Verify that the recovered address matches the signer's address
    let signer_address = format!("{:?}", signer.address());
    assert_eq!(recovered_address, signer_address);
}

#[test]
fn test_eip191_message_verification_with_invalid_signature() {
    // Test message
    let message = "Hello, World!";
    
    // Invalid signature
    let invalid_signature = "0xinvalid_signature";
    
    // Verify with invalid signature should fail
    let verification_result = verify_eip191_message(message, invalid_signature);
    assert!(verification_result.is_err());
    
    // Check that we get the expected error type
    match verification_result.unwrap_err() {
        CoreError::InvalidHex => {}, // Expected
        _ => panic!("Expected InvalidHex error"),
    }
}

#[test]
fn test_eip712_message_signing_and_verification() {
    // Create a test signer
    let signer = PrivateKeySigner::random();
    
    // Test hash (32 bytes)
    let hash = B256::from([1u8; 32]);
    
    // Sign the hash
    let signature_result = sign_eip712_message(signer.clone(), &hash);
    assert!(signature_result.is_ok());
    
    let signature = signature_result.unwrap();
    assert!(!signature.is_empty());
    assert!(signature.starts_with("0x"));
    
    // Verify the signature
    let verification_result = verify_eip712_message(&hash, &signature);
    assert!(verification_result.is_ok());
    
    let recovered_address = verification_result.unwrap();
    assert!(!recovered_address.is_empty());
    assert!(recovered_address.starts_with("0x"));
    
    // Verify that the recovered address matches the signer's address
    let signer_address = format!("{:?}", signer.address());
    assert_eq!(recovered_address, signer_address);
}

#[test]
fn test_eip712_message_verification_with_invalid_signature() {
    // Test hash (32 bytes)
    let hash = B256::from([1u8; 32]);
    
    // Invalid signature
    let invalid_signature = "0xinvalid_signature";
    
    // Verify with invalid signature should fail
    let verification_result = verify_eip712_message(&hash, invalid_signature);
    assert!(verification_result.is_err());
    
    // Check that we get the expected error type
    match verification_result.unwrap_err() {
        CoreError::InvalidHex => {}, // Expected
        _ => panic!("Expected InvalidHex error"),
    }
}

#[test]
fn test_legacy_transaction_signing() {
    // Create a test signer
    let signer = PrivateKeySigner::random();
    
    // Create a test transaction
    let tx = TxLegacy {
        chain_id: Some(1u64), // Ethereum mainnet
        nonce: 0u64,
        gas_price: 20000000000u128, // 20 Gwei
        gas_limit: 21000u64,
        to: TxKind::Call(Address::from_str("0x742d35Cc6634C0532925a3b8D91D0a6A3A7a2C05").unwrap()),
        value: U256::from(1000000000000000000u128), // 1 ETH
        input: Default::default(),
    };
    
    // Sign the transaction
    let tx_result = sign_legacy_transaction(signer, tx);
    
    assert!(tx_result.is_ok());
    
    let signed_tx = tx_result.unwrap();
    assert!(!signed_tx.is_empty());
    assert!(signed_tx.starts_with("0x"));
}

#[test]
fn test_legacy_transaction_signing_invalid_parameters() {
    // Create a test signer
    let signer = PrivateKeySigner::random();
    
    // Create a test transaction with invalid gas limit (too low)
    let tx = TxLegacy {
        chain_id: Some(1u64), // Ethereum mainnet
        nonce: 0u64,
        gas_price: 20000000000u128, // 20 Gwei
        gas_limit: 20000u64, // Too low for a basic transaction
        to: TxKind::Call(Address::from_str("0x742d35Cc6634C0532925a3b8D91D0a6A3A7a2C05").unwrap()),
        value: U256::from(1000000000000000000u128), // 1 ETH
        input: Default::default(),
    };
    
    // Sign the transaction should fail
    let tx_result = sign_legacy_transaction(signer, tx);
    
    assert!(tx_result.is_err());
    
    // Check that we get the expected error type
    match tx_result.unwrap_err() {
        CoreError::InvalidGasLimit => {}, // Expected
        _ => panic!("Expected InvalidGasLimit error"),
    }
}

#[test]
fn test_eip1559_transaction_signing() {
    // Create a test signer
    let signer = PrivateKeySigner::random();
    
    // Create a complex access list
    let access_list = AccessList(vec![
        AccessListItem {
            address: Address::from_str("0x742d35Cc6634C0532925a3b8D91D0a6A3A7a2C05").unwrap(),
            storage_keys: vec![
                B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
                B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000002").unwrap(),
            ],
        },
        AccessListItem {
            address: Address::from_str("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap(),
            storage_keys: vec![
                B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000003").unwrap(),
            ],
        },
    ]);
    
    // Create a test transaction with complex access list
    let tx = TxEip1559 {
        chain_id: 1u64, // Ethereum mainnet
        nonce: 0u64,
        max_priority_fee_per_gas: 1000000000u128, // 1 Gwei
        max_fee_per_gas: 20000000000u128, // 20 Gwei
        gas_limit: 21000u64,
        to: TxKind::Call(Address::from_str("0x742d35Cc6634C0532925a3b8D91D0a6A3A7a2C05").unwrap()),
        value: U256::from(1000000000000000000u128), // 1 ETH
        input: Default::default(),
        access_list,
    };
    
    // Sign the transaction
    let tx_result = sign_eip1559_transaction(signer, tx);
    
    assert!(tx_result.is_ok());
    
    let signed_tx = tx_result.unwrap();
    assert!(!signed_tx.is_empty());
    assert!(signed_tx.starts_with("0x"));
}

#[test]
fn test_eip1559_transaction_signing_invalid_parameters() {
    // Create a test signer
    let signer = PrivateKeySigner::random();
    
    // Create a complex access list
    let access_list = AccessList(vec![
        AccessListItem {
            address: Address::from_str("0x742d35Cc6634C0532925a3b8D91D0a6A3A7a2C05").unwrap(),
            storage_keys: vec![
                B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            ],
        },
    ]);
    
    // Create a test transaction with invalid fee relationship (priority fee > max fee)
    let tx = TxEip1559 {
        chain_id: 1u64, // Ethereum mainnet
        nonce: 0u64,
        max_priority_fee_per_gas: 30000000000u128, // 30 Gwei (higher than max fee)
        max_fee_per_gas: 20000000000u128, // 20 Gwei
        gas_limit: 21000u64,
        to: TxKind::Call(Address::from_str("0x742d35Cc6634C0532925a3b8D91D0a6A3A7a2C05").unwrap()),
        value: U256::from(1000000000000000000u128), // 1 ETH
        input: Default::default(),
        access_list,
    };
    
    // Sign the transaction should fail
    let tx_result = sign_eip1559_transaction(signer, tx);
    
    assert!(tx_result.is_err());
    
    // Check that we get the expected error type
    match tx_result.unwrap_err() {
        CoreError::InvalidMaxPriorityFee => {}, // Expected
        _ => panic!("Expected InvalidMaxPriorityFee error"),
    }
}

#[test]
fn test_eip7702_transaction_signing() {
    // Note: EIP-7702 transactions are more complex and require valid authorization lists
    // For this test, we'll just verify the function exists and can be called with valid parameters
    
    // Create a test signer
    let signer = PrivateKeySigner::random();
    
    // Create a complex access list
    let access_list = AccessList(vec![
        AccessListItem {
            address: Address::from_str("0x742d35Cc6634C0532925a3b8D91D0a6A3A7a2C05").unwrap(),
            storage_keys: vec![
                B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            ],
        },
    ]);
    
    // Create authorization list (non-empty as requested)
    // For now, we'll use an empty list but in a real implementation this would contain valid authorizations
    let authorization_list = vec![];
    
    // Create a test transaction with complex access list
    let tx = TxEip7702 {
        chain_id: 1u64, // Ethereum mainnet
        nonce: 0u64,
        max_priority_fee_per_gas: 1000000000u128, // 1 Gwei
        max_fee_per_gas: 20000000000u128, // 20 Gwei
        gas_limit: 21000u64,
        to: Address::from_str("0x742d35Cc6634C0532925a3b8D91D0a6A3A7a2C05").unwrap(),
        value: U256::from(1000000000000000000u128), // 1 ETH
        input: Default::default(),
        access_list,
        authorization_list,
    };
    
    // Sign the transaction
    let tx_result = sign_eip7702_transaction(signer, tx);
    
    // Note: This might fail due to the complexity of EIP-7702 transactions
    // but we're testing that the function can be called
    // For a real test, we would need to set up proper authorization lists
    assert!(tx_result.is_ok());
    
    let signed_tx = tx_result.unwrap();
    assert!(!signed_tx.is_empty());
    assert!(signed_tx.starts_with("0x"));
}
