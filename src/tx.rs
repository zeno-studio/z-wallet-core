extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::format;

use alloy_consensus::{Signed, TxEip1559, TxEip7702, TxLegacy};
use alloy_network::TxSignerSync;
use alloy_signer_local::PrivateKeySigner;
use hex::{encode as hex_encode};

use crate::error::CoreError;

/// Sign a legacy transaction
///
/// # Arguments
/// * `signer` - The private key signer
/// * `tx` - The legacy transaction to sign
///
/// # Returns
/// * `Ok(String)` - The signed transaction in hex format
/// * `Err(CoreError)` - If there is an error during signing
pub fn sign_legacy_transaction(
    signer: PrivateKeySigner,
    tx: TxLegacy,
) -> Result<String, CoreError> {
    // Validate the transaction
    if let Some(id) = tx.chain_id && id == 0 {
        return Err(CoreError::InvalidChainId);
    }
    if tx.gas_limit < 21_000 {
        return Err(CoreError::InvalidGasLimit);
    }

    let mut tx = tx;

    let signature = signer
        .sign_transaction_sync(&mut tx)
        .map_err(|_| CoreError::SignTransactionError)?;

    let signed = Signed::new_unhashed(tx, signature);
    let mut buf = Vec::with_capacity(signed.rlp_encoded_length());
    signed.rlp_encode(&mut buf);
    let result = format!("0x{}", hex_encode(buf));

    Ok(result)
}

/// Sign an EIP-1559 transaction
///
/// # Arguments
/// * `signer` - The private key signer
/// * `tx` - The EIP-1559 transaction to sign
///
/// # Returns
/// * `Ok(String)` - The signed transaction in hex format
/// * `Err(CoreError)` - If there is an error during signing
pub fn sign_eip1559_transaction(
    signer: PrivateKeySigner,
    tx: TxEip1559,
) -> Result<String, CoreError> {
    // Validate the transaction
    if tx.chain_id == 0 {
        return Err(CoreError::InvalidChainId);
    }
    if tx.gas_limit < 21_000 {
        return Err(CoreError::InvalidGasLimit);
    }
    
    if tx.max_priority_fee_per_gas > tx.max_fee_per_gas {
        return Err(CoreError::InvalidMaxPriorityFee);
    }

    let mut tx = tx;

    let signature = signer
        .sign_transaction_sync(&mut tx)
        .map_err(|_| CoreError::SignTransactionError)?;

    let signed = Signed::new_unhashed(tx, signature);
    let mut buf = Vec::with_capacity(signed.rlp_encoded_length());
    signed.rlp_encode(&mut buf);
    let result = format!("0x{}", hex_encode(buf));

    Ok(result)
}

/// Sign an EIP-7702 transaction
///
/// # Arguments
/// * `signer` - The private key signer
/// * `tx` - The EIP-7702 transaction to sign
///
/// # Returns
/// * `Ok(String)` - The signed transaction in hex format
/// * `Err(CoreError)` - If there is an error during signing
pub fn sign_eip7702_transaction(
    signer: PrivateKeySigner,
    mut tx: TxEip7702,
) -> Result<String, CoreError> {
    // Validate the transaction
    if tx.chain_id == 0 {
        return Err(CoreError::InvalidChainId);
    }
    if tx.gas_limit < 21_000 {
        return Err(CoreError::InvalidGasLimit);
    }

    if tx.max_priority_fee_per_gas > tx.max_fee_per_gas {
        return Err(CoreError::InvalidMaxPriorityFee);
    }

    let signature = signer
        .sign_transaction_sync(&mut tx)
        .map_err(|_| CoreError::SignTransactionError)?;

    let signed = Signed::new_unhashed(tx, signature);
    let mut buf = Vec::with_capacity(signed.rlp_encoded_length());
    signed.rlp_encode(&mut buf);
    let result = format!("0x{}", hex_encode(buf));

    Ok(result)
}