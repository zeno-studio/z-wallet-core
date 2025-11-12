extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::format;

use alloy_consensus::{Signed, TxEip1559, TxEip7702, TxLegacy};
use alloy_eips::eip2930::AccessList;
use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, TxKind, U256};
use alloy_signer::SignerSync;
use core::str::FromStr;     
use alloy_signer_local::PrivateKeySigner;
use hex::{decode as hex_decode, encode as hex_encode};
use serde_json_core;

use crate::error::CoreError;


/// Sign a legacy transaction
///
/// # Arguments
/// * `signer` - The private key signer
/// * `nonce` - The transaction nonce
/// * `gas_price_wei` - The gas price in wei
/// * `gas_limit` - The gas limit
/// * `to` - The recipient address (optional)
/// * `value_wei` - The value to transfer in wei
/// * `data_hex` - The transaction data in hex format (optional)
/// * `chain_id` - The chain ID (optional)
///
/// # Returns
/// * `Ok(String)` - The signed transaction in hex format
/// * `Err(CoreError)` - If there is an error during signing
pub fn sign_legacy_transaction(
        signer:PrivateKeySigner,
        nonce: u64,
        gas_price_wei: u128,
        gas_limit: u64,
        to: Option< &str>,
        value_wei: U256,
        data_hex: Option< &str>,
        chain_id: Option<u64>,
    ) -> Result<String, CoreError> {
        if let Some(id) = chain_id
            && id == 0
        {
            return Err(CoreError::InvalidChainId);
        }
        if gas_limit < 21_000 {
            return Err(CoreError::InvalidGasLimit);
        }
       
        let to_txkind: TxKind = match to.as_ref() {
            Some(s) if !s.is_empty() => match Address::from_str(s) {
                Ok(a) => TxKind::Call(a),
                Err(_) => {
                    return Err(CoreError::InvalidAddress);
                }
            },
            _ => TxKind::Create,
        };

        let input_bytes = match parse_bytes_opt(data_hex) {
            Ok(b) => b,
            Err(_) => {
                return Err(CoreError::InvalidTxData);
            }
        };

        let mut tx = TxLegacy {
            to: to_txkind,
            value: value_wei,
            gas_limit,
            nonce,
            gas_price: gas_price_wei,
            input: input_bytes.into(),
            chain_id,
        };

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
    /// * `nonce` - The transaction nonce
    /// * `max_priority_fee_per_gas_wei` - The max priority fee per gas in wei
    /// * `max_fee_per_gas_wei` - The max fee per gas in wei
    /// * `gas_limit` - The gas limit
    /// * `to` - The recipient address (optional)
    /// * `value_wei` - The value to transfer in wei
    /// * `data_hex` - The transaction data in hex format (optional)
    /// * `chain_id` - The chain ID
    /// * `access_list_json` - The access list in JSON format (optional)
    ///
    /// # Returns
    /// * `Ok(String)` - The signed transaction in hex format
    /// * `Err(CoreError)` - If there is an error during signing
    pub fn sign_eip1559_transaction(
        signer:PrivateKeySigner,
        nonce: u64,
        max_priority_fee_per_gas_wei: u128,
        max_fee_per_gas_wei: u128,
        gas_limit: u64,
        to: Option< &str>,
        value_wei: U256,
        data_hex: Option< &str>,
        chain_id: u64,
        access_list_json: Option<&str>,
    ) -> Result<String, CoreError> {
        if chain_id == 0 {
            return Err(CoreError::InvalidChainId);
        }
        if gas_limit < 21_000 {
            return Err(CoreError::InvalidGasLimit);
        }
      
        if max_priority_fee_per_gas_wei > max_fee_per_gas_wei {
            return Err(CoreError::InvalidMaxPriorityFee);
        }

        let to_txkind: TxKind = match to.as_ref() {
            Some(s) if !s.is_empty() => match Address::from_str(s) {
                Ok(a) => TxKind::Call(a),
                Err(_) => {
                    return Err(CoreError::InvalidAddress);
                }
            },
            _ => TxKind::Create,
        };


        let input_bytes = match parse_bytes_opt(data_hex) {
            Ok(b) => b,
            Err(_) => {
                return Err(CoreError::InvalidTxData);
            }
        };

        let access_list: AccessList = match access_list_json {
            None => AccessList::default(),
            Some("") => AccessList::default(),
            Some(s) => serde_json_core::from_str(s).map_err(|_| CoreError::InvalidAccessList)?.0,
        };

        let mut tx = TxEip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas: max_priority_fee_per_gas_wei,
            max_fee_per_gas: max_fee_per_gas_wei,
            gas_limit,
            to: to_txkind,
            value: value_wei,
            input: input_bytes.into(),  // 修复类型错误
            access_list,
        };

        let signature = signer
            .sign_transaction_sync(&mut tx)  // 修复方法调用
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
    /// * `nonce` - The transaction nonce
    /// * `max_priority_fee_per_gas_wei` - The max priority fee per gas in wei
    /// * `max_fee_per_gas_wei` - The max fee per gas in wei
    /// * `gas_limit` - The gas limit
    /// * `to` - The recipient address (optional)
    /// * `value_wei` - The value to transfer in wei
    /// * `data_hex` - The transaction data in hex format (optional)
    /// * `chain_id` - The chain ID
    /// * `access_list_json` - The access list in JSON format (optional)
    /// * `authorization_list_json` - The authorization list in JSON format
    ///
    /// # Returns
    /// * `Ok(String)` - The signed transaction in hex format
    /// * `Err(CoreError)` - If there is an error during signing
    pub fn sign_eip7702_transaction(
        signer:PrivateKeySigner,
        nonce: u64,
        max_priority_fee_per_gas_wei: u128,
        max_fee_per_gas_wei: u128,
        gas_limit: u64,
        to: Option<&str>,
        value_wei: U256,
        data_hex: Option< &str>,
        chain_id: u64,
        access_list_json: Option< &str>,
        authorization_list_json:  &str,
    ) -> Result<String, CoreError> {
        if chain_id == 0 {
            return Err(CoreError::InvalidChainId);
        }
        if gas_limit < 21_000 {
            return Err(CoreError::InvalidGasLimit);
        }

        let to_addr: Address = match to.as_ref() {
            Some(s) if !s.is_empty() => match Address::from_str(s) {
                Ok(a) => a,
                Err(_) => {
                    return Err(CoreError::InvalidAddress);
                }
            },
            _ => Address::default(),
        };

        if max_priority_fee_per_gas_wei > max_fee_per_gas_wei {
            return Err(CoreError::InvalidMaxPriorityFee);
        }

        let input_bytes = match parse_bytes_opt(data_hex) {
            Ok(b) => b,
            Err(_) => {
                return Err(CoreError::InvalidTxData);
            }
        };

        let access_list: AccessList = match access_list_json {
            None => AccessList::default(),
            Some("") => AccessList::default(),
            Some(s) => serde_json_core::from_str(s).map_err(|_| CoreError::InvalidAccessList)?.0,
        };

         if authorization_list_json.trim().is_empty() {
            return Err(CoreError::InvalidAuthorizationList);
        }

        let authorizations: Vec<Authorization> = serde_json_core::from_str(authorization_list_json)
            .map_err(|_| CoreError::InvalidAuthorizationList)?.0;

        let mut authorization_list: Vec<SignedAuthorization> =
            Vec::with_capacity(authorizations.len());
        for auth in authorizations {
            // EIP-7702: signature_hash = keccak(0x04 || rlp([chain_id, address, nonce]))
            let digest = auth.signature_hash();
            // digest is already B256, use it directly
            let sig = signer
                .sign_hash_sync(&digest)
                .map_err(|_| CoreError::CreateSignatureFailed)?;
            authorization_list.push(auth.into_signed(sig));
        }

        let mut tx = TxEip7702 {
            chain_id,
            nonce,
            max_priority_fee_per_gas: max_priority_fee_per_gas_wei,
            max_fee_per_gas: max_fee_per_gas_wei,
            gas_limit,
            to: to_addr,
            value: value_wei,
            input: input_bytes.into(),
            access_list,
            authorization_list
        };

        // rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, value, data, access_list, authorization_list, signature_y_parity, signature_r, signature_s])
        // authorization_list = [[chain_id, address, nonce, y_parity, r, s], ...]

        let signature = signer
            .sign_transaction_sync(&mut tx)
            .map_err(|_| CoreError::SignTransactionError)?;

        let signed = Signed::new_unhashed(tx, signature);
        let mut buf = Vec::with_capacity(signed.rlp_encoded_length());
        signed.rlp_encode(&mut buf);
        let result = format!("0x{}", hex_encode(buf));

        Ok(result)
    }


/// Parse optional hex string to bytes
///
/// # Arguments
/// * `hex` - The optional hex string to parse
///
/// # Returns
/// * `Ok(Vec<u8>)` - The parsed bytes, or empty vector if input is None or empty
/// * `Err(CoreError)` - If hex decoding fails
fn parse_bytes_opt(hex: Option< &str>) -> Result<Vec<u8>, CoreError> {
    match hex {
        None => Ok(Vec::new()),
        Some("") => Ok(Vec::new()),
        Some(s) => {
            hex_decode(s.trim_start_matches("0x"))
                .map_err(|_| CoreError::InvalidHex)
        }
    }
}