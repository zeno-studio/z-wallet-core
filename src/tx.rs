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
use serde_json;

use crate::error::CoreError;


pub fn sign_legacy_transaction(
        signer:PrivateKeySigner,
        nonce: u64,
        gas_price_wei: &str,
        gas_limit: u64,
        to: Option< &str>,
        value_wei: &str,
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
        // parse as U256 and convert to u128
        let gas_price = match U256::from_str(gas_price_wei) {
            Ok(g) => match g.try_into() {
                Ok(val) => val,
                Err(_) => {
                    return Err(CoreError::InvalidGasPrice);
                }
            },
            Err(_) => {
                return Err(CoreError::InvalidGasPrice);
            }
        };

        let to_txkind: TxKind = match to.as_ref() {
            Some(s) if !s.is_empty() => match Address::from_str(s) {
                Ok(a) => TxKind::Call(a),
                Err(_) => {
                    return Err(CoreError::InvalidAddress);
                }
            },
            _ => TxKind::Create,
        };

        let value = match U256::from_str(value_wei) {
            Ok(v) => v,
            Err(_) => {
                return Err(CoreError::InvalidValue);
            }
        };

        let input_bytes = match parse_bytes_opt(data_hex) {
            Ok(b) => b,
            Err(_) => {
                return Err(CoreError::InvalidTxData);
            }
        };

        let mut tx = TxLegacy {
            to: to_txkind,
            value,
            gas_limit,
            nonce,
            gas_price,
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

    pub fn sign_eip1559_transaction(
        signer:PrivateKeySigner,
        nonce: u64,
        max_priority_fee_per_gas_wei: &str,
        max_fee_per_gas_wei: &str,
        gas_limit: u64,
        to: Option< &str>,
        value_wei: &str,
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
       let max_priority_fee_per_gas = match U256::from_str(max_priority_fee_per_gas_wei) {
            Ok(v) => match v.try_into() {
                Ok(val) => val,
                Err(_) => {
                    return Err(CoreError::InvalidMaxPriorityFee);
                }
            },
            Err(_) => {
                return Err(CoreError::InvalidMaxPriorityFee);
            }
        };

        let max_fee_per_gas = match U256::from_str(max_fee_per_gas_wei) {
            Ok(v) => match v.try_into() {
                Ok(val) => val,
                Err(_) => {
                    return Err(CoreError::InvalidMaxFee);
                }
            },
            Err(_) => {
                return Err(CoreError::InvalidMaxFee);
            }
        };

        if max_priority_fee_per_gas > max_fee_per_gas {
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

        let value = match U256::from_str(value_wei) {
            Ok(v) => v,
            Err(_) => {
                return Err(CoreError::InvalidValue);
            }
        };

        let input_bytes = match parse_bytes_opt(data_hex) {
            Ok(b) => b,
            Err(_) => {
                return Err(CoreError::InvalidTxData);
            }
        };

        let access_list: AccessList = match access_list_json {
            None => AccessList::default(),
            Some(ref s) if s.is_empty() => AccessList::default(),
            Some(ref s) => serde_json::from_str(s).map_err(|_| CoreError::InvalidAccessList)?,
        };

        let mut tx = TxEip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: to_txkind,
            value,
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

    pub fn sign_eip7702_transaction(
        signer:PrivateKeySigner,
        nonce: u64,
        max_priority_fee_per_gas_wei: &str,
        max_fee_per_gas_wei: &str,
        gas_limit: u64,
        to: Option<&str>,
        value_wei: &str,
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

        let max_priority_fee_per_gas = match U256::from_str(max_priority_fee_per_gas_wei) {
            Ok(v) => match v.try_into() {
                Ok(val) => val,
                Err(_) => {
                    return Err(CoreError::InvalidMaxPriorityFee);
                }
            },
            Err(_) => {
                return Err(CoreError::InvalidMaxPriorityFee);
            }
        };

        let max_fee_per_gas = match U256::from_str(max_fee_per_gas_wei) {
            Ok(v) => match v.try_into() {
                Ok(val) => val,
                Err(_) => {
                    return Err(CoreError::InvalidMaxFee);
                }
            },
            Err(_) => {
                return Err(CoreError::InvalidMaxFee);
            }
        };

        if max_priority_fee_per_gas > max_fee_per_gas {
            return Err(CoreError::InvalidMaxPriorityFee);
        }

        let value = match U256::from_str(value_wei) {
            Ok(v) => v,
            Err(_) => {
                return Err(CoreError::InvalidValue);
            }
        };

        let input_bytes = match parse_bytes_opt(data_hex) {
            Ok(b) => b,
            Err(_) => {
                return Err(CoreError::InvalidTxData);
            }
        };

        let access_list: AccessList = match access_list_json {
            None => AccessList::default(),
            Some(ref s) if s.is_empty() => AccessList::default(),
            Some(ref s) => serde_json::from_str(s).map_err(|_| CoreError::InvalidAccessList)?,
        };

         if authorization_list_json.trim().is_empty() {
            return Err(CoreError::InvalidAuthorizationList);
        }

        let authorizations: Vec<Authorization> = serde_json::from_str(&authorization_list_json)
            .map_err(|_| CoreError::InvalidAuthorizationList)?;
       

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
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: to_addr,
            value,
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


// 添加缺失的辅助函数
fn parse_bytes_opt(data_hex: Option< &str>) -> Result<Vec<u8>, CoreError> {
    match data_hex {
        None => Ok(Vec::new()),
        Some(s) if s.is_empty() => Ok(Vec::new()),
        Some(s) => {
            hex_decode(s.trim_start_matches("0x"))
                .map_err(|_| CoreError::InvalidTxData)
        }
    }
}