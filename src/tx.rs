use alloy_consensus::{Signed, TxEip1559, TxEip7702, TxLegacy};
use alloy_eips::eip2930::AccessList;
use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_network::TxSignerSync;
use alloy_primitives::{Address,TxKind, U256};
use alloy_signer::SignerSync;
use core::str::FromStr;     
use alloy_signer_local::PrivateKeySigner;
use hex::{decode as hex_decode, encode as hex_encode};

use crate::error::WalletError;


pub fn sign_legacy_transaction(
        signer:PrivateKeySigner,
        nonce: u64,
        gas_price_wei: &str,
        gas_limit: u64,
        to: Option<String>,
        value_wei: &str,
        data_hex: Option<String>,
        chain_id: Option<u64>,
    ) -> Result<String, WalletError> {
        if let Some(id) = chain_id
            && id == 0
        {
            return Err(WalletError::InvalidChainId);
        }
        if gas_limit < 21_000 {
            return Err(WalletError::InvalidGasLimit);
        }
        // parse as U256 and convert to u128
        let gas_price = match U256::from_str(gas_price_wei) {
            Ok(g) => match g.try_into() {
                Ok(val) => val,
                Err(_) => return Err(WalletError::InvalidGasPrice),
            },
            Err(_) => return Err(WalletError::InvalidGasPrice),
        };

        let to_txkind: TxKind = match to.as_ref() {
            Some(s) if !s.is_empty() => match Address::from_str(s) {
                Ok(a) => TxKind::Call(a),
                Err(_) => return Err(WalletError::InvalidAddress),
            },
            _ => TxKind::Create,
        };

        let value = match U256::from_str(value_wei) {
            Ok(v) => v,
            Err(_) => return Err(WalletError::InvalidValue),
        };

        let input_bytes = match parse_bytes_opt(data_hex) {
            Ok(b) => b,
            Err(_) => return Err(WalletError::InvalidTxData),
        };

        let mut tx = TxLegacy {
            to: to_txkind,
            value,
            gas_limit,
            nonce,
            gas_price,
            input: input_bytes,
            chain_id,
        };

        let signature = signer
            .sign_transaction_sync(&mut tx)
            .map_err(|_| WalletError::SignTransactionError)?;

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
        to: Option<String>,
        value_wei: &str,
        data_hex: Option<String>,
        chain_id: u64,
        access_list_json: Option<String>,
    ) -> Result<String, WalletError> {
        if chain_id == 0 {
            return Err(WalletError::InvalidChainId);
        }
        if gas_limit < 21_000 {
            return Err(WalletError::InvalidGasLimit);
        }
       let max_priority_fee_per_gas = match U256::from_str(max_priority_fee_per_gas_wei) {
            Ok(v) => match v.try_into() {
                Ok(val) => val,
                Err(_) => return Err(WalletError::InvalidMaxPriorityFee),
            },
            Err(_) => return Err(WalletError::InvalidMaxPriorityFee),
        };

        let max_fee_per_gas = match U256::from_str(max_fee_per_gas_wei) {
            Ok(v) => match v.try_into() {
                Ok(val) => val,
                Err(_) => return Err(WalletError::InvalidMaxFee),
            },
            Err(_) => return Err(WalletError::InvalidMaxFee),
        };

        if max_priority_fee_per_gas > max_fee_per_gas {
            return Err(WalletError::InvalidMaxPriorityFee);
        }

        let to_txkind: TxKind = match to.as_ref() {
            Some(s) if !s.is_empty() => match Address::from_str(s) {
                Ok(a) => TxKind::Call(a),
                Err(_) => return Err(WalletError::InvalidAddress),
            },
            _ => TxKind::Create,
        };

        let value = match U256::from_str(value_wei) {
            Ok(v) => v,
            Err(_) => return Err(WalletError::InvalidValue),
        };

        let input_bytes = match parse_bytes_opt(data_hex) {
            Ok(b) => b,
            Err(_) => return Err(WalletError::InvalidTxData),
        };

        let access_list: AccessList = match access_list_json {
            None => AccessList::default(),
            Some(ref s) if s.is_empty() => AccessList::default(),
            Some(ref s) => serde_json::from_str(s).map_err(|_| WalletError::InvalidAccessList)?,
        };

        let mut tx = TxEip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: to_txkind,
            value,
            input: input_bytes,
            access_list,
        };

        let signature = signer
            .sign_transaction_sync(&mut tx)
            .map_err(|_| WalletError::SignTransactionError)?;

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
        to: Option<String>,
        value_wei: &str,
        data_hex: Option<String>,
        chain_id: u64,
        access_list_json: Option<String>,
        authorization_list_json: String,
    ) -> Result<String, WalletError> {
        if chain_id == 0 {
            return Err(WalletError::InvalidChainId);
        }
        if gas_limit < 21_000 {
            return Err(WalletError::InvalidGasLimit);
        }

        let to_addr: Address = match to.as_ref() {
            Some(s) if !s.is_empty() => match Address::from_str(s) {
                Ok(a) => a,
                Err(_) => return Err(WalletError::InvalidAddress),
            },
            _ => Address::default(),
        };

        let max_priority_fee_per_gas = match U256::from_str(max_priority_fee_per_gas_wei) {
            Ok(v) => match v.try_into() {
                Ok(val) => val,
                Err(_) => return Err(WalletError::InvalidMaxPriorityFee),
            },
            Err(_) => return Err(WalletError::InvalidMaxPriorityFee),
        };

        let max_fee_per_gas = match U256::from_str(max_fee_per_gas_wei) {
            Ok(v) => match v.try_into() {
                Ok(val) => val,
                Err(_) => return Err(WalletError::InvalidMaxFee),
            },
            Err(_) => return Err(WalletError::InvalidMaxFee),
        };

        if max_priority_fee_per_gas > max_fee_per_gas {
            return Err(WalletError::InvalidMaxPriorityFee);
        }

        let value = match U256::from_str(value_wei) {
            Ok(v) => v,
            Err(_) => return Err(WalletError::InvalidValue),
        };

        let input_bytes = match parse_bytes_opt(data_hex) {
            Ok(b) => b,
            Err(_) => return Err(WalletError::InvalidTxData),
        };

        let access_list: AccessList = match access_list_json {
            None => AccessList::default(),
            Some(ref s) if s.is_empty() => AccessList::default(),
            Some(ref s) => serde_json::from_str(s).map_err(|_| WalletError::InvalidAccessList)?,
        };

        // parse authorizations array
        if authorization_list_json.trim().is_empty() {
            return Err(WalletError::InvalidAuthorizationList);
        }

        let authorizations: Vec<Authorization> = serde_json::from_str(&authorization_list_json)
            .map_err(|_| WalletError::InvalidAuthorizationList)?;
        if authorizations.is_empty() {
            return Err(WalletError::EmptyAuthorizationList);
        }

        let mut authorization_list: Vec<SignedAuthorization> =
            Vec::with_capacity(authorizations.len());
        for auth in authorizations {
            let digest = auth.signature_hash();
            // digest is already B256, use it directly
            let sig = signer
                .sign_hash_sync(&digest)
                .map_err(|_| WalletError::CreateSignatureFailed)?;
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
            input: input_bytes,
            access_list,
            authorization_list,
        };

        let signature = signer
            .sign_transaction_sync(&mut tx)
            .map_err(|_| WalletError::SignTransactionError)?;

        let signed = Signed::new_unhashed(tx, signature);
        let mut buf = Vec::with_capacity(signed.rlp_encoded_length());
        signed.rlp_encode(&mut buf);
        let result = format!("0x{}", hex_encode(buf));

        Ok(result)
    }

    pub(crate) fn parse_bytes_opt(hex_opt: Option<String>) -> Result<alloy_primitives::Bytes, ()> {
    match hex_opt {
        None => Ok(alloy_primitives::Bytes::default()),
        Some(ref h) if h.is_empty() => Ok(alloy_primitives::Bytes::default()),
        Some(h) => {
            let s = h.strip_prefix("0x").unwrap_or(&h);
            match hex_decode(s) {
                Ok(b) => Ok(alloy_primitives::Bytes::from(b)),
                Err(_) => Err(()),
            }
        }
    }
}
