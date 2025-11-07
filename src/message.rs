extern crate alloc;
use alloc::string::String;
use alloc::format;

use alloy_primitives::{Signature, keccak256, B256};
use alloy_signer::SignerSync;
use hex::{decode as hex_decode, encode as hex_encode};
use alloy_signer_local::PrivateKeySigner;

use crate::error::CoreError;

pub fn sign_eip191_message(
    signer: PrivateKeySigner,
    message: &str,
) -> Result<String, CoreError> {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let digest = keccak256([prefix.as_bytes(), message.as_bytes()].concat());
    // digest is already B256, use it directly
    let sig = signer
        .sign_hash_sync(&digest)
        .map_err(|_| CoreError::MessageSigningFailed)?;
    Ok(format!("0x{}", hex_encode(sig.as_bytes())))
}

pub fn verify_eip191_message(message: &str, signature_hex: &str) -> Result<String, CoreError> {
    let sig_bytes =
        hex_decode(signature_hex.trim_start_matches("0x")).map_err(|_| CoreError::InvalidHex)?;
    let sig =
        Signature::try_from(sig_bytes.as_slice()).map_err(|_| CoreError::InvalidSignature)?;

    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let digest = keccak256([prefix.as_bytes(), message.as_bytes()].concat());
    // digest is already B256, use it directly
    let recovered = sig
        .recover_from_prehash(&digest)
        .map_err(|_| CoreError::RecoverFailed)?;

    let binding = recovered.to_encoded_point(false);
    let pubkey_bytes = binding.as_bytes();
    let address_bytes = &keccak256(&pubkey_bytes[1..])[12..];
    let address_hex = format!("0x{}", hex_encode(address_bytes));
    Ok(address_hex)
}

// 使用外部 EIP-712 crate 进行签名和验证
pub fn sign_eip712_message(
    signer: PrivateKeySigner,
    hash: &B256,
) -> Result<String, CoreError> {  
    let sig = signer
        .sign_hash_sync(hash)
        .map_err(|_| CoreError::MessageSigningFailed)?;
    Ok(format!("0x{}", hex_encode(sig.as_bytes())))
}

// 移除了 create_eip712_message 函数，因为我们不再需要创建 EIP-712 消息

pub fn verify_eip712_message(hash: &B256, signature_hex: &str) -> Result<String, CoreError> {
    let sig_bytes =
        hex_decode(signature_hex.trim_start_matches("0x")).map_err(|_| CoreError::InvalidHex)?;
    let sig =
        Signature::try_from(sig_bytes.as_slice()).map_err(|_| CoreError::InvalidSignature)?;

    let recovered = sig
        .recover_from_prehash(hash)
        .map_err(|_| CoreError::RecoverFailed)?;

    let binding = recovered.to_encoded_point(false);
    let pubkey_bytes = binding.as_bytes();
    let address_bytes = &keccak256(&pubkey_bytes[1..])[12..];
    let address_hex = format!("0x{}", hex_encode(address_bytes));
    Ok(address_hex)
}