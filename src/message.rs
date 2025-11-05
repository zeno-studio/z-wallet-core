use alloy_primitives::{Signature, keccak256};
use alloy_signer::SignerSync;
use hex::{decode as hex_decode, encode as hex_encode};
use alloy_signer_local::PrivateKeySigner;

use crate::EIP712;
use crate::error::WalletError;

pub fn sign_eip191_message(
    signer:PrivateKeySigner,
    message: &str,
) -> Result<String, WalletError> {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let digest = keccak256([prefix.as_bytes(), message.as_bytes()].concat());
    // digest is already B256, use it directly
    let sig = signer
        .sign_hash_sync(&digest)
        .map_err(|_| WalletError::MessageSigningFailed)?;
    Ok(format!("0x{}", hex_encode(sig.as_bytes())))
}

pub fn verify_eip191_message(message: &str, signature_hex: &str) -> Result<String, WalletError> {
    let sig_bytes =
        hex_decode(signature_hex.trim_start_matches("0x")).map_err(|_| WalletError::InvalidHex)?;
    let sig =
        Signature::try_from(sig_bytes.as_slice()).map_err(|_| WalletError::InvalidSignature)?;

    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let digest = keccak256([prefix.as_bytes(), message.as_bytes()].concat());
    // digest is already B256, use it directly
    let recovered = sig
        .recover_from_prehash(&digest)
        .map_err(|_| WalletError::RecoverFailed)?;

    let binding = recovered.to_encoded_point(false);
    let pubkey_bytes = binding.as_bytes();
    let address_bytes = &keccak256(&pubkey_bytes[1..])[12..];
    let address_hex = format!("0x{}", hex_encode(address_bytes));
    Ok(address_hex)
}

pub fn sign_eip712_message(
    signer:PrivateKeySigner,
    json: &str,
) -> Result<String, WalletError> {
    let digest = EIP712::hash_eip712_message(json)?;

    // digest is already B256, use it directly
    let sig = signer
        .sign_hash_sync(&digest)
        .map_err(|_| WalletError::MessageSigningFailed)?;
    Ok(format!("0x{}", hex_encode(sig.as_bytes())))
}

pub fn create_eip712_message(json: &str) -> Result<String, WalletError> {
    let digest = EIP712::hash_eip712_message(json)?;
    // digest is B256, convert to hex string with 0x prefix
    Ok(format!("0x{}", hex_encode(digest)))
}

pub fn verify_eip712_message(json: &str, signature_hex: &str) -> Result<String, WalletError> {
    let sig_bytes =
        hex_decode(signature_hex.trim_start_matches("0x")).map_err(|_| WalletError::InvalidHex)?;
    let sig =
        Signature::try_from(sig_bytes.as_slice()).map_err(|_| WalletError::InvalidSignature)?;

    let digest = EIP712::hash_eip712_message(json)?;

    // digest is already B256, use it directly
    let recovered = sig
        .recover_from_prehash(&digest)
        .map_err(|_| WalletError::RecoverFailed)?;

    let binding = recovered.to_encoded_point(false);
    let pubkey_bytes = binding.as_bytes();
    let address_bytes = &keccak256(&pubkey_bytes[1..])[12..];
    let address_hex = format!("0x{}", hex_encode(address_bytes));
    Ok(address_hex)
}
