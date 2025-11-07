extern crate alloc;

use crate::{CoreError};
use crate::constants::{ENTROPY_128, ENTROPY_256, ARGON2_SALT_LEN,XCHACHA_XNONCE_LEN};
use bip39::Mnemonic;
use alloc::vec::Vec;
use core::str::FromStr;

pub fn validate_entropy(bits: u64) -> Result<(), CoreError> {
    match bits {
        ENTROPY_128 | ENTROPY_256 => Ok(()),
        _ => Err(CoreError::InvalidEntropyBits),
    }
}

pub fn validate_salt(salt: [u8; ARGON2_SALT_LEN]) -> Result<(), CoreError> {
    if is_zero(&salt) {
        return Err(CoreError::EmptySalt);
    }
    Ok(())
}

pub fn validate_nonce(nonce: [u8; XCHACHA_XNONCE_LEN]) -> Result<(), CoreError> {
    if is_zero(&nonce) {
        return Err(CoreError::EmptyNonce);
    }
    Ok(())
}

// 通用零值检查（no_std 友好）

pub fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, &b| acc | b) == 0
}

pub fn validate_password(password: &str) -> Result<(), CoreError> {
    if password.is_empty() {
        return Err(CoreError::EmptyPassword);
    }
    Ok(())
}

pub fn validate_ciphertext(ciphertext: Vec<u8>) -> Result<(), CoreError> {
    if is_zero(&ciphertext){
        return Err(CoreError::EmptyCiphertext);
    }
    Ok(())
}

pub fn validate_mnemonic(mnemonic: &str) -> Result<(), CoreError> {
    // 检查助记词是否为空
    if mnemonic.is_empty() {
        return Err(CoreError::MnemonicGenerationFailed);
    }
    
    // 尝试解析助记词，验证是否符合 BIP39 标准
    let parsed_mnemonic = Mnemonic::from_str(mnemonic)
        .map_err(|_| CoreError::MnemonicGenerationFailed)?;
    
    // 验证熵长度是否符合 ENTROPY_128 或 ENTROPY_256
    let entropy = parsed_mnemonic.to_entropy();
    let entropy_bits = entropy.len() * 8;
    
    match entropy_bits as u64 {
        ENTROPY_128 | ENTROPY_256 => Ok(()),
        _ => Err(CoreError::InvalidEntropyBits),
    }
}