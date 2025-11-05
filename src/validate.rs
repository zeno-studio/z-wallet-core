use crate::{WalletError, XCHACHA_SALT_LEN};
use crate::constants::{ENTROPY_128, ENTROPY_256, XCHACHA_XNONCE_LEN};
use bip39::Mnemonic;
use std::str::FromStr;

pub fn validate_entropy(bits: u64) -> Result<(), WalletError> {
    match bits {
        ENTROPY_128 | ENTROPY_256 => Ok(()),
        _ => Err(WalletError::InvalidEntropyBits),
    }
}

pub fn validate_salt(salt: Vec<u8>) -> Result<(), WalletError> {
    if salt.len() != XCHACHA_SALT_LEN {
        return Err(WalletError::EmptySalt);
    }
    Ok(())
}

pub fn validate_nonce(nonce: Vec<u8>) -> Result<(), WalletError> {
    if nonce.len() != XCHACHA_XNONCE_LEN {
        return Err(WalletError::InvalidNonce);
    }
    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), WalletError> {
    if password.is_empty() {
        return Err(WalletError::EmptyPassword);
    }
    Ok(())
}

pub fn validate_ciphertext(ciphertext: Vec<u8>) -> Result<(), WalletError> {
    if ciphertext.is_empty() {
        return Err(WalletError::EmptyCiphertext);
    }
    Ok(())
}

pub fn validate_mnemonic(mnemonic: &str) -> Result<(), WalletError> {
    // 检查助记词是否为空
    if mnemonic.is_empty() {
        return Err(WalletError::MnemonicGenerationFailed);
    }
    
    // 尝试解析助记词，验证是否符合 BIP39 标准
    let parsed_mnemonic = Mnemonic::from_str(mnemonic)
        .map_err(|_| WalletError::MnemonicGenerationFailed)?;
    
    // 验证熵长度是否符合 ENTROPY_128 或 ENTROPY_256
    let entropy = parsed_mnemonic.to_entropy();
    let entropy_bits = entropy.len() * 8;
    
    match entropy_bits as u64 {
        ENTROPY_128 | ENTROPY_256 => Ok(()),
        _ => Err(WalletError::InvalidEntropyBits),
    }
}