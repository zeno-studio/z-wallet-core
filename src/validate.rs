extern crate alloc;

use crate::{CoreError};
use crate::constants::{VERSION_TAG_1, ENTROPY_128, ENTROPY_256, ARGON2_SALT_LEN,XCHACHA_XNONCE_LEN};
use bip39::Mnemonic;
use core::str::FromStr;
use alloc::string::{ToString};

/// Validate entropy bits
///
/// # Arguments
/// * `bits` - The entropy bits to validate
///
/// # Returns
/// * `Ok(())` - If the entropy bits are valid (128 or 256)
/// * `Err(CoreError)` - If the entropy bits are invalid
pub fn validate_entropy(bits: u64) -> Result<(), CoreError> {
    match bits {
        ENTROPY_128 | ENTROPY_256 => Ok(()),
        _ => Err(CoreError::InvalidEntropyBits),
    }
}

/// Validate salt
///
/// # Arguments
/// * `salt` - The salt to validate (must be ARGON2_SALT_LEN bytes)
///
/// # Returns
/// * `Ok(())` - If the salt is valid
/// * `Err(CoreError)` - If the salt is invalid or wrong length
pub fn validate_salt(salt: &[u8]) -> Result<(), CoreError> {
    if salt.len() != ARGON2_SALT_LEN {
        return Err(CoreError::EmptySalt);
    }
    if is_zero(salt) {
        return Err(CoreError::EmptySalt);
    }
    Ok(())
}

/// Validate nonce
///
/// # Arguments
/// * `nonce` - The nonce to validate (must be XCHACHA_XNONCE_LEN bytes)
///
/// # Returns
/// * `Ok(())` - If the nonce is valid
/// * `Err(CoreError)` - If the nonce is invalid or wrong length
pub fn validate_nonce(nonce: &[u8]) -> Result<(), CoreError> {
    if nonce.len() != XCHACHA_XNONCE_LEN {
        return Err(CoreError::EmptyNonce);
    }
    if is_zero(nonce) {
        return Err(CoreError::EmptyNonce);
    }
    Ok(())
}

/// Check if bytes are all zero (no_std friendly)
///
/// # Arguments
/// * `bytes` - The bytes to check
///
/// # Returns
/// * `true` - If all bytes are zero
/// * `false` - If any byte is non-zero
pub fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, &b| acc | b) == 0
}

/// Validate password
///
/// # Arguments
/// * `password` - The password to validate
///
/// # Returns
/// * `Ok(())` - If the password is not empty
/// * `Err(CoreError)` - If the password is empty
pub fn validate_password(password: &str) -> Result<(), CoreError> {
    if password.is_empty() {
        return Err(CoreError::EmptyPassword);
    }
    Ok(())
}

/// Validate mnemonic
///
/// # Arguments
/// * `mnemonic` - The mnemonic to validate
///
/// # Returns
/// * `Ok(())` - If the mnemonic is valid
/// * `Err(CoreError)` - If the mnemonic is invalid
pub fn validate_mnemonic(mnemonic: &str) -> Result<(), CoreError> {
    // Check if mnemonic is empty
    if mnemonic.is_empty() {
        return Err(CoreError::MnemonicGenerationFailed);
    }
    
    // Try to parse mnemonic, verify it conforms to BIP39 standard
    let parsed_mnemonic = Mnemonic::from_str(mnemonic)
        .map_err(|_| CoreError::MnemonicGenerationFailed)?;
    
    // Verify entropy length conforms to ENTROPY_128 or ENTROPY_256
    let entropy = parsed_mnemonic.to_entropy();
    let entropy_bits = entropy.len() * 8;
    
    match entropy_bits as u64 {
        ENTROPY_128 | ENTROPY_256 => Ok(()),
        _ => Err(CoreError::InvalidEntropyBits),
    }
}


pub fn validate_version(version: &[u8]) -> Result<(), CoreError>  {
    let const_version: [u8; 7] = VERSION_TAG_1.as_bytes().try_into().map_err(|_| CoreError::VaultInvalidVersion { version: VERSION_TAG_1.to_string() })?;
    if version.len() != 7 || version != const_version {
        let version_str = alloc::string::String::from_utf8_lossy(version).to_string();
        return Err(CoreError::VaultInvalidVersion { version: version_str });
    }  
    Ok(())
}