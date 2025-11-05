use alloy_signer_local::{
    MnemonicBuilder, PrivateKeySigner, coins_bip39::English,
};
use argon2::Argon2;
use bip39::{Language, Mnemonic};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use zeroize::Zeroizing;

use crate::{WalletError, constants};

type SensitiveBytes = Zeroizing<[u8; 32]>;

pub fn password_kdf_argon2(password: &str, salt: &[u8]) -> Result<SensitiveBytes, WalletError> {
    let mut dkey = Zeroizing::new([0u8; constants::ARGON2_OUTPUT_LEN]);

    let params = argon2::Params::new(
        constants::ARGON2_MEMORY,
        constants::ARGON2_ITERATIONS,
        constants::ARGON2_PARALLELISM,
        Some(constants::ARGON2_OUTPUT_LEN),
    )
    .map_err(|_| WalletError::Argon2BuildError)?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    argon2
        .hash_password_into(password.as_bytes(), salt, dkey.as_mut())
        .map_err(|_| WalletError::PasswordHashError)?;
    Ok(dkey) // 返回 Zeroizing，自动擦除
}

pub fn encrypt_xchacha(
    phrase: &str,
    dkey: &SensitiveBytes,
    nonce: &[u8],
) -> Result<Vec<u8>, WalletError> {
    let cipher = XChaCha20Poly1305::new_from_slice(dkey.as_slice())
        .map_err(|_| WalletError::InvalidKeyLength)?;

    let nonce_array: [u8; constants::XCHACHA_XNONCE_LEN] =
        nonce.try_into().map_err(|_| WalletError::InvalidNonce)?;

    let xnonce = XNonce::from(nonce_array);

    let ciphertext = cipher
        .encrypt(&xnonce, phrase.as_bytes())
        .map_err(|_| WalletError::EncryptionFailed)?;

    Ok(ciphertext)
}


pub fn decrypt_xchacha(
    ciphertext: &[u8],
    dkey: &SensitiveBytes,
    nonce: &[u8],
) -> Result<String, WalletError> {
    let cipher = XChaCha20Poly1305::new_from_slice(dkey.as_slice())
        .map_err(|_| WalletError::InvalidKeyLength)?;

    let nonce_array: [u8; constants::XCHACHA_XNONCE_LEN] =
        nonce.try_into().map_err(|_| WalletError::InvalidNonce)?;

    let xnonce = XNonce::from(nonce_array);

    let plaintext = cipher
        .decrypt(&xnonce, ciphertext)
        .map_err(|_| WalletError::DecryptionFailed)?;

    Ok(String::from_utf8(plaintext).map_err(|_| WalletError::DecryptionFailed)?)
}

pub fn generate_entropy(bits: u64) -> Result<Zeroizing<Vec<u8>>, WalletError> {
    let bytes = (bits / 8) as usize;
    let mut entropy = vec![0u8; bytes];
    getrandom::fill(&mut entropy).map_err(|_| WalletError::EntropyGenerationFailed)?;
    Ok(Zeroizing::new(entropy))
}


pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<Zeroizing<String>, WalletError> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
        .map_err(|_| WalletError::MnemonicGenerationFailed)?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

pub fn mnemonic_to_signer(mnemonic: &str, index: u32) -> Result<PrivateKeySigner, WalletError> {
     MnemonicBuilder::<English>::default()
        .phrase(mnemonic)
        .index(index)
        .map_err(|_| WalletError::SignerBuildError)?
        .build()
        .map_err(|_| WalletError::SignerBuildError)
}

