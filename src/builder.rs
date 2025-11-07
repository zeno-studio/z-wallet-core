extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::vec;
use alloc::string::ToString;

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

use crate::{CoreError, constants};

pub fn password_kdf_argon2(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; constants::ARGON2_OUTPUT_LEN]>, CoreError> {
    let mut dkey = Zeroizing::new(vec![0u8]);

    let params = argon2::Params::new(
        constants::ARGON2_MEMORY,
        constants::ARGON2_ITERATIONS,
        constants::ARGON2_PARALLELISM,
        Some(constants::ARGON2_OUTPUT_LEN),
    )
    .map_err(|_| CoreError::Argon2BuildError)?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    argon2
        .hash_password_into(password.as_bytes(), salt, dkey.as_mut())
        .map_err(|_| CoreError::PasswordHashError)?;
     let mut dkey_array = [0u8; constants::ARGON2_OUTPUT_LEN];
        dkey_array.copy_from_slice(dkey.as_slice());

    Ok(Zeroizing::new(dkey_array)) // 返回 Zeroizing，自动擦除
}

pub fn encrypt_xchacha(
    phrase: &str,
    dkey: &Zeroizing<[u8; constants::ARGON2_OUTPUT_LEN]>,
    nonce: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let cipher = XChaCha20Poly1305::new_from_slice(dkey.as_slice())
        .map_err(|_| CoreError::InvalidKeyLength)?;

    let nonce_array: [u8; constants::XCHACHA_XNONCE_LEN] =
        nonce.try_into().map_err(|_| CoreError::EmptyNonce)?;

    let xnonce = XNonce::from(nonce_array);

    let ciphertext = cipher
        .encrypt(&xnonce, phrase.as_bytes())
        .map_err(|_| CoreError::EncryptionFailed)?;

    Ok(ciphertext)
}

pub fn decrypt_xchacha(
    ciphertext: &[u8],
    dkey: &Zeroizing<[u8; constants::ARGON2_OUTPUT_LEN]>,
    nonce: &[u8],
) -> Result<String, CoreError> {
    let cipher = XChaCha20Poly1305::new_from_slice(dkey.as_slice())
        .map_err(|_| CoreError::InvalidKeyLength)?;

    let nonce_array: [u8; constants::XCHACHA_XNONCE_LEN] =
        nonce.try_into().map_err(|_| CoreError::EmptyNonce)?;

    let xnonce = XNonce::from(nonce_array);

    let plaintext = cipher
        .decrypt(&xnonce, ciphertext)
        .map_err(|_| CoreError::DecryptionFailed)?;

    Ok(String::from_utf8(plaintext).map_err(|_| CoreError::DecryptionFailed)?)
}

pub fn generate_entropy_bytes(bytes: u64) -> Result<Vec<u8>, CoreError> {
    let mut entropy = vec![0u8; bytes as usize];
    getrandom::fill(&mut entropy).map_err(|_| CoreError::EntropyGenerationFailed)?;
    Ok(entropy)
}

pub fn generate_entropy_bits(bits: u64) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let bytes = (bits / 8) as usize;
    let mut entropy = vec![0u8; bytes];
    getrandom::fill(&mut entropy).map_err(|_| CoreError::EntropyGenerationFailed)?;
    Ok(Zeroizing::new(entropy))
}

pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<Zeroizing<String>, CoreError> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
        .map_err(|_| CoreError::MnemonicGenerationFailed)?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

pub fn mnemonic_to_signer(mnemonic: &str, index: u32) -> Result<PrivateKeySigner, CoreError> {
     MnemonicBuilder::<English>::default()
        .phrase(mnemonic)
        .index(index)
        .map_err(|_| CoreError::SignerBuildError)?
        .build()
        .map_err(|_| CoreError::SignerBuildError)
}