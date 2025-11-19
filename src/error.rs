use core::fmt;

/// CoreError carries a numeric code and a human-readable message.
/// Internally we use strong typed variants; externally you can use `code()` and `message()`.
#[derive(Debug)]
pub enum CoreError {
    // General errors
    /// The provided password is invalid
    InvalidPassword,
    /// The provided password is empty
    EmptyPassword,
    /// The derived key is invalid
    InvalidDerivedKey,
    /// The derived key is empty
    EmptyDerivedKey,
    /// The nonce is empty
    EmptyNonce,
    /// The salt is empty
    EmptySalt,
    /// The cache time is empty
    EmptyCacheTime,
    /// The key length is invalid
    InvalidKeyLength,
    /// Decryption failed
    DecryptionFailed,
    /// Encryption failed
    EncryptionFailed,
    /// Entropy generation failed
    EntropyGenerationFailed,
    /// The ciphertext is empty
    EmptyCiphertext,
    /// The entropy bits are invalid
    InvalidEntropyBits,
    /// Mnemonic generation failed
    MnemonicGenerationFailed,
    /// Signer build error
    SignerBuildError,
    /// Argon2 build error
    Argon2BuildError,
    /// Password hash error
    PasswordHashError,
    /// Vault parsing error
    VaultParseError,
    /// Vault has an invalid version
    VaultInvalidVersion{version: alloc::string::String},
    /// Base58 decoding error
    Bs58DecodeError,
    /// The vault is invalid
    InvalidVault,
    /// Signing transaction error
    SignTransactionError,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::InvalidPassword => write!(f, "Core Error: Invalid password"),
            CoreError::EmptyPassword => write!(f, "Core Error: Empty password"),
            CoreError::InvalidDerivedKey => write!(f, "Core Error: Invalid derived key"),
            CoreError::EmptyDerivedKey => write!(f, "Core Error: Empty derived key"),
            CoreError::EmptyNonce => write!(f, "Core Error: Empty nonce"),
            CoreError::EmptySalt => write!(f, "Core Error: Empty salt"),
            CoreError::EmptyCacheTime => write!(f, "Core Error: Empty cache time"),
            CoreError::InvalidKeyLength => write!(f, "Core Error: Invalid key length"),
            CoreError::DecryptionFailed => write!(f, "Core Error: Decryption failed"),
            CoreError::EncryptionFailed => write!(f, "Core Error: Encryption failed"),
            CoreError::EntropyGenerationFailed => write!(f, "Core Error: Entropy generation failed"),
            CoreError::EmptyCiphertext => write!(f, "Core Error: Empty ciphertext"),
            CoreError::InvalidEntropyBits => write!(f, "Core Error: Invalid entropy bits"),
            CoreError::MnemonicGenerationFailed => write!(f, "Core Error: Mnemonic generation failed"),
            CoreError::SignerBuildError => write!(f, "Core Error: Signer build error"),
            CoreError::Argon2BuildError => write!(f, "Core Error: Argon2 build error"),
            CoreError::PasswordHashError => write!(f, "Core Error: Password hash error"),
            CoreError::VaultInvalidVersion{version} => write!(f, "Core Error: Vault invalid version: {}", version),          
            CoreError::VaultParseError => write!(f, "Core Error: Vault parse error"),
            CoreError::Bs58DecodeError => write!(f, "Core Error: BS58 decode error"),
            CoreError::InvalidVault => write!(f, "Core Error: Invalid vault"),   
            CoreError::SignTransactionError => write!(f, "Core Error: Sign transaction error"),
        }
    }
}