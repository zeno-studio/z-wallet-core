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
    /// The UTF-8 string is invalid
    InvalidUtf8,
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
    /// Serialization error
    SerializationError,
    /// The hex string is invalid
    InvalidHex,
    /// The cache time is empty
    EmptyCacheTime,
    /// Message signing failed
    MessageSigningFailed,

    // JSON errors
    /// JSON parsing error
    JsonParseError,
    /// Vault parsing error
    VaultParseError,
    /// Vault has an invalid version
    VaultInvalidVersion{version: alloc::string::String},
    /// Base58 decoding error
    Bs58DecodeError,
    /// The vault is invalid
    InvalidVault,

    // Transaction errors
    /// The address is invalid
    InvalidAddress,
    /// The address is empty
    EmptyAddress,
    /// The value is invalid
    InvalidValue,
    /// The value is empty
    EmptyValue,
    /// The gas price is invalid
    InvalidGasPrice,
    /// The gas price is empty
    EmptyGasPrice,
    /// The transaction data is invalid
    InvalidTxData,
    /// The transaction data is empty
    EmptyTxData,
    /// The max priority fee is invalid
    InvalidMaxPriorityFee,
    /// The max priority fee is empty
    EmptyMaxPriorityFee,
    /// The max fee is invalid
    InvalidMaxFee,
    /// The max fee is empty
    EmptyMaxFee,
    /// Signing transaction error
    SignTransactionError,
    /// The access list is invalid
    InvalidAccessList,
    /// The authorization list is invalid
    InvalidAuthorizationList,
    /// The authorization list is empty
    EmptyAuthorizationList,
    /// Value overflow
    ValueOverflow,
    /// The chain ID is invalid
    InvalidChainId,
    /// The gas limit is invalid
    InvalidGasLimit,
    /// The signature is invalid
    InvalidSignature,
    /// Recovery failed
    RecoverFailed,
    /// Creating signature failed
    CreateSignatureFailed,
    /// The signed authorization list is invalid
    InvalidSignedAuthorizationList,

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
            CoreError::InvalidKeyLength => write!(f, "Core Error: Invalid key length"),
            CoreError::DecryptionFailed => write!(f, "Core Error: Decryption failed"),
            CoreError::EncryptionFailed => write!(f, "Core Error: Encryption failed"),
            CoreError::EntropyGenerationFailed => write!(f, "Core Error: Entropy generation failed"),
            CoreError::EmptyCiphertext => write!(f, "Core Error: Empty ciphertext"),
            CoreError::InvalidUtf8 => write!(f, "Core Error: Invalid UTF-8"),
            CoreError::InvalidEntropyBits => write!(f, "Core Error: Invalid entropy bits"),
            CoreError::MnemonicGenerationFailed => write!(f, "Core Error: Mnemonic generation failed"),
            CoreError::SignerBuildError => write!(f, "Core Error: Signer build error"),
            CoreError::Argon2BuildError => write!(f, "Core Error: Argon2 build error"),
            CoreError::PasswordHashError => write!(f, "Core Error: Password hash error"),
            CoreError::SerializationError => write!(f, "Core Error: Serialization error"),
            CoreError::InvalidHex => write!(f, "Core Error: Invalid hex"),
            CoreError::EmptyCacheTime => write!(f, "Core Error: Empty cache time"),
            CoreError::JsonParseError => write!(f, "Core Error: JSON parse error"),
            CoreError::VaultInvalidVersion{version} => write!(f, "Core Error: Vault invalid version: {}", version),          
            CoreError::VaultParseError => write!(f, "Core Error: Vault parse error"),
            CoreError::Bs58DecodeError => write!(f, "Core Error: BS58 decode error"),
            CoreError::InvalidVault => write!(f, "Core Error: Invalid vault"),   
            CoreError::InvalidAddress => write!(f, "Core Error: Invalid address"),
            CoreError::EmptyAddress => write!(f, "Core Error: Empty address"),
            CoreError::InvalidValue => write!(f, "Core Error: Invalid value"),
            CoreError::EmptyValue => write!(f, "Core Error: Empty value"),
            CoreError::InvalidGasPrice => write!(f, "Core Error: Invalid gas price"),
            CoreError::EmptyGasPrice => write!(f, "Core Error: Empty gas price"),
            CoreError::InvalidTxData => write!(f, "Core Error: Invalid transaction data"),
            CoreError::EmptyTxData => write!(f, "Core Error: Empty transaction data"),
            CoreError::InvalidMaxPriorityFee => write!(f, "Core Error: Invalid max priority fee"),
            CoreError::EmptyMaxPriorityFee => write!(f, "Core Error: Empty max priority fee"),
            CoreError::InvalidMaxFee => write!(f, "Core Error: Invalid max fee"),
            CoreError::EmptyMaxFee => write!(f, "Core Error: Empty max fee"),
            CoreError::SignTransactionError => write!(f, "Core Error: Sign transaction error"),
            CoreError::InvalidAccessList => write!(f, "Core Error: Invalid access list"),
            CoreError::InvalidAuthorizationList => write!(f, "Core Error: Invalid authorization list"),
            CoreError::EmptyAuthorizationList => write!(f, "Core Error: Empty authorization list"),
            CoreError::ValueOverflow => write!(f, "Core Error: Value overflow"),
            CoreError::InvalidChainId => write!(f, "Core Error: Invalid chain ID"),
            CoreError::InvalidGasLimit => write!(f, "Core Error: Invalid gas limit"),
            CoreError::InvalidSignature => write!(f, "Core Error: Invalid signature"),
            CoreError::RecoverFailed => write!(f, "Core Error: Recover failed"),
            CoreError::CreateSignatureFailed => write!(f, "Core Error: Create signature failed"),
            CoreError::MessageSigningFailed => write!(f, "Core Error: Message signing failed"),
            CoreError::InvalidSignedAuthorizationList => write!(f, "Core Error: Invalid signed authorization list"),
        }
    }
}