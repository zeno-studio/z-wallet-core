use core::fmt;

/// CoreError carries a numeric code and a human-readable message.
/// Internally we use strong typed variants; externally you can use `code()` and `message()`.
#[derive(Debug)]
pub enum CoreError {
    // General
    InvalidPassword,
    EmptyPassword,
    InvalidDerivedKey,
    EmptyDerivedKey,
    EmptyNonce,
    EmptySalt,
    InvalidKeyLength,
    DecryptionFailed,
    EncryptionFailed,
    EntropyGenerationFailed,
    EmptyCiphertext,
    InvalidUtf8,
    InvalidEntropyBits,
    MnemonicGenerationFailed,
    SignerBuildError,
    Argon2BuildError,
    PasswordHashError,
    SerializationError,
    InvalidHex,
    EmptyCacheTime,
    MessageSigningFailed,  // 添加缺失的错误变体

    // JSON
    JsonParseError,

    // Transaction
    InvalidAddress,
    EmptyAddress,
    InvalidValue,
    EmptyValue,
    InvalidGasPrice,
    EmptyGasPrice,
    InvalidTxData,
    EmptyTxData,
    InvalidMaxPriorityFee,
    EmptyMaxPriorityFee,
    InvalidMaxFee,
    EmptyMaxFee,
    SignTransactionError,
    InvalidAccessList,
    InvalidAuthorizationList,
    EmptyAuthorizationList,
    ValueOverflow,
    InvalidChainId,
    InvalidGasLimit,
    InvalidSignature,
    RecoverFailed,
    CreateSignatureFailed,
    InvalidSignedAuthorizationList,  // 添加缺失的错误变体
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