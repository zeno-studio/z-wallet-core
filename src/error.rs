use thiserror::Error;
use serde::Serialize;

/// WalletError carries a numeric code and a human-readable message.
/// Internally we use strong typed variants; externally you can use `code()` and `message()`.
#[derive(Debug, Error)]
pub enum WalletError {
    // General
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Empty password")]
    EmptyPassword,
    #[error("Invalid derived key")]
    InvalidDerivedKey,
    #[error("Empty derived key")]
    EmptyDerivedKey,
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Empty nonce")]
    EmptyNonce,
    #[error("Invalid salt")]
    InvalidSalt,
    #[error("Empty salt")]
    EmptySalt,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Entropy generation failed")]
    EntropyGenerationFailed,
    #[error("Empty ciphertext")]
    EmptyCiphertext,
    #[error("Invalid UTF-8")]
    InvalidUtf8,
    #[error("Invalid entropy bits")]
    InvalidEntropyBits,
    #[error("Mnemonic generation failed")]
    MnemonicGenerationFailed,
    #[error("Signer build error")]
    SignerBuildError,
    #[error("Argon2 build error")]
    Argon2BuildError,
    #[error("Password hash error")]
    PasswordHashError,
    #[error("Serialization error")]
    SerializationError,
    #[error("Invalid hex")]
    InvalidHex,
    #[error("Empty cache time")]
    EmptyCacheTime,

    // JSON
    #[error("JSON parse error")]
    JsonParseError,

    // Transaction
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Empty address")]
    EmptyAddress,
    #[error("Invalid value")]
    InvalidValue,
    #[error("Empty value")]
    EmptyValue,
    #[error("Invalid gas price")]
    InvalidGasPrice,
    #[error("Empty gas price")]
    EmptyGasPrice,
    #[error("Invalid transaction data")]
    InvalidTxData,
    #[error("Empty transaction data")]
    EmptyTxData,
    #[error("Invalid max priority fee")]
    InvalidMaxPriorityFee,
    #[error("Empty max priority fee")]
    EmptyMaxPriorityFee,
    #[error("Invalid max fee")]
    InvalidMaxFee,
    #[error("Empty max fee")]
    EmptyMaxFee,
    #[error("Sign transaction error")]
    SignTransactionError,
    #[error("Invalid access list")]
    InvalidAccessList,
    #[error("Invalid authorization list")]
    InvalidAuthorizationList,
    #[error("Empty authorization list")]
    EmptyAuthorizationList,
    #[error("Value overflow")]
    ValueOverflow,
    #[error("Invalid chain ID")]
    InvalidChainId,
    #[error("Invalid gas limit")]
    InvalidGasLimit,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Recover failed")]
    RecoverFailed,
    #[error("Create signature failed")]
    CreateSignatureFailed,

    // EIP-712
    #[error("Invalid domain")]
    InvalidDomain,
    #[error("Missing domain")]
    MissingDomain,
    #[error("Invalid types")]
    InvalidTypes,
    #[error("Missing types")]
    MissingTypes,
    #[error("Invalid primary type")]
    InvalidPrimaryType,
    #[error("Missing primary type")]
    MissingPrimaryType,
    #[error("Missing message")]
    MissingMessage,
    #[error("Type fields is not array")]
    TypeFieldsNotArray,
    #[error("Field missing name")]
    FieldMissingName,
    #[error("Field missing type")]
    FieldMissingType,
    #[error("Missing field value")]
    MissingFieldValue,
    #[error("Invalid number")]
    InvalidNumber,
    #[error("Invalid bytes hex")]
    InvalidBytesHex,
    #[error("Unsupported type")]
    UnsupportedType,
    #[error("Cycle detected")]
    CycleDetected,
    #[error("Invalid type prefix")]
    InvalidTypePrefix,
    #[error("Type not found")]
    TypeNotFound,
    #[error("Message signing failed")]
    MessageSigningFailed,
    #[error("EIP712 struct hash error")]
    Eip712StructHashError,
    #[error("Domain fallback invalid")]
    DomainFallbackInvalid,
    #[error("Encode value error")]
    EncodeValue,
    #[error("Type hash cache lock error")]
    TypeHashCacheLock,
    #[error("Type hash cache poisoned")]
    TypeHashCachePoisoned,
    #[error("Type hash compute error")]
    TypeHashCompute,
    #[error("Struct hash compute error")]
    StructHashCompute,
    #[error("Digest build error")]
    DigestBuildError,
}

impl WalletError {
    /// Numeric code mapping for each error variant (inline codes, no consts).
    pub fn code(&self) -> u32 {
        match self {
            // General (1xxx)
            WalletError::InvalidPassword => 1001,
            WalletError::EmptyPassword => 1002,
            WalletError::InvalidDerivedKey => 1003,
            WalletError::EmptyDerivedKey => 1004,
            WalletError::InvalidNonce => 1005,
            WalletError::EmptyNonce => 1006,
            WalletError::InvalidSalt => 1007,
            WalletError::EmptySalt => 1008,
            WalletError::DecryptionFailed => 1009,
            WalletError::EncryptionFailed => 1010,
            WalletError::EntropyGenerationFailed => 1011,
            WalletError::EmptyCiphertext => 1012,
            WalletError::InvalidUtf8 => 1013,
            WalletError::InvalidEntropyBits => 1014,
            WalletError::MnemonicGenerationFailed => 1015,
            WalletError::SignerBuildError => 1017,
            WalletError::Argon2BuildError => 1018,
            WalletError::PasswordHashError => 1019,
            WalletError::SerializationError => 1020,
            WalletError::InvalidHex => 1021,
            WalletError::EmptyCacheTime => 1022,

            // JSON (2xxx)
            WalletError::JsonParseError => 2001,

            // Transaction (3xxx)
            WalletError::InvalidAddress => 3001,
            WalletError::EmptyAddress => 3002,
            WalletError::InvalidValue => 3003,
            WalletError::EmptyValue => 3004,
            WalletError::InvalidGasPrice => 3005,
            WalletError::EmptyGasPrice => 3006,
            WalletError::InvalidTxData => 3007,
            WalletError::EmptyTxData => 3008,
            WalletError::InvalidMaxPriorityFee => 3009,
            WalletError::EmptyMaxPriorityFee => 3010,
            WalletError::InvalidMaxFee => 3011,
            WalletError::EmptyMaxFee => 3012,
            WalletError::SignTransactionError => 3013,
            WalletError::InvalidAccessList => 3031,
            WalletError::InvalidAuthorizationList => 3032,
            WalletError::EmptyAuthorizationList => 3033,
            WalletError::ValueOverflow => 3034,
            WalletError::InvalidChainId => 3035,
            WalletError::InvalidGasLimit => 3036,
            WalletError::InvalidSignature => 3037,
            WalletError::RecoverFailed => 3038,
            WalletError::CreateSignatureFailed => 3039,

            // EIP-712 (4xxx)
            WalletError::InvalidDomain => 4001,
            WalletError::MissingDomain => 4002,
            WalletError::InvalidTypes => 4003,
            WalletError::MissingTypes => 4004,
            WalletError::InvalidPrimaryType => 4005,
            WalletError::MissingPrimaryType => 4006,
            WalletError::MissingMessage => 4007,
            WalletError::TypeFieldsNotArray => 4008,
            WalletError::FieldMissingName => 4009,
            WalletError::FieldMissingType => 4010,
            WalletError::MissingFieldValue => 4011,
            WalletError::InvalidNumber => 4012,
            WalletError::InvalidBytesHex => 4013,
            WalletError::UnsupportedType => 4014,
            WalletError::CycleDetected => 4015,
            WalletError::InvalidTypePrefix => 4016,
            WalletError::TypeNotFound => 4017,
            WalletError::MessageSigningFailed => 4018,
            WalletError::Eip712StructHashError => 4019,
            WalletError::DomainFallbackInvalid => 4020,
            WalletError::EncodeValue => 4021,
            WalletError::TypeHashCacheLock => 4022,
            WalletError::TypeHashCachePoisoned => 4023,
            WalletError::TypeHashCompute => 4024,
            WalletError::StructHashCompute => 4025,
            WalletError::DigestBuildError => 4026,
        }
    }

    /// Human-readable message derived from Display.
    pub fn message(&self) -> String {
        self.to_string()
    }

    /// Convenience helper to build { code, message } for boundary outputs.
    pub fn as_response(&self) -> ErrorResponse {
        ErrorResponse {
            code: self.code(),
            message: self.message(),
        }
    }
}

/// Serializable error response for frontend/boundary layers.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub code: u32,
    pub message: String,
}

impl From<WalletError> for ErrorResponse {
    fn from(e: WalletError) -> Self {
        ErrorResponse {
            code: e.code(),
            message: e.message(),
        }
    }
}