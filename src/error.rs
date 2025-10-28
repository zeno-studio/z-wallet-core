/// Error codes used across the wallet module.
/// `100` indicates success, non-zero values indicate specific errors.
pub const SUCCESS: u32 = 100;

/// General error codes
pub const ERR_INVALID_PASSWORD: u32 = 1001;
pub const ERR_EMPTY_PASSWORD: u32 = 1002;
pub const ERR_INVALID_DERIVED_KEY: u32 = 1003;
pub const ERR_EMPTY_DERIVED_KEY: u32 = 1004;
pub const ERR_INVALID_NONCE: u32 = 1005;
pub const ERR_EMPTY_NONCE: u32 = 1006;
pub const ERR_INVALID_SALT: u32 = 1007;
pub const ERR_EMPTY_SALT: u32 = 1008;
pub const ERR_DECRYPTION_FAILED: u32 = 1009;
pub const ERR_ENCRYPTION_FAILED: u32 = 1010;
pub const ERR_ENTROPY_GENERATION_FAILED: u32 = 1011;
pub const ERR_EMPTY_CIPHERTEXT: u32 = 1012;
pub const ERR_INVALID_UTF8: u32 = 1013;
pub const ERR_INVALID_ENTROPY_BITS: u32 = 1014;
pub const ERR_MNEMONIC_GENERATION_FAILED: u32 = 1015;
pub const ERR_SIGNER_BUILD_ERROR: u32 = 1017;
pub const ERR_ARGON2_BUILD_ERROR: u32 = 1018;
pub const ERR_PASSWORD_HASH_ERROR: u32 = 1019;
pub const ERR_SERIALIZATION_ERROR: u32 = 1020;
pub const ERR_INVALID_HEX: u32 = 1021;
pub const ERR_EMPTY_CACHE_TIME: u32 = 1022; 

/// JSON parsing and serialization errors (more specific than a single ERR_JSON_PARSE_ERROR)
pub const ERR_JSON_PARSE_ERROR: u32 = 2001;
pub const ERR_JSON_INVALID_FORMAT: u32 = 2002;
pub const ERR_JSON_MISSING_FIELD: u32 = 2003;
pub const ERR_JSON_TYPE_MISMATCH: u32 = 2004;
pub const ERR_JSON_UNEXPECTED_NULL: u32 = 2005;
pub const ERR_JSON_ARRAY_EXPECTED: u32 = 2006;
pub const ERR_JSON_OBJECT_EXPECTED: u32 = 2007;


/// Transaction error codes
pub const ERR_INVALID_ADDRESS: u32 = 3001;
pub const ERR_EMPTY_ADDRESS: u32 = 3002;
pub const ERR_INVALID_VALUE: u32 = 3003;
pub const ERR_EMPTY_VALUE: u32 = 3004;
pub const ERR_INVALID_GAS_PRICE: u32 = 3005;
pub const ERR_EMPTY_GAS_PRICE: u32 = 3006;
pub const ERR_INVALID_TX_DATA: u32 = 3007;
pub const ERR_EMPTY_TX_DATA: u32 = 3008;
pub const ERR_INVALID_MAX_PRIORITY_FEE: u32 = 3009;
pub const ERR_EMPTY_MAX_PRIORITY_FEE: u32 = 3010;
pub const ERR_INVALID_MAX_FEE: u32 = 3011;
pub const ERR_EMPTY_MAX_FEE: u32 = 3012;
pub const ERR_SIGN_TRANSACTION_ERROR: u32 = 3013;
pub const ERR_INVALID_ACCESS_LIST: u32 = 3031;
pub const ERR_INVALID_AUTHORIZATION_LIST: u32 = 3032;
pub const ERR_EMPTY_AUTHORIZATION_LIST: u32 = 3033;
pub const ERR_VALUE_OVERFLOW: u32 = 3034;
pub const ERR_INVALID_CHAIN_ID: u32 = 3035;
pub const ERR_INVALID_GAS_LIMIT: u32 = 3036;
pub const ERR_INVALID_SIGNATURE: u32 = 3037;
pub const ERR_RECOVER_FAILED: u32 = 3038;
pub const ERR_CREATE_SIGNATURE_FAILED: u32 = 3039;

/// message sign and verify error codes (kept and/or added to match implementation)
pub const ERR_INVALID_DOMAIN: u32 = 4001;
pub const ERR_MISSING_DOMAIN: u32 = 4002;
pub const ERR_INVALID_TYPES: u32 = 4003;
pub const ERR_MISSING_TYPES: u32 = 4004;
pub const ERR_INVALID_PRIMARY_TYPE: u32 = 4005;
pub const ERR_MISSING_PRIMARY_TYPE: u32 = 4006;
pub const ERR_MISSING_MESSAGE: u32 = 4007;
pub const ERR_TYPE_FIELDS_NOT_ARRAY: u32 = 4008;
pub const ERR_FIELD_MISSING_NAME: u32 = 4009;
pub const ERR_FIELD_MISSING_TYPE: u32 = 4010;
pub const ERR_MISSING_FIELD_VALUE: u32 = 4011;
pub const ERR_INVALID_NUMBER: u32 = 4012;
pub const ERR_INVALID_BYTES_HEX: u32 = 4013;
pub const ERR_UNSUPPORTED_TYPE: u32 = 4014;
pub const ERR_CYCLE_DETECTED: u32 = 4015;
pub const ERR_INVALID_TYPE_PREFIX: u32 = 4016;
pub const ERR_TYPE_NOT_FOUND: u32 = 4017;
pub const ERR_MESSAGE_SIGNING_FAILED: u32 = 4018;
pub const ERR_EIP712_STRUCT_HASH_ERROR: u32 = 4019;
pub const ERR_DOMAIN_FALLBACK_INVALID: u32 = 4020;
pub const ERR_ENCODE_VALUE: u32 = 4021;
pub const ERR_TYPE_HASH_CACHE_LOCK: u32 = 4022;
pub const ERR_TYPE_HASH_CACHE_POISONED: u32 = 4023;
pub const ERR_TYPE_HASH_COMPUTE: u32 = 4024;
pub const ERR_STRUCT_HASH_COMPUTE: u32 = 4025;
pub const ERR_DIGEST_BUILD_ERROR: u32 = 4026;
