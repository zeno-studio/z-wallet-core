// Argon2 key derivation parameters
pub const ARGON2_MEMORY: u32 = 12288; // KB
pub const ARGON2_ITERATIONS: u32 = 4;
pub const ARGON2_PARALLELISM: u32 = 2;
pub const ARGON2_OUTPUT_LEN: usize = 32; // Output key length in bytes
pub const ARGON2_SALT_LEN: usize = 16; // Salt length in bytes

// XChaCha20Poly1305 encryption parameters
pub const XCHACHA_XNONCE_LEN: usize = 24; // Nonce length in bytes

// Entropy parameters
pub const ENTROPY_128: u64 = 128; // 128 bits entropy
pub const ENTROPY_256: u64 = 256; // 256 bits entropy
pub const DEFAULT_ENTROPY_BITS: u64 = ENTROPY_128; // Default entropy bits

// Cache parameters
pub const DEFAULT_CACHE_DURATION: u64 = 900; // Default cache duration in seconds (15 minutes)

// Version parameters
pub const VERSION_TAG_1: &str = "ZENO_v1"; // Version tag
pub const VERSION_TAG_LEN: usize = 7; // Version tag length in bytes

pub const DEFAULT_DERIVATION_PATH_PREFIX: &str = "m/44'/60'/0'/0/";
