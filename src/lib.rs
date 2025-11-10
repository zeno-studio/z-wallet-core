#![no_std]

// Import necessary modules
extern crate alloc;

// Import standard library modules
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

// Import third-party libraries
use alloy_primitives::Address;
use alloy_signer_local::LocalSignerError;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use hex::encode as hex_encode;
use zeroize::{Zeroize, Zeroizing};

// Import local modules
pub mod builder;
pub mod constants;
pub mod error;
pub mod message;
pub mod tx;
pub mod validate;

// Import contents from local modules
pub use builder::*;
pub use constants::*;
pub use error::CoreError;
pub use message::*;
pub use tx::*;
pub use validate::*;

/// Core wallet functionality with encrypted storage
///
/// This struct represents the core wallet functionality with encrypted storage.
/// It manages the encrypted mnemonic phrase, derived keys, and related security parameters.
/// The wallet uses Argon2 for key derivation and XChaCha20Poly1305 for encryption.
#[derive(Debug, Clone)]
pub struct WalletCore {
    /// Encrypted mnemonic phrase ciphertext
    ///
    /// This field stores the encrypted mnemonic phrase that represents the wallet.
    /// It is None when no wallet has been created or loaded yet.
    pub ciphertext: Option<Vec<u8>>,
    
    /// Derived key for encryption/decryption
    ///
    /// This field stores the derived key used for encryption and decryption operations.
    /// The key is derived from the user's password using Argon2 and is cached for a
    /// configurable duration. It is None when no key has been derived yet or when
    /// the cache has expired.
    pub derived_key: Option<[u8; 32]>,
    
    /// Salt used in key derivation
    ///
    /// This field stores the salt used in the Argon2 key derivation process.
    /// The salt is generated randomly when a new wallet is created and is stored
    /// alongside the encrypted ciphertext.
    pub salt: Option<[u8; constants::ARGON2_SALT_LEN]>,
    
    /// Nonce for encryption
    ///
    /// This field stores the nonce used in the XChaCha20Poly1305 encryption process.
    /// The nonce is generated randomly when a new wallet is created and is stored
    /// alongside the encrypted ciphertext.
    pub nonce: Option<[u8; constants::XCHACHA_XNONCE_LEN]>,
    
    /// Expiration time for cached key
    ///
    /// This field stores the Unix timestamp when the cached derived key will expire.
    /// When this time is reached, the derived key will be zeroized and removed from memory.
    pub expire_time: Option<u64>,
    
    /// Cache duration in seconds
    ///
    /// This field stores the duration for which the derived key should be cached in memory.
    /// After this duration has passed, the key will be automatically zeroized and removed.
    pub cache_duration: Option<u64>,
    
    /// Entropy bits for mnemonic generation
    ///
    /// This field stores the number of entropy bits used for mnemonic generation.
    /// Valid values are 128 (12 words) or 256 (24 words).
    pub entropy_bits: Option<u64>,
}


/// Implement Default trait for WalletCore
///
/// This implementation allows creating a new WalletCore instance with default values
/// using the Default trait. It is equivalent to calling WalletCore::new().
impl Default for WalletCore {
    fn default() -> Self {
        Self::new()
    }
}
/// Encrypted wallet vault for secure storage
///
/// This struct represents an encrypted wallet vault for secure storage and transfer.
/// It contains all the necessary data to reconstruct a wallet, including the encrypted
/// mnemonic phrase, salt, nonce, and version information. The vault can be serialized
/// to a Base58-encoded string for easy storage and transfer.
#[derive(Debug, Clone)]
pub struct Vault {
    /// Version tag for vault format
    ///
    /// This field stores the version tag for the vault format. It is used to ensure
    /// compatibility when deserializing vaults and to allow for future format changes.
    pub version: [u8; 7], //const VERSION_TAG_1: &str = "ZENO_v1"
    
    /// Salt used in key derivation (16 bytes)
    ///
    /// This field stores the salt used in the Argon2 key derivation process.
    /// The salt is generated randomly when a new vault is created.
    pub salt: [u8; constants::ARGON2_SALT_LEN], // Fixed length 16 bytes
    
    /// Nonce for encryption (24 bytes)
    ///
    /// This field stores the nonce used in the XChaCha20Poly1305 encryption process.
    /// The nonce is generated randomly when a new vault is created.
    pub nonce: [u8; constants::XCHACHA_XNONCE_LEN], // Fixed length 24 bytes
    
    /// Encrypted mnemonic phrase ciphertext
    ///
    /// This field stores the encrypted mnemonic phrase that represents the wallet.
    /// The mnemonic is encrypted using XChaCha20Poly1305 with a key derived from
    /// the user's password.
    pub ciphertext: Vec<u8>,
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}
impl Vault {

    /// Create a new Vault instance with default values
    ///
    /// This function creates a new Vault instance with default configuration values.
    /// Note that the vault will be in an uninitialized state with zeroed salt and nonce.
    /// This is primarily used for deserialization purposes.
    ///
    /// # Returns
    /// * `Vault` - A new Vault instance with default values
    pub fn new() -> Self {
        let salt = [0u8; ARGON2_SALT_LEN];
        let nonce = [0u8; XCHACHA_XNONCE_LEN];
        Vault {
            version: VERSION_TAG_1.as_bytes().try_into().unwrap(),
            salt,
            nonce,
            ciphertext: Vec::new(), 
        }
    }
    /// Serialize the vault to a Base58-encoded keystore string
    ///
    /// This method serializes the vault data into a byte array and encodes it using Base58
    /// for easy storage and transfer. The encoded string is suitable for QR codes.
    ///
    /// # Returns
    /// * `Ok(String)` - The Base58-encoded keystore string
    /// * `Err(CoreError)` - If the vault fields are not properly initialized
    pub fn to_keystore_string(&mut self) -> Result<String, CoreError> {
        // Check if fields are properly initialized (not zeroed)
        if self.salt.iter().all(|&b| b == 0) || 
           self.nonce.iter().all(|&b| b == 0) || 
           self.ciphertext.is_empty() {
            return Err(CoreError::InvalidVault);
        }
        let const_version: [u8; 7] = VERSION_TAG_1.as_bytes().try_into().unwrap();
        if self.version != const_version {
            self.version = const_version;
        }
        let mut bytes = Vec::with_capacity(7 + ARGON2_SALT_LEN + 24 + self.ciphertext.len());
        bytes.extend_from_slice(&self.version);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);

        Ok(bs58::encode(bytes).into_string())
    }
    
    /// Deserialize a vault from a Base58-encoded keystore string
    ///
    /// This method decodes a Base58-encoded keystore string and reconstructs a Vault instance
    /// from the serialized data. It validates the data format and version.
    ///
    /// # Arguments
    /// * `keystore` - The Base58-encoded keystore string
    ///
    /// # Returns
    /// * `Ok(Vault)` - The deserialized vault
    /// * `Err(CoreError)` - If the keystore string is invalid or malformed
    pub fn from_keystore_string(keystore: &str) -> Result<Self, CoreError> {
        let bytes = bs58::decode(keystore)
            .into_vec()
            .map_err(|_| CoreError::Bs58DecodeError)?;

        let min_len = VERSION_TAG_LEN + ARGON2_SALT_LEN + XCHACHA_XNONCE_LEN;
        if bytes.len() < min_len {
            return Err(CoreError::VaultParseError);
        }

        let const_version: [u8; 7] = VERSION_TAG_1.as_bytes().try_into().unwrap();
        let mut offset = 0;
        let version = bytes[offset..offset + VERSION_TAG_LEN].try_into().unwrap();
        if version != const_version {
            return Err(CoreError::VaultInvalidVersion { version });
        }
        offset += VERSION_TAG_LEN;

        let salt = bytes[offset..offset + ARGON2_SALT_LEN].try_into().unwrap();
        offset += ARGON2_SALT_LEN;

        let nonce = bytes[offset..offset + 24].try_into().unwrap();
        offset += XCHACHA_XNONCE_LEN;

        let ciphertext = bytes[offset..].to_vec();

        Ok(Vault {
            version,
            salt,
            nonce,
            ciphertext,
        })
    }
}

// WalletCore implementation
impl WalletCore {
    /// Create a new WalletCore instance with default values
    ///
    /// This function creates a new WalletCore instance with default configuration values.
    /// The wallet will be in an uninitialized state with no ciphertext, derived key,
    /// salt, or nonce. Default cache duration and entropy bits are set according to
    /// the constants defined in the constants module.
    ///
    /// # Returns
    /// * `WalletCore` - A new WalletCore instance with default values
    ///
    /// # Example
    /// ```
    /// let wallet = WalletCore::new();
    /// ```
    pub fn new() -> WalletCore {
        WalletCore {
            ciphertext: None,
            derived_key: None,
            salt: None,
            nonce: None,
            expire_time: None,
            cache_duration: Some(constants::DEFAULT_CACHE_DURATION),
            entropy_bits: Some(constants::DEFAULT_ENTROPY_BITS),
        }
    }

    /// Load an existing vault into the wallet core
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted mnemonic phrase
    /// * `salt` - The salt used for key derivation (16 bytes)
    /// * `nonce` - The nonce used for encryption (24 bytes)
    ///
    /// # Returns
    /// * `Ok(())` if the vault is loaded successfully
    /// * `Err(CoreError)` if there is an error during loading
    pub fn load_vault(
        &mut self,
        ciphertext: Vec<u8>,
        salt: [u8; constants::ARGON2_SALT_LEN], // Fixed length 16 bytes
        nonce: [u8; constants::XCHACHA_XNONCE_LEN], // Fixed length 24 bytes
    ) -> Result<(), CoreError> {
        if ciphertext.is_empty() {
            return Err(CoreError::EmptyCiphertext);
        }
        validate::validate_salt(salt)?;
        validate::validate_nonce(nonce)?;
        self.derived_key = None;
        self.expire_time = None;
        self.cache_duration = Some(900);
        self.entropy_bits = Some(128);
        self.ciphertext = Some(ciphertext);
        self.salt = Some(salt);
        self.nonce = Some(nonce);
        Ok(())
    }

    /// Set the cache duration for derived keys
    ///
    /// # Arguments
    /// * `duration` - The duration in seconds
    pub fn set_cache_duration(&mut self, duration: u64) {
        self.cache_duration = Some(duration);
    }

    /// Get the cache duration for derived keys
    ///
    /// This function returns the cache duration for derived keys in seconds.
    /// If no cache duration has been explicitly set, it returns the default
    /// cache duration defined in the constants module.
    ///
    /// # Returns
    /// * `u64` - The cache duration in seconds
    pub fn get_cache_duration(&self) -> u64 {
        self.cache_duration
            .unwrap_or(constants::DEFAULT_CACHE_DURATION)
    }

    /// Set the entropy bits for mnemonic generation
    ///
    /// # Arguments
    /// * `bits` - The entropy bits (128 or 256)
    ///
    /// # Returns
    /// * `Ok(())` if the entropy bits are valid
    /// * `Err(CoreError)` if the entropy bits are invalid
    pub fn set_entropy_bits(&mut self, bits: u64) -> Result<(), CoreError> {
        match bits {
            constants::ENTROPY_128 | constants::ENTROPY_256 => {
                self.entropy_bits = Some(bits);
                Ok(())
            }
            _ => Err(CoreError::InvalidEntropyBits),
        }
    }

    /// Get the entropy bits for mnemonic generation
    ///
    /// This function returns the entropy bits used for mnemonic generation.
    /// If no entropy bits have been explicitly set, it returns the default
    /// entropy bits defined in the constants module (128 bits).
    ///
    /// # Returns
    /// * `u64` - The entropy bits (128 or 256)
    pub fn get_entropy_bits(&self) -> u64 {
        self.entropy_bits.unwrap_or(constants::DEFAULT_ENTROPY_BITS)
    }

    /// Return ciphertext hex (does NOT consume stored ciphertext).
    pub fn get_ciphertext(&self) -> Result<String, CoreError> {
        if let Some(ct) = &self.ciphertext {
            return Ok(hex_encode(ct));
        }
        Err(CoreError::EmptyCiphertext)
    }

    /// Get the salt as a hex-encoded string
    ///
    /// This function returns the salt used in key derivation as a hex-encoded string.
    /// If no salt has been set, it returns an EmptySalt error.
    ///
    /// # Returns
    /// * `Ok(String)` - The hex-encoded salt
    /// * `Err(CoreError)` - If no salt has been set
    pub fn get_salt(&self) -> Result<String, CoreError> {
        if let Some(s) = &self.salt {
            return Ok(hex_encode(s));
        }
        Err(CoreError::EmptySalt)
    }

    /// Get the nonce as a hex-encoded string
    ///
    /// This function returns the nonce used in encryption as a hex-encoded string.
    /// If no nonce has been set, it returns an EmptyNonce error.
    ///
    /// # Returns
    /// * `Ok(String)` - The hex-encoded nonce
    /// * `Err(CoreError)` - If no nonce has been set
    pub fn get_nonce(&self) -> Result<String, CoreError> {
        if let Some(n) = &self.nonce {
            return Ok(hex_encode(n));
        }
        Err(CoreError::EmptyNonce)
    }

    /// Get the expiration time of the cached derived key
    ///
    /// # Returns
    /// * `Ok(u64)` - The expiration time as Unix timestamp
    /// * `Err(CoreError)` - If no expiration time is set
    pub fn get_expire_time(&self) -> Result<u64, CoreError> {
        self.expire_time.ok_or(CoreError::EmptyCacheTime)
    }

    /// Expire cache if needed, zeroize derived key when removed.
    ///
    /// # Arguments
    /// * `now` - The current Unix timestamp
    pub fn tick(&mut self, now: u64) {
        if let Some(ct) = self.expire_time && now > ct {
            if let Some(mut dk) = self.derived_key.take() {
                dk.zeroize();
            }
            self.expire_time = None;
        }
        if self.expire_time.is_none()
            && let Some(mut dk) = self.derived_key.take()
        {
            // For HeaplessVec, we need to manually zeroize
            for byte in dk.iter_mut() {
                *byte = 0;
            }
        }
    }

    /// Check if a derived key is currently cached
    ///
    /// # Returns
    /// * `true` if a derived key is cached
    /// * `false` if no derived key is cached
    pub fn has_derived_key(&self) -> bool {
        // do not mutate here; tick() handles expiry/zeroize
        self.derived_key.is_some()
    }

    /// Create a new wallet vault with a mnemonic phrase
    ///
    /// # Arguments
    /// * `password` - The password to encrypt the mnemonic
    /// * `entropy_bits` - The entropy bits for mnemonic generation (128 or 256)
    /// * `duration` - The cache duration in seconds
    /// * `now` - The current Unix timestamp
    ///
    /// # Returns
    /// * `Ok((Vault, Address))` - The created vault and the wallet address
    /// * `Err(CoreError)` - If there is an error during creation
    pub fn create_vault(
        &mut self,
        password: &str,
        entropy_bits: u64,
        duration: u64,
        now: u64,
    ) -> Result<(Vault, Address), CoreError> {
        validate_entropy(entropy_bits)?;
        validate_password(password)?;
        let salt = builder::generate_entropy_bytes(ARGON2_SALT_LEN as u64)?;
        let nonce = builder::generate_entropy_bytes(XCHACHA_XNONCE_LEN as u64)?;
        let entropy = builder::generate_entropy_bits(entropy_bits)?;
        let mnemonic = builder::entropy_to_mnemonic(&entropy)?;
        let signer = builder::mnemonic_to_signer(&mnemonic, 0)?;
        let address = signer.address(); // Use format instead of to_string
        let dkey = builder::password_kdf_argon2(password, &salt)?;
        let ciphertext = builder::encrypt_xchacha(&mnemonic, &dkey, &nonce)?;

        self.ciphertext = Some(ciphertext.clone());

        // Convert Vec<u8> to fixed length array
        let mut dkey_array = [0u8; constants::ARGON2_OUTPUT_LEN];
        dkey_array.copy_from_slice(dkey.as_slice());
        self.derived_key = Some(dkey_array);

        let mut salt_array = [0u8; constants::ARGON2_SALT_LEN];
        salt_array.copy_from_slice(salt.as_slice());
        self.salt = Some(salt_array);

        let mut nonce_array = [0u8; constants::XCHACHA_XNONCE_LEN];
        nonce_array.copy_from_slice(nonce.as_slice());
        self.nonce = Some(nonce_array);

        self.expire_time = Some(now + duration);
        self.cache_duration = Some(duration);
        self.entropy_bits = Some(entropy_bits);
        let const_version: [u8; 7] = VERSION_TAG_1.as_bytes().try_into().unwrap();
        let vault = Vault {
            version: const_version,
            ciphertext,
            salt: salt_array,
            nonce: nonce_array,
        };

        Ok((vault, address))
    }

    /// Derive an account from the mnemonic phrase
    ///
    /// # Arguments
    /// * `password` - The password to decrypt the mnemonic (can be empty)
    /// * `index` - The derivation index
    /// * `now` - The current Unix timestamp
    ///
    /// # Returns
    /// * `Ok(String)` - The derived account address
    /// * `Err(CoreError)` - If there is an error during derivation
    pub fn derive_account(
        &mut self,
        password: &str,
        index: u32,
        now: u64,
    ) -> Result<String, CoreError> {
        let mnemonic_str = self.get_mnemonic(
            if password.is_empty() {
                None
            } else {
                Some(password)
            },
            now,
        )?;
        let signer = builder::mnemonic_to_signer(&mnemonic_str, index)?;
        Ok(format!("{:?}", signer.address())) // Use format instead of to_string
    }

    /// Verify password and cache derived key
    ///
    /// This function verifies the provided password by attempting to derive the encryption key
    /// and decrypt the stored ciphertext. If successful, it caches the derived key for future
    /// operations according to the configured cache duration.
    ///
    /// # Arguments
    /// * `password` - The password to verify
    /// * `now` - The current Unix timestamp for cache management
    ///
    /// # Returns
    /// * `Ok(true)` - If the password is correct and verification succeeded
    /// * `Ok(false)` - If the password is incorrect
    /// * `Err(CoreError)` - If there is an error during the verification process
    ///
    /// # Security
    /// This function implements secure key derivation using Argon2 and XChaCha20Poly1305
    /// decryption. It also manages the caching of derived keys with automatic expiration.
    pub fn verify_password(&mut self, password: &str, now: u64) -> Result<bool, CoreError> {
        self.tick(now);

        let salt = self
            .salt
            .as_ref()
            .filter(|v| !v.is_empty())
            .ok_or(CoreError::EmptySalt)?;
        let nonce = self
            .nonce
            .as_ref()
            .filter(|v| !v.is_empty())
            .ok_or(CoreError::EmptyNonce)?;

        let dkey = builder::password_kdf_argon2(password, salt)?;

        if let Some(cached_dk) = &self.derived_key {
            let equal = cached_dk.as_slice() == dkey.as_slice();
            if equal {
                let duration = self.cache_duration.unwrap_or(900);
                self.expire_time = Some(now + duration);
                return Ok(true);
            } else {
                return Ok(false);
            }
        }
        let ct = self.ciphertext.as_ref().ok_or(CoreError::EmptyCiphertext)?;

        // zeroize key? Key from array will be dropped; sensitive dkey will be zeroized after decrypt
        match builder::decrypt_xchacha(ct, &dkey, nonce) {
            Ok(_) => {
                self.derived_key = Some(
                    dkey.as_slice()
                        .try_into()
                        .map_err(|_| CoreError::InvalidDerivedKey)?,
                );
                let duration = self
                    .cache_duration
                    .unwrap_or(constants::DEFAULT_CACHE_DURATION);
                self.expire_time = Some(now + duration);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    /// Change the password for the encrypted mnemonic
    ///
    /// # Arguments
    /// * `old_pass` - The current password
    /// * `new_pass` - The new password
    /// * `now` - The current Unix timestamp
    ///
    /// # Returns
    /// * `Ok(true)` - If the password is changed successfully
    /// * `Err(CoreError)` - If there is an error during the password change
    pub fn change_ciphertext_password(
        &mut self,
        old_pass: &str,
        new_pass: &str,
        now: u64,
    ) -> Result<bool, CoreError> {
        validate_password(new_pass)?;
        validate_password(old_pass)?;

        let mut mnemonic = self.get_mnemonic(Some(old_pass), now)?;
        let new_salt = builder::generate_entropy_bytes(ARGON2_SALT_LEN as u64)?;
        let new_nonce = builder::generate_entropy_bytes(XCHACHA_XNONCE_LEN as u64)?;
        let dkey = builder::password_kdf_argon2(new_pass, &new_salt)?;
        let new_ciphertext = builder::encrypt_xchacha(&mnemonic, &dkey, &new_nonce)?;
        mnemonic.zeroize();

        // Convert Vec<u8> to fixed length array
        let mut salt_array = [0u8; ARGON2_SALT_LEN];
        salt_array.copy_from_slice(new_salt.as_slice());
        self.salt = Some(salt_array);

        let mut nonce_array = [0u8; XCHACHA_XNONCE_LEN];
        nonce_array.copy_from_slice(new_nonce.as_slice());
        self.nonce = Some(nonce_array);

        self.ciphertext = Some(new_ciphertext.clone());
        self.derived_key = Some(*dkey);
        self.expire_time = Some(now + DEFAULT_CACHE_DURATION);

        Ok(true)
    }

    /// Create a signer from the mnemonic phrase
    ///
    /// # Arguments
    /// * `password` - The password to decrypt the mnemonic (optional)
    /// * `index` - The derivation index
    /// * `now` - The current Unix timestamp
    ///
    /// # Returns
    /// * `Ok(PrivateKeySigner)` - The created signer
    /// * `Err(CoreError)` - If there is an error during signer creation
    pub(crate) fn create_signer(
        &mut self,
        password: Option<&str>,
        index: u32,
        now: u64,
    ) -> Result<PrivateKeySigner, CoreError> {
        let mnemonic_str = self.get_mnemonic(password, now)?;
        MnemonicBuilder::<English>::default()
            .phrase(&mnemonic_str)
            .index(index)
            .map_err(|_: LocalSignerError| CoreError::SignerBuildError)?
            .build()
            .map_err(|_| CoreError::SignerBuildError)
    }

    /// Get the address for a given index
    ///
    /// # Arguments
    /// * `password` - The password to decrypt the mnemonic (optional)
    /// * `index` - The derivation index
    /// * `now` - The current Unix timestamp
    ///
    /// # Returns
    /// * `Ok(String)` - The derived address in hex format
    /// * `Err(CoreError)` - If there is an error during address derivation
    pub fn get_address(
        &mut self,
        password: Option<String>,
        index: u32,
        now: u64,
    ) -> Result<String, CoreError> {
        let pw = password
            .as_ref()
            .and_then(|s| if s.is_empty() { None } else { Some(s.as_str()) });
        let signer = self.create_signer(pw, index, now)?;
        let address = format!("{:?}", signer.address()); // Use format instead of to_string
        Ok(address)
    }

    /// Retrieve mnemonic (internal)
    ///
    /// # Arguments
    /// * `password` - The password to decrypt the mnemonic (optional)
    /// * `now` - The current Unix timestamp
    ///
    /// # Returns
    /// * `Ok(String)` - The decrypted mnemonic phrase
    /// * `Err(CoreError)` - If there is an error during mnemonic retrieval
    pub(crate) fn get_mnemonic(
        &mut self,
        password: Option<&str>,
        now: u64,
    ) -> Result<String, CoreError> {
        self.tick(now);
        if let Some(pw) = password {
            if pw.is_empty() {
                self.get_mnemonic_dk_impl()
            } else {
                self.get_mnemonic_ps_impl(pw, now)
            }
        } else {
            self.get_mnemonic_dk_impl()
        }
    }

    /// Get mnemonic using derived key implementation
    ///
    /// # Returns
    /// * `Ok(String)` - The decrypted mnemonic phrase
    /// * `Err(CoreError)` - If there is an error during decryption
    fn get_mnemonic_dk_impl(&mut self) -> Result<String, CoreError> {
        if self.expire_time.is_none() && self.derived_key.is_some() {
            // derived_key expired
            if let Some(mut dk) = self.derived_key.take() {
                dk.zeroize();
                self.derived_key = None;
            }
            return Err(CoreError::InvalidDerivedKey);
        }

        let d = self
            .derived_key
            .as_ref()
            .filter(|v| !v.is_empty())
            .ok_or(CoreError::EmptyDerivedKey)?;
        let dkey = Zeroizing::new(*d);
        let nonce = self
            .nonce
            .as_ref()
            .filter(|v| !v.is_empty())
            .ok_or(CoreError::EmptyNonce)?;
        let ct = self
            .ciphertext
            .as_ref()
            .filter(|v| !v.is_empty())
            .ok_or(CoreError::EmptyCiphertext)?;
        let decrypted = builder::decrypt_xchacha(ct, &dkey, nonce.as_slice())?;
        Ok(decrypted)
    }

    /// Get mnemonic using password implementation
    ///
    /// # Arguments
    /// * `password` - The password to derive the key from
    /// * `now` - The current Unix timestamp
    ///
    /// # Returns
    /// * `Ok(String)` - The decrypted mnemonic phrase
    /// * `Err(CoreError)` - If there is an error during decryption
    fn get_mnemonic_ps_impl(&mut self, password: &str, now: u64) -> Result<String, CoreError> {
        let salt = self
            .salt
            .as_ref()
            .filter(|v| !v.is_empty())
            .ok_or(CoreError::EmptySalt)?;
        let dkey = builder::password_kdf_argon2(password, salt.as_slice())?;
        let nonce = self
            .nonce
            .as_ref()
            .filter(|v| !v.is_empty())
            .ok_or(CoreError::EmptyNonce)?;
        let ct = self
            .ciphertext
            .as_ref()
            .filter(|v| !v.is_empty())
            .ok_or(CoreError::EmptyCiphertext)?;

        match builder::decrypt_xchacha(ct, &dkey, nonce.as_slice()) {
            Ok(decrypted) => {
                self.derived_key = Some(*dkey);
                // key will be dropped
                let duration = self
                    .cache_duration
                    .unwrap_or(constants::DEFAULT_CACHE_DURATION);
                self.expire_time = Some(now + duration);
                Ok(decrypted)
            }
            Err(_) => Err(CoreError::InvalidPassword),
        }
    }

    #[cfg(feature = "airgap")]
    /// Import wallet from mnemonic phrase
    ///
    /// # Arguments
    /// * `mnemonic` - The mnemonic phrase to import
    /// * `password` - The password to encrypt the mnemonic
    /// * `duration` - The cache duration in seconds
    /// * `now` - The current Unix timestamp
    ///
    /// # Returns
    /// * `Ok(Vault)` - The created vault
    /// * `Err(CoreError)` - If there is an error during import
    pub fn import_from_mnemonic(
        &mut self,
        mnemonic: &str,
        password: &str,
        duration: u64,
        now: u64,
    ) -> Result<Vault, CoreError> {
        // Validate mnemonic
        validate_mnemonic(mnemonic)?;

        let signer = builder::mnemonic_to_signer(mnemonic, 0)?;
        let address = format!("{:?}", signer.address()); // Use format instead of to_string

        let salt = builder::generate_entropy_bytes(ARGON2_SALT_LEN as u64)?;
        let nonce = builder::generate_entropy_bytes(XCHACHA_XNONCE_LEN as u64)?;
        let dkey = builder::password_kdf_argon2(password, &salt)?;
        let ciphertext = builder::encrypt_xchacha(&mnemonic, &dkey, &nonce)?;

        self.ciphertext = Some(ciphertext.clone());

        let mut salt_array = [0u8; ARGON2_SALT_LEN];
        salt_array.copy_from_slice(salt.as_slice());
        self.salt = Some(salt_array);

        let mut nonce_array = [0u8; XCHACHA_XNONCE_LEN];
        nonce_array.copy_from_slice(nonce.as_slice());
        self.nonce = Some(nonce_array);
        self.expire_time = Some(now + duration); // Simplified implementation
        self.cache_duration = Some(duration);
        self.entropy_bits = Some(128); // Default to 128 bits

        let const_version: [u8; 7] = VERSION_TAG_1.as_bytes().try_into().unwrap();
        Ok(Vault {
            version: const_version,
            ciphertext,
            salt: salt_array,
            nonce: nonce_array,
        })
    }

    #[cfg(feature = "airgap")]
    /// Export mnemonic phrase
    ///
    /// # Arguments
    /// * `password` - The password to decrypt the mnemonic (optional)
    /// * `now` - The current Unix timestamp
    ///
    /// # Returns
    /// * `Ok(String)` - The decrypted mnemonic phrase
    /// * `Err(CoreError)` - If there is an error during export
    pub fn export_to_mnemonic(
        &mut self,
        password: Option<&str>,
        now: u64,
    ) -> Result<String, CoreError> {
        let mnemonic = Zeroizing::new(self.get_mnemonic(password, now)?);
        validate_mnemonic(&mnemonic)?;
        Ok((*mnemonic).clone())
    }
}
