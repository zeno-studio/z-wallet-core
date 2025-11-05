use alloy_signer_local::{
    LocalSignerError, MnemonicBuilder, PrivateKeySigner, coins_bip39::English,
};
use hex::encode as hex_encode;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

mod error;
pub use error::*;
mod eip712;
pub use eip712::EIP712;
mod constants;
pub use constants::*;
mod validate;
pub use validate::*;
mod builder;
pub use builder::*;
mod tx;
pub use tx::*;
mod message;
pub use message::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletState {
    ciphertext: Option<Vec<u8>>,
    derived_key: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    cache_time: Option<u64>,
    cache_duration: Option<u64>,
    entropy_bits: Option<u64>,
}

#[derive(Debug, Clone,Serialize, Deserialize)]
pub struct Vault {
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub address0: Option<String>,
}

impl Default for WalletState {
    fn default() -> Self {
        Self::new()
    }
}

impl WalletState {
    pub fn new() -> WalletState {
        WalletState {
            ciphertext: None,
            derived_key: None,
            salt: None,
            nonce: None,
            cache_time: None,
            cache_duration: Some(constants::DEFAULT_CACHE_DURATION),
            entropy_bits: Some(constants::DEFAULT_ENTROPY_BITS),
        }
    }

    pub fn load_vault(
        &mut self,
        ciphertext: Vec<u8>,
        salt: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<(), WalletError> {
        if ciphertext.is_empty() {
            return Err(WalletError::EmptyCiphertext);
        }
        validate::validate_salt(salt.clone())?;
        validate::validate_nonce(nonce.clone())?;
        self.derived_key = None;
        self.cache_time = None;
        self.cache_duration = Some(900);
        self.entropy_bits = Some(128);
        self.ciphertext = Some(ciphertext);
        self.salt = Some(salt);
        self.nonce = Some(nonce);
        Ok(())
    }

    pub fn set_cache_duration(&mut self, duration: u64) {
        self.cache_duration = Some(duration);
    }

    /// Return cache duration
    pub fn get_cache_duration(&self) -> u64 {
        self.cache_duration
            .unwrap_or(constants::DEFAULT_CACHE_DURATION)
    }

    pub fn set_entropy_bits(&mut self, bits: u64) -> Result<(), WalletError> {
        match bits {
            constants::ENTROPY_128 | constants::ENTROPY_256 => {
                self.entropy_bits = Some(bits);
                Ok(())
            }
            _ => Err(WalletError::InvalidEntropyBits),
        }
    }

    pub fn get_entropy_bits(&self) -> u64 {
        self.entropy_bits.unwrap_or(constants::DEFAULT_ENTROPY_BITS)
    }

    /// Return ciphertext hex (does NOT consume stored ciphertext).
    pub fn get_ciphertext(&self) -> Result<String, WalletError> {
        if let Some(ct) = &self.ciphertext {
            return Ok(hex_encode(ct));
        }
        Err(WalletError::EmptyCiphertext)
    }

    pub fn get_salt(&self) -> Result<String, WalletError> {
        if let Some(s) = &self.salt {
            return Ok(hex_encode(s));
        }
        Err(WalletError::EmptySalt)
    }

    pub fn get_nonce(&self) -> Result<String, WalletError> {
        if let Some(n) = &self.nonce {
            return Ok(hex_encode(n));
        }
        Err(WalletError::EmptyNonce)
    }

    pub fn get_cache_time(&self) -> Result<u64, WalletError> {
        self.cache_time.ok_or(WalletError::EmptyCacheTime)
    }

    /// Expire cache if needed, zeroize derived key when removed.
    pub fn tick(&mut self) {
        if let Some(ct) = self.cache_time {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > ct {
                if let Some(mut dk) = self.derived_key.take() {
                    dk.zeroize();
                }
                self.cache_time = None;
            }
        }
        // ensure no dangling derived_key without cache_time
        if self.cache_time.is_none()
            && let Some(mut dk) = self.derived_key.take()
        {
            dk.zeroize();
        }
    }

    pub fn has_derived_key(&self) -> bool {
        // do not mutate here; tick() handles expiry/zeroize
        self.derived_key.is_some()
    }
    pub fn create_vault(
        &mut self,
        password: &str,
        entropy_bits: u64,
        duration: u64,
    ) -> Result<Vault, WalletError> {
        validate_entropy(entropy_bits)?;
        validate_password(password)?;
        let salt = builder::generate_entropy(XCHACHA_SALT_LEN as u64)?;
        let nonce = builder::generate_entropy(XCHACHA_XNONCE_LEN as u64)?;
        let entropy = builder::generate_entropy(entropy_bits)?;
        let mnemonic = builder::entropy_to_mnemonic(&entropy)?;
        let signer = builder::mnemonic_to_signer(&mnemonic, 0)?;
        let address = signer.address().to_string();
        let dkey = builder::password_kdf_argon2(password, &salt)?;
        let ciphertext = builder::encrypt_xchacha(&mnemonic, &dkey, &nonce)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.ciphertext = Some(ciphertext.clone());
        self.derived_key = Some(dkey.to_vec());
        self.salt = Some(salt.clone().to_vec());
        self.nonce = Some(nonce.clone().to_vec());
        self.cache_time = Some(now + duration);
        self.cache_duration = Some(duration);
        self.entropy_bits = Some(entropy_bits);
        let ciphertext = builder::encrypt_xchacha(&mnemonic, &dkey, &nonce)?; // ← 独立！

        Ok(Vault {
            ciphertext,
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            address0: Some(address),
        })
    }

    pub fn derive_account(&mut self, password: &str, index: u32) -> Result<String, WalletError> {
        let mnemonic_str = match self.get_mnemonic(if password.is_empty() {
            None
        } else {
            Some(password)
        }) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let signer = builder::mnemonic_to_signer(&mnemonic_str, index)?;
        Ok(signer.address().to_string())
    }

    /// Verify password and cache derived key
    pub fn verify_password(&mut self, password: &str) -> Result<bool, WalletError> {
        self.tick();

        let salt = self.salt.as_ref().ok_or(WalletError::InvalidSalt)?;
        validate_salt(salt.clone())?;
        let nonce = self.nonce.as_ref().ok_or(WalletError::InvalidNonce)?;
        validate_nonce(nonce.clone())?;

        let dkey = builder::password_kdf_argon2(password, &salt)?;

        if let Some(cached_dk) = &self.derived_key {
            let equal = cached_dk.as_slice() == dkey.as_slice();
            if equal {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let duration = self.cache_duration.unwrap_or(900);
                self.cache_time = Some(now + duration);
                return Ok(true);
            } else {
                return Ok(false);
            }
        }
        let ct = self
            .ciphertext
            .as_ref()
            .ok_or(WalletError::EmptyCiphertext)?;

        // zeroize key? Key from array will be dropped; sensitive dkey will be zeroized after decrypt
        match builder::decrypt_xchacha(ct, &dkey, &nonce) {
            Ok(_) => {
                self.derived_key = Some(dkey.to_vec());
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let duration = self
                    .cache_duration
                    .unwrap_or(constants::DEFAULT_CACHE_DURATION);
                self.cache_time = Some(now + duration);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    pub fn change_ciphertext_password(
        &mut self,
        old_pass: &str,
        new_pass: &str,
    ) -> Result<Vault, WalletError> {
        validate_password(new_pass)?;
        validate_password(old_pass)?;

        let mut mnemonic = match self.get_mnemonic(Some(old_pass)) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let new_salt = builder::generate_entropy(XCHACHA_SALT_LEN as u64)?;
        let new_nonce = builder::generate_entropy(XCHACHA_XNONCE_LEN as u64)?;

        let signer = builder::mnemonic_to_signer(&mnemonic, 0)?;
        let address = signer.address().to_string();
        let dkey = builder::password_kdf_argon2(new_pass, &new_salt)?;
        let new_ciphertext = builder::encrypt_xchacha(&mnemonic, &dkey, &new_nonce)?;
        mnemonic.zeroize();

        self.salt = Some(new_salt.clone().to_vec());
        self.nonce = Some(new_nonce.to_vec());
        self.ciphertext = Some(new_ciphertext.clone());
        self.derived_key = Some(dkey.to_vec());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let duration = self
            .cache_duration
            .unwrap_or(constants::DEFAULT_CACHE_DURATION);
        self.cache_time = Some(now + duration);
        Ok(Vault {
            ciphertext: new_ciphertext,
            salt: new_salt.to_vec(),
            nonce: new_nonce.to_vec(),
            address0: Some(address),
        })
    }

    pub(crate) fn create_signer(
        &mut self,
        password: Option<&str>,
        index: u32,
    ) -> Result<PrivateKeySigner, WalletError> {
        let mnemonic_str = self.get_mnemonic(password)?;
        MnemonicBuilder::<English>::default()
            .phrase(&mnemonic_str)
            .index(index)
            .map_err(|_: LocalSignerError| WalletError::SignerBuildError)?
            .build()
            .map_err(|_| WalletError::SignerBuildError)
    }

    pub fn get_address(
        &mut self,
        password: Option<String>,
        index: u32,
    ) -> Result<String, WalletError> {
        let pw = password
            .as_ref()
            .and_then(|s| if s.is_empty() { None } else { Some(s.as_str()) });
        let signer = self.create_signer(pw, index)?;
        let address = signer.address().to_string();
        Ok(address)
    }

    /// Retrieve mnemonic (internal)
    pub(crate) fn get_mnemonic(&mut self, password: Option<&str>) -> Result<String, WalletError> {
        if let Some(pw) = password {
            if pw.is_empty() {
                self.get_mnemonic_dk_impl()
            } else {
                self.get_mnemonic_ps_impl(pw)
            }
        } else {
            self.get_mnemonic_dk_impl()
        }
    }

    fn get_mnemonic_dk_impl(&mut self) -> Result<String, WalletError> {
        if self.cache_time.is_none() && self.derived_key.is_some() {
            // derived_key expired
            if let Some(mut dk) = self.derived_key.take() {
                dk.zeroize();
                self.derived_key = None;
            }
            return Err(WalletError::InvalidDerivedKey);
        }

        let dkey = self
            .derived_key
            .as_ref()
            .ok_or(WalletError::InvalidDerivedKey)?;
        if dkey.len() != constants::ARGON2_OUTPUT_LEN {
            return Err(WalletError::InvalidDerivedKey);
        }
        let dkey_array: [u8; constants::ARGON2_OUTPUT_LEN] = dkey
            .as_slice()
            .try_into()
            .map_err(|_| WalletError::InvalidDerivedKey)?;
        let dkey = Zeroizing::new(dkey_array);

        let nonce = self.nonce.as_ref().ok_or(WalletError::InvalidNonce)?;
        validate_nonce(nonce.clone())?;
        let ct = self
            .ciphertext
            .as_ref()
            .ok_or(WalletError::EmptyCiphertext)?;
        let decrypted = builder::decrypt_xchacha(&ct, &dkey, &nonce)?;
        Ok(decrypted)
    }

    fn get_mnemonic_ps_impl(&mut self, password: &str) -> Result<String, WalletError> {
        let salt = self.salt.as_ref().ok_or(WalletError::InvalidSalt)?;
        validate_salt(salt.clone())?;
        let dkey = builder::password_kdf_argon2(password, &salt)?;
        let nonce = self.nonce.as_ref().ok_or(WalletError::InvalidNonce)?;
        let ct = self
            .ciphertext
            .as_ref()
            .ok_or(WalletError::EmptyCiphertext)?;
        validate_nonce(nonce.clone())?;
        match builder::decrypt_xchacha(&ct, &dkey, &nonce) {
            Ok(decrypted) => {
                self.derived_key = Some(dkey.to_vec());
                // key will be dropped
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let duration = self
                    .cache_duration
                    .unwrap_or(constants::DEFAULT_CACHE_DURATION);
                self.cache_time = Some(now + duration);
                Ok(decrypted)
            }
            Err(_) => Err(WalletError::InvalidPassword),
        }
    }

     #[cfg(feature = "airgap")]
     pub fn import_from_mnemonic(&mut self, mnemonic: &str, password: &str, duration: u64) -> Result<Vault, WalletError> {
        // 验证助记词
        validate_mnemonic(mnemonic)?;
        
        let signer = builder::mnemonic_to_signer(mnemonic, 0)?;
        let address = signer.address().to_string();
        
        let salt = builder::generate_entropy(XCHACHA_SALT_LEN as u64)?;
        let nonce = builder::generate_entropy(XCHACHA_XNONCE_LEN as u64)?;
        let dkey = builder::password_kdf_argon2(password, &salt)?;
        let ciphertext = builder::encrypt_xchacha(mnemonic, &dkey, &nonce)?;
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        self.ciphertext = Some(ciphertext.clone());
        self.derived_key = Some(dkey.to_vec());
        self.salt = Some(salt.clone().to_vec());
        self.nonce = Some(nonce.clone().to_vec());
        self.cache_time = Some(now + duration);
        self.cache_duration = Some(duration);
        self.entropy_bits = Some(128); // 默认128位
        
        Ok(Vault {
            ciphertext,
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            address0: Some(address),
        })
    }
    
}
