#![no_std]

// 引入必要的模块
extern crate alloc;

// 引入标准库中的模块
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

// 引入第三方库
use alloy_signer_local::LocalSignerError;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use hex::encode as hex_encode;
use zeroize::{Zeroize, Zeroizing};

// 引入本地模块
mod builder;
mod constants;
mod error;
mod message;
mod tx;
mod validate;

// 引入本地模块中的内容
pub use builder::*;
use constants::*;
use error::CoreError;
pub use message::*;
pub use tx::*;
use validate::*;

// 定义 CoreState 结构体
#[derive(Debug, Clone)]
pub struct CoreState {
    pub ciphertext: Option<Vec<u8>>,
    pub derived_key: Option<[u8; 32]>, // 固定长度32字节
    pub salt: Option<[u8; constants::ARGON2_SALT_LEN]>, // 固定长度32字节
    pub nonce: Option<[u8; constants::XCHACHA_XNONCE_LEN]>, // 固定长度24字节
    pub expire_time: Option<u64>,
    pub cache_duration: Option<u64>,
    pub entropy_bits: Option<u64>,
}

// 定义 Vault 结构体
#[derive(Debug, Clone)]
pub struct Vault {
    pub ciphertext: Vec<u8>,
    pub salt: [u8; constants::ARGON2_SALT_LEN], // 固定长度32字节
    pub nonce: [u8; constants::XCHACHA_XNONCE_LEN], // 固定长度24字节
    pub address0: Option<String>,
}

// CoreState 实现
impl CoreState {
    pub fn new() -> CoreState {
        CoreState {
            ciphertext: None,
            derived_key: None,
            salt: None,
            nonce: None,
            expire_time: None,
            cache_duration: Some(constants::DEFAULT_CACHE_DURATION),
            entropy_bits: Some(constants::DEFAULT_ENTROPY_BITS),
        }
    }

    pub fn load_vault(
        &mut self,
        ciphertext: Vec<u8>,
        salt: [u8; constants::ARGON2_SALT_LEN], // 固定长度32字节
        nonce: [u8; constants::XCHACHA_XNONCE_LEN], // 固定长度24字节
    ) -> Result<(), CoreError> {
        if ciphertext.is_empty() {
            return Err(CoreError::EmptyCiphertext);
        }
        validate::validate_salt(salt.clone())?;
        validate::validate_nonce(nonce.clone())?;
        self.derived_key = None;
        self.expire_time = None;
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

    pub fn set_entropy_bits(&mut self, bits: u64) -> Result<(), CoreError> {
        match bits {
            constants::ENTROPY_128 | constants::ENTROPY_256 => {
                self.entropy_bits = Some(bits);
                Ok(())
            }
            _ => Err(CoreError::InvalidEntropyBits),
        }
    }

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

    pub fn get_salt(&self) -> Result<String, CoreError> {
        if let Some(s) = &self.salt {
            return Ok(hex_encode(s));
        }
        Err(CoreError::EmptySalt)
    }

    pub fn get_nonce(&self) -> Result<String, CoreError> {
        if let Some(n) = &self.nonce {
            return Ok(hex_encode(n));
        }
        Err(CoreError::EmptyNonce)
    }

    pub fn get_expire_time(&self) -> Result<u64, CoreError> {
        self.expire_time.ok_or(CoreError::EmptyCacheTime)
    }

    /// Expire cache if needed, zeroize derived key when removed.
    pub fn tick(&mut self, now: u64) {
        if let Some(ct) = self.expire_time {
            if now > ct {
                if let Some(mut dk) = self.derived_key.take() {
                    dk.zeroize();
                }
                self.expire_time = None;
            }
        }
        if self.expire_time.is_none()
            && let Some(mut dk) = self.derived_key.take()
        {
            // 对于 HeaplessVec，我们需要手动清零
            for byte in dk.iter_mut() {
                *byte = 0;
            }
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
        now: u64,
    ) -> Result<Vault, CoreError> {
        validate_entropy(entropy_bits)?;
        validate_password(password)?;
        let salt = builder::generate_entropy_bytes(ARGON2_SALT_LEN as u64)?;
        let nonce = builder::generate_entropy_bytes(XCHACHA_XNONCE_LEN as u64)?;
        let entropy = builder::generate_entropy_bits(entropy_bits)?;
        let mnemonic = builder::entropy_to_mnemonic(&entropy)?;
        let signer = builder::mnemonic_to_signer(&mnemonic, 0)?;
        let address = format!("{:?}", signer.address()); // 使用 format 替代 to_string
        let dkey = builder::password_kdf_argon2(password, &salt)?;
        let ciphertext = builder::encrypt_xchacha(&mnemonic, &dkey, &nonce)?;

        self.ciphertext = Some(ciphertext.clone());

        // 将 Vec<u8> 转换为固定长度数组
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

        Ok(Vault {
            ciphertext,
            salt: salt_array,
            nonce: nonce_array,
            address0: Some(address),
        })
    }

    pub fn derive_account(
        &mut self,
        password: &str,
        index: u32,
        now: u64,
    ) -> Result<String, CoreError> {
        let mnemonic_str = match self.get_mnemonic(
            if password.is_empty() {
                None
            } else {
                Some(password)
            },
            now,
        ) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let signer = builder::mnemonic_to_signer(&mnemonic_str, index)?;
        Ok(format!("{:?}", signer.address())) // 使用 format 替代 to_string
    }

    /// Verify password and cache derived key
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

    pub fn change_ciphertext_password(
        &mut self,
        old_pass: &str,
        new_pass: &str,
        now: u64,
    ) -> Result<Vault, CoreError> {
        validate_password(new_pass)?;
        validate_password(old_pass)?;

        let mut mnemonic = match self.get_mnemonic(Some(old_pass), now) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let new_salt = builder::generate_entropy_bytes(ARGON2_SALT_LEN as u64)?;
        let new_nonce = builder::generate_entropy_bytes(XCHACHA_XNONCE_LEN as u64)?;

        let signer = builder::mnemonic_to_signer(&mnemonic, 0)?;
        let address = format!("{:?}", signer.address()); // 使用 format 替代 to_string
        let dkey = builder::password_kdf_argon2(new_pass, &new_salt)?;
        let new_ciphertext = builder::encrypt_xchacha(&mnemonic, &dkey, &new_nonce)?;
        mnemonic.zeroize();

        // 将 Vec<u8> 转换为固定长度数组
        let mut salt_array = [0u8; ARGON2_SALT_LEN];
        salt_array.copy_from_slice(new_salt.as_slice());
        self.salt = Some(salt_array);

        let mut nonce_array = [0u8; XCHACHA_XNONCE_LEN];
        nonce_array.copy_from_slice(new_nonce.as_slice());
        self.nonce = Some(nonce_array);

        self.ciphertext = Some(new_ciphertext.clone());
        self.derived_key = Some(*dkey);

        // 移除时间相关的代码
        Ok(Vault {
            ciphertext: new_ciphertext,
            salt: salt_array,
            nonce: nonce_array,
            address0: Some(address),
        })
    }

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
        let address = format!("{:?}", signer.address()); // 使用 format 替代 to_string
        Ok(address)
    }

    /// Retrieve mnemonic (internal)
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
        let dkey = Zeroizing::new(d.clone());
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
        let decrypted = builder::decrypt_xchacha(&ct, &dkey, &nonce.as_slice())?;
        Ok(decrypted)
    }

    fn get_mnemonic_ps_impl(&mut self, password: &str, now: u64) -> Result<String, CoreError> {
        let salt = self
            .salt
            .as_ref()
            .filter(|v| !v.is_empty())
            .ok_or(CoreError::EmptySalt)?;
        let dkey = builder::password_kdf_argon2(password, &salt.as_slice())?;
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

        match builder::decrypt_xchacha(&ct, &dkey, &nonce.as_slice()) {
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
    //  #[cfg(feature = "airgap")]
    pub fn import_from_mnemonic(
        &mut self,
        mnemonic: &str,
        password: &str,
        duration: u64,
        now: u64,
    ) -> Result<Vault, CoreError> {
        // 验证助记词
        validate_mnemonic(mnemonic)?;

        let signer = builder::mnemonic_to_signer(mnemonic, 0)?;
        let address = format!("{:?}", signer.address()); // 使用 format 替代 to_string

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
        self.expire_time = Some(now + duration); // 简化实现
        self.cache_duration = Some(duration);
        self.entropy_bits = Some(128); // 默认128位

        Ok(Vault {
            ciphertext,
            salt: salt_array,
            nonce: nonce_array,
            address0: Some(address),
        })
    }
}
