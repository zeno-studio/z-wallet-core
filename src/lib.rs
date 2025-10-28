use alloy_consensus::{Signed, TxEip1559, TxEip7702, TxLegacy};
use alloy_eips::eip2930::AccessList;
use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, Signature, TxKind, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::{
    LocalSignerError, MnemonicBuilder, PrivateKeySigner, coins_bip39::English,
};
use argon2::Argon2;
use bip39::{Language, Mnemonic};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use core::str::FromStr;
use hex::{decode as hex_decode, encode as hex_encode};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use std::time::{SystemTime, UNIX_EPOCH};

mod error;
pub use error::*;

mod eip712;
pub use eip712::EIP712;





const ARGON2_MEMORY: u32 = 12288; // KB
const ARGON2_ITERATIONS: u32 = 4;
const ARGON2_PARALLELISM: u32 = 2;
const ARGON2_OUTPUT_LEN: usize = 32;
const SALT_LEN: usize = 16;
const XNONCE_LEN: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletState {
    ciphertext: Option<Vec<u8>>,
    derived_key: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    cache_time: Option<u64>,
    cache_duration: Option<u64>,
    entropy_bits: Option<usize>,
}

#[derive(Serialize, Deserialize)]
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
            cache_duration: Some(900),
            entropy_bits: Some(128),
        }
    }

    pub fn load_vault(&mut self, ciphertext: Vec<u8>, salt: Vec<u8>, nonce: Vec<u8>) -> Result<(), WalletError> {
        if ciphertext.is_empty() {
            return Err(WalletError::EmptyCiphertext);
        }
        if nonce.len() != XNONCE_LEN {
            return Err(WalletError::InvalidNonce);
        }
        if salt.len() != SALT_LEN {
            return Err(WalletError::InvalidSalt);
        }
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
        self.cache_duration.unwrap_or(900)
    }

    pub fn set_entropy_bits(&mut self, bits: usize) -> Result<(), WalletError> {
        match bits {
            128 | 256 => {
                self.entropy_bits = Some(bits);
                Ok(())
            }
            _ => Err(WalletError::InvalidEntropyBits),
        }
    }

    pub fn get_entropy_bits(&self) -> usize {
        self.entropy_bits.unwrap_or(128)
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
        if self.cache_time.is_none() && let Some(mut dk) = self.derived_key.take() {
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
        salt: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<Vault, WalletError> {
        if entropy_bits != 128 && entropy_bits != 256 {
            return Err(WalletError::InvalidEntropyBits);
        }
        let entropy_bits_usize = entropy_bits as usize;
        if salt.is_empty() {
            return Err(WalletError::EmptySalt);
        }
        if nonce.len() != XNONCE_LEN {
            return Err(WalletError::InvalidNonce);
        }
        if password.is_empty() {
            return Err(WalletError::EmptyPassword);
        }

        let entropy_bytes = (entropy_bits_usize) / 8;
        let mut entropy = vec![0u8; entropy_bytes];
        if getrandom::fill(&mut entropy).is_err() {
            return Err(WalletError::EntropyGenerationFailed);
        }

        let mut mnemonic = match Mnemonic::from_entropy_in(Language::English, &entropy) {
            Ok(m) => m,
            Err(_) => {
                entropy.zeroize();
                return Err(WalletError::MnemonicGenerationFailed);
            }
        };
        entropy.zeroize();
        let mut phrase = mnemonic.to_string();
        mnemonic.zeroize();

        let signer = match MnemonicBuilder::<English>::default()
            .phrase(&phrase)
            .index(0u32)
            .map_err(|_| WalletError::SignerBuildError)
            .and_then(|builder| builder.build().map_err(|_| WalletError::SignerBuildError))
        {
            Ok(s) => s,
            Err(e) => {
                phrase.zeroize();
                return Err(e);
            }
        };
        let address_str = signer.address().to_string();

        let mut dkey = [0u8; ARGON2_OUTPUT_LEN];
        let params = match argon2::Params::new(
            ARGON2_MEMORY,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(ARGON2_OUTPUT_LEN),
        ) {
            Ok(p) => p,
            Err(_) => {
                phrase.zeroize();
                return Err(WalletError::Argon2BuildError);
            }
        };
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        if argon2.hash_password_into(password.as_bytes(), &salt, &mut dkey).is_err() {
            phrase.zeroize();
            return Err(WalletError::PasswordHashError);
        }

        let mut key = Key::from(dkey);
        let nonce_array: [u8; XNONCE_LEN] = match nonce.clone().try_into() {
            Ok(n) => n,
            Err(_) => {
                // zeroize sensitive
                key.zeroize();
                dkey.zeroize();
                phrase.zeroize();
                return Err(WalletError::InvalidNonce);
            }
        };
        let xnonce = XNonce::from(nonce_array);
        let cipher = XChaCha20Poly1305::new(&key);
        let ciphertext = match cipher.encrypt(&xnonce, phrase.as_bytes()) {
            Ok(c) => c,
            Err(_) => {
                // zeroize
                // Key does not implement Zeroize, but underlying dkey will be zeroized below
                phrase.zeroize();
                return Err(WalletError::EncryptionFailed);
            }
        };
        phrase.zeroize();
        // zeroize dkey array
        let dkey_vec = dkey.to_vec();
        // zeroize local array
        dkey.zeroize();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.ciphertext = Some(ciphertext.clone());
        self.derived_key = Some(dkey_vec);
        self.salt = Some(salt.clone());
        self.nonce = Some(nonce.clone());
        self.cache_time = Some(now + duration);
        self.cache_duration = Some(duration);
        self.entropy_bits = Some(entropy_bits_usize);

        let vault = Vault {
            ciphertext,
            salt,
            nonce,
            address0: Some(address_str),
        };

        Ok(vault)
    }

    pub fn derive_account(&mut self, password: &str, index: u32) -> Result<String, WalletError> {
        let mnemonic_str = match self.get_mnemonic(if password.is_empty() { None } else { Some(password) }) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let signer = match MnemonicBuilder::<English>::default()
            .phrase(&mnemonic_str)
            .index(index)
            .map_err(|_| WalletError::SignerBuildError)
            .and_then(|builder| builder.build().map_err(|_| WalletError::SignerBuildError))
        {
            Ok(s) => s,
            Err(_) => {
                // zeroize mnemonic
                // mnemonic_str may be sensitive
                return Err(WalletError::SignerBuildError);
            }
        };

        let address: Address = signer.address();
        Ok(address.to_string())
    }

    /// Verify password and cache derived key
    pub fn verify_password(&mut self, password: &str) -> Result<bool, WalletError> {
        self.tick();

        let salt_bytes = self.salt.as_ref().ok_or(WalletError::InvalidSalt)?;
        if salt_bytes.is_empty() {
            return Err(WalletError::InvalidSalt);
        }

        let mut dkey = [0u8; ARGON2_OUTPUT_LEN];
        let params = argon2::Params::new(
            ARGON2_MEMORY,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(|_| WalletError::Argon2BuildError)?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        argon2.hash_password_into(password.as_bytes(), salt_bytes, &mut dkey)
            .map_err(|_| WalletError::PasswordHashError)?;

        if let Some(cached_dk) = &self.derived_key {
            let equal = cached_dk.as_slice() == dkey.as_slice();
            if equal {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let duration = self.cache_duration.unwrap_or(900);
                self.cache_time = Some(now + duration);
                dkey.zeroize();
                return Ok(true);
            } else {
                dkey.zeroize();
                return Ok(false);
            }
        }

        let key = Key::from(dkey);
        let nonce_bytes = self.nonce.as_ref().ok_or(WalletError::InvalidNonce)?;
        if nonce_bytes.len() != XNONCE_LEN {
            return Err(WalletError::InvalidNonce);
        }
        let nonce_array: [u8; XNONCE_LEN] = nonce_bytes.clone().try_into().map_err(|_| WalletError::InvalidNonce)?;
        let xnonce = XNonce::from(nonce_array);
        let ct = self.ciphertext.as_ref().ok_or(WalletError::EmptyCiphertext)?;
        let cipher = XChaCha20Poly1305::new(&key);
        // zeroize key? Key from array will be dropped; sensitive dkey will be zeroized after decrypt
        match cipher.decrypt(&xnonce, ct.as_ref()) {
            Ok(decrypted) => {
                let _ = String::from_utf8(decrypted).map_err(|_| WalletError::DecryptionFailed)?;
                self.derived_key = Some(dkey.to_vec());
                dkey.zeroize();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let duration = self.cache_duration.unwrap_or(900);
                self.cache_time = Some(now + duration);
                Ok(true)
            }
            Err(_) => {
                dkey.zeroize();
                Ok(false)
            }
        }
    }

    pub fn change_ciphertext_password(
        &mut self,
        old_pass: &str,
        new_pass: &str,
        new_salt: Vec<u8>,
        new_nonce: Vec<u8>,
    ) -> Result<(), WalletError> {
        if new_salt.is_empty() {
            return Err(WalletError::InvalidSalt);
        }
        if new_nonce.len() != XNONCE_LEN {
            return Err(WalletError::InvalidNonce);
        }
        if old_pass.is_empty() || new_pass.is_empty() {
            return Err(WalletError::EmptyPassword);
        }

        let mut mnemonic_str = match self.get_mnemonic(Some(old_pass)) {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let mut new_dk = [0u8; ARGON2_OUTPUT_LEN];
        let params = match argon2::Params::new(
            ARGON2_MEMORY,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(ARGON2_OUTPUT_LEN),
        ) {
            Ok(p) => p,
            Err(_) => return Err(WalletError::Argon2BuildError),
        };
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        if argon2.hash_password_into(new_pass.as_bytes(), &new_salt, &mut new_dk).is_err() {
            return Err(WalletError::PasswordHashError);
        }

        let key = Key::from(new_dk);
        let nonce_array: [u8; XNONCE_LEN] = match new_nonce.clone().try_into() {
            Ok(n) => n,
            Err(_) => {
                // zeroize
                // new_dk will be dropped below
                return Err(WalletError::InvalidNonce);
            }
        };
        let xnonce = XNonce::from(nonce_array);
        let cipher = XChaCha20Poly1305::new(&key);
        let new_ciphertext = match cipher.encrypt(&xnonce, mnemonic_str.as_bytes()) {
            Ok(ct) => ct,
            Err(_) => {
                mnemonic_str.zeroize();
                return Err(WalletError::EncryptionFailed);
            }
        };
        mnemonic_str.zeroize();

        self.salt = Some(new_salt);
        self.nonce = Some(new_nonce);
        self.ciphertext = Some(new_ciphertext.clone());
        self.derived_key = Some(new_dk.to_vec());
        new_dk.zeroize();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let duration = self.cache_duration.unwrap_or(900);
        self.cache_time = Some(now + duration);

        Ok(())
    }

    fn create_signer(&mut self, password: Option<&str>, index: u32) -> Result<PrivateKeySigner, WalletError> {
        let mnemonic_str = self.get_mnemonic(password)?;
        MnemonicBuilder::<English>::default()
            .phrase(&mnemonic_str)
            .index(index)
            .map_err(|_: LocalSignerError| WalletError::SignerBuildError)?
            .build()
            .map_err(|_| WalletError::SignerBuildError)
    }

    pub fn sign_eip155_transaction(
        &mut self,
        password: Option<String>,
        index: u32,
        nonce: u64,
        gas_price_wei: &str,
        gas_limit: u64,
        to: Option<String>,
        value_wei: &str,
        data_hex: Option<String>,
        chain_id: Option<u64>,
    ) -> Result<String, WalletError> {
        if let Some(id) = chain_id && id == 0 {
            return Err(WalletError::InvalidChainId);
        }
        if gas_limit < 21_000 {
            return Err(WalletError::InvalidGasLimit);
        }
        let pw = password.as_ref().and_then(|s| if s.is_empty() { None } else { Some(s.as_str()) });
        let signer = self.create_signer(pw, index)?;

        // parse as U256 and convert to u128
        let gas_price = match U256::from_str(gas_price_wei) {
            Ok(g) => match g.try_into() {
                Ok(val) => val,
                Err(_) => return Err(WalletError::InvalidGasPrice),
            },
            Err(_) => return Err(WalletError::InvalidGasPrice),
        };

        let to_txkind: TxKind = match to.as_ref() {
            Some(s) if !s.is_empty() => match Address::from_str(s) {
                Ok(a) => TxKind::Call(a),
                Err(_) => return Err(WalletError::InvalidAddress),
            },
            _ => TxKind::Create,
        };

        let value = match U256::from_str(value_wei) {
            Ok(v) => v,
            Err(_) => return Err(WalletError::InvalidValue),
        };

        let input_bytes = match parse_bytes_opt(data_hex) {
            Ok(b) => b,
            Err(_) => return Err(WalletError::InvalidTxData),
        };

        let mut tx = TxLegacy {
            to: to_txkind,
            value,
            gas_limit,
            nonce,
            gas_price,
            input: input_bytes,
            chain_id,
        };

        let signature = signer.sign_transaction_sync(&mut tx)
            .map_err(|_| WalletError::SignTransactionError)?;

        let signed = Signed::new_unhashed(tx, signature);
        let mut buf = Vec::with_capacity(signed.rlp_encoded_length());
        signed.rlp_encode(&mut buf);
        let result = format!("0x{}", hex_encode(buf));

        Ok(result)
    }

    pub fn sign_eip1559_transaction(
        &mut self,
        password: Option<String>,
        index: u32,
        nonce: u64,
        max_priority_fee_per_gas_wei: &str,
        max_fee_per_gas_wei: &str,
        gas_limit: u64,
        to: Option<String>,
        value_wei: &str,
        data_hex: Option<String>,
        chain_id: u64,
        access_list_json: Option<String>,
    ) -> Result<String, WalletError> {
        if chain_id == 0 {
            return Err(WalletError::InvalidChainId);
        }
        if gas_limit < 21_000 {
            return Err(WalletError::InvalidGasLimit);
        }
        let pw = password.as_ref().and_then(|s| if s.is_empty() { None } else { Some(s.as_str()) });
        let signer = self.create_signer(pw, index)?;

        let max_priority_fee_per_gas = match U256::from_str(max_priority_fee_per_gas_wei) {
            Ok(v) => match v.try_into() {
                Ok(val) => val,
                Err(_) => return Err(WalletError::InvalidMaxPriorityFee),
            },
            Err(_) => return Err(WalletError::InvalidMaxPriorityFee),
        };

        let max_fee_per_gas = match U256::from_str(max_fee_per_gas_wei) {
            Ok(v) => match v.try_into() {
                Ok(val) => val,
                Err(_) => return Err(WalletError::InvalidMaxFee),
            },
            Err(_) => return Err(WalletError::InvalidMaxFee),
        };

        if max_priority_fee_per_gas > max_fee_per_gas {
            return Err(WalletError::InvalidMaxPriorityFee);
        }

        let to_txkind: TxKind = match to.as_ref() {
            Some(s) if !s.is_empty() => match Address::from_str(s) {
                Ok(a) => TxKind::Call(a),
                Err(_) => return Err(WalletError::InvalidAddress),
            },
            _ => TxKind::Create,
        };

        let value = match U256::from_str(value_wei) {
            Ok(v) => v,
            Err(_) => return Err(WalletError::InvalidValue),
        };

        let input_bytes = match parse_bytes_opt(data_hex) {
            Ok(b) => b,
            Err(_) => return Err(WalletError::InvalidTxData),
        };

        let access_list: AccessList = match access_list_json {
            None => AccessList::default(),
            Some(ref s) if s.is_empty() => AccessList::default(),
            Some(ref s) => serde_json::from_str(s).map_err(|_| WalletError::InvalidAccessList)?,
        };

        let mut tx = TxEip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: to_txkind,
            value,
            input: input_bytes,
            access_list,
        };

        let signature = signer.sign_transaction_sync(&mut tx)
            .map_err(|_| WalletError::SignTransactionError)?;

        let signed = Signed::new_unhashed(tx, signature);
        let mut buf = Vec::with_capacity(signed.rlp_encoded_length());
        signed.rlp_encode(&mut buf);
        let result = format!("0x{}", hex_encode(buf));

        Ok(result)
    }

    pub fn sign_eip7702_transaction(
        &mut self,
        password: Option<String>,
        index: u32,
        nonce: u64,
        max_priority_fee_per_gas_wei: &str,
        max_fee_per_gas_wei: &str,
        gas_limit: u64,
        to: Option<String>,
        value_wei: &str,
        data_hex: Option<String>,
        chain_id: u64,
        access_list_json: Option<String>,
        authorization_list_json: String,
    ) -> Result<String, WalletError> {
        if chain_id == 0 {
            return Err(WalletError::InvalidChainId);
        }
        if gas_limit < 21_000 {
            return Err(WalletError::InvalidGasLimit);
        }
        let pw = password.as_ref().and_then(|s| if s.is_empty() { None } else { Some(s.as_str()) });
        let signer = self.create_signer(pw, index)?;

        let to_addr: Address = match to.as_ref() {
            Some(s) if !s.is_empty() => match Address::from_str(s) {
                Ok(a) => a,
                Err(_) => return Err(WalletError::InvalidAddress),
            },
            _ => Address::default(),
        };

        let max_priority_fee_per_gas = match U256::from_str(max_priority_fee_per_gas_wei) {
            Ok(v) => match v.try_into() {
                Ok(val) => val,
                Err(_) => return Err(WalletError::InvalidMaxPriorityFee),
            },
            Err(_) => return Err(WalletError::InvalidMaxPriorityFee),
        };

        let max_fee_per_gas = match U256::from_str(max_fee_per_gas_wei) {
            Ok(v) => match v.try_into() {
                Ok(val) => val,
                Err(_) => return Err(WalletError::InvalidMaxFee),
            },
            Err(_) => return Err(WalletError::InvalidMaxFee),
        };

        if max_priority_fee_per_gas > max_fee_per_gas {
            return Err(WalletError::InvalidMaxPriorityFee);
        }

        let value = match U256::from_str(value_wei) {
            Ok(v) => v,
            Err(_) => return Err(WalletError::InvalidValue),
        };

        let input_bytes = match parse_bytes_opt(data_hex) {
            Ok(b) => b,
            Err(_) => return Err(WalletError::InvalidTxData),
        };

        let access_list: AccessList = match access_list_json {
            None => AccessList::default(),
            Some(ref s) if s.is_empty() => AccessList::default(),
            Some(ref s) => serde_json::from_str(s).map_err(|_| WalletError::InvalidAccessList)?,
        };

        // parse authorizations array
        if authorization_list_json.trim().is_empty() {
            return Err(WalletError::InvalidAuthorizationList);
        }

        let authorizations: Vec<Authorization> = serde_json::from_str(&authorization_list_json)
            .map_err(|_| WalletError::InvalidAuthorizationList)?;
        if authorizations.is_empty() {
            return Err(WalletError::EmptyAuthorizationList);
        }

        let mut authorization_list: Vec<SignedAuthorization> = Vec::with_capacity(authorizations.len());
        for auth in authorizations {
            let digest = auth.signature_hash();
            // digest is already B256, use it directly
            let sig = signer.sign_hash_sync(&digest)
                .map_err(|_| WalletError::CreateSignatureFailed)?;
            authorization_list.push(auth.into_signed(sig));
        }

        let mut tx = TxEip7702 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: to_addr,
            value,
            input: input_bytes,
            access_list,
            authorization_list,
        };

        let signature = signer.sign_transaction_sync(&mut tx)
            .map_err(|_| WalletError::SignTransactionError)?;

        let signed = Signed::new_unhashed(tx, signature);
        let mut buf = Vec::with_capacity(signed.rlp_encoded_length());
        signed.rlp_encode(&mut buf);
        let result = format!("0x{}", hex_encode(buf));

        Ok(result)
    }

    pub fn get_address(&mut self, password: Option<String>, index: u32) -> Result<String, WalletError> {
        let pw = password.as_ref().and_then(|s| if s.is_empty() { None } else { Some(s.as_str()) });
        let signer = self.create_signer(pw, index)?;
        let address = signer.address().to_string();
        Ok(address)
    }

    pub fn sign_eip191_message(&mut self, password: Option<String>, index: u32, message: &str) -> Result<String, WalletError> {
        let pw = password.as_ref().and_then(|s| if s.is_empty() { None } else { Some(s.as_str()) });
        let signer = self.create_signer(pw, index)?;

        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let digest = keccak256([prefix.as_bytes(), message.as_bytes()].concat());
        // digest is already B256, use it directly
        let sig = signer.sign_hash_sync(&digest)
            .map_err(|_| WalletError::MessageSigningFailed)?;

        Ok(sig.to_string())
    }

    pub fn verify_eip191_message(&mut self, message: &str, signature_hex: &str) -> Result<String, WalletError> {
        let sig_bytes = hex_decode(signature_hex.trim_start_matches("0x"))
            .map_err(|_| WalletError::InvalidHex)?;
        let sig = Signature::try_from(sig_bytes.as_slice())
            .map_err(|_| WalletError::InvalidSignature)?;

        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let digest = keccak256([prefix.as_bytes(), message.as_bytes()].concat());
        // digest is already B256, use it directly
        let recovered = sig.recover_from_prehash(&digest)
            .map_err(|_| WalletError::RecoverFailed)?;

        let binding = recovered.to_encoded_point(false);
        let pubkey_bytes = binding.as_bytes();
        let address_bytes = &keccak256(&pubkey_bytes[1..])[12..];
        let address_hex = format!("0x{}", hex_encode(address_bytes));
        Ok(address_hex)
    }

    pub fn sign_eip712_message(&mut self, password: Option<String>, index: u32, json: &str) -> Result<String, WalletError> {
        let pw = password.as_ref().and_then(|s| if s.is_empty() { None } else { Some(s.as_str()) });
        let signer = self.create_signer(pw, index)?;

        let digest = EIP712::hash_eip712_message(json)
            .map_err(|_| WalletError::Eip712StructHashError)?;

        // digest is already B256, use it directly
        let sig = signer.sign_hash_sync(&digest)
            .map_err(|_| WalletError::MessageSigningFailed)?;

        Ok(sig.to_string())
    }

    pub fn create_eip712_message(&mut self, json: &str) -> Result<String, WalletError> {
        let digest = EIP712::hash_eip712_message(json)
            .map_err(|_| WalletError::Eip712StructHashError)?;
        // digest is B256, convert to hex string with 0x prefix
        Ok(format!("0x{}", hex_encode(digest)))
    }

    pub fn verify_eip712_message(&mut self, json: &str, signature_hex: &str) -> Result<String, WalletError> {
        let sig_bytes = hex_decode(signature_hex.trim_start_matches("0x"))
            .map_err(|_| WalletError::InvalidHex)?;
        let sig = Signature::try_from(sig_bytes.as_slice())
            .map_err(|_| WalletError::InvalidSignature)?;

        let digest = EIP712::hash_eip712_message(json)
            .map_err(|_| WalletError::Eip712StructHashError)?;

        // digest is already B256, use it directly
        let recovered = sig.recover_from_prehash(&digest)
            .map_err(|_| WalletError::RecoverFailed)?;

        let binding = recovered.to_encoded_point(false);
        let pubkey_bytes = binding.as_bytes();
        let address_bytes = &keccak256(&pubkey_bytes[1..])[12..];
        let address_hex = format!("0x{}", hex_encode(address_bytes));
        Ok(address_hex)
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
            }
            return Err(WalletError::InvalidDerivedKey);
        }

        let dkey = self.derived_key.as_ref().ok_or(WalletError::InvalidDerivedKey)?;
        if dkey.len() != ARGON2_OUTPUT_LEN {
            return Err(WalletError::InvalidDerivedKey);
        }
        let dkey_array: [u8; ARGON2_OUTPUT_LEN] = dkey.as_slice().try_into().map_err(|_| WalletError::InvalidDerivedKey)?;
        let key = Key::from(dkey_array);

        let nonce_bytes = self.nonce.as_ref().ok_or(WalletError::InvalidNonce)?;
        if nonce_bytes.len() != XNONCE_LEN {
            return Err(WalletError::InvalidNonce);
        }
        let nonce_array: [u8; XNONCE_LEN] = nonce_bytes.as_slice().try_into().map_err(|_| WalletError::InvalidNonce)?;
        let xnonce = XNonce::from(nonce_array);

        let ct = self.ciphertext.as_ref().ok_or(WalletError::EmptyCiphertext)?;
        let cipher = XChaCha20Poly1305::new(&key);
        let decrypted = cipher.decrypt(&xnonce, ct.as_ref()).map_err(|_| WalletError::DecryptionFailed)?;
        let mnemonic_str = String::from_utf8(decrypted).map_err(|_| WalletError::InvalidUtf8)?;
        Ok(mnemonic_str)
    }

    fn get_mnemonic_ps_impl(&mut self, password: &str) -> Result<String, WalletError> {
        let salt_bytes = self.salt.as_ref().ok_or(WalletError::InvalidSalt)?;
        if salt_bytes.is_empty() {
            return Err(WalletError::InvalidSalt);
        }

        let mut dkey_array = [0u8; ARGON2_OUTPUT_LEN];
        let params = argon2::Params::new(
            ARGON2_MEMORY,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(ARGON2_OUTPUT_LEN),
        )
        .map_err(|_| WalletError::Argon2BuildError)?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        argon2.hash_password_into(password.as_bytes(), salt_bytes.as_slice(), &mut dkey_array)
            .map_err(|_| WalletError::PasswordHashError)?;

        let key = Key::from(dkey_array);
        let nonce_bytes = self.nonce.as_ref().ok_or(WalletError::InvalidNonce)?;
        if nonce_bytes.len() != XNONCE_LEN {
            return Err(WalletError::InvalidNonce);
        }
        let nonce_array: [u8; XNONCE_LEN] = nonce_bytes.clone().try_into().map_err(|_| WalletError::InvalidNonce)?;
        let xnonce = XNonce::from(nonce_array);
        let ct = self.ciphertext.as_ref().ok_or(WalletError::EmptyCiphertext)?;
        let cipher = XChaCha20Poly1305::new(&key);

        match cipher.decrypt(&xnonce, ct.as_ref()) {
            Ok(decrypted) => {
                let mnemonic_str = String::from_utf8(decrypted).map_err(|_| WalletError::InvalidUtf8)?;
                self.derived_key = Some(dkey_array.to_vec());
                dkey_array.zeroize();
                // key will be dropped
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let duration = self.cache_duration.unwrap_or(900);
                self.cache_time = Some(now + duration);
                Ok(mnemonic_str)
            }
            Err(_) => {
                dkey_array.zeroize();
                Err(WalletError::InvalidPassword)
            }
        }
    }
}

/// Parse optional hex string into Bytes (alloy_primitives::Bytes)
pub(crate) fn parse_bytes_opt(hex_opt: Option<String>) -> Result<alloy_primitives::Bytes, ()> {
    match hex_opt {
        None => Ok(alloy_primitives::Bytes::default()),
        Some(ref h) if h.is_empty() => Ok(alloy_primitives::Bytes::default()),
        Some(h) => {
            let s = h.strip_prefix("0x").unwrap_or(&h);
            match hex_decode(s) {
                Ok(b) => Ok(alloy_primitives::Bytes::from(b)),
                Err(_) => Err(()),
            }
        }
    }
}

