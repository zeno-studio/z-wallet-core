//! WASM bindings for wallet core functionality
//!
//! This module provides WASM bindings for secure wallet operations.
//! It wraps WalletCore in a JavaScript-compatible class.

#![cfg(feature = "wasm")]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use alloy_consensus::TxEip7702;
use alloy_eip7702::Authorization;
use alloy_primitives::B256;
use alloy_rlp::Decodable;
use hex::encode as hex_encode;
use wasm_bindgen::prelude::*;


use crate::builder;

use crate::{validate, Vault, WalletCore};

/// WASM-compatible result type
type WasmResult<T> = Result<T, JsValue>;

/// JavaScript wrapper for WalletCore
#[wasm_bindgen]
pub struct WalletCoreJs {
    inner: WalletCore,
}

#[wasm_bindgen]
impl WalletCoreJs {
    /// Create a new WalletCoreJs instance
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        WalletCoreJs {
            inner: WalletCore::new(),
        }
    }

    /// Load a vault into the wallet
    ///
    /// # Arguments
    /// * `vault_string` - Base58-encoded vault string
    ///
    /// # Returns
    /// * `true` if successful
    pub fn load_vault(&mut self, vault_string: &str) -> WasmResult<bool> {
        let vault = Vault::from_keystore_string(vault_string).map_err(JsValue::from)?;
        self.inner
            .load_vault(vault)
            .map_err(JsValue::from)?;
        Ok(true)
    }

    /// Get vault string (Base58-encoded)
    pub fn get_vault_string(&mut self) -> WasmResult<String> {
        self.inner
            .vault
            .to_keystore_string()
            .map_err(JsValue::from)
    }

    /// Set cache duration for derived key
    ///
    /// # Arguments
    /// * `duration` - Duration in seconds
    pub fn set_cache_duration(&mut self, duration: u64) {
        self.inner.set_cache_duration(duration);
    }

    /// Get cache duration
    ///
    /// # Returns
    /// * Cache duration in seconds
    pub fn get_cache_duration(&self) -> u64 {
        self.inner.get_cache_duration()
    }

    /// Get entropy bits
    ///
    /// # Returns
    /// * Entropy bits (128 or 256)
    pub fn get_entropy_bits(&self) -> u64 {
        self.inner.get_entropy_bits()
    }

    /// Get expire time
    ///
    /// # Returns
    /// * Expire time as Unix timestamp
    pub fn get_expire_time(&self) -> WasmResult<u64> {
        self.inner.get_expire_time().map_err(JsValue::from)
    }

    /// Check if derived key is cached
    ///
    /// # Returns
    /// * `true` if derived key is cached
    pub fn has_derived_key(&self) -> bool {
        self.inner.has_derived_key()
    }

    /// Create a new vault with encrypted mnemonic
    ///
    /// # Arguments
    /// * `password` - The password to encrypt the mnemonic
    /// * `entropy_bits` - Entropy bits (128 or 256)
    /// * `cache_duration` - Cache duration in seconds
    /// * `now` - Current Unix timestamp
    ///
    /// # Returns
    /// * Object containing:
    ///   - `vault`: Base58-encoded vault string
    ///   - `address`: Wallet address
    ///   - `path`: Derivation path
    pub fn create_vault(
        &mut self,
        password: &str,
        entropy_bits: u64,
        cache_duration: u64,
        now: u64,
    ) -> WasmResult<JsValue> {
        let (mut vault, address, path) = self
            .inner
            .create_vault(password, entropy_bits, Some(cache_duration), now)
            .map_err(JsValue::from)?;

        let vault_string = vault.to_keystore_string().map_err(JsValue::from)?;

        let result = js_sys::Object::new();
        js_sys::Reflect::set(&result, &JsValue::from_str("vault"), &JsValue::from_str(&vault_string))?;
        js_sys::Reflect::set(&result, &JsValue::from_str("address"), &JsValue::from_str(&address))?;
        js_sys::Reflect::set(&result, &JsValue::from_str("path"), &JsValue::from_str(&path))?;

        Ok(result.into())
    }

    /// Import an existing vault
    ///
    /// # Arguments
    /// * `password` - The password to decrypt the vault
    /// * `vault_string` - Base58-encoded vault string
    /// * `cache_duration` - Cache duration in seconds
    /// * `now` - Current Unix timestamp
    ///
    /// # Returns
    /// * Object containing:
    ///   - `address`: Wallet address
    ///   - `path`: Derivation path
    pub fn import_vault(
        &mut self,
        password: &str,
        vault_string: &str,
        cache_duration: u64,
        now: u64,
    ) -> WasmResult<JsValue> {
        let vault = Vault::from_keystore_string(vault_string).map_err(JsValue::from)?;

        let (address, path) = self
            .inner
            .import_vault(password, vault, Some(cache_duration), now)
            .map_err(JsValue::from)?;

        let result = js_sys::Object::new();
        js_sys::Reflect::set(&result, &JsValue::from_str("address"), &JsValue::from_str(&address))?;
        js_sys::Reflect::set(&result, &JsValue::from_str("path"), &JsValue::from_str(&path))?;

        Ok(result.into())
    }

    /// Derive account at a specific index
    ///
    /// # Arguments
    /// * `password` - The password to decrypt the mnemonic (empty string uses cached key)
    /// * `index` - Derivation index
    /// * `now` - Current Unix timestamp
    ///
    /// # Returns
    /// * Object containing:
    ///   - `address`: Derived wallet address
    ///   - `path`: Derivation path
    pub fn derive_account(
        &mut self,
        password: &str,
        index: u32,
        now: u64,
    ) -> WasmResult<JsValue> {
        let (address, path) = self
            .inner
            .derive_account(password, index, now)
            .map_err(JsValue::from)?;

        let result = js_sys::Object::new();
        js_sys::Reflect::set(&result, &JsValue::from_str("address"), &JsValue::from_str(&address))?;
        js_sys::Reflect::set(&result, &JsValue::from_str("path"), &JsValue::from_str(&path))?;

        Ok(result.into())
    }

    /// Verify password and cache derived key
    ///
    /// # Arguments
    /// * `password` - The password to verify
    /// * `now` - Current Unix timestamp
    ///
    /// # Returns
    /// * Boolean indicating if password is correct
    pub fn verify_password(&mut self, password: &str, now: u64) -> WasmResult<bool> {
        self.inner
            .verify_password(password, now)
            .map_err(JsValue::from)
    }

    /// Get address at a specific index
    ///
    /// # Arguments
    /// * `password` - The password to decrypt the mnemonic (optional, use empty string for cached key)
    /// * `index` - Derivation index
    /// * `now` - Current Unix timestamp
    ///
    /// # Returns
    /// * Address string
    pub fn get_address(
        &mut self,
        password: Option<String>,
        index: u32,
        now: u64,
    ) -> WasmResult<String> {
        self.inner
            .get_address(password, index, now)
            .map_err(JsValue::from)
    }

    /// Change vault password
    ///
    /// # Arguments
    /// * `old_password` - Current password
    /// * `new_password` - New password
    /// * `now` - Current Unix timestamp
    ///
    /// # Returns
    /// * `true` if successful
    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
        now: u64,
    ) -> WasmResult<bool> {
        self.inner
            .change_ciphertext_password(old_password, new_password, now)
            .map_err(JsValue::from)
    }

    /// Sign a hash with the private key at the specified index
    ///
    /// # Arguments
    /// * `password` - The password to decrypt the mnemonic
    /// * `index` - Derivation index
    /// * `hash_hex` - Hex-encoded hash to sign (64 chars, 32 bytes)
    /// * `now` - Current Unix timestamp
    ///
    /// # Returns
    /// * Hex-encoded signature (130 chars, 65 bytes with v)
    pub fn sign_hash(
        &mut self,
        password: &str,
        index: u32,
        hash_hex: &str,
        now: u64,
    ) -> WasmResult<String> {
        // Parse hash from hex
        let hash_bytes = hex::decode(hash_hex).map_err(|_| JsValue::from_str("Invalid hex hash"))?;
        if hash_bytes.len() != 32 {
            return Err(JsValue::from_str("Invalid hash length: expected 32 bytes"));
        }
        let hash_array: [u8; 32] = hash_bytes
            .try_into()
            .map_err(|_| JsValue::from_str("Invalid hash length"))?;
        let b256 = B256::from(hash_array);

        let signature = self
            .inner
            .sign_hash(password, index, now, &b256)
            .map_err(JsValue::from)?;

        // Encode signature as hex (65 bytes: r, s, v)
        let sig_bytes = signature.as_bytes();
        Ok(hex_encode(sig_bytes))
    }

    /// Sign a hash and return signature components
    ///
    /// # Arguments
    /// * `password` - The password to decrypt the mnemonic
    /// * `index` - Derivation index
    /// * `hash_hex` - Hex-encoded hash to sign (64 chars, 32 bytes)
    /// * `now` - Current Unix timestamp
    ///
    /// # Returns
    /// * Object containing:
    ///   - `r`: R component of signature (hex)
    ///   - `s`: S component of signature (hex)
    ///   - `v`: V component of signature (hex)
    pub fn sign_hash_components(
        &mut self,
        password: &str,
        index: u32,
        hash_hex: &str,
        now: u64,
    ) -> WasmResult<JsValue> {
        // Parse hash from hex
        let hash_bytes = hex::decode(hash_hex).map_err(|_| JsValue::from_str("Invalid hex hash"))?;
        if hash_bytes.len() != 32 {
            return Err(JsValue::from_str("Invalid hash length: expected 32 bytes"));
        }
        let hash_array: [u8; 32] = hash_bytes
            .try_into()
            .map_err(|_| JsValue::from_str("Invalid hash length"))?;
        let b256 = B256::from(hash_array);

        let signature = self
            .inner
            .sign_hash(password, index, now, &b256)
            .map_err(JsValue::from)?;

        let sig_ref = &signature;
        let r = hex_encode(sig_ref.r().as_le_bytes());
        let s = hex_encode(sig_ref.s().as_le_bytes());
        let v = format!("{:02x}", signature.v() as u8);

        let result = js_sys::Object::new();
        js_sys::Reflect::set(&result, &JsValue::from_str("r"), &JsValue::from_str(&r))?;
        js_sys::Reflect::set(&result, &JsValue::from_str("s"), &JsValue::from_str(&s))?;
        js_sys::Reflect::set(&result, &JsValue::from_str("v"), &JsValue::from_str(&v))?;

        Ok(result.into())
    }

    /// Parse authorization from RLP hex
    ///
    /// Authorization is RLP encoded: [chain_id, address, nonce]
    fn parse_authorization(auth_hex: &str) -> Result<Authorization, JsValue> {
        let auth_bytes = hex::decode(auth_hex)
            .map_err(|_| JsValue::from_str("Invalid authorization hex"))?;

        // Use RLP decoding
        let auth = Authorization::decode(&mut auth_bytes.as_slice())
            .map_err(|_| JsValue::from_str("Failed to decode authorization"))?;

        Ok(auth)
    }

    /// Sign EIP-7702 authorizations
    ///
    /// # Arguments
    /// * `password` - The password to decrypt the mnemonic
    /// * `index` - Derivation index
    /// * `auth_list_hex` - Hex-encoded authorization list
    /// * `now` - Current Unix timestamp
    ///
    /// # Returns
    /// * Array of hex-encoded signed authorizations
    pub fn sign_authorization(
        &mut self,
        password: &str,
        index: u32,
        auth_list_hex: &str,
        now: u64,
    ) -> WasmResult<JsValue> {
        // Parse authorization list
        let auth_bytes = hex::decode(auth_list_hex)
            .map_err(|_| JsValue::from_str("Invalid auth list hex"))?;

        // Each authorization is 68 bytes
        if auth_bytes.len() % 68 != 0 {
            return Err(JsValue::from_str(
                "Invalid authorization list: length must be multiple of 68",
            ));
        }

        let auth_count = auth_bytes.len() / 68;
        let mut authorizations = Vec::with_capacity(auth_count);

        for i in 0..auth_count {
            let start = i * 68;
            let end = start + 68;
            let auth_hex = hex_encode(&auth_bytes[start..end]);
            authorizations.push(Self::parse_authorization(&auth_hex)?);
        }

        let signed_auths = self
            .inner
            .sign_authorization(password, index, now, &authorizations)
            .map_err(JsValue::from)?;

        // Encode signed authorizations as hex
        let result = js_sys::Array::new();
        for signed_auth in signed_auths {
            // Encode as RLP bytes then hex
            let encoded = alloy_rlp::encode(&signed_auth);
            result.push(&JsValue::from_str(&hex_encode(encoded)));
        }

        Ok(result.into())
    }

    /// Sign EIP-7702 transaction
    ///
    /// # Arguments
    /// * `password` - The password to decrypt the mnemonic
    /// * `index` - Derivation index
    /// * `tx_hex` - Hex-encoded unsigned 7702 transaction (RLP)
    /// * `auth_list_hex` - Optional hex-encoded authorization list
    /// * `now` - Current Unix timestamp
    ///
    /// # Returns
    /// * Hex-encoded signed transaction (RLP)
    pub fn sign_7702(
        &mut self,
        password: &str,
        index: u32,
        tx_hex: &str,
        auth_list_hex: Option<String>,
        now: u64,
    ) -> WasmResult<String> {
        // Decode transaction from hex
        let tx_bytes = hex::decode(tx_hex).map_err(|_| JsValue::from_str("Invalid tx hex"))?;

        // Parse the transaction
        let tx = TxEip7702::decode(&mut tx_bytes.as_slice()).map_err(|_| JsValue::from_str("Failed to decode transaction"))?;

        // Parse authorizations if provided
        let authorizations: Option<Vec<Authorization>> = auth_list_hex
            .map(|hex| {
                let auth_bytes = hex::decode(&hex).map_err(|_| JsValue::from_str("Invalid auth hex"))?;

                // Each authorization is 68 bytes
                if auth_bytes.len() % 68 != 0 {
                    return Err(JsValue::from_str(
                        "Invalid authorization list: length must be multiple of 68",
                    ));
                }

                let auth_count = auth_bytes.len() / 68;
                let mut auths = Vec::with_capacity(auth_count);

                for i in 0..auth_count {
                    let start = i * 68;
                    let end = start + 68;
                    let auth_hex = hex_encode(&auth_bytes[start..end]);
                    auths.push(Self::parse_authorization(&auth_hex)?);
                }
                Ok::<Vec<Authorization>, JsValue>(auths)
            })
            .transpose()?;

        let signed_tx = self
            .inner
            .sign_7702(password, index, now, tx, authorizations.as_ref())
            .map_err(JsValue::from)?;

        Ok(signed_tx)
    }


}

