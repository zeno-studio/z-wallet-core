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

use crate::{Vault, WalletCore};

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
        self.inner.load_vault(vault).map_err(JsValue::from)?;
        Ok(true)
    }

    /// Get vault string (Base58-encoded)
    pub fn get_vault_string(&mut self) -> WasmResult<String> {
        self.inner.vault.to_keystore_string().map_err(JsValue::from)
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

    /// Lock the wallet by clearing the cached derived key and expire time.
    ///
    /// This function provides a way to manually invalidate the cached derived key,
    /// effectively "logging out" the user.
    pub fn lock(&mut self) {
        self.inner.lock()
    }

    /// Expire cache if needed, zeroize derived key when removed.
    ///
    /// # Arguments
    /// * `now` - The current Unix timestamp
    pub fn tick(&mut self, now: u64) {
        self.inner.tick(now)
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
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("vault"),
            &JsValue::from_str(&vault_string),
        )?;
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("address"),
            &JsValue::from_str(&address),
        )?;
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("path"),
            &JsValue::from_str(&path),
        )?;

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
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("address"),
            &JsValue::from_str(&address),
        )?;
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("path"),
            &JsValue::from_str(&path),
        )?;

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
    pub fn derive_account(&mut self, password: &str, index: u32, now: u64) -> WasmResult<JsValue> {
        let (address, path) = self
            .inner
            .derive_account(password, index, now)
            .map_err(JsValue::from)?;

        let result = js_sys::Object::new();
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("address"),
            &JsValue::from_str(&address),
        )?;
        js_sys::Reflect::set(
            &result,
            &JsValue::from_str("path"),
            &JsValue::from_str(&path),
        )?;

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
        let hash_bytes =
            hex::decode(hash_hex).map_err(|_| JsValue::from_str("Invalid hex hash"))?;
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

    /// Parse authorization list from RLP hex (continuous RLP list)
    fn parse_auth_list_rlp(list_rlp_hex: &str) -> WasmResult<Vec<Authorization>> {
        let bytes = hex::decode(list_rlp_hex.trim_start_matches("0x"))
            .map_err(|e| JsValue::from_str(&format!("Invalid auth list RLP hex: {}", e)))?;

        // alloy_rlp supports direct decoding of Vec<T> where T: Decodable
        Vec::<Authorization>::decode(&mut bytes.as_slice())
            .map_err(|e| JsValue::from_str(&format!("Auth list RLP decode failed: {:?}", e)))
    }

    /// Parse unsigned EIP-7702 tx from RLP hex (with 0x04 prefix)
    fn parse_unsigned_tx_rlp(tx_rlp_hex: &str) -> WasmResult<TxEip7702> {
        let bytes = hex::decode(tx_rlp_hex.trim_start_matches("0x"))
            .map_err(|e| JsValue::from_str(&format!("Invalid tx RLP hex: {}", e)))?;

        // Use TxEip7702::decode directly (cleanest approach)
        TxEip7702::decode(&mut bytes.as_slice())
            .map_err(|e| JsValue::from_str(&format!("Tx RLP decode failed: {:?}", e)))
    }

    /// Sign EIP-7702 transaction from RLP-encoded hex inputs
    ///
    /// JS side should RLP encode unsigned tx and auth list first (recommend using viem's encodeTransaction or alloy.js)
    ///
    /// @param password - The password to decrypt the mnemonic
    /// @param index - Derivation index
    /// @param tx_rlp_hex - unsigned EIP-7702 tx RLP hex (must include 0x04 type byte)
    /// @param auth_list_rlp_hex - optional: unsigned authorizations RLP list hex (RLP([auth1, auth2, ...]))
    /// @param now - Current Unix timestamp
    pub fn sign_7702_rlp(
        &mut self,
        password: &str,
        index: u32,
        tx_rlp_hex: &str,
        auth_list_rlp_hex: Option<String>,
        now: u64,
    ) -> WasmResult<String> {
        // 1. Parse unsigned tx
        let tx = Self::parse_unsigned_tx_rlp(tx_rlp_hex)?;

        // 2. Parse auth list (if provided)
        let auths: Option<Vec<Authorization>> = if let Some(rlp_hex) = auth_list_rlp_hex {
            if rlp_hex.trim().is_empty() {
                None
            } else {
                Some(Self::parse_auth_list_rlp(&rlp_hex)?)
            }
        } else {
            None
        };

        // 3. Sign and attach (inner function consumes tx)
        let signed_hex = self.inner.sign_7702(password, index, now, tx, auths)?;

        Ok(signed_hex)
    }
}
