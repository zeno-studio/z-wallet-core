# Yami Wallet Core

Yami Wallet Core is a secure, no-std compatible wallet library for Ethereum-based applications. It provides core functionality for wallet creation, encryption, decryption, and signature operations.

## Features

- **Secure Storage**: Uses Argon2 for key derivation and XChaCha20Poly1305 for encryption
- **Mnemonic Generation**: BIP39 compliant mnemonic phrase generation
- **Signature Operations**: Support for hash signing and EIP-7702 authorization signing
- **no-std Compatibility**: Can be used in environments without standard library
- **WASM Support**: Can be compiled to WebAssembly for JavaScript/TypeScript usage
- **Airgap Support**: Optional airgap feature for enhanced security

## Architecture

The library is organized into several modules:

- `builder`: Core cryptographic functions for key derivation, encryption, and decryption
- `constants`: Configuration constants for cryptographic parameters
- `error`: Error types and handling
- `validate`: Validation functions for various inputs

## Security

- **Zeroization**: Sensitive data is automatically zeroized after use
- **Encrypted Storage**: Wallet data is stored in encrypted format
- **Time-based Caching**: Derived keys are cached with expiration times
- **Secure Random Generation**: Uses secure random number generation for entropy

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
yami_wallet_core = { path = "." }
```

## Usage

### Basic Wallet Creation

```rust
use yami_wallet_core::WalletCore;

let mut wallet = WalletCore::new();
let password = "secure_password";
let entropy_bits = 128; // or 256
let duration = 3600; // cache duration in seconds
let now = 1000; // current timestamp

let result = wallet.create_vault(password, entropy_bits, Some(duration), now);
```

### Hash Signing

```rust
// Sign a hash
let hash = B256::from([1u8; 32]);
let signature = wallet.sign_hash(password, index, now, &hash);
```

### EIP-7702 Authorization Signing

```rust
// Sign EIP-7702 authorizations
let auths = vec![auth1, auth2, auth3];
let signed_auths = wallet.sign_authorization(password, index, now, &auths);
```

### EIP-7702 Transaction Signing

```rust
// For maximum flexibility, sign authorizations and transaction separately
let signed_auths = wallet.sign_authorization(password, index, now, &auths);
tx.authorization_list = signed_auths;
let signed_tx = wallet.sign_7702(password, index, now, tx, None);

// Or sign both authorizations and transaction in one step
let signed_tx = wallet.sign_7702(password, index, now, tx, Some(auths));
```

## WASM Usage

The library can be compiled to WebAssembly for use in JavaScript/TypeScript applications:

```bash
# Build WASM
cargo build --features wasm --target target/wasm32-unknown-unknown/release/yami_wallet_core.wasm
```

### JavaScript Usage

```javascript
import init, { WalletCoreJs } from 'yami-wallet-core';

await init();
const wallet = new WalletCoreJs();

// Create vault
const vault = wallet.create_vault("password", 128, 3600, Date.now());

// Sign EIP-7702 transaction from RLP hex
const signedTx = wallet.sign_7702_rlp(
    "password",
    0,
    "0x...", // unsigned tx RLP hex
    "0x...", // optional: auth list RLP hex
    Date.now()
);
```

## Testing

Run tests with:

```bash
# Run all tests
cargo test

# Run tests with airgap feature
cargo test --features airgap

# Run tests with wasm feature
cargo test --features wasm

# Run specific test file
cargo test --test integration_tests
```

## Features

### Airgap

The airgap feature provides additional security by enabling functions for importing and exporting mnemonic phrases:

```bash
cargo test --features airgap
```

### WASM

The wasm feature enables WebAssembly compilation for JavaScript/TypeScript integration:

```bash
cargo build --features wasm --target wasm32-unknown-unknown
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.