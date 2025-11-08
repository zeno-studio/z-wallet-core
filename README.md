# Z Wallet Core

Z Wallet Core is a secure, no-std compatible wallet library for Ethereum-based applications. It provides core functionality for wallet creation, encryption, decryption, transaction signing, and message verification.

## Features

- **Secure Storage**: Uses Argon2 for key derivation and XChaCha20Poly1305 for encryption
- **Mnemonic Generation**: BIP39 compliant mnemonic phrase generation
- **Transaction Signing**: Support for Legacy, EIP-1559, and EIP-7702 transactions
- **Message Signing**: Support for EIP-191 and EIP-712 message signing
- **no-std Compatibility**: Can be used in environments without standard library
- **Airgap Support**: Optional airgap feature for enhanced security

## Architecture

The library is organized into several modules:

- `builder`: Core cryptographic functions for key derivation, encryption, and decryption
- `constants`: Configuration constants for cryptographic parameters
- `error`: Error types and handling
- `message`: Message signing and verification functions
- `tx`: Transaction signing functions
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
z-wallet-core = { path = "." }
```

## Usage

### Basic Wallet Creation

```rust
use z_wallet_core::WalletCore;

let mut wallet = WalletCore::new();
let password = "secure_password";
let entropy_bits = 128; // or 256
let duration = 3600; // cache duration in seconds
let now = 1000; // current timestamp

let result = wallet.create_vault(password, entropy_bits, duration, now);
```

### Transaction Signing

```rust
// Sign a legacy transaction
let signed_tx = z_wallet_core::sign_legacy_transaction(
    signer,
    nonce,
    gas_price_wei,
    gas_limit,
    to,
    value_wei,
    data_hex,
    chain_id,
);
```

### Message Signing

```rust
// Sign an EIP-191 message
let signature = z_wallet_core::sign_eip191_message(signer, message);
```

## Testing

Run tests with:

```bash
# Run all tests
cargo test

# Run tests with airgap feature
cargo test --features airgap

# Run specific test file
cargo test --test integration_tests
```

## Features

### Airgap

The airgap feature provides additional security by enabling functions for importing and exporting mnemonic phrases:

```bash
cargo test --features airgap
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.