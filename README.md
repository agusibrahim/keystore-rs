# jks

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/jks)](https://crates.io/crates/jks)

Java KeyStore (JKS) and PKCS12 encoder/decoder for Rust. Supports WebAssembly (WASM).

## About

`jks` is a Rust library for reading and writing Java KeyStore (JKS) and PKCS12 files. It provides compatibility with Java's `keytool` and Android keystores, and can be used to:

- Read JKS files (keystores, truststores)
- Read PKCS12 files (Android `.keystore`, `.p12`, `.pfx`)
- Create new JKS files with private keys and certificates
- Extract private keys and certificates from keystores
- Convert keystores to PEM format and vice versa

**Note:** Private keys are assumed to be PKCS#8 encoded.

## Features

- ✅ **Read JKS files** - Load existing Java keystores
- ✅ **Read PKCS12 files** - Load Android keystores, `.p12`, `.pfx` files (with `openssl` feature)
- ✅ **Auto-detect format** - Automatically detects JKS vs PKCS12 format
- ✅ **Write JKS files** - Create new keystores compatible with Java
- ✅ **Password-based encryption** - Private keys encrypted using password (XOR + SHA-1)
- ✅ **Private Key entries** - Support for private keys with certificate chains
- ✅ **Trusted Certificate entries** - Support for trusted certificates
- ✅ **Case-insensitive aliases** - Alias matching is case-insensitive by default
- ✅ **Ordered aliases** - Optional alphabetical sorting of aliases
- ✅ **Custom password validation** - Configurable minimum password length

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
jks = "0.3.2"
```

### Features

- **default** - Includes `rand` and `openssl` (PKCS12 support)
- **rand** - Enable random number generation for JKS encryption
- **openssl** - Enable PKCS12 support (for Android keystores)
- **wasm** - Build for WebAssembly (without `rand` or `openssl`)

To disable PKCS12 support (reduce dependencies):

```toml
[dependencies]
jks = { version = "0.3", default-features = false, features = ["rand"] }
```

## Quick Start

### Reading a Keystore

```rust
use jks::KeyStore;
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open and read keystore
    let mut file = File::open("keystore.jks")?;
    let mut ks = KeyStore::new();
    ks.load(&mut file, b"password")?;

    // List all aliases
    for alias in ks.aliases() {
        println!("{}", alias);
    }

    Ok(())
}
```

### Creating a New Keystore

```rust
use jks::{KeyStore, PrivateKeyEntry, Certificate};
use std::fs::File;
use std::time::SystemTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut ks = KeyStore::new();

    // Create a private key entry
    let entry = PrivateKeyEntry {
        creation_time: SystemTime::now(),
        private_key: /* PKCS#8 private key bytes */ vec![],
        certificate_chain: vec![
            Certificate {
                cert_type: "X509".to_string(),
                content: /* DER encoded certificate */ vec![],
            }
        ],
    };

    // Add to keystore (private key will be encrypted)
    ks.set_private_key_entry("myalias", entry, b"password")?;

    // Save to file
    let mut file = File::create("keystore.jks")?;
    ks.store(&mut file, b"password")?;

    Ok(())
}
```

## API Reference

### `KeyStore`

Main struct for working with Java keystores.

#### Creating a Keystore

```rust
use jks::KeyStore;

// Default options
let ks = KeyStore::new();

// With custom options
let ks = KeyStore::with_options(KeyStoreOptions {
    ordered_aliases: true,
    case_exact_aliases: false,
    min_password_len: 6,
    ..Default::default()
});
```

#### Loading & Saving

```rust
use jks::KeyStore;
use std::fs::File;

let mut ks = KeyStore::new();

// Load from file (JKS format)
let mut file = File::open("keystore.jks")?;
ks.load(&mut file, b"password")?;

// Auto-detect format (JKS or PKCS12)
let mut file = File::open("keystore.jks")?;
ks.load_auto_detect(&mut file, b"password")?;

// Load PKCS12 file (Android .keystore, .p12, .pfx)
let mut file = File::open("android.keystore")?;
ks.load_pkcs12(&mut file, b"password")?;

// Save to file
let mut file = File::create("keystore.jks")?;
ks.store(&mut file, b"password")?;
```

#### PKCS12 Support (Android Keystores)

```rust
use jks::KeyStore;
use std::fs::File;

let mut ks = KeyStore::new();

// Load Android keystore (PKCS12 format)
let mut file = File::open("my-release-key.keystore")?;
ks.load_pkcs12(&mut file, b"password")?;

// Or use auto-detect (works for both JKS and PKCS12)
let mut file = File::open("my-release-key.keystore")?;
ks.load_auto_detect(&mut file, b"password")?;

// Get private key entry (already decrypted for PKCS12)
let alias = "key_0"; // PKCS12 entries use generic aliases
if ks.is_private_key_entry(alias) {
    // For PKCS12, use get_raw_private_key_entry() since keys are already decrypted
    let entry = ks.get_raw_private_key_entry(alias)?;

    // Access certificate chain
    for cert in &entry.certificate_chain {
        println!("Certificate: {} bytes", cert.content.len());
    }
}
```

**Note:** PKCS12 files (like Android keystores) are supported via the `openssl` feature. The private keys from PKCS12 are already decrypted, so use `get_raw_private_key_entry()` instead of `get_private_key_entry()`.

#### Private Key Entries

```rust
use jks::{KeyStore, PrivateKeyEntry, Certificate};

let mut ks = KeyStore::new();

// Add a private key entry
let entry = PrivateKeyEntry {
    creation_time: SystemTime::now(),
    private_key: private_key_bytes, // PKCS#8 encoded
    certificate_chain: vec![certificate],
};

// Private key will be encrypted before storing
ks.set_private_key_entry("mykey", entry, b"password")?;

// Retrieve and decrypt
let entry = ks.get_private_key_entry("mykey", b"password")?;

// Get certificate chain only
let chain = ks.get_private_key_entry_certificate_chain("mykey")?;

// Check if entry exists
if ks.is_private_key_entry("mykey") {
    println!("Found private key entry");
}
```

#### Trusted Certificate Entries

```rust
use jks::{KeyStore, TrustedCertificateEntry, Certificate};

let mut ks = KeyStore::new();

// Add a trusted certificate
let entry = TrustedCertificateEntry {
    creation_time: SystemTime::now(),
    certificate: Certificate {
        cert_type: "X509".to_string(),
        content: cert_bytes,
    },
};

ks.set_trusted_certificate_entry("mycert", entry)?;

// Retrieve
let entry = ks.get_trusted_certificate_entry("mycert")?;

// Check if entry exists
if ks.is_trusted_certificate_entry("mycert") {
    println!("Found trusted certificate");
}
```

#### Working with Aliases

```rust
use jks::KeyStore;

let ks = KeyStore::new();

// Get all aliases
let aliases = ks.aliases();

// Check number of entries
let count = ks.len();
let empty = ks.is_empty();

// Delete an entry
ks.delete_entry("oldalias");

// Case sensitivity
let ks = KeyStore::with_options(KeyStoreOptions {
    case_exact_aliases: true,  // "MyKey" != "mykey"
    ..Default::default()
});
```

### Types

#### `PrivateKeyEntry`

Represents a private key with its certificate chain.

```rust
pub struct PrivateKeyEntry {
    /// When this entry was created
    pub creation_time: SystemTime,

    /// Private key in PKCS#8 format (encrypted when stored)
    pub private_key: Vec<u8>,

    /// Certificate chain (end-entity first, then intermediates)
    pub certificate_chain: Vec<Certificate>,
}
```

#### `TrustedCertificateEntry`

Represents a trusted certificate without a private key.

```rust
pub struct TrustedCertificateEntry {
    /// When this entry was created
    pub creation_time: SystemTime,

    /// The trusted certificate
    pub certificate: Certificate,
}
```

#### `Certificate`

Represents a single certificate.

```rust
pub struct Certificate {
    /// Certificate type (e.g., "X509")
    pub cert_type: String,

    /// Raw DER-encoded certificate content
    pub content: Vec<u8>,
}
```

#### `KeyStoreOptions`

Configuration options for keystore behavior.

```rust
pub struct KeyStoreOptions {
    /// Order aliases alphabetically when iterating
    pub ordered_aliases: bool,

    /// Preserve original case of aliases (default: case-insensitive)
    pub case_exact_aliases: bool,

    /// Minimum password length
    pub min_password_len: usize,

    /// Custom random number generator for salt generation
    pub rng: Box<dyn RandomReader>,

    /// Custom password bytes transformation
    pub password_bytes: fn(&[u8]) -> Vec<u8>,
}
```

### Error Handling

All operations return `Result<T, KeyStoreError>`:

```rust
pub enum KeyStoreError {
    EntryNotFound,
    WrongEntryType,
    EmptyPrivateKey,
    EmptyCertificateType,
    EmptyCertificateContent,
    ShortPassword,
    InvalidMagic,
    InvalidDigest,
    UnknownVersion(u32),
    UnknownEntryTag(u32),
    UnsupportedAlgorithm,
    ExtraDataInEncryptedKey,
    InvalidEntry,
    Io(std::io::Error),
    Asn1(String),
    Other(String),
}
```

## Examples

The library includes several examples demonstrating common usage:

### 1. PEM to JKS

Convert PEM files to a JKS keystore:

```bash
cargo run --example pem -- --help
```

### 2. Read Keystore

Read and display entries from a keystore:

```bash
cargo run --example keypass -- examples/data/agus_key.jks password
```

### 3. Read Truststore

Read Java's cacerts truststore:

```bash
cargo run --example truststore -- /path/to/cacerts changeit
```

### 4. JKS to PEM

Convert a JKS keystore to separate PEM files:

```bash
# Convert to separate PEM files
cargo run --example jks_to_pem -- keystore.jks password myalias output

# Output files:
#   output_private_key.pem     - Private key (PKCS#8)
#   output_certificate.pem     - End-entity certificate
#   output_chain.pem           - Full certificate chain
```

### 5. JKS to PEM Bundle

Convert a JKS keystore to a single combined PEM bundle:

```bash
# Convert to single bundle file
cargo run --example jks_to_pem_bundle -- keystore.jks password myalias bundle.pem

# Bundle contains:
#   -----BEGIN PRIVATE KEY-----
#   -----END PRIVATE KEY-----
#   -----BEGIN CERTIFICATE-----
#   -----END CERTIFICATE-----
```

### 6. Compare Keystores

Test deterministic keystore output:

```bash
cargo run --example compare
```

## Password Security

**Important:** Always zero out passwords after use:

```rust
let mut password = b"mysecret".to_vec();

// Use password...
ks.store(&mut file, &password)?;

// Zero out sensitive data
jks::zeroing(&mut password);
```

## JKS Format Details

This library implements the JKS (Java KeyStore) format:

| Component | Value |
|-----------|-------|
| Magic Number | `0xfeedfeed` |
| Version | 2 (latest) |
| Digest Algorithm | SHA-1 |
| Key Encryption | Password-based XOR + SHA-1 |
| Salt Length | 20 bytes |
| Byte Order | Big-endian |

### Private Key Encryption

Private keys are encrypted using:

1. Generate 20-byte random salt
2. Derive encryption key using SHA-1(password + salt) iterated
3. XOR private key with derived key
4. Append SHA-1 digest for verification

### Entry Tags

| Tag | Type | Description |
|-----|------|-------------|
| 1 | Private Key | Private key with certificate chain |
| 2 | Trusted Certificate | Trusted certificate without private key |

## Testing

Run the test suite:

```bash
# Run all tests
cargo test

# Run library tests
cargo test --lib

# Run specific example
cargo run --example pem
```

## WebAssembly (WASM) Support

This library can be compiled to WebAssembly for use in browser environments or Node.js-WASM. Runtime tested and verified working.

### Building for WASM

```bash
# Build the library for WASM (without rand feature)
cargo build --target wasm32-unknown-unknown --lib --no-default-features

# Output: target/wasm32-unknown-unknown/debug/jks.wasm
```

### Using in Your Project

Add to your `Cargo.toml`:

```toml
[dependencies]
jks = { version = "0.2", default-features = false }
```

### Providing a Custom RNG for WASM

Since the default RNG isn't available in WASM, you need to provide your own using `KeyStoreOptions`:

```rust
use jks::{KeyStore, KeyStoreOptions, common::RandomReader};
use std::io::{self, Write};

struct BrowserRng;

impl RandomReader for BrowserRng {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        // Use browser's crypto API or provide your own implementation
        // In browsers: window.crypto.getRandomValues()
        // In Node.js: require('crypto').randomFillSync()
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = KeyStoreOptions {
        rng: Box::new(BrowserRng),
        ..Default::default()
    };
    let mut ks = KeyStore::with_options(options);
    // ...
}
```

### WASM Runtime Testing

The library has been verified working in WebAssembly runtime environment:

```bash
# Run the WASM runtime tests
cargo build --target wasm32-unknown-unknown \
    --manifest-path=tests/wasm/Cargo.toml --release

# Test with Node.js
node tests/wasm/test.js
```

**Test Results (verified):**
- ✅ `test_create_trusted_cert()` - PASSED
- ✅ `test_alias_count()` - PASSED
- ✅ `test_all()` - PASSED

WASM binary size: ~56 KB (release build)

### Compatibility

- ✅ Java KeyStore (JKS) format
- ✅ Java `keytool` generated keystores
- ✅ Java cacerts truststore
- ✅ OpenSSL generated certificates
- ✅ PKCS#8 private keys

## Requirements

- Rust 1.70 or later
- No external C dependencies

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

This library is a Rust port of the excellent Go implementation:

[keystore-go](https://github.com/pavlo-v-chernykh/keystore-go) by Pavlo Chernykh

## Author

[agusibrahim](https://github.com/agusibrahim)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
