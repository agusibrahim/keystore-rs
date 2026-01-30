# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/claude-code) when working with code in this repository.

## Project Overview

This is `jks` - a Rust library for reading and writing Java KeyStore (JKS) and PKCS12 files. It provides compatibility with Java's `keytool` and Android keystores. The library is published on crates.io as the `jks` crate.

## Common Commands

### Build
```bash
cargo build                    # Debug build
cargo build --release          # Release build
```

### Test
```bash
cargo test                     # Run all tests
cargo test --lib               # Run library tests only
```

### Build for WASM
```bash
cargo build --target wasm32-unknown-unknown --lib --no-default-features
```

### Run WASM Tests (Node.js)
```bash
# First build the WASM test module
cargo build --target wasm32-unknown-unknown --manifest-path=tests/wasm/Cargo.toml --release

# Then run tests
node tests/wasm/test.js
```

### Run Examples
```bash
# Read keystore entries
cargo run --example keypass -- examples/data/agus_key.jks password

# Convert JKS to PEM files
cargo run --example jks_to_pem -- keystore.jks password myalias output

# Convert JKS to single PEM bundle
cargo run --example jks_to_pem_bundle -- keystore.jks password myalias bundle.pem

# Read Java cacerts truststore
cargo run --example truststore -- /path/to/cacerts changeit

# Create JKS from PEM files
cargo run --example pem -- --help

# Test deterministic output
cargo run --example compare
```

### Publish to crates.io
```bash
cargo publish
```

## Architecture

### Source Files (`src/`)

| File | Description |
|------|-------------|
| `lib.rs` | Main entry point. Defines `KeyStore`, `Entry`, `KeyStoreError`, and public API |
| `common.rs` | Common types: `Certificate`, `PrivateKeyEntry`, `TrustedCertificateEntry`, `KeyStoreOptions`, constants |
| `encoder.rs` | Binary encoding for writing JKS files (big-endian, SHA-1 digest) |
| `decoder.rs` | Binary decoding for reading JKS files |
| `keyprotector.rs` | Password-based encryption/decryption of private keys (XOR + SHA-1) |
| `pkcs12.rs` | PKCS12 format support via pure Rust p12-keystore (Android `.keystore`, `.p12`, `.pfx` files) |

### Feature Flags

| Feature | Description |
|---------|-------------|
| `default` | Includes `rand` and `pkcs12` |
| `rand` | Enable random number generation for JKS encryption |
| `pkcs12` | Enable PKCS12 support using pure Rust p12-keystore library |
| `wasm` | Build for WebAssembly (without `rand` or `pkcs12`) |

### Key Types

- **`KeyStore`** - Main struct containing entries (HashMap of alias -> Entry)
- **`Entry`** - Enum: `PrivateKey(PrivateKeyEntry)` or `TrustedCertificate(TrustedCertificateEntry)`
- **`PrivateKeyEntry`** - Contains PKCS#8 private key + certificate chain
- **`TrustedCertificateEntry`** - Contains single trusted certificate
- **`Certificate`** - Contains cert_type (usually "X509") and DER-encoded content

### Format Detection

The library supports auto-detection of keystore format:
- **JKS format**: Magic bytes `0xFEEDFEED` (big-endian)
- **PKCS12 format**: Starts with `0x30` (ASN.1 SEQUENCE tag)

Use `load_auto_detect()` to automatically detect and load either format.

### PKCS12 Notes

- PKCS12 files (Android `.keystore`, `.p12`, `.pfx`) are loaded via pure Rust p12-keystore library (no OpenSSL dependency)
- Private keys from PKCS12 are already decrypted after parsing
- Use `get_raw_private_key_entry()` for PKCS12 (not `get_private_key_entry()`)
- Alias is extracted from PKCS12 `friendlyName` attribute, falling back to certificate subject
- Supported encryption schemes: PBES1 (3DES, RC2) and PBES2 (AES-256)

### JKS Format Details

| Component | Value |
|-----------|-------|
| Magic Number | `0xfeedfeed` |
| Version | 2 (latest) |
| Digest Algorithm | SHA-1 |
| Key Encryption | Password-based XOR + SHA-1 |
| Salt Length | 20 bytes |
| Byte Order | Big-endian |

Entry tags: 1 = Private Key, 2 = Trusted Certificate

## Testing

Test files are located in `examples/data/`. The library has both unit tests in source files and integration examples.

## WASM Support

For WASM builds, you must provide a custom RNG via `KeyStoreOptions::rng` since the default RNG is not available. Use browser's `crypto.getRandomValues()` or Node.js `crypto.randomFillSync()`.
