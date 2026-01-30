// Copyright (c) 2024 agusibrahim
// SPDX-License-Identifier: MIT

//! WebAssembly test example for jks library
//!
//! This example demonstrates using the jks library in a WASM environment.
//!
//! Build:
//! ```bash
//! cargo build --target wasm32-unknown-unknown --example wasm-test
//! ```

use jks::{Certificate, KeyStore, PrivateKeyEntry, TrustedCertificateEntry};
use std::time::SystemTime;

// Custom RNG for WASM (would use browser crypto in real usage)
struct WasmRng;

impl jks::common::RandomReader for WasmRng {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        // Simple fallback - in production use browser's crypto API
        // For demo purposes, just fill with zeros
        for b in buf.iter_mut() {
            *b = 0;
        }
        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn create_trusted_cert() -> usize {
    // Create a simple trusted certificate entry
    let cert = TrustedCertificateEntry {
        creation_time: SystemTime::UNIX_EPOCH,
        certificate: Certificate {
            cert_type: "X509".to_string(),
            content: vec![1, 2, 3], // Dummy cert data
        },
    };

    // Create keystore
    let mut ks = KeyStore::new();

    // Add trusted certificate
    match ks.set_trusted_certificate_entry("test", cert) {
        Ok(_) => 1, // Success
        Err(_) => 0, // Error
    }
}

#[no_mangle]
pub extern "C" fn get_alias_count() -> usize {
    let ks = KeyStore::new();
    ks.aliases().len()
}

// Test function to verify the library works in WASM
#[no_mangle]
pub extern "C" fn test_wasm() -> i32 {
    let mut ks = KeyStore::new();

    // Test trusted certificate entry
    let tce = TrustedCertificateEntry {
        creation_time: SystemTime::UNIX_EPOCH,
        certificate: Certificate {
            cert_type: "X509".to_string(),
            content: vec![1, 2, 3],
        },
    };

    if ks.set_trusted_certificate_entry("test", tce).is_err() {
        return -1; // Failed
    }

    if !ks.is_trusted_certificate_entry("test") {
        return -2; // Failed
    }

    // Test aliases
    let aliases = ks.aliases();
    if aliases.len() != 1 || aliases[0] != "test" {
        return -3; // Failed
    }

    0 // Success
}
