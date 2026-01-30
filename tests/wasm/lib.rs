// Copyright (c) 2024 agusibrahim
// SPDX-License-Identifier: MIT

//! Minimal WASM library for testing jks core functionality

use jks::{Certificate, KeyStore, TrustedCertificateEntry};
use std::time::SystemTime;

/// Test creating a trusted certificate entry
#[no_mangle]
pub extern "C" fn test_create_trusted_cert() -> i32 {
    let cert = TrustedCertificateEntry {
        creation_time: SystemTime::UNIX_EPOCH,
        certificate: Certificate {
            cert_type: "X509".to_string(),
            content: vec![1, 2, 3],
        },
    };

    let mut ks = KeyStore::new();
    match ks.set_trusted_certificate_entry("test", cert) {
        Ok(_) => 0,  // Success
        Err(_) => -1, // Error
    }
}

/// Test getting alias count
#[no_mangle]
pub extern "C" fn test_alias_count() -> usize {
    let ks = KeyStore::new();
    ks.aliases().len()
}

/// Test complete keystore operations
#[no_mangle]
pub extern "C" fn test_all() -> i32 {
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

    let aliases = ks.aliases();
    if aliases.len() != 1 || aliases[0] != "test" {
        return -3; // Failed
    }

    0 // Success
}
