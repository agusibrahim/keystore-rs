// Copyright (c) 2024 agusibrahim
// SPDX-License-Identifier: MIT

//! WASM library for testing jks core functionality with PKCS12 support

use jks::{Certificate, KeyStore, KeyStoreOptions, PrivateKeyEntry, TrustedCertificateEntry};
use std::io::Cursor;
use std::time::SystemTime;
use wasm_bindgen::prelude::*;

/// Custom RNG that uses a simple counter (for testing only)
struct TestRng {
    counter: u8,
}

impl jks::common::RandomReader for TestRng {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        for b in buf.iter_mut() {
            *b = self.counter;
            self.counter = self.counter.wrapping_add(1);
        }
        Ok(())
    }
}

/// Load JKS file and return aliases as JSON array
#[wasm_bindgen]
pub fn load_jks(data: &[u8], password: &str) -> Result<String, String> {
    let mut ks = KeyStore::new();

    ks.load(Cursor::new(data), password.as_bytes())
        .map_err(|e| format!("Error loading JKS: {:?}", e))?;

    let aliases: Vec<String> = ks.aliases();
    let result = serde_like_json(&aliases, ks.len());
    Ok(result)
}

/// Load PKCS12 file and return aliases as JSON-like string
#[wasm_bindgen]
pub fn load_pkcs12(data: &[u8], password: &str) -> Result<String, String> {
    let mut ks = KeyStore::new();

    ks.load_pkcs12(Cursor::new(data), password.as_bytes())
        .map_err(|e| format!("Error loading PKCS12: {:?}", e))?;

    let aliases: Vec<String> = ks.aliases();
    let result = serde_like_json(&aliases, ks.len());
    Ok(result)
}

/// Auto-detect format and load keystore
#[wasm_bindgen]
pub fn load_auto_detect(data: &[u8], password: &str) -> Result<String, String> {
    let mut ks = KeyStore::new();

    ks.load_auto_detect(Cursor::new(data), password.as_bytes())
        .map_err(|e| format!("Error loading keystore: {:?}", e))?;

    let aliases: Vec<String> = ks.aliases();
    let result = serde_like_json(&aliases, ks.len());
    Ok(result)
}

/// Get private key info from JKS
#[wasm_bindgen]
pub fn get_private_key_info(data: &[u8], password: &str, alias: &str) -> Result<String, String> {
    let mut ks = KeyStore::new();

    ks.load(Cursor::new(data), password.as_bytes())
        .map_err(|e| format!("Error loading JKS: {:?}", e))?;

    let entry = ks
        .get_private_key_entry(alias, password.as_bytes())
        .map_err(|e| format!("Error getting private key: {:?}", e))?;

    Ok(format!(
        "{{\"alias\":\"{}\",\"privateKeyLength\":{},\"certChainLength\":{}}}",
        alias,
        entry.private_key.len(),
        entry.certificate_chain.len()
    ))
}

/// Get raw private key info from PKCS12 (no decryption needed)
#[wasm_bindgen]
pub fn get_pkcs12_private_key_info(data: &[u8], password: &str, alias: &str) -> Result<String, String> {
    let mut ks = KeyStore::new();

    ks.load_pkcs12(Cursor::new(data), password.as_bytes())
        .map_err(|e| format!("Error loading PKCS12: {:?}", e))?;

    let entry = ks
        .get_raw_private_key_entry(alias)
        .map_err(|e| format!("Error getting private key: {:?}", e))?;

    Ok(format!(
        "{{\"alias\":\"{}\",\"privateKeyLength\":{},\"certChainLength\":{}}}",
        alias,
        entry.private_key.len(),
        entry.certificate_chain.len()
    ))
}

/// Test basic keystore operations
#[wasm_bindgen]
pub fn test_basic_operations() -> Result<String, String> {
    // Create keystore with custom RNG for WASM
    let options = KeyStoreOptions {
        rng: Box::new(TestRng { counter: 0 }),
        ..Default::default()
    };
    let mut ks = KeyStore::with_options(options);

    // Test trusted certificate entry
    let tce = TrustedCertificateEntry {
        creation_time: SystemTime::UNIX_EPOCH,
        certificate: Certificate {
            cert_type: "X509".to_string(),
            content: vec![1, 2, 3, 4, 5],
        },
    };

    ks.set_trusted_certificate_entry("test", tce)
        .map_err(|e| format!("Failed to set trusted cert: {:?}", e))?;

    // Test private key entry
    let pke = PrivateKeyEntry {
        creation_time: SystemTime::UNIX_EPOCH,
        private_key: vec![0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x00],
        certificate_chain: vec![Certificate {
            cert_type: "X509".to_string(),
            content: vec![0x30, 0x82, 0x01, 0x00],
        }],
    };

    let password = b"testpassword";
    ks.set_private_key_entry("mykey", pke, password)
        .map_err(|e| format!("Failed to set private key: {:?}", e))?;

    // Test store and reload
    let mut buffer = Vec::new();
    ks.store(&mut buffer, password)
        .map_err(|e| format!("Failed to store: {:?}", e))?;

    let options2 = KeyStoreOptions {
        rng: Box::new(TestRng { counter: 0 }),
        ..Default::default()
    };
    let mut ks2 = KeyStore::with_options(options2);
    ks2.load(Cursor::new(&buffer), password)
        .map_err(|e| format!("Failed to load: {:?}", e))?;

    if ks2.len() != 2 {
        return Err(format!("Wrong entry count: expected 2, got {}", ks2.len()));
    }

    ks2.get_private_key_entry("mykey", password)
        .map_err(|e| format!("Failed to decrypt: {:?}", e))?;

    Ok("All basic operations passed".to_string())
}

// Simple JSON-like output without serde
fn serde_like_json(aliases: &[String], count: usize) -> String {
    let aliases_json: Vec<String> = aliases.iter().map(|a| format!("\"{}\"", a)).collect();
    format!("{{\"count\":{},\"aliases\":[{}]}}", count, aliases_json.join(","))
}
