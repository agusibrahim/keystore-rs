// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

//! Example: Create a keystore from PEM files
//!
//! This example demonstrates how to:
//! 1. Read a private key and certificate from PEM files
//! 2. Create a PrivateKeyEntry
//! 3. Store it in a keystore
//! 4. Load the keystore back and verify
//!
//! To generate test PEM files:
//! ```bash
//! openssl req -x509 -sha256 -nodes -days 365 -subj '/CN=localhost' \
//!   -newkey rsa:2048 -outform pem -keyout examples/data/key.pem \
//!   -out examples/data/cert.pem
//! ```

use jks::{Certificate, KeyStore, PrivateKeyEntry};
use std::fs::File;
use std::io::Read;
use std::time::SystemTime;

fn read_private_key_pem(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut pem_file = File::open(path)?;
    let mut pem_data = String::new();
    pem_file.read_to_string(&mut pem_data)?;

    // Parse PEM to get the base64 content
    let pem = pem::parse(&pem_data)?;
    Ok(pem.into_contents())
}

fn read_certificate_pem(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut pem_file = File::open(path)?;
    let mut pem_data = String::new();
    pem_file.read_to_string(&mut pem_data)?;

    let pem = pem::parse(&pem_data)?;
    Ok(pem.into_contents())
}

fn read_keystore(path: &str, password: &[u8]) -> Result<KeyStore, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut ks = KeyStore::new();
    ks.load(&mut file, password)?;
    Ok(ks)
}

fn write_keystore(ks: &KeyStore, path: &str, password: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(path)?;
    ks.store(&mut file, password)?;
    Ok(())
}

fn zeroing(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut password = *b"password";

    // Create a new keystore
    let mut ks1 = KeyStore::new();

    // Read private key and certificate from PEM files
    let private_key = read_private_key_pem("examples/data/key.pem")?;
    let cert_content = read_certificate_pem("examples/data/cert.pem")?;

    // Create a private key entry
    let pke = PrivateKeyEntry {
        creation_time: SystemTime::now(),
        private_key,
        certificate_chain: vec![Certificate {
            cert_type: "X509".to_string(),
            content: cert_content,
        }],
    };

    // Add the entry to the keystore
    ks1.set_private_key_entry("alias", pke, &password)?;
    println!("Added private key entry with alias 'alias'");

    // Write the keystore to a file
    write_keystore(&ks1, "keystore.jks", &password)?;
    println!("Wrote keystore to keystore.jks");

    // Load the keystore back
    let ks2 = read_keystore("keystore.jks", &password)?;
    println!("Loaded keystore from keystore.jks");

    // Retrieve and verify the entry
    let retrieved = ks2.get_private_key_entry("alias", &password)?;
    println!("Retrieved private key entry:");
    println!("  Certificate chain length: {}", retrieved.certificate_chain.len());
    println!(
        "  Certificate type: {}",
        retrieved.certificate_chain[0].cert_type
    );
    println!("  Private key length: {} bytes", retrieved.private_key.len());

    // Clean up password
    zeroing(&mut password);

    println!("\nExample completed successfully!");

    Ok(())
}
