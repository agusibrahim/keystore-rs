// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

//! Example: Compare two keystores for equality
//!
//! This example demonstrates:
//! 1. Creating keystores with custom RNG for deterministic output
//! 2. Writing and reading keystores
//! 3. Comparing keystores for equality
//!
//! When using a fixed RNG (all bytes = 1), the salt for encryption
//! will be the same, resulting in identical encrypted output.

use jks::{Certificate, KeyStore, KeyStoreOptions, PrivateKeyEntry};
use std::fs::File;
use std::io::Read;
use std::time::SystemTime;

/// A fixed RNG that returns all ones (for deterministic testing)
struct FixedRandom(u8);

impl jks::common::RandomReader for FixedRandom {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        buf.fill(self.0);
        Ok(())
    }
}

fn read_private_key_pem(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut pem_file = File::open(path)?;
    let mut pem_data = String::new();
    pem_file.read_to_string(&mut pem_data)?;

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

    // Read PEM files
    let private_key = read_private_key_pem("examples/data/key.pem")?;
    let cert_content = read_certificate_pem("examples/data/cert.pem")?;

    let ct = SystemTime::now();

    // Create first keystore with fixed RNG
    let options1 = KeyStoreOptions {
        ordered_aliases: true,
        rng: Box::new(FixedRandom(1)),
        ..Default::default()
    };
    let mut ks1 = KeyStore::with_options(options1);

    let pke1 = PrivateKeyEntry {
        creation_time: ct,
        private_key: private_key.clone(),
        certificate_chain: vec![Certificate {
            cert_type: "X509".to_string(),
            content: cert_content.clone(),
        }],
    };

    ks1.set_private_key_entry("pke1", pke1, &password)?;

    let pke2 = PrivateKeyEntry {
        creation_time: ct,
        private_key: private_key.clone(),
        certificate_chain: vec![Certificate {
            cert_type: "X509".to_string(),
            content: cert_content.clone(),
        }],
    };

    ks1.set_private_key_entry("pke2", pke2, &password)?;

    // Create second keystore with same fixed RNG
    let options2 = KeyStoreOptions {
        ordered_aliases: true,
        rng: Box::new(FixedRandom(1)),
        ..Default::default()
    };
    let mut ks2 = KeyStore::with_options(options2);

    let pke3 = PrivateKeyEntry {
        creation_time: ct,
        private_key,
        certificate_chain: vec![Certificate {
            cert_type: "X509".to_string(),
            content: cert_content,
        }],
    };

    ks2.set_private_key_entry("pke1", pke3, &password)?;

    let pke4 = PrivateKeyEntry {
        creation_time: ct,
        private_key: vec![0; 100], // Different key to distinguish
        certificate_chain: vec![Certificate {
            cert_type: "X509".to_string(),
            content: vec![0; 100],
        }],
    };

    ks2.set_private_key_entry("pke2", pke4, &password)?;

    // Write both keystores
    write_keystore(&ks1, "keystore1.jks", &password)?;
    println!("Wrote keystore1.jks");

    write_keystore(&ks2, "keystore2.jks", &password)?;
    println!("Wrote keystore2.jks");

    // Read them back
    let ks1_loaded = read_keystore("keystore1.jks", &password)?;
    println!("Loaded keystore1.jks");

    let ks2_loaded = read_keystore("keystore2.jks", &password)?;
    println!("Loaded keystore2.jks");

    // Compare
    println!("\nComparing keystores...");

    let aliases1 = ks1_loaded.aliases();
    let aliases2 = ks2_loaded.aliases();

    println!("Keystore 1 aliases: {:?}", aliases1);
    println!("Keystore 2 aliases: {:?}", aliases2);

    // Compare entry counts
    let is_equal = ks1_loaded.len() == ks2_loaded.len()
        && aliases1 == aliases2
        && ks1_loaded.len() == 2;

    if is_equal {
        println!("\nKeystores have the same structure!");
        println!("- Both have {} entries", ks1_loaded.len());
        println!("- Both have the same aliases");

        // Compare individual entries
        for alias in &aliases1 {
            let entry1 = ks1_loaded.get_private_key_entry(alias, &password)?;
            let entry2 = ks2_loaded.get_private_key_entry(alias, &password)?;

            let keys_equal = entry1.private_key == entry2.private_key;
            println!(
                "- Entry '{}': keys are {}",
                alias,
                if keys_equal { "EQUAL" } else { "DIFFERENT" }
            );
        }
    } else {
        println!("\nKeystores differ!");
    }

    // Clean up password
    zeroing(&mut password);

    println!("\nExample completed successfully!");

    Ok(())
}
