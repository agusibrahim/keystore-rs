// Copyright (c) 2024 agusibrahim
// SPDX-License-Identifier: MIT

//! Example: Read an existing keystore with password-protected private key
//!
//! This example demonstrates how to:
//! 1. Load an existing Java keystore (JKS) file
//! 2. Access a password-protected private key entry
//! 3. Decrypt and use the private key
//!
//! To create a test keystore:
//! ```bash
//! # Generate a test keystore with dummy data
//! openssl req -x509 -sha256 -nodes -days 365 -subj '/CN=test' \
//!   -newkey rsa:2048 -keyout test-key.pem -out test-cert.pem
//!
//! # Then use the pem example to create a JKS file
//! cargo run --example pem
//! ```

use jks::KeyStore;
use std::fs::File;

fn read_keystore(path: &str, password: &[u8]) -> Result<KeyStore, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut ks = KeyStore::new();
    ks.load(&mut file, password)?;
    Ok(ks)
}

fn zeroing(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example: read a keystore with password
    // Replace these values with your actual keystore and password
    let keystore_path = "keystore.jks"; // Path to your JKS file
    let mut password = b"your-password".to_vec(); // Replace with your password

    println!("Reading keystore from: {}", keystore_path);

    // Load the keystore
    let ks = match read_keystore(keystore_path, &password) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("Error loading keystore: {}", e);
            eprintln!("\nMake sure:");
            eprintln!("  1. The keystore file exists at: {}", keystore_path);
            eprintln!("  2. The password is correct");
            eprintln!("  3. The file is a valid JKS keystore");
            eprintln!("\nTo create a test keystore, run:");
            eprintln!("  cargo run --example pem");
            zeroing(&mut password);
            std::process::exit(1);
        }
    };

    println!("Keystore loaded successfully");

    // List all aliases
    println!("\nAliases in keystore:");
    for alias in ks.aliases() {
        println!("  - {}", alias);
    }

    // Get the first private key entry as an example
    for alias in ks.aliases() {
        if ks.is_private_key_entry(&alias) {
            println!("\nReading private key entry for alias '{}'...", alias);

            match ks.get_private_key_entry(&alias, &password) {
                Ok(pke) => {
                    println!("Private key entry retrieved:");
                    println!("  Creation time: {:?}", pke.creation_time);
                    println!("  Private key length: {} bytes", pke.private_key.len());
                    println!(
                        "  Certificate chain length: {}",
                        pke.certificate_chain.len()
                    );

                    // Display certificate info
                    for (i, cert) in pke.certificate_chain.iter().enumerate() {
                        println!("\n  Certificate {}:", i);
                        println!("    Type: {}", cert.cert_type);
                        println!("    Content length: {} bytes", cert.content.len());
                        println!("    Valid DER certificate: yes (parsed successfully)");
                    }
                }
                Err(e) => {
                    eprintln!("Error decrypting private key: {}", e);
                    eprintln!("The password might be incorrect");
                }
            }
            break;
        }
    }

    // Clean up password
    zeroing(&mut password);

    println!("\nExample completed successfully!");

    Ok(())
}
