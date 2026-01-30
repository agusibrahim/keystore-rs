// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

//! Example: Read Java's cacerts truststore
//!
//! This example demonstrates how to:
//! 1. Load a Java truststore (cacerts)
//! 2. Iterate through trusted certificate entries
//! 3. Parse and display certificate information
//!
//! Usage:
//! ```bash
//! cargo run --example truststore -- /path/to/cacerts changeit
//! ```
//!
//! Typical cacerts locations:
//! - macOS: /Library/Java/JavaVirtualMachines/<jdk>/Contents/Home/lib/security/cacerts
//! - Linux: /usr/lib/jvm/java-<version>/jre/lib/security/cacerts
//! - Or use: $JAVA_HOME/lib/security/cacerts

use jks::KeyStore;
use std::env;
use std::fs::File;
use std::process;

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
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <path-to-cacerts> <password>", args[0]);
        eprintln!("\nExample:");
        eprintln!("  {} /Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home/lib/security/cacerts changeit", args[0]);
        eprintln!("\nDefault cacerts password is usually 'changeit'");
        process::exit(1);
    }

    let path = &args[1];
    let password = args[2].as_bytes();
    let mut password_owned = password.to_vec();

    println!("Reading truststore from: {}", path);

    // Load the truststore
    let ks = match read_keystore(path, password) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("Error loading keystore: {}", e);
            eprintln!("\nMake sure the path is correct and the password is valid.");
            eprintln!("Default password for Java cacerts is 'changeit'");
            process::exit(1);
        }
    };

    println!("Truststore loaded successfully");
    println!("\nTotal entries: {}", ks.len());

    // Get all aliases
    let aliases = ks.aliases();
    println!("\nTrusted certificates (showing first 20):\n");

    for (i, alias) in aliases.iter().take(20).enumerate() {
        if let Ok(tce) = ks.get_trusted_certificate_entry(alias) {
            println!("{}. {}", i + 1, alias);
            println!("   Type: {}", tce.certificate.cert_type);
            println!("   Length: {} bytes", tce.certificate.content.len());
        }
    }

    if aliases.len() > 20 {
        println!("\n... and {} more entries", aliases.len() - 20);
    }

    // Clean up password
    zeroing(&mut password_owned);

    println!("\nExample completed successfully!");

    Ok(())
}
