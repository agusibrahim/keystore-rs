// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

//! Example: Convert JKS keystore to PEM files
//!
//! This example demonstrates how to:
//! 1. Load a Java keystore (JKS) file
//! 2. Extract private keys and certificates
//! 3. Save them as PEM files
//!
//! Usage:
//! ```bash
//! cargo run --example jks_to_pem -- <keystore.jks> <password> <alias> [output_prefix]
//! ```
//!
//! Example:
//! ```bash
//! # First create a test keystore using the pem example
//! cargo run --example pem
//!
//! # Then convert it to PEM files
//! cargo run --example jks_to_pem -- keystore.jks password alias mykey
//! # Output: mykey_private_key.pem, mykey_certificate.pem
//! ```

use jks::KeyStore;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process;

fn read_keystore(path: &str, password: &[u8]) -> Result<KeyStore, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut ks = KeyStore::new();
    ks.load(&mut file, password)?;
    Ok(ks)
}

fn write_pem(path: PathBuf, label: &str, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = base64::encode(data);
    let mut file = File::create(&path)?;

    writeln!(file, "-----BEGIN {}-----", label)?;
    for chunk in encoded.as_bytes().chunks(64) {
        writeln!(file, "{}", String::from_utf8_lossy(chunk))?;
    }
    writeln!(file, "-----END {}-----", label)?;

    println!("Created: {}", path.display());
    Ok(())
}

fn zeroing(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

fn print_usage(program_name: &str) {
    eprintln!("Usage: {} <keystore.jks> <password> <alias> [output_prefix]", program_name);
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  keystore.jks   Path to the JKS keystore file");
    eprintln!("  password       Keystore password");
    eprintln!("  alias          Alias of the entry to export");
    eprintln!("  output_prefix  Optional prefix for output files (default: <alias>)");
    eprintln!();
    eprintln!("Example:");
    eprintln!("  {} keystore.jks password alias output", program_name);
    eprintln!();
    eprintln!("Output files:");
    eprintln!("  <output_prefix>_private_key.pem    Private key in PKCS#8 format");
    eprintln!("  <output_prefix>_certificate.pem    Certificate(s)");
    eprintln!("  <output_prefix>_chain.pem          Full certificate chain");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        print_usage(&args[0]);
        process::exit(1);
    }

    let keystore_path = &args[1];
    let password_str = &args[2];
    let alias = &args[3];
    let output_prefix = if args.len() >= 5 {
        args[4].clone()
    } else {
        alias.clone()
    };

    let mut password = password_str.as_bytes().to_vec();

    println!("JKS to PEM Converter");
    println!("===================");
    println!("Keystore: {}", keystore_path);
    println!("Alias: {}", alias);
    println!("Output prefix: {}", output_prefix);
    println!();

    // Load the keystore
    let ks = match read_keystore(keystore_path, &password) {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!("Error loading keystore: {}", e);
            zeroing(&mut password);
            process::exit(1);
        }
    };

    println!("Keystore loaded successfully");

    // List all aliases
    let aliases = ks.aliases();
    println!("\nAvailable aliases ({}):", aliases.len());
    for a in &aliases {
        println!("  - {}", a);
    }
    println!();

    // Check if it's a private key entry
    if ks.is_private_key_entry(alias) {
        println!("Found PrivateKeyEntry for '{}'", alias);

        let pke = match ks.get_private_key_entry(alias, &password) {
            Ok(entry) => entry,
            Err(e) => {
                eprintln!("Error decrypting private key: {}", e);
                eprintln!("Make sure the key password matches the keystore password");
                zeroing(&mut password);
                process::exit(1);
            }
        };

        println!("  Private key size: {} bytes", pke.private_key.len());
        println!("  Certificate chain: {} certificate(s)", pke.certificate_chain.len());

        // Write private key
        let key_path = format!("{}_private_key.pem", output_prefix);
        write_pem(
            PathBuf::from(&key_path),
            "PRIVATE KEY",
            &pke.private_key,
        )?;

        // Write each certificate in the chain
        for (i, cert) in pke.certificate_chain.iter().enumerate() {
            let cert_path = if pke.certificate_chain.len() == 1 {
                format!("{}_certificate.pem", output_prefix)
            } else {
                format!("{}_certificate_{}.pem", output_prefix, i)
            };
            // Use "CERTIFICATE" label for OpenSSL compatibility
            let label = if cert.cert_type == "X509" || cert.cert_type == "X.509" {
                "CERTIFICATE"
            } else {
                &cert.cert_type
            };
            write_pem(PathBuf::from(&cert_path), label, &cert.content)?;
        }

        // Write full certificate chain in one file
        let chain_path = format!("{}_chain.pem", output_prefix);
        let mut chain_file = File::create(&chain_path)?;
        for cert in &pke.certificate_chain {
            let label = if cert.cert_type == "X509" || cert.cert_type == "X.509" {
                "CERTIFICATE"
            } else {
                &cert.cert_type
            };
            let encoded = base64::encode(&cert.content);
            writeln!(chain_file, "-----BEGIN {}-----", label)?;
            for chunk in encoded.as_bytes().chunks(64) {
                writeln!(chain_file, "{}", String::from_utf8_lossy(chunk))?;
            }
            writeln!(chain_file, "-----END {}-----", label)?;
            writeln!(chain_file)?;
        }
        println!("Created: {}", chain_path);

    } else if ks.is_trusted_certificate_entry(alias) {
        println!("Found TrustedCertificateEntry for '{}'", alias);

        let tce = ks.get_trusted_certificate_entry(alias)?;

        let cert_path = format!("{}_certificate.pem", output_prefix);
        let label = if tce.certificate.cert_type == "X509" || tce.certificate.cert_type == "X.509" {
            "CERTIFICATE"
        } else {
            &tce.certificate.cert_type
        };
        write_pem(
            PathBuf::from(&cert_path),
            label,
            &tce.certificate.content,
        )?;

    } else {
        eprintln!("Error: Alias '{}' not found in keystore", alias);
        eprintln!("Available aliases: {:?}", aliases);
        zeroing(&mut password);
        process::exit(1);
    }

    zeroing(&mut password);

    println!();
    println!("Conversion completed successfully!");

    Ok(())
}

// Simple base64 encoder modul
mod base64 {
    const ENCODE_TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(data: &[u8]) -> String {
        let mut result = String::new();
        let chunks = data.chunks(3);

        for chunk in chunks {
            let mut group = [0u8; 3];
            group[..chunk.len()].copy_from_slice(chunk);

            let b0 = group[0];
            let b1 = if chunk.len() > 1 { group[1] } else { 0 };
            let b2 = if chunk.len() > 2 { group[2] } else { 0 };

            let index0 = b0 >> 2;
            let index1 = ((b0 & 0x03) << 4) | (b1 >> 4);
            let index2 = ((b1 & 0x0F) << 2) | (b2 >> 6);
            let index3 = b2 & 0x3F;

            result.push(ENCODE_TABLE[index0 as usize] as char);
            result.push(ENCODE_TABLE[index1 as usize] as char);

            if chunk.len() > 1 {
                result.push(ENCODE_TABLE[index2 as usize] as char);
            } else {
                result.push('=');
            }

            if chunk.len() > 2 {
                result.push(ENCODE_TABLE[index3 as usize] as char);
            } else {
                result.push('=');
            }
        }

        result
    }
}
