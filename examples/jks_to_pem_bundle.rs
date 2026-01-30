// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

//! Example: Convert JKS keystore to single combined PEM bundle file
//!
//! This example demonstrates how to:
//! 1. Load a Java keystore (JKS) file
//! 2. Extract private keys and certificates
//! 3. Save them as a single combined PEM bundle file
//!
//! The bundle format is commonly used for:
//! - Nginx (ssl_certificate_key + ssl_certificate in one file)
//! - HAProxy
//! - PostgreSQL client certificates
//! - Docker TLS authentication
//!
//! Usage:
//! ```bash
//! cargo run --example jks_to_pem_bundle -- <keystore.jks> <password> <alias> [output.pem]
//! ```
//!
//! Example:
//! ```bash
//! # First create a test keystore using the pem example
//! cargo run --example pem
//!
//! # Then convert it to a bundle
//! cargo run --example jks_to_pem_bundle -- keystore.jks password alias bundle.pem
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

fn write_pem_section(writer: &mut File, label: &str, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = base64::encode(data);

    writeln!(writer, "-----BEGIN {}-----", label)?;
    for chunk in encoded.as_bytes().chunks(64) {
        writeln!(writer, "{}", String::from_utf8_lossy(chunk))?;
    }
    writeln!(writer, "-----END {}-----", label)?;
    writeln!(writer)?;

    Ok(())
}

fn zeroing(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

fn print_usage(program_name: &str) {
    eprintln!("Usage: {} <keystore.jks> <password> <alias> [output.pem]", program_name);
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  keystore.jks   Path to the JKS keystore file");
    eprintln!("  password       Keystore password");
    eprintln!("  alias          Alias of the entry to export");
    eprintln!("  output.pem     Optional output filename (default: <alias>.pem)");
    eprintln!();
    eprintln!("Example:");
    eprintln!("  {} keystore.jks password alias bundle.pem", program_name);
    eprintln!();
    eprintln!("Bundle file format:");
    eprintln!("  -----BEGIN PRIVATE KEY-----");
    eprintln!("  ...");
    eprintln!("  -----END PRIVATE KEY-----");
    eprintln!("  -----BEGIN CERTIFICATE-----");
    eprintln!("  ...");
    eprintln!("  -----END CERTIFICATE-----");
    eprintln!("  -----BEGIN CERTIFICATE-----  (if chain has more certs)");
    eprintln!("  ...");
    eprintln!("  -----END CERTIFICATE-----");
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
    let output_file = if args.len() >= 4 {
        args[4].clone()
    } else {
        format!("{}.pem", alias)
    };

    let mut password = password_str.as_bytes().to_vec();

    println!("JKS to PEM Bundle Converter");
    println!("===========================");
    println!("Keystore: {}", keystore_path);
    println!("Alias: {}", alias);
    println!("Output: {}", output_file);
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

    // Create the bundle file
    let mut bundle_file = File::create(&output_file)?;

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

        // Write private key first
        println!("\nWriting private key...");
        write_pem_section(&mut bundle_file, "PRIVATE KEY", &pke.private_key)?;

        // Write certificate chain
        println!("Writing certificate chain...");
        for (i, cert) in pke.certificate_chain.iter().enumerate() {
            let label = if cert.cert_type == "X509" || cert.cert_type == "X.509" {
                "CERTIFICATE"
            } else {
                &cert.cert_type
            };
            println!("  Certificate {} ({} bytes)", i + 1, cert.content.len());
            write_pem_section(&mut bundle_file, label, &cert.content)?;
        }

        println!("\nCreated bundle file: {}", output_file);
        println!("File contains:");
        println!("  1x Private Key (PKCS#8)");
        println!("  {}x Certificate(s)", pke.certificate_chain.len());

    } else if ks.is_trusted_certificate_entry(alias) {
        println!("Found TrustedCertificateEntry for '{}'", alias);

        let tce = ks.get_trusted_certificate_entry(alias)?;

        println!("Certificate only (no private key)");

        let label = if tce.certificate.cert_type == "X509" || tce.certificate.cert_type == "X.509" {
            "CERTIFICATE"
        } else {
            &tce.certificate.cert_type
        };

        write_pem_section(&mut bundle_file, label, &tce.certificate.content)?;

        println!("\nCreated bundle file: {}", output_file);

    } else {
        eprintln!("Error: Alias '{}' not found in keystore", alias);
        eprintln!("Available aliases: {:?}", aliases);
        zeroing(&mut password);
        process::exit(1);
    }

    zeroing(&mut password);

    println!("\nConversion completed successfully!");
    println!("\nYou can now use this bundle file with:");
    println!("  - Nginx: ssl_certificate and ssl_certificate_key");
    println!("  - HAProxy: crt-list");
    println!("  - Docker: --tlscert flag");
    println!("  - PostgreSQL: sslkey + sslcert");
    println!("  - Custom applications that accept PEM bundles");

    Ok(())
}

// Simple base64 encoder module
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
