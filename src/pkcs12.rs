// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

//! PKCS12 keystore support using OpenSSL
//!
//! This module provides support for reading PKCS12 formatted keystores.
//! PKCS12 is the successor to JKS and is the default format for Android keystores.

use crate::{Certificate, Entry, KeyStore, KeyStoreError, PrivateKeyEntry, Result};
use std::io::Read;

/// PKCS12 magic bytes (ASN.1 SEQUENCE tag = 0x30)
pub const PKCS12_MAGIC: u8 = 0x30;

/// Detect if data is PKCS12 format
pub fn is_pkcs12_data(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == PKCS12_MAGIC
}

/// Try to extract alias from certificate (CN or friendly name)
fn extract_alias_from_cert(cert: &openssl::x509::X509) -> String {
    // Try to get friendly name first (if available)
    // Note: OpenSSL's Rust bindings don't expose friendly_name directly

    // Fall back to subject CN (Common Name)
    let name = cert.subject_name();
    let mut cn_entry = name.entries_by_nid(openssl::nid::Nid::COMMONNAME);
    if let Some(cn) = cn_entry.next() {
        let cn_data = cn.data();
        let cn_bytes = cn_data.as_slice();
        if let Ok(cn_str) = std::string::String::from_utf8(cn_bytes.to_vec()) {
            if !cn_str.is_empty() {
                return cn_str;
            }
        }
    }

    // Final fallback
    "key_0".to_string()
}

impl KeyStore {
    /// Load a PKCS12 keystore from reader
    ///
    /// PKCS12 is the standard keystore format used by:
    /// - Android (`.keystore` files)
    /// - Java (`.p12`/`.pfx` files)
    /// - OpenSSL
    pub fn load_pkcs12<R: Read>(&mut self, mut reader: R, password: &[u8]) -> Result<()> {
        #[cfg(feature = "openssl")]
        {
            use openssl::pkcs12::Pkcs12;

            let mut buffer = Vec::new();
            reader.read_to_end(&mut buffer)?;

            let password_str = std::str::from_utf8(password)
                .map_err(|_| KeyStoreError::Other("Invalid UTF-8 password".to_string()))?;

            // Parse the PKCS12 structure
            let pkcs12 = Pkcs12::from_der(&buffer)
                .map_err(|e| KeyStoreError::Other(format!("PKCS12 parse error: {}", e)))?;

            // Extract the identity (private key + certificate chain)
            let parsed = pkcs12
                .parse2(password_str)
                .map_err(|e| KeyStoreError::Other(format!("PKCS12 decrypt error: {}", e)))?;

            // Clear existing entries
            self.entries.clear();

            // Process the identity (private key + cert chain)
            if let Some(pkey) = parsed.pkey {
                let private_key = pkey
                    .private_key_to_pkcs8()
                    .map_err(|e| KeyStoreError::Other(format!("Failed to export private key: {}", e)))?;

                // Build certificate chain: cert (end-entity) + ca (intermediate + root)
                let mut cert_chain = Vec::new();

                // Extract alias from certificate
                let alias = if let Some(cert) = &parsed.cert {
                    // Store the certificate in chain
                    cert_chain.push(Certificate {
                        cert_type: "X509".to_string(),
                        content: cert.to_der().unwrap_or_default(),
                    });

                    // Try to extract alias from certificate
                    extract_alias_from_cert(cert)
                } else {
                    "key_0".to_string()
                };

                // Add CA certificates if present
                if let Some(ca_stack) = parsed.ca {
                    for cert in ca_stack.iter() {
                        cert_chain.push(Certificate {
                            cert_type: "X509".to_string(),
                            content: cert.to_der().unwrap_or_default(),
                        });
                    }
                }

                let entry = PrivateKeyEntry {
                    creation_time: std::time::SystemTime::now(),
                    private_key,
                    certificate_chain: cert_chain,
                };

                self.entries.insert(self.convert_alias(&alias), Entry::PrivateKey(entry));
            }

            Ok(())
        }

        #[cfg(not(feature = "openssl"))]
        {
            Err(KeyStoreError::Other(
                "OpenSSL feature not enabled. Enable with: cargo build --features openssl".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_pkcs12_data() {
        // PKCS12 starts with ASN.1 SEQUENCE tag (0x30)
        assert!(is_pkcs12_data(&[0x30, 0x82, 0x00, 0x00]));
        assert!(!is_pkcs12_data(&[0xFE, 0xED, 0xFE, 0xED])); // JKS magic
    }
}
