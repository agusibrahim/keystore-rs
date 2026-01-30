// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

//! PKCS12 keystore support using pure Rust p12-keystore library
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

impl KeyStore {
    /// Load a PKCS12 keystore from reader
    ///
    /// PKCS12 is the standard keystore format used by:
    /// - Android (`.keystore` files)
    /// - Java (`.p12`/`.pfx` files)
    /// - OpenSSL
    pub fn load_pkcs12<R: Read>(&mut self, mut reader: R, password: &[u8]) -> Result<()> {
        #[cfg(feature = "pkcs12")]
        {
            use p12_keystore::{KeyStore as P12KeyStore, KeyStoreEntry as P12Entry};

            let mut buffer = Vec::new();
            reader.read_to_end(&mut buffer)?;

            let password_str = std::str::from_utf8(password)
                .map_err(|_| KeyStoreError::Other("Invalid UTF-8 password".to_string()))?;

            // Parse the PKCS12 structure using p12-keystore
            let p12_ks = P12KeyStore::from_pkcs12(&buffer, password_str)
                .map_err(|e| KeyStoreError::Other(format!("PKCS12 parse error: {}", e)))?;

            // Clear existing entries
            self.entries.clear();

            // Process all entries
            for (alias, entry) in p12_ks.entries() {
                match entry {
                    P12Entry::PrivateKeyChain(chain) => {
                        // Get the private key in PKCS#8 DER format
                        let private_key = chain.key().as_der().to_vec();

                        // Build certificate chain
                        let cert_chain: Vec<Certificate> = chain
                            .certs()
                            .iter()
                            .map(|cert| Certificate {
                                cert_type: "X509".to_string(),
                                content: cert.as_der().to_vec(),
                            })
                            .collect();

                        let entry = PrivateKeyEntry {
                            // Use UNIX_EPOCH for WASM compatibility (SystemTime::now() panics in WASM)
                            creation_time: std::time::SystemTime::UNIX_EPOCH,
                            private_key,
                            certificate_chain: cert_chain,
                        };

                        self.entries
                            .insert(self.convert_alias(alias), Entry::PrivateKey(entry));
                    }
                    P12Entry::Certificate(cert) => {
                        // Trusted certificate entry
                        let tce = crate::TrustedCertificateEntry {
                            // Use UNIX_EPOCH for WASM compatibility (SystemTime::now() panics in WASM)
                            creation_time: std::time::SystemTime::UNIX_EPOCH,
                            certificate: Certificate {
                                cert_type: "X509".to_string(),
                                content: cert.as_der().to_vec(),
                            },
                        };
                        self.entries
                            .insert(self.convert_alias(alias), Entry::TrustedCertificate(tce));
                    }
                    P12Entry::Secret(_) => {
                        // Secret entries are not supported in JKS format, skip
                    }
                }
            }

            Ok(())
        }

        #[cfg(not(feature = "pkcs12"))]
        {
            let _ = (reader, password);
            Err(KeyStoreError::Other(
                "PKCS12 feature not enabled. Enable with: cargo build --features pkcs12"
                    .to_string(),
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

#[cfg(all(test, feature = "pkcs12"))]
mod integration_tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_load_pbes2_keystore() {
        let data = include_bytes!("../p12-keystore-main/tests/assets/pbes2-keystore.p12");
        let mut ks = KeyStore::new();
        ks.load_pkcs12(Cursor::new(data.as_slice()), b"changeit").unwrap();
        
        // Should have at least one entry
        assert!(!ks.is_empty(), "Keystore should not be empty");
        
        // Check that we can access the entries
        for alias in ks.aliases() {
            if ks.is_private_key_entry(&alias) {
                let entry = ks.get_raw_private_key_entry(&alias).unwrap();
                assert!(!entry.private_key.is_empty());
                assert!(!entry.certificate_chain.is_empty());
            }
        }
    }
    
    #[test]
    fn test_load_auto_detect_pkcs12() {
        let data = include_bytes!("../p12-keystore-main/tests/assets/pbes2-keystore.p12");
        let mut ks = KeyStore::new();
        ks.load_auto_detect(Cursor::new(data.as_slice()), b"changeit").unwrap();
        
        assert!(!ks.is_empty(), "Keystore should not be empty after auto-detect load");
    }
}
