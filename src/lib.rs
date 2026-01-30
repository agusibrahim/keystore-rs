// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

//! # Keystore-RS
//!
//! A Rust implementation of Java KeyStore (JKS) encoder/decoder.
//!
//! ## Example
//!
//! ```no_run
//! use jks::{KeyStore, PrivateKeyEntry, Certificate};
//! use std::time::SystemTime;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut ks = KeyStore::new();
//!
//! let entry = PrivateKeyEntry {
//!     creation_time: SystemTime::now(),
//!     private_key: vec![/* PKCS#8 private key */],
//!     certificate_chain: vec![
//!         Certificate {
//!             cert_type: "X509".to_string(),
//!             content: vec![/* certificate bytes */],
//!         }
//!     ],
//! };
//!
//! let password = b"password";
//! ks.set_private_key_entry("myalias", entry, password)?;
//!
//! // Write to file
//! let mut file = std::fs::File::create("keystore.jks")?;
//! ks.store(&mut file, password)?;
//! # Ok(())
//! # }
//! ```

pub mod common;
pub mod decoder;
pub mod encoder;
pub mod keyprotector;

pub use common::{
    zeroing, Certificate, KeyStoreOptions, PrivateKeyEntry, TrustedCertificateEntry,
};
use encoder::Encoder;
use std::collections::HashMap;
use std::io::{self, Read, Write};

/// Main error type for keystore operations
#[derive(thiserror::Error, Debug)]
pub enum KeyStoreError {
    #[error("entry not found")]
    EntryNotFound,

    #[error("wrong entry type")]
    WrongEntryType,

    #[error("empty private key")]
    EmptyPrivateKey,

    #[error("empty certificate type")]
    EmptyCertificateType,

    #[error("empty certificate content")]
    EmptyCertificateContent,

    #[error("short password")]
    ShortPassword,

    #[error("got invalid magic")]
    InvalidMagic,

    #[error("got invalid digest")]
    InvalidDigest,

    #[error("got unknown version: {0}")]
    UnknownVersion(u32),

    #[error("got unknown entry tag: {0}")]
    UnknownEntryTag(u32),

    #[error("got unsupported private key encryption algorithm")]
    UnsupportedAlgorithm,

    #[error("got extra data in encrypted key")]
    ExtraDataInEncryptedKey,

    #[error("got invalid entry")]
    InvalidEntry,

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("ASN.1 error: {0}")]
    Asn1(String),

    #[error("other error: {0}")]
    Other(String),
}

/// Result type for keystore operations
pub type Result<T> = std::result::Result<T, KeyStoreError>;

/// Java KeyStore (JKS) implementation
///
/// A KeyStore is a mapping of alias to either a PrivateKeyEntry or TrustedCertificateEntry.
pub struct KeyStore {
    entries: HashMap<String, Entry>,
    options: KeyStoreOptions,
}

/// Entry types in the keystore
#[derive(Debug, Clone)]
pub enum Entry {
    PrivateKey(PrivateKeyEntry),
    TrustedCertificate(TrustedCertificateEntry),
}

impl KeyStore {
    /// Creates a new empty KeyStore with default options
    pub fn new() -> Self {
        Self::with_options(KeyStoreOptions::default())
    }

    /// Creates a new empty KeyStore with custom options
    pub fn with_options(options: KeyStoreOptions) -> Self {
        Self {
            entries: HashMap::new(),
            options,
        }
    }

    /// Writes the keystore to the writer with password-based signature
    ///
    /// It is strongly recommended to zero out the password after use.
    pub fn store<W: Write>(&self, mut w: W, password: &[u8]) -> Result<()> {
        if password.len() < self.options.min_password_len {
            return Err(KeyStoreError::ShortPassword);
        }

        let mut encoder = Encoder::new(&mut w);

        // Write password to digest
        let password_bytes = common::password_bytes(password);
        encoder.update_digest(&password_bytes);

        // Write whitener message to digest
        encoder.update_digest(common::WHITENER_MESSAGE);

        // Write magic
        encoder.write_u32(common::MAGIC)?;

        // Always write latest version
        encoder.write_u32(common::VERSION_02)?;

        // Write number of entries
        encoder.write_u32(self.entries.len() as u32)?;

        // Write entries
        let aliases: Vec<String> = if self.options.ordered_aliases {
            let mut aliases: Vec<_> = self.entries.keys().cloned().collect();
            aliases.sort();
            aliases
        } else {
            self.entries.keys().cloned().collect()
        };

        for alias in aliases {
            let entry = self.entries.get(&alias).unwrap();
            match entry {
                Entry::PrivateKey(pke) => encoder.write_private_key_entry(&alias, pke)?,
                Entry::TrustedCertificate(tce) => {
                    encoder.write_trusted_certificate_entry(&alias, tce)?;
                }
            }
        }

        // Write digest
        encoder.write_digest()?;

        Ok(())
    }

    /// Reads a keystore from the reader and verifies its signature
    ///
    /// It is strongly recommended to zero out the password after use.
    pub fn load<R: Read>(&mut self, mut r: R, password: &[u8]) -> Result<()> {
        use decoder::Decoder;

        let mut decoder = Decoder::new(&mut r);

        // Update digest with password
        let password_bytes = common::password_bytes(password);
        decoder.update_digest(&password_bytes);

        // Update digest with whitener message
        decoder.update_digest(common::WHITENER_MESSAGE);

        // Read and verify magic
        let magic = decoder.read_u32()?;
        if magic != common::MAGIC {
            return Err(KeyStoreError::InvalidMagic);
        }

        // Read version
        let version = decoder.read_u32()?;

        // Read number of entries
        let count = decoder.read_u32()?;

        // Clear existing entries
        self.entries.clear();

        // Read entries
        for _ in 0..count {
            let (alias, entry) = decoder.read_entry(version)?;
            self.entries.insert(alias, entry);
        }

        // Verify digest
        decoder.verify_digest()?;

        Ok(())
    }

    /// Adds a PrivateKeyEntry encrypted with the password
    ///
    /// It is strongly recommended to zero out the password after use.
    pub fn set_private_key_entry(
        &mut self,
        alias: &str,
        mut entry: PrivateKeyEntry,
        password: &[u8],
    ) -> Result<()> {
        entry.validate()?;

        if password.len() < self.options.min_password_len {
            return Err(KeyStoreError::ShortPassword);
        }

        // Encrypt the private key
        let encrypted = keyprotector::encrypt(
            self.options.rng.as_mut(),
            &entry.private_key,
            password,
            self.options.password_bytes,
        )?;
        entry.private_key = encrypted;

        self.entries.insert(self.convert_alias(alias), Entry::PrivateKey(entry));
        Ok(())
    }

    /// Returns and decrypts a PrivateKeyEntry with the password
    ///
    /// It is strongly recommended to zero out the password after use.
    pub fn get_private_key_entry(
        &self,
        alias: &str,
        password: &[u8],
    ) -> Result<PrivateKeyEntry> {
        let entry = self
            .entries
            .get(&self.convert_alias(alias))
            .ok_or(KeyStoreError::EntryNotFound)?;

        match entry {
            Entry::PrivateKey(pke) => {
                let decrypted =
                    keyprotector::decrypt(&pke.private_key, password, self.options.password_bytes)?;
                Ok(PrivateKeyEntry {
                    private_key: decrypted,
                    ..pke.clone()
                })
            }
            Entry::TrustedCertificate(_) => Err(KeyStoreError::WrongEntryType),
        }
    }

    /// Returns the certificate chain associated with a PrivateKeyEntry
    pub fn get_private_key_entry_certificate_chain(
        &self,
        alias: &str,
    ) -> Result<Vec<Certificate>> {
        let entry = self
            .entries
            .get(&self.convert_alias(alias))
            .ok_or(KeyStoreError::EntryNotFound)?;

        match entry {
            Entry::PrivateKey(pke) => Ok(pke.certificate_chain.clone()),
            Entry::TrustedCertificate(_) => Err(KeyStoreError::WrongEntryType),
        }
    }

    /// Returns true if the alias exists and is a PrivateKeyEntry
    pub fn is_private_key_entry(&self, alias: &str) -> bool {
        match self.entries.get(&self.convert_alias(alias)) {
            Some(Entry::PrivateKey(_)) => true,
            _ => false,
        }
    }

    /// Adds a TrustedCertificateEntry (not encrypted, just stored)
    pub fn set_trusted_certificate_entry(
        &mut self,
        alias: &str,
        entry: TrustedCertificateEntry,
    ) -> Result<()> {
        entry.validate()?;
        self.entries
            .insert(self.convert_alias(alias), Entry::TrustedCertificate(entry));
        Ok(())
    }

    /// Returns a TrustedCertificateEntry
    pub fn get_trusted_certificate_entry(&self, alias: &str) -> Result<TrustedCertificateEntry> {
        let entry = self
            .entries
            .get(&self.convert_alias(alias))
            .ok_or(KeyStoreError::EntryNotFound)?;

        match entry {
            Entry::TrustedCertificate(tce) => Ok(tce.clone()),
            Entry::PrivateKey(_) => Err(KeyStoreError::WrongEntryType),
        }
    }

    /// Returns true if the alias exists and is a TrustedCertificateEntry
    pub fn is_trusted_certificate_entry(&self, alias: &str) -> bool {
        match self.entries.get(&self.convert_alias(alias)) {
            Some(Entry::TrustedCertificate(_)) => true,
            _ => false,
        }
    }

    /// Deletes an entry from the keystore
    pub fn delete_entry(&mut self, alias: &str) {
        self.entries.remove(&self.convert_alias(alias));
    }

    /// Returns all aliases in the keystore
    ///
    /// If ordered_aliases is set, returns aliases sorted alphabetically.
    pub fn aliases(&self) -> Vec<String> {
        let mut aliases: Vec<_> = self.entries.keys().cloned().collect();
        if self.options.ordered_aliases {
            aliases.sort();
        }
        aliases
    }

    /// Returns the number of entries in the keystore
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the keystore is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn convert_alias(&self, alias: &str) -> String {
        if self.options.case_exact_aliases {
            alias.to_string()
        } else {
            alias.to_lowercase()
        }
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::SystemTime;

    fn create_test_entry() -> PrivateKeyEntry {
        // Minimal PKCS#8 private key for testing (dummy data)
        let private_key = vec![
            0x30, 0x82, 0x01, 0x53, // SEQUENCE, length 339
            0x02, 0x01, 0x00, // INTEGER 0 (version)
            0x30, 0x0B, 0x06, 0x03, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // RSA OID
            0x05, 0x00, // NULL
            0x04, 0x82, 0x01, 0x3E, // OCTET STRING, length 318
            // RSA private key data (dummy)
        ];

        let mut cert_content = vec![0u8; 200];
        // Fill with some pattern
        for (i, b) in cert_content.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }

        PrivateKeyEntry {
            creation_time: SystemTime::UNIX_EPOCH,
            private_key,
            certificate_chain: vec![Certificate {
                cert_type: "X509".to_string(),
                content: cert_content,
            }],
        }
    }

    #[test]
    fn test_create_empty_keystore() {
        let ks = KeyStore::new();
        assert!(ks.is_empty());
        assert_eq!(ks.len(), 0);
        assert!(ks.aliases().is_empty());
    }

    #[test]
    fn test_set_private_key_entry() {
        let mut ks = KeyStore::new();
        let entry = create_test_entry();
        let password = b"password";

        ks.set_private_key_entry("test", entry, password)
            .unwrap();

        assert_eq!(ks.len(), 1);
        assert!(ks.is_private_key_entry("test"));
        assert!(!ks.is_trusted_certificate_entry("test"));
        assert!(ks.aliases().contains(&"test".to_string()));
    }

    #[test]
    fn test_get_private_key_entry() {
        let mut ks = KeyStore::new();
        let entry = create_test_entry();
        let password = b"password";
        let original_key = entry.private_key.clone();

        ks.set_private_key_entry("test", entry, password)
            .unwrap();

        let retrieved = ks.get_private_key_entry("test", password).unwrap();
        assert_eq!(retrieved.private_key, original_key);
        assert_eq!(retrieved.certificate_chain.len(), 1);
    }

    #[test]
    fn test_entry_not_found() {
        let ks = KeyStore::new();
        let result = ks.get_private_key_entry("nonexistent", b"password");
        assert!(matches!(result, Err(KeyStoreError::EntryNotFound)));
    }

    #[test]
    fn test_wrong_entry_type() {
        let mut ks = KeyStore::new();
        let tce = TrustedCertificateEntry {
            creation_time: SystemTime::UNIX_EPOCH,
            certificate: Certificate {
                cert_type: "X509".to_string(),
                content: vec![1, 2, 3],
            },
        };

        ks.set_trusted_certificate_entry("test", tce).unwrap();

        let result = ks.get_private_key_entry("test", b"password");
        assert!(matches!(result, Err(KeyStoreError::WrongEntryType)));
    }

    #[test]
    fn test_trusted_certificate_entry() {
        let mut ks = KeyStore::new();
        let tce = TrustedCertificateEntry {
            creation_time: SystemTime::UNIX_EPOCH,
            certificate: Certificate {
                cert_type: "X509".to_string(),
                content: vec![1, 2, 3, 4],
            },
        };

        ks.set_trusted_certificate_entry("test", tce).unwrap();

        assert!(ks.is_trusted_certificate_entry("test"));
        assert!(!ks.is_private_key_entry("test"));

        let retrieved = ks.get_trusted_certificate_entry("test").unwrap();
        assert_eq!(retrieved.certificate.content, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_delete_entry() {
        let mut ks = KeyStore::new();
        let entry = create_test_entry();

        ks.set_private_key_entry("test", entry, b"password")
            .unwrap();
        assert_eq!(ks.len(), 1);

        ks.delete_entry("test");
        assert!(ks.is_empty());
    }

    #[test]
    fn test_case_insensitive_alias() {
        let mut ks = KeyStore::new();
        let entry = create_test_entry();

        ks.set_private_key_entry("TestAlias", entry, b"password")
            .unwrap();

        // Should find with different case
        assert!(ks.is_private_key_entry("testalias"));
        assert!(ks.is_private_key_entry("TESTALIAS"));
        assert!(ks.is_private_key_entry("TestAlias"));
    }

    #[test]
    fn test_case_exact_alias() {
        let mut ks = KeyStore::with_options(KeyStoreOptions {
            case_exact_aliases: true,
            ..Default::default()
        });
        let entry = create_test_entry();

        ks.set_private_key_entry("TestAlias", entry, b"password")
            .unwrap();

        // Should only find with exact case
        assert!(ks.is_private_key_entry("TestAlias"));
        assert!(!ks.is_private_key_entry("testalias"));
        assert!(!ks.is_private_key_entry("TESTALIAS"));
    }

    #[test]
    fn test_ordered_aliases() {
        let mut ks = KeyStore::with_options(KeyStoreOptions {
            ordered_aliases: true,
            ..Default::default()
        });
        let entry = create_test_entry();

        ks.set_private_key_entry("zebra", entry.clone(), b"password")
            .unwrap();
        ks.set_private_key_entry("apple", entry.clone(), b"password")
            .unwrap();
        ks.set_private_key_entry("banana", entry, b"password")
            .unwrap();

        let aliases = ks.aliases();
        assert_eq!(aliases, vec!["apple", "banana", "zebra"]);
    }

    #[test]
    fn test_store_and_load() {
        let mut ks1 = KeyStore::new();
        let entry = create_test_entry();
        let password = b"password";

        ks1.set_private_key_entry("test", entry, password)
            .unwrap();

        // Add a trusted cert too
        let tce = TrustedCertificateEntry {
            creation_time: SystemTime::UNIX_EPOCH,
            certificate: Certificate {
                cert_type: "X509".to_string(),
                content: vec![5, 6, 7, 8],
            },
        };
        ks1.set_trusted_certificate_entry("trusted", tce)
            .unwrap();

        // Store to buffer
        let mut buffer = Vec::new();
        ks1.store(&mut buffer, password).unwrap();

        // Load from buffer
        let mut ks2 = KeyStore::new();
        ks2.load(Cursor::new(buffer), password).unwrap();

        // Verify
        assert_eq!(ks2.len(), 2);
        assert!(ks2.is_private_key_entry("test"));
        assert!(ks2.is_trusted_certificate_entry("trusted"));

        let retrieved = ks2.get_private_key_entry("test", password).unwrap();
        assert_eq!(retrieved.certificate_chain.len(), 1);
    }

    #[test]
    fn test_empty_private_key_error() {
        let mut ks = KeyStore::new();
        let entry = PrivateKeyEntry {
            creation_time: SystemTime::UNIX_EPOCH,
            private_key: vec![],
            certificate_chain: vec![],
        };

        let result = ks.set_private_key_entry("test", entry, b"password");
        assert!(matches!(result, Err(KeyStoreError::EmptyPrivateKey)));
    }

    #[test]
fn test_empty_certificate_type_error() {
        let mut ks = KeyStore::new();
        let entry = PrivateKeyEntry {
            creation_time: SystemTime::UNIX_EPOCH,
            private_key: vec![1, 2, 3],
            certificate_chain: vec![Certificate {
                cert_type: String::new(),
                content: vec![1, 2, 3],
            }],
        };

        let result = ks.set_private_key_entry("test", entry, b"password");
        assert!(matches!(result, Err(KeyStoreError::EmptyCertificateType)));
    }

    #[test]
    fn test_empty_certificate_content_error() {
        let mut ks = KeyStore::new();
        let entry = PrivateKeyEntry {
            creation_time: SystemTime::UNIX_EPOCH,
            private_key: vec![1, 2, 3],
            certificate_chain: vec![Certificate {
                cert_type: "X509".to_string(),
                content: vec![],
            }],
        };

        let result = ks.set_private_key_entry("test", entry, b"password");
        assert!(matches!(result, Err(KeyStoreError::EmptyCertificateContent)));
    }

    #[test]
    fn test_short_password_with_min_length() {
        let mut ks = KeyStore::with_options(KeyStoreOptions {
            min_password_len: 10,
            ..Default::default()
        });
        let entry = create_test_entry();

        let result = ks.set_private_key_entry("test", entry, b"short");
        assert!(matches!(result, Err(KeyStoreError::ShortPassword)));
    }

    #[test]
    fn test_wrong_password_digest_fails() {
        let mut ks = KeyStore::new();
        let entry = create_test_entry();
        let correct_password = b"password";

        ks.set_private_key_entry("test", entry, correct_password)
            .unwrap();

        let mut buffer = Vec::new();
        ks.store(&mut buffer, correct_password).unwrap();

        // Try to load with wrong password
        let mut ks2 = KeyStore::new();
        let result = ks2.load(Cursor::new(buffer), b"wrongpassword");
        assert!(matches!(result, Err(KeyStoreError::InvalidDigest)));
    }
}
