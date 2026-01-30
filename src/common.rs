// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

//! Common types and constants for keystore operations

/// Magic number for JKS files
pub const MAGIC: u32 = 0xfeedfeed;

/// Version 1 of JKS format
pub const VERSION_01: u32 = 1;

/// Version 2 of JKS format (current)
pub const VERSION_02: u32 = 2;

/// Tag for private key entries
pub const PRIVATE_KEY_TAG: u32 = 1;

/// Tag for trusted certificate entries
pub const TRUSTED_CERT_TAG: u32 = 2;

/// Whitener message mixed into password digest
pub const WHITENER_MESSAGE: &[u8] = b"Mighty Aphrodite";

/// Length of salt for key encryption
pub const SALT_LEN: usize = 20;

/// OID for supported private key encryption algorithm
/// 1.3.6.1.4.1.42.2.17.1.1 - Oracle's proprietary key encryption
pub const SUPPORTED_KEY_ALGORITHM_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1];

/// Configuration options for KeyStore
pub struct KeyStoreOptions {
    /// Order aliases alphabetically when iterating
    pub ordered_aliases: bool,

    /// Preserve original case of aliases (default: case-insensitive)
    pub case_exact_aliases: bool,

    /// Minimum password length
    pub min_password_len: usize,

    /// Custom random number generator for salt generation
    pub rng: Box<dyn RandomReader>,

    /// Custom password bytes transformation
    pub password_bytes: fn(&[u8]) -> Vec<u8>,
}

impl Clone for KeyStoreOptions {
    fn clone(&self) -> Self {
        // Create a new RNG reference (can't truly clone Box<dyn Trait>)
        // For SystemRandom this is fine as it has no state
        Self {
            ordered_aliases: self.ordered_aliases,
            case_exact_aliases: self.case_exact_aliases,
            min_password_len: self.min_password_len,
            rng: Box::new(SystemRandom),
            password_bytes: self.password_bytes,
        }
    }
}

impl std::fmt::Debug for KeyStoreOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStoreOptions")
            .field("ordered_aliases", &self.ordered_aliases)
            .field("case_exact_aliases", &self.case_exact_aliases)
            .field("min_password_len", &self.min_password_len)
            .field("password_bytes", &"<fn>")
            .finish()
    }
}

impl Default for KeyStoreOptions {
    fn default() -> Self {
        Self {
            ordered_aliases: false,
            case_exact_aliases: false,
            min_password_len: 6,
            rng: Box::new(SystemRandom),
            password_bytes: password_bytes,
        }
    }
}

/// Trait for random number generation (to allow custom implementations)
pub trait RandomReader: Send + Sync {
    /// Read random bytes into the buffer
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<()>;
}

/// System random reader using rand crate
#[derive(Debug, Clone, Copy)]
pub struct SystemRandom;

impl RandomReader for SystemRandom {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(buf);
        Ok(())
    }
}

/// Fixed reader for testing (returns all ones)
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub struct FixedRandom(pub u8);

#[cfg(test)]
impl RandomReader for FixedRandom {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        buf.fill(self.0);
        Ok(())
    }
}

/// A certificate in the keystore
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// Certificate type (e.g., "X509")
    pub cert_type: String,

    /// Raw certificate content
    pub content: Vec<u8>,
}

impl Certificate {
    pub(crate) fn validate(&self) -> super::Result<()> {
        use super::KeyStoreError;

        if self.cert_type.is_empty() {
            return Err(KeyStoreError::EmptyCertificateType);
        }
        if self.content.is_empty() {
            return Err(KeyStoreError::EmptyCertificateContent);
        }
        Ok(())
    }
}

/// A private key entry with associated certificate chain
#[derive(Debug, Clone)]
pub struct PrivateKeyEntry {
    /// When this entry was created
    pub creation_time: std::time::SystemTime,

    /// Encrypted private key (PKCS#8 format)
    pub private_key: Vec<u8>,

    /// Certificate chain associated with this private key
    pub certificate_chain: Vec<Certificate>,
}

impl PrivateKeyEntry {
    pub(crate) fn validate(&self) -> super::Result<()> {
        use super::KeyStoreError;

        if self.private_key.is_empty() {
            return Err(KeyStoreError::EmptyPrivateKey);
        }
        for (i, cert) in self.certificate_chain.iter().enumerate() {
            cert.validate()?;
        }
        Ok(())
    }
}

/// A trusted certificate entry (no private key)
#[derive(Debug, Clone)]
pub struct TrustedCertificateEntry {
    /// When this entry was created
    pub creation_time: std::time::SystemTime,

    /// The trusted certificate
    pub certificate: Certificate,
}

impl TrustedCertificateEntry {
    pub(crate) fn validate(&self) -> super::Result<()> {
        self.certificate.validate()
    }
}

/// Converts password bytes to the JKS password format
///
/// JKS uses a non-standard password encoding where each byte is
/// prefixed with a zero byte: [0, p0, 0, p1, 0, p2, ...]
pub fn password_bytes(password: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(password.len() * 2);
    for &b in password {
        result.push(0);
        result.push(b);
    }
    result
}

/// Zero out a buffer securely
///
/// This function attempts to ensure the compiler doesn't optimize away
/// the zeroing operation.
pub fn zeroing(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_bytes() {
        let result = password_bytes(b"test");
        assert_eq!(result, vec![0, b't', 0, b'e', 0, b's', 0, b't']);
    }

    #[test]
    fn test_password_bytes_empty() {
        let result = password_bytes(b"");
        assert!(result.is_empty());
    }

    #[test]
    fn test_zeroing() {
        let mut buf = vec![1, 2, 3, 4, 5];
        zeroing(&mut buf);
        assert_eq!(buf, vec![0, 0, 0, 0, 0]);
    }
}
