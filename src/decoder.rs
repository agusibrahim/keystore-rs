// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

//! Decoder for reading JKS format

use crate::common::{Certificate, PRIVATE_KEY_TAG, TRUSTED_CERT_TAG, VERSION_01, VERSION_02};
use crate::{Entry, PrivateKeyEntry, Result, TrustedCertificateEntry, KeyStoreError};
use sha1::{Digest, Sha1};
use std::io::Read;

/// Decoder for reading JKS keystore format
pub struct Decoder<'a, R: Read> {
    reader: &'a mut R,
    hasher: Sha1,
}

impl<'a, R: Read> Decoder<'a, R> {
    pub fn new(reader: &'a mut R) -> Self {
        Self {
            reader,
            hasher: Sha1::new(),
        }
    }

    /// Update the running digest with data
    pub fn update_digest(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Read a u16 in big-endian format
    pub fn read_u16(&mut self) -> Result<u16> {
        let mut bytes = [0u8; 2];
        self.read_bytes(&mut bytes)?;
        Ok(u16::from_be_bytes(bytes))
    }

    /// Read a u32 in big-endian format
    pub fn read_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.read_bytes(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Read a u64 in big-endian format
    pub fn read_u64(&mut self) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.read_bytes(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Read exact bytes, updating digest
    fn read_bytes(&mut self, buf: &mut [u8]) -> Result<()> {
        self.reader.read_exact(buf)?;
        self.hasher.update(buf);
        Ok(())
    }

    /// Read a length-prefixed string
    pub fn read_string(&mut self) -> Result<String> {
        let len = self.read_u16()? as usize;
        let mut buf = vec![0u8; len];
        self.read_bytes(&mut buf)?;
        String::from_utf8(buf)
            .map_err(|e| KeyStoreError::Other(format!("invalid UTF-8 in string: {}", e)))
    }

    /// Read a certificate
    pub fn read_certificate(&mut self, version: u32) -> Result<Certificate> {
        let cert_type = match version {
            VERSION_01 => "X509".to_string(),
            VERSION_02 => self.read_string()?,
            _ => return Err(KeyStoreError::UnknownVersion(version)),
        };

        let len = self.read_u32()? as usize;
        let mut content = vec![0u8; len];
        self.read_bytes(&mut content)?;

        Ok(Certificate {
            cert_type,
            content,
        })
    }

    /// Read a private key entry
    pub fn read_private_key_entry(&mut self, version: u32) -> Result<PrivateKeyEntry> {
        let timestamp_ms = self.read_u64()?;
        let creation_time =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(timestamp_ms);

        let len = self.read_u32()? as usize;
        let mut private_key = vec![0u8; len];
        self.read_bytes(&mut private_key)?;

        let cert_count = self.read_u32()? as usize;
        let mut certificate_chain = Vec::with_capacity(cert_count);

        for i in 0..cert_count {
            let cert = self
                .read_certificate(version)
                .map_err(|e| KeyStoreError::Other(format!("certificate {}: {}", i, e)))?;
            certificate_chain.push(cert);
        }

        Ok(PrivateKeyEntry {
            creation_time,
            private_key,
            certificate_chain,
        })
    }

    /// Read a trusted certificate entry
    pub fn read_trusted_certificate_entry(&mut self, version: u32) -> Result<TrustedCertificateEntry> {
        let timestamp_ms = self.read_u64()?;
        let creation_time =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(timestamp_ms);

        let certificate = self.read_certificate(version)?;

        Ok(TrustedCertificateEntry {
            creation_time,
            certificate,
        })
    }

    /// Read an entry (determines type by tag)
    pub fn read_entry(&mut self, version: u32) -> Result<(String, Entry)> {
        let tag = self.read_u32()?;
        let alias = self.read_string()?;

        let entry = match tag {
            PRIVATE_KEY_TAG => {
                let pke = self.read_private_key_entry(version)?;
                Entry::PrivateKey(pke)
            }
            TRUSTED_CERT_TAG => {
                let tce = self.read_trusted_certificate_entry(version)?;
                Entry::TrustedCertificate(tce)
            }
            _ => return Err(KeyStoreError::UnknownEntryTag(tag)),
        };

        Ok((alias, entry))
    }

    /// Verify the digest at the end of the file
    pub fn verify_digest(&mut self) -> Result<()> {
        let computed = self.hasher.clone().finalize();

        let mut stored = [0u8; 20];
        self.reader.read_exact(&mut stored)?;

        if computed.as_slice() != stored {
            return Err(KeyStoreError::InvalidDigest);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u16() {
        let data = [0x12, 0x34];
        let mut cursor = std::io::Cursor::new(data);
        let mut decoder = Decoder::new(&mut cursor);

        assert_eq!(decoder.read_u16().unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u32() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let mut cursor = std::io::Cursor::new(data);
        let mut decoder = Decoder::new(&mut cursor);

        assert_eq!(decoder.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_read_u64() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let mut cursor = std::io::Cursor::new(data);
        let mut decoder = Decoder::new(&mut cursor);

        assert_eq!(decoder.read_u64().unwrap(), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_read_string() {
        let data = [0, 4, b't', b'e', b's', b't'];
        let mut cursor = std::io::Cursor::new(data);
        let mut decoder = Decoder::new(&mut cursor);

        assert_eq!(decoder.read_string().unwrap(), "test");
    }

    #[test]
    fn test_read_empty_string() {
        let data = [0, 0];
        let mut cursor = std::io::Cursor::new(data);
        let mut decoder = Decoder::new(&mut cursor);

        assert_eq!(decoder.read_string().unwrap(), "");
    }
}
