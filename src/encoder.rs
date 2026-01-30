// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

//! Encoder for writing JKS format

use crate::common::Certificate;
use crate::{PrivateKeyEntry, Result, TrustedCertificateEntry};
use sha1::{Digest, Sha1};
use std::io::Write;

/// Encoder for writing JKS keystore format
pub struct Encoder<'a, W: Write> {
    writer: &'a mut W,
    hasher: Sha1,
}

impl<'a, W: Write> Encoder<'a, W> {
    pub fn new(writer: &'a mut W) -> Self {
        Self {
            writer,
            hasher: Sha1::new(),
        }
    }

    /// Update the running digest with data
    pub fn update_digest(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Write a u16 in big-endian format
    pub fn write_u16(&mut self, value: u16) -> Result<()> {
        let bytes = value.to_be_bytes();
        self.write_bytes(&bytes)
    }

    /// Write a u32 in big-endian format
    pub fn write_u32(&mut self, value: u32) -> Result<()> {
        let bytes = value.to_be_bytes();
        self.write_bytes(&bytes)
    }

    /// Write a u64 in big-endian format
    pub fn write_u64(&mut self, value: u64) -> Result<()> {
        let bytes = value.to_be_bytes();
        self.write_bytes(&bytes)
    }

    /// Write raw bytes to both output and digest
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_all(data)?;
        self.hasher.update(data);
        Ok(())
    }

    /// Write a length-prefixed string (u16 length + bytes)
    pub fn write_string(&mut self, value: &str) -> Result<()> {
        if value.len() > u16::MAX as usize {
            return Err(crate::KeyStoreError::Other(format!(
                "string too long: {} bytes (max {})",
                value.len(),
                u16::MAX
            )));
        }
        self.write_u16(value.len() as u16)?;
        self.write_bytes(value.as_bytes())
    }

    /// Write a certificate (type + length + content)
    pub fn write_certificate(&mut self, cert: &Certificate) -> Result<()> {
        self.write_string(&cert.cert_type)?;
        self.write_u32(cert.content.len() as u32)?;
        self.write_bytes(&cert.content)
    }

    /// Write a private key entry
    pub fn write_private_key_entry(&mut self, alias: &str, entry: &PrivateKeyEntry) -> Result<()> {
        self.write_u32(crate::common::PRIVATE_KEY_TAG)?;
        self.write_string(alias)?;

        let timestamp = entry
            .creation_time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| crate::KeyStoreError::Other(format!("invalid creation time: {}", e)))?
            .as_millis() as u64;

        self.write_u64(timestamp)?;

        if entry.private_key.len() > u32::MAX as usize {
            return Err(crate::KeyStoreError::Other(format!(
                "private key too long: {} bytes",
                entry.private_key.len()
            )));
        }
        self.write_u32(entry.private_key.len() as u32)?;
        self.write_bytes(&entry.private_key)?;

        if entry.certificate_chain.len() > u32::MAX as usize {
            return Err(crate::KeyStoreError::Other(format!(
                "certificate chain too long: {} entries",
                entry.certificate_chain.len()
            )));
        }
        self.write_u32(entry.certificate_chain.len() as u32)?;

        for (i, cert) in entry.certificate_chain.iter().enumerate() {
            self.write_certificate(cert)
                .map_err(|e| crate::KeyStoreError::Other(format!("certificate {}: {}", i, e)))?;
        }

        Ok(())
    }

    /// Write a trusted certificate entry
    pub fn write_trusted_certificate_entry(
        &mut self,
        alias: &str,
        entry: &TrustedCertificateEntry,
    ) -> Result<()> {
        self.write_u32(crate::common::TRUSTED_CERT_TAG)?;
        self.write_string(alias)?;

        let timestamp = entry
            .creation_time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| crate::KeyStoreError::Other(format!("invalid creation time: {}", e)))?
            .as_millis() as u64;

        self.write_u64(timestamp)?;
        self.write_certificate(&entry.certificate)
    }

    /// Write the final digest
    pub fn write_digest(&mut self) -> Result<()> {
        let digest = self.hasher.clone().finalize();
        self.writer.write_all(&digest)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_u16() {
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(&mut buffer);

        encoder.write_u16(0x1234).unwrap();
        assert_eq!(buffer, vec![0x12, 0x34]);
    }

    #[test]
    fn test_write_u32() {
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(&mut buffer);

        encoder.write_u32(0x12345678).unwrap();
        assert_eq!(buffer, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_write_u64() {
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(&mut buffer);

        encoder.write_u64(0x123456789ABCDEF0).unwrap();
        assert_eq!(buffer, vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
    }

    #[test]
    fn test_write_string() {
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(&mut buffer);

        encoder.write_string("test").unwrap();
        assert_eq!(buffer, vec![0, 4, b't', b'e', b's', b't']);
    }

    #[test]
    fn test_write_empty_string() {
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(&mut buffer);

        encoder.write_string("").unwrap();
        assert_eq!(buffer, vec![0, 0]);
    }
}
