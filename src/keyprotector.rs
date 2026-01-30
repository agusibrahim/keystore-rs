// Copyright (c) 2024 Keystore-RS Contributors
// SPDX-License-Identifier: MIT

//! Key protection (encryption/decryption) for private keys

use crate::common::SALT_LEN;
use crate::{KeyStoreError, Result};
use sha1::{Digest, Sha1};

/// Decrypt a private key using password-based encryption
pub fn decrypt(
    data: &[u8],
    password: &[u8],
    password_transform: fn(&[u8]) -> Vec<u8>,
) -> Result<Vec<u8>> {
    // Parse ASN.1 structure manually
    if data.is_empty() || data[0] != 0x30 {
        return Err(KeyStoreError::Asn1("not a DER sequence".to_string()));
    }

    let mut pos = 1;

    // Read length
    let (length, bytes_read) = read_der_length(&data[pos..])?;
    pos += bytes_read;

    if pos + length > data.len() {
        return Err(KeyStoreError::Asn1("length exceeds data".to_string()));
    }

    // Parse AlgorithmIdentifier sequence
    if data[pos] != 0x30 {
        return Err(KeyStoreError::Asn1("expected algorithm sequence".to_string()));
    }
    pos += 1;

    let (algo_len, bytes_read) = read_der_length(&data[pos..])?;
    pos += bytes_read;

    let algo_end = pos + algo_len;

    // Read OID
    if data[pos] != 0x06 {
        return Err(KeyStoreError::Asn1("expected OID".to_string()));
    }
    pos += 1;

    let oid_len = data[pos] as usize;
    pos += 1;

    // Check OID: 1.3.6.1.4.1.42.2.17.1.1
    // DER encoding: first byte = 40 * 1 + 3 = 43 (0x2B)
    // Then: 6 1 4 1 42 2 17 1 1
    let expected_oid_prefix = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x11, 0x01, 0x01];
    if &data[pos..pos + oid_len.min(expected_oid_prefix.len())] != &expected_oid_prefix[..oid_len.min(expected_oid_prefix.len())] {
        return Err(KeyStoreError::UnsupportedAlgorithm);
    }
    pos += oid_len;

    // Check for NULL parameters
    if pos < algo_end && data[pos] == 0x05 {
        pos += 1;
        if data[pos] == 0x00 {
            let _ = pos + 1; // Skip NULL byte value (pos is reset below)
        }
    }

    // Skip to the end of algorithm identifier
    pos = algo_end;

    // Read OCTET STRING
    if data[pos] != 0x04 {
        return Err(KeyStoreError::Asn1("expected octet string".to_string()));
    }
    pos += 1;

    let (octet_len, bytes_read) = read_der_length(&data[pos..])?;
    pos += bytes_read;

    let key_data = &data[pos..pos + octet_len];
    let _ = pos + octet_len; // Position not used after this point

    if key_data.len() < SALT_LEN + Sha1::output_size() {
        return Err(KeyStoreError::Other(
            "encrypted data too short".to_string(),
        ));
    }

    // Extract components
    let salt = &key_data[..SALT_LEN];
    let digest_size = Sha1::output_size();
    let encrypted_key_len = key_data.len() - SALT_LEN - digest_size;
    let encrypted_key = &key_data[SALT_LEN..SALT_LEN + encrypted_key_len];
    let stored_digest = &key_data[SALT_LEN + encrypted_key_len..];

    // Derive XOR key
    let xor_key = derive_xor_key(salt, password, password_transform, encrypted_key_len)?;

    // Decrypt using XOR
    let mut plain_key = vec![0u8; encrypted_key_len];
    for (i, &b) in encrypted_key.iter().enumerate() {
        plain_key[i] = b ^ xor_key[i];
    }

    // Verify digest
    let mut hasher = Sha1::new();
    hasher.update(password_transform(password));
    hasher.update(&plain_key);
    let computed_digest = hasher.finalize();

    if computed_digest.as_slice() != stored_digest {
        return Err(KeyStoreError::InvalidDigest);
    }

    Ok(plain_key)
}

/// Encrypt a private key using password-based encryption
pub fn encrypt(
    rng: &mut dyn crate::common::RandomReader,
    plain_key: &[u8],
    password: &[u8],
    password_transform: fn(&[u8]) -> Vec<u8>,
) -> Result<Vec<u8>> {
    let key_len = plain_key.len();

    // Generate salt
    let mut salt = vec![0u8; SALT_LEN];
    rng.read(&mut salt)?;

    // Derive XOR key
    let xor_key = derive_xor_key(&salt, password, password_transform, key_len)?;

    // Encrypt using XOR
    let mut encrypted_key = vec![0u8; key_len];
    for (i, &b) in plain_key.iter().enumerate() {
        encrypted_key[i] = b ^ xor_key[i];
    }

    // Compute digest of password + plaintext
    let mut hasher = Sha1::new();
    hasher.update(password_transform(password));
    hasher.update(plain_key);
    let digest = hasher.finalize();

    // Build encrypted data: salt + encrypted key + digest
    let mut encrypted_data = Vec::with_capacity(SALT_LEN + key_len + digest.len());
    encrypted_data.extend_from_slice(&salt);
    encrypted_data.extend_from_slice(&encrypted_key);
    encrypted_data.extend_from_slice(&digest);

    // Encode as ASN.1
    let encoded = encode_asn1_private_key_info(&encrypted_data)?;

    Ok(encoded)
}

/// Derive XOR key from salt and password
fn derive_xor_key(
    salt: &[u8],
    password: &[u8],
    password_transform: fn(&[u8]) -> Vec<u8>,
    length: usize,
) -> Result<Vec<u8>> {
    let digest_size = Sha1::output_size();
    let num_rounds = (length + digest_size - 1) / digest_size;

    let mut xor_key = vec![0u8; length];
    let mut digest = salt.to_vec();

    for i in 0..num_rounds {
        let mut hasher = Sha1::new();
        hasher.update(password_transform(password));
        hasher.update(&digest);
        digest = hasher.finalize().to_vec();

        let offset = i * digest_size;
        let remaining = (length - offset).min(digest_size);
        xor_key[offset..offset + remaining].copy_from_slice(&digest[..remaining]);
    }

    Ok(xor_key)
}

/// Read DER length (supports short and long form)
fn read_der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(KeyStoreError::Asn1("no data for length".to_string()));
    }

    let first_byte = data[0];

    if first_byte & 0x80 == 0 {
        // Short form
        Ok((first_byte as usize, 1))
    } else {
        // Long form
        let num_bytes = (first_byte & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
            return Err(KeyStoreError::Asn1("invalid length".to_string()));
        }

        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }
        Ok((length, 1 + num_bytes))
    }
}

/// Write DER length (supports short and long form)
fn write_der_length(data: &mut Vec<u8>, length: usize) {
    if length < 128 {
        data.push(length as u8);
    } else if length < 256 {
        data.push(0x81);
        data.push(length as u8);
    } else if length < 65536 {
        data.push(0x82);
        data.push((length >> 8) as u8);
        data.push(length as u8);
    } else {
        data.push(0x83);
        data.push((length >> 16) as u8);
        data.push((length >> 8) as u8);
        data.push(length as u8);
    }
}

/// Encode the encrypted data as ASN.1 PrivateKeyInfo structure
fn encode_asn1_private_key_info(encrypted_data: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();

    // SEQUENCE tag
    result.push(0x30);

    // We'll build the content first, then calculate length
    let mut content = Vec::new();

    // AlgorithmIdentifier sequence
    let mut algo_seq = Vec::new();

    // OID: 1.3.6.1.4.1.42.2.17.1.1
    // DER encoding
    let oid_bytes = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x11, 0x01, 0x01];
    algo_seq.push(0x06); // OID tag
    algo_seq.push(oid_bytes.len() as u8);
    algo_seq.extend_from_slice(&oid_bytes);

    // NULL parameters (tag 0x05, length 0)
    algo_seq.push(0x05);
    algo_seq.push(0x00);

    // Add AlgorithmIdentifier
    content.push(0x30); // SEQUENCE tag
    write_der_length(&mut content, algo_seq.len());
    content.extend_from_slice(&algo_seq);

    // OCTET STRING containing encrypted data
    content.push(0x04); // OCTET STRING tag
    write_der_length(&mut content, encrypted_data.len());
    content.extend_from_slice(encrypted_data);

    // Total length
    let total_len = content.len();
    write_der_length(&mut result, total_len);

    result.extend_from_slice(&content);

    Ok(result)
}

#[cfg(all(test, feature = "rand"))]
mod tests {
    use super::*;
    use crate::common::{password_bytes, FixedRandom};

    #[test]
    fn test_read_der_length_short_form() {
        let data = [0x64]; // 100
        let (len, bytes) = read_der_length(&data).unwrap();
        assert_eq!(len, 100);
        assert_eq!(bytes, 1);
    }

    #[test]
    fn test_read_der_length_long_form() {
        let data = [0x81, 0xFF]; // 255
        let (len, bytes) = read_der_length(&data).unwrap();
        assert_eq!(len, 255);
        assert_eq!(bytes, 2);
    }

    #[test]
    fn test_read_der_length_long_form_2bytes() {
        let data = [0x82, 0x01, 0x00]; // 256
        let (len, bytes) = read_der_length(&data).unwrap();
        assert_eq!(len, 256);
        assert_eq!(bytes, 3);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let password = b"testpassword";

        let mut rng = FixedRandom(0x42);
        let encrypted =
            encrypt(&mut rng, &original, password, password_bytes).unwrap();

        let decrypted = decrypt(&encrypted, password, password_bytes).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_decrypt_with_wrong_password_fails() {
        let original = vec![1, 2, 3, 4, 5];
        let password = b"correctpassword";
        let wrong_password = b"wrongpassword";

        let mut rng = FixedRandom(0x42);
        let encrypted =
            encrypt(&mut rng, &original, password, password_bytes).unwrap();

        let result = decrypt(&encrypted, wrong_password, password_bytes);
        assert!(matches!(result, Err(KeyStoreError::InvalidDigest)));
    }

    #[test]
    fn test_encrypt_decrypt_longer_key() {
        let original: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let password = b"longerpassword";

        let mut rng = FixedRandom(0x99);
        let encrypted =
            encrypt(&mut rng, &original, password, password_bytes).unwrap();

        let decrypted = decrypt(&encrypted, password, password_bytes).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_encrypt_multiple_times_different_ciphertext() {
        let original = vec![1, 2, 3, 4, 5];
        let password = b"password";

        let mut rng1 = crate::common::SystemRandom;
        let encrypted1 = encrypt(&mut rng1, &original, password, password_bytes).unwrap();

        let mut rng2 = crate::common::SystemRandom;
        let encrypted2 = encrypt(&mut rng2, &original, password, password_bytes).unwrap();

        // Different salt should produce different ciphertext
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same value
        let decrypted1 = decrypt(&encrypted1, password, password_bytes).unwrap();
        let decrypted2 = decrypt(&encrypted2, password, password_bytes).unwrap();
        assert_eq!(original, decrypted1);
        assert_eq!(original, decrypted2);
    }
}
