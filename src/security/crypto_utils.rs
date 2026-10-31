//! Cryptographic Utilities for SigmaOS
//!
//! This module uses the operating system entropy source and RustCrypto Argon2.

use std::vec;
use std::vec::Vec;

/// Error types for cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    RandomGenerationFailed,
    InvalidKeyLength,
    InvalidNonce,
    PasswordHashFailed,
}

/// Access to the platform's cryptographic random number source.
pub struct SecureRandom;

impl SecureRandom {
    pub fn new() -> Self {
        Self
    }

    /// Fill a buffer from the system entropy source.
    ///
    /// Freestanding targets fail closed until SigmaOS supplies a platform RNG.
    pub fn fill_bytes(&mut self, buffer: &mut [u8]) -> Result<(), CryptoError> {
        #[cfg(not(target_os = "none"))]
        {
            getrandom::fill(buffer).map_err(|_| CryptoError::RandomGenerationFailed)
        }

        #[cfg(target_os = "none")]
        {
            let _ = buffer;
            Err(CryptoError::RandomGenerationFailed)
        }
    }

    /// Generate a random key of specified length
    pub fn generate_key(&mut self, length: usize) -> Result<Vec<u8>, CryptoError> {
        if length == 0 {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut key = vec![0u8; length];
        self.fill_bytes(&mut key)?;
        Ok(key)
    }

    /// Generate a random 256-bit (32-byte) key suitable for AES-256
    pub fn generate_aes256_key(&mut self) -> Result<[u8; 32], CryptoError> {
        let mut key = [0u8; 32];
        self.fill_bytes(&mut key)?;
        Ok(key)
    }

    /// Generate a random 128-bit (16-byte) key suitable for AES-128
    pub fn generate_aes128_key(&mut self) -> Result<[u8; 16], CryptoError> {
        let mut key = [0u8; 16];
        self.fill_bytes(&mut key)?;
        Ok(key)
    }

    /// Generate a random nonce for cryptographic operations
    pub fn generate_nonce(&mut self, length: usize) -> Result<Vec<u8>, CryptoError> {
        if length == 0 || length > 64 {
            return Err(CryptoError::InvalidNonce);
        }
        self.generate_key(length)
    }
}

impl Default for SecureRandom {
    fn default() -> Self {
        Self::new()
    }
}

/// Constant-time comparison for cryptographic values (CWE-208 / CWE-385)
///
/// Prevents timing side-channel leaks by avoiding early returns on slice length mismatch
/// and shielding comparison logic against compiler loop shortcut optimizations via `black_box`.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Accumulate length discrepancy into bitmask to avoid timing leak on length mismatch
    let mut result = (a.len() != b.len()) as u8;

    for (&byte_a, &byte_b) in a.iter().zip(b.iter()) {
        result |= byte_a ^ byte_b;
    }

    core::hint::black_box(result) == 0
}

/// Create a PHC-encoded Argon2id password hash with a fresh 16-byte salt.
pub fn hash_password(password: &str, rng: &mut SecureRandom) -> Result<String, CryptoError> {
    use argon2::password_hash::PasswordHasher;

    let mut salt_bytes = [0u8; 16];
    rng.fill_bytes(&mut salt_bytes)?;
    argon2::Argon2::default()
        .hash_password_with_salt(password.as_bytes(), &salt_bytes)
        .map(|hash| hash.to_string())
        .map_err(|_| CryptoError::PasswordHashFailed)
}

/// Verify a password against its PHC-encoded Argon2id hash.
pub fn verify_password(password: &str, encoded_hash: &str) -> bool {
    use argon2::password_hash::{phc::PasswordHash, PasswordVerifier};

    let Ok(parsed_hash) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    argon2::Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random_generation() {
        let mut rng = SecureRandom::new();

        let mut buffer = [0u8; 32];
        assert!(rng.fill_bytes(&mut buffer).is_ok());

        // Ensure we don't get all zeros (statistically unlikely)
        let all_zeros = buffer.iter().all(|&b| b == 0);
        assert!(!all_zeros);
    }

    #[test]
    fn test_key_generation() {
        let mut rng = SecureRandom::new();

        let key = rng.generate_aes256_key();
        assert!(key.is_ok());

        let key = key.unwrap();
        // Ensure key is not all zeros
        let all_zeros = key.iter().all(|&b| b == 0);
        assert!(!all_zeros);
    }

    #[test]
    fn test_constant_time_comparison() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn test_constant_time_different_lengths() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3, 4];

        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_nonce_generation() {
        let mut rng = SecureRandom::new();

        let nonce = rng.generate_nonce(12);
        assert!(nonce.is_ok());

        let nonce = nonce.unwrap();
        assert_eq!(nonce.len(), 12);
    }

    #[test]
    fn test_invalid_nonce_length() {
        let mut rng = SecureRandom::new();

        let nonce = rng.generate_nonce(0);
        assert!(nonce.is_err());

        let nonce = rng.generate_nonce(65);
        assert!(nonce.is_err());
    }
}
