//! Cryptographic operations with secure defaults
//! Follows: Secure Defaults, Memory Safety, Zero-Knowledge

use std::sync::atomic::{AtomicBool, Ordering};

/// Cryptographic key
#[derive(Debug, Clone)]
pub struct CryptoKey {
    key_data: Vec<u8>,
    is_secure: AtomicBool,
}

impl CryptoKey {
    pub fn new(key_data: Vec<u8>) -> Self {
        CryptoKey {
            key_data,
            is_secure: AtomicBool::new(true),
        }
    }

    /// Get key data (secure access)
    pub fn data(&self) -> &[u8] {
        if self.is_secure.load(Ordering::SeqCst) {
            &self.key_data
        } else {
            &[]
        }
    }

    /// Securely wipe key data
    pub fn wipe(&mut self) {
        for byte in self.key_data.iter_mut() {
            *byte = 0;
        }
        self.is_secure.store(false, Ordering::SeqCst);
        log::info!("Key securely wiped");
    }

    /// Check if key is still secure
    pub fn is_secure(&self) -> bool {
        self.is_secure.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_security() {
        let key = CryptoKey::new(vec![1, 2, 3, 4]);
        assert!(key.is_secure());
        assert_eq!(key.data(), &[1, 2, 3, 4]);
    }
}
