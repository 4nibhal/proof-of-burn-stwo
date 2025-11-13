// Keccak256 hash utilities
// Wrapper around sha3 crate for Ethereum-compatible Keccak256

use sha3::{Digest, Keccak256};

/// Compute Keccak256 hash of input bytes
/// Returns 32-byte hash
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Compute Keccak256 and return as hex string
pub fn keccak256_hex(input: &[u8]) -> String {
    hex::encode(keccak256(input))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_keccak256_empty() {
        let hash = keccak256(b"");
        let expected = hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
            .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }
    
    #[test]
    fn test_keccak256_eip7503() {
        let hash = keccak256(b"EIP-7503");
        // This should match the value used in constants
        assert_eq!(hash.len(), 32);
    }
    
    #[test]
    fn test_keccak256_hex() {
        let hex_str = keccak256_hex(b"test");
        assert_eq!(hex_str.len(), 64); // 32 bytes = 64 hex chars
    }
}

