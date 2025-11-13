// Proof-of-Work checker for burn keys
// Reference: proof-of-burn/circuits/utils/proof_of_work.circom
//
// Verifies that keccak256(burnKey || revealAmount || burnExtraCommitment || "EIP-7503")
// starts with `minimum_zero_bytes` zero bytes to increase security

use crate::utils::keccak::keccak256;
use alloy_primitives::U256;
use crate::field::M31;

/// Verify that burnKey satisfies Proof-of-Work requirement
/// 
/// The hash of (burnKey || revealAmount || burnExtraCommitment || "EIP-7503")
/// must start with at least `minimum_zero_bytes` zero bytes
/// 
/// This adds 8 * minimum_zero_bytes bits of security to prevent
/// address-hash collision attacks
pub fn verify_pow(
    burn_key: M31,
    reveal_amount: U256,
    burn_extra_commitment: M31,
    minimum_zero_bytes: usize,
) -> bool {
    let hash = compute_pow_hash(burn_key, reveal_amount, burn_extra_commitment);
    check_leading_zero_bytes(&hash, minimum_zero_bytes)
}

/// Compute the PoW hash for verification
pub fn compute_pow_hash(
    burn_key: M31,
    reveal_amount: U256,
    burn_extra_commitment: M31,
) -> [u8; 32] {
    // Concatenate: burnKey || revealAmount || burnExtraCommitment || "EIP-7503"
    let mut input = Vec::new();
    
    // burnKey (32 bytes, big-endian)
    input.extend_from_slice(&burn_key.0.to_be_bytes());
    input.extend_from_slice(&[0u8; 28]); // Pad to 32 bytes
    
    // revealAmount (32 bytes)
    let mut amount_bytes = [0u8; 32];
    reveal_amount.to_be_bytes_vec().iter().rev().enumerate().for_each(|(i, &b)| {
        if i < 32 {
            amount_bytes[31 - i] = b;
        }
    });
    input.extend_from_slice(&amount_bytes);
    
    // burnExtraCommitment (32 bytes, big-endian)
    input.extend_from_slice(&burn_extra_commitment.0.to_be_bytes());
    input.extend_from_slice(&[0u8; 28]); // Pad to 32 bytes
    
    // "EIP-7503" string
    input.extend_from_slice(b"EIP-7503");
    
    keccak256(&input)
}

/// Check if hash starts with at least `minimum_zero_bytes` zero bytes
fn check_leading_zero_bytes(hash: &[u8; 32], minimum_zero_bytes: usize) -> bool {
    if minimum_zero_bytes == 0 {
        return true;
    }
    
    if minimum_zero_bytes > 32 {
        return false;
    }
    
    // Check first N bytes are zero
    for i in 0..minimum_zero_bytes {
        if hash[i] != 0 {
            return false;
        }
    }
    
    true
}

/// Find a valid burnKey that satisfies PoW requirement (for testing/mining)
/// This is computationally expensive and should be done off-chain
pub fn find_valid_burn_key(
    reveal_amount: U256,
    burn_extra_commitment: M31,
    minimum_zero_bytes: usize,
) -> Option<M31> {
    // Brute force search (simplified version)
    // In practice, you'd want a more sophisticated mining algorithm
    for i in 0..100000 {
        let candidate = M31::from(i);
        if verify_pow(candidate, reveal_amount, burn_extra_commitment, minimum_zero_bytes) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_check_leading_zero_bytes() {
        let hash_with_zeros = [
            0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        
        assert!(check_leading_zero_bytes(&hash_with_zeros, 0));
        assert!(check_leading_zero_bytes(&hash_with_zeros, 1));
        assert!(check_leading_zero_bytes(&hash_with_zeros, 2));
        assert!(!check_leading_zero_bytes(&hash_with_zeros, 3));
    }
    
    #[test]
    fn test_compute_pow_hash() {
        let burn_key = M31::from(12345);
        let reveal_amount = U256::from(1000000000000000000u64);
        let burn_extra_commitment = M31::from(67890);
        
        let hash = compute_pow_hash(burn_key, reveal_amount, burn_extra_commitment);
        
        // Hash should be 32 bytes
        assert_eq!(hash.len(), 32);
    }
    
    #[test]
    fn test_verify_pow_zero_requirement() {
        let burn_key = M31::from(42);
        let reveal_amount = U256::from(1000000000000000000u64);
        let burn_extra_commitment = M31::from(100);
        
        // With 0 zero bytes requirement, should always pass
        assert!(verify_pow(burn_key, reveal_amount, burn_extra_commitment, 0));
    }
    
    #[test]
    fn test_find_valid_burn_key() {
        let reveal_amount = U256::from(1000000000000000000u64);
        let burn_extra_commitment = M31::from(100);
        
        // Try to find a key with 0 leading zero bytes (should be easy)
        let result = find_valid_burn_key(reveal_amount, burn_extra_commitment, 0);
        assert!(result.is_some());
    }
}

