// Burn address computation
// Reference: proof-of-burn/circuits/utils/burn_address.circom
//
// The burn address is the first 20 bytes of:
//   Poseidon4(POSEIDON_BURN_ADDRESS_PREFIX, burnKey, revealAmount, burnExtraCommitment)

use crate::constants::poseidon_burn_address_prefix;
use crate::utils::keccak::keccak256;
use crate::utils::poseidon::{poseidon4, u256_to_m31};
use alloy_primitives::{Address, U256};
use crate::field::M31;

/// Compute burn address from burnKey and commitments
/// 
/// Returns the 20-byte Ethereum address where ETH should be burned
pub fn compute_burn_address(
    burn_key: M31,
    reveal_amount: U256,
    burn_extra_commitment: M31,
) -> Address {
    // Compute Poseidon4 hash
    let reveal_amount_m31 = u256_to_m31(reveal_amount);
    
    let poseidon_output = poseidon4([
        poseidon_burn_address_prefix(),
        burn_key,
        reveal_amount_m31,
        burn_extra_commitment,
    ]);
    
    // Convert M31 output to bytes and hash with Keccak to get full 32 bytes
    let value_bytes = poseidon_output.value().to_be_bytes();
    let full_hash = keccak256(&value_bytes);
    
    // Take first 20 bytes as Ethereum address
    let mut address_bytes = [0u8; 20];
    address_bytes.copy_from_slice(&full_hash[..20]);
    
    Address::from(address_bytes)
}

/// Compute the Keccak256 hash of the burn address
/// This is used as the key in Ethereum's Merkle-Patricia-Trie
pub fn compute_burn_address_hash(
    burn_key: M31,
    reveal_amount: U256,
    burn_extra_commitment: M31,
) -> [u8; 32] {
    let address = compute_burn_address(burn_key, reveal_amount, burn_extra_commitment);
    keccak256(address.as_slice())
}

/// Convert address hash to nibbles (4-bit values)
/// Ethereum MPT uses nibbles as path elements
pub fn address_hash_to_nibbles(address_hash: &[u8; 32]) -> Vec<u8> {
    crate::utils::rlp::bytes_to_nibbles(address_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compute_burn_address() {
        let burn_key = M31::from(12345);
        let reveal_amount = U256::from(1000000000000000000u64); // 1 ETH
        let burn_extra_commitment = M31::from(67890);
        
        let address = compute_burn_address(burn_key, reveal_amount, burn_extra_commitment);
        
        // Should be a valid 20-byte Ethereum address
        assert_eq!(address.as_slice().len(), 20);
    }
    
    #[test]
    fn test_compute_burn_address_hash() {
        let burn_key = M31::from(12345);
        let reveal_amount = U256::from(1000000000000000000u64);
        let burn_extra_commitment = M31::from(67890);
        
        let hash = compute_burn_address_hash(burn_key, reveal_amount, burn_extra_commitment);
        
        // Should be a 32-byte hash
        assert_eq!(hash.len(), 32);
    }
    
    #[test]
    fn test_address_hash_to_nibbles() {
        let hash = [0xAB; 32];
        let nibbles = address_hash_to_nibbles(&hash);
        
        // 32 bytes = 64 nibbles
        assert_eq!(nibbles.len(), 64);
        
        // Each byte 0xAB becomes two nibbles 0xA and 0xB
        assert_eq!(nibbles[0], 0x0A);
        assert_eq!(nibbles[1], 0x0B);
    }
    
    #[test]
    fn test_burn_address_deterministic() {
        let burn_key = M31::from(42);
        let reveal_amount = U256::from(1000000000000000000u64);
        let burn_extra_commitment = M31::from(100);
        
        let addr1 = compute_burn_address(burn_key, reveal_amount, burn_extra_commitment);
        let addr2 = compute_burn_address(burn_key, reveal_amount, burn_extra_commitment);
        
        // Should be deterministic
        assert_eq!(addr1, addr2);
    }
    
    #[test]
    fn test_different_keys_different_addresses() {
        let reveal_amount = U256::from(1000000000000000000u64);
        let burn_extra_commitment = M31::from(100);
        
        let addr1 = compute_burn_address(M31::from(1), reveal_amount, burn_extra_commitment);
        let addr2 = compute_burn_address(M31::from(2), reveal_amount, burn_extra_commitment);
        
        // Different keys should produce different addresses
        assert_ne!(addr1, addr2);
    }
}

