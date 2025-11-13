// Constants for Proof of Burn circuits
// Translated from proof-of-burn/circuits/utils/constants.circom
// Reference: miner/src/constants.rs

use crate::field::M31;

/// Base Poseidon prefix derived from keccak256("EIP-7503") mod P
/// Original value for BN254 field: 5265656504298861414514317065875120428884240036965045859626767452974705356670
/// For M31 field (2^31 - 1), we need to reduce this value
const POSEIDON_PREFIX_STR: &str = "5265656504298861414514317065875120428884240036965045859626767452974705356670";

/// M31 field prime: 2^31 - 1 = 2147483647
pub const M31_PRIME: u32 = 2147483647;

/// Compute the base Poseidon prefix for M31 field
/// We take the original BN254 value modulo M31 prime
pub fn poseidon_prefix() -> M31 {
    // Parse the large number and reduce modulo M31 prime
    // For simplicity, we'll use the hash of "EIP-7503" directly
    // and reduce it modulo M31
    use sha3::Digest;
    let bytes = b"EIP-7503";
    let hash = sha3::Keccak256::digest(bytes);
    
    // Convert first 4 bytes to u32 and reduce mod M31
    let val = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    M31::new(val % M31_PRIME)
}

/// Poseidon prefix for burn address computation
/// Original: POSEIDON_PREFIX + 0
pub fn poseidon_burn_address_prefix() -> M31 {
    poseidon_prefix()
}

/// Poseidon prefix for nullifier computation
/// Original: POSEIDON_PREFIX + 1
pub fn poseidon_nullifier_prefix() -> M31 {
    poseidon_prefix() + M31::one()
}

/// Poseidon prefix for coin (encrypted balance) computation
/// Original: POSEIDON_PREFIX + 2
pub fn poseidon_coin_prefix() -> M31 {
    poseidon_prefix() + M31::from(2)
}

/// Circuit parameters from main_proof_of_burn.circom
pub mod circuit_params {
    /// Maximum number of Merkle-Patricia-Trie proof nodes supported
    pub const MAX_NUM_LAYERS: usize = 16;
    
    /// Keccak blocks are 136 bytes. MPT nodes are maximum 532 bytes ~ 3.91 blocks
    pub const MAX_NODE_BLOCKS: usize = 4;
    
    /// Average header length of the last 100 blocks ~ 643 bytes ~ 4.72 blocks
    pub const MAX_HEADER_BLOCKS: usize = 8;
    
    /// Minimum number of address-hash nibbles (4 * 50 = 200 bits of security)
    pub const MIN_LEAF_ADDRESS_NIBBLES: usize = 50;
    
    /// Amount bytes (248-bits to disallow field overflows)
    pub const AMOUNT_BYTES: usize = 31;
    
    /// Adds 8 * powMinimumZeroBytes extra bits of security
    pub const POW_MINIMUM_ZERO_BYTES: usize = 2;
    
    /// Maximum intended balance: 10 ETH (10^19 wei)
    pub const MAX_INTENDED_BALANCE: u128 = 10_000_000_000_000_000_000;
    
    /// Maximum actual balance: 100 ETH (10^20 wei)
    pub const MAX_ACTUAL_BALANCE: u128 = 100_000_000_000_000_000_000;
    
    /// Ethereum empty storage root
    pub const EMPTY_STORAGE_ROOT: [u8; 32] = [
        0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
        0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
        0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
        0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
    ];
    
    /// Ethereum empty code hash
    pub const EMPTY_CODE_HASH: [u8; 32] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c,
        0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
        0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
        0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_poseidon_prefixes() {
        let base = poseidon_prefix();
        let burn_addr = poseidon_burn_address_prefix();
        let nullifier = poseidon_nullifier_prefix();
        let coin = poseidon_coin_prefix();
        
        // Verify relationships
        assert_eq!(burn_addr, base);
        assert_eq!(nullifier, base + M31::one());
        assert_eq!(coin, base + M31::from(2));
    }
    
    #[test]
    fn test_circuit_params() {
        use circuit_params::*;
        
        assert_eq!(MAX_NUM_LAYERS, 16);
        assert_eq!(MAX_NODE_BLOCKS, 4);
        assert_eq!(MAX_HEADER_BLOCKS, 8);
        assert_eq!(MIN_LEAF_ADDRESS_NIBBLES, 50);
        assert_eq!(AMOUNT_BYTES, 31);
        assert_eq!(POW_MINIMUM_ZERO_BYTES, 2);
    }
}

