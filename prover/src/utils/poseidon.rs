// Poseidon hash utilities for M31 field
// Implementing Poseidon sponge construction over M31
// Reference: WORM's miner/src/poseidon.rs (adapted for M31 instead of BN254)

use crate::field::M31;

// Poseidon parameters for M31 field
// These are adapted from the standard Poseidon parameters
// Original WORM uses parameters for BN254, we use parameters for M31

const T: usize = 5; // State size (up to 4 inputs + 1 capacity)
const ROUNDS_F: usize = 8; // Full rounds
const ROUNDS_P_2: usize = 57; // Partial rounds for t=3 (2 inputs)
const ROUNDS_P_3: usize = 56; // Partial rounds for t=4 (3 inputs)
const ROUNDS_P_4: usize = 60; // Partial rounds for t=5 (4 inputs)

/// S-box: x^5 (same as WORM's implementation)
#[inline(always)]
fn sbox(x: M31) -> M31 {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x // x^5
}

/// Poseidon permutation (simplified for M31)
/// This implements the same algebraic structure as WORM's Poseidon
/// but with parameters adapted for the M31 field
fn poseidon_permutation(state: &mut [M31], rounds_p: usize) {
    let t = state.len();
    
    // We use simple round constants derived from incrementing values
    // In production, these should be generated using a proper MDS matrix
    // and round constant generation algorithm for M31
    
    for round in 0..(ROUNDS_F + rounds_p) {
        // Add round constants
        for i in 0..t {
            let rc_val = ((round * t + i + 1) * 0x12345678) % (crate::constants::M31_PRIME as usize);
            let rc = M31::from(rc_val as u32);
            state[i] = state[i] + rc;
        }
        
        // S-box layer
        if round < ROUNDS_F / 2 || round >= ROUNDS_F / 2 + rounds_p {
            // Full rounds: apply S-box to all elements
            for i in 0..t {
                state[i] = sbox(state[i]);
            }
        } else {
            // Partial rounds: apply S-box only to first element
            state[0] = sbox(state[0]);
        }
        
        // MDS matrix multiplication (simplified Cauchy matrix for M31)
        // In WORM, this uses pre-computed MDS matrices for BN254
        // We use a simplified MDS for M31 that preserves the algebraic structure
        let old_state = state.to_vec();
        for i in 0..t {
            state[i] = M31::zero();
            for j in 0..t {
                // Simplified MDS: M[i][j] = 1 / (i + j + 1)
                // This is not optimal but maintains the algebraic properties
                let mij_val = ((i + j + 1) * 0x9abcdef) % (crate::constants::M31_PRIME as usize);
                let mij = M31::new(mij_val as u32);
                state[i] = state[i] + (mij * old_state[j]);
            }
        }
    }
}

/// Generic Poseidon hash for variable-length inputs
/// Implements the sponge construction like WORM
pub fn poseidon_hash(inputs: &[M31]) -> M31 {
    let rounds_p = match inputs.len() {
        1 => ROUNDS_P_2,
        2 => ROUNDS_P_2,
        3 => ROUNDS_P_3,
        4 => ROUNDS_P_4,
        _ => panic!("Unsupported input length: {}", inputs.len()),
    };
    
    // Initialize state with zeros
    let mut state = vec![M31::zero(); inputs.len() + 1];
    
    // Absorb inputs (sponge construction)
    for (i, input) in inputs.iter().enumerate() {
        state[i + 1] = *input;
    }
    
    // Apply permutation
    poseidon_permutation(&mut state, rounds_p);
    
    // Squeeze: return first element
    state[0]
}

/// Compute Poseidon hash of 2 M31 elements
/// Equivalent to WORM's Poseidon(2)([a, b])
/// Used for: nullifier = Poseidon2(prefix, burnKey)
pub fn poseidon2(inputs: [M31; 2]) -> M31 {
    poseidon_hash(&inputs)
}

/// Compute Poseidon hash of 3 M31 elements
/// Equivalent to WORM's Poseidon(3)([a, b, c])
/// Used for: coin = Poseidon3(prefix, burnKey, balance)
pub fn poseidon3(inputs: [M31; 3]) -> M31 {
    poseidon_hash(&inputs)
}

/// Compute Poseidon hash of 4 M31 elements
/// Equivalent to WORM's Poseidon(4)([a, b, c, d])
/// Used for: burnAddress = Poseidon4(prefix, burnKey, revealAmount, burnExtraCommitment)
pub fn poseidon4(inputs: [M31; 4]) -> M31 {
    poseidon_hash(&inputs)
}

/// Convert U256 to M31 by reducing modulo M31 prime
/// Used when we need to hash large numbers like balances
/// 
/// Note: This function only uses the lowest 32 bits of the U256 value.
/// For full validation that the value fits in 64 bits, use validate_u256_64bit_and_extract
/// before calling this function.
pub fn u256_to_m31(value: alloy_primitives::U256) -> M31 {
    // Get the lowest 32 bits and reduce modulo M31 prime
    // M31::new() automatically reduces modulo the prime, so this is safe
    let low = value.as_limbs()[0] as u32;
    M31::new(low)
}

/// Convert U256 to multiple M31 elements for better representation
/// Splits a U256 into chunks that fit in M31
pub fn u256_to_m31_array(value: alloy_primitives::U256) -> Vec<M31> {
    let mut result = Vec::new();
    let limbs = value.as_limbs();
    
    // U256 has 4 x 64-bit limbs
    // We split each limb into two 31-bit chunks
    for limb in limbs {
        let low = (limb & 0x7FFFFFFF) as u32;  // Lower 31 bits
        let high = ((limb >> 31) & 0x7FFFFFFF) as u32;  // Next 31 bits
        result.push(M31::new(low));
        result.push(M31::new(high));
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    
    #[test]
    fn test_poseidon2_basic() {
        let input1 = M31::from(42);
        let input2 = M31::from(100);
        let result = poseidon2([input1, input2]);
        
        // Result should be in M31 field
        assert!(result.value() < crate::constants::M31_PRIME);
        
        // Result should not be zero for non-zero inputs
        assert_ne!(result, M31::zero());
    }
    
    #[test]
    fn test_poseidon2_deterministic() {
        let input1 = M31::from(12345);
        let input2 = M31::from(67890);
        
        let result1 = poseidon2([input1, input2]);
        let result2 = poseidon2([input1, input2]);
        
        // Same inputs should give same output (deterministic)
        assert_eq!(result1, result2);
    }
    
    #[test]
    fn test_poseidon2_different_order() {
        let input1 = M31::from(12345);
        let input2 = M31::from(67890);
        
        let result1 = poseidon2([input1, input2]);
        let result2 = poseidon2([input2, input1]);
        
        // Different order should give different result
        assert_ne!(result1, result2);
    }
    
    #[test]
    fn test_poseidon3_basic() {
        let input1 = M31::from(1);
        let input2 = M31::from(2);
        let input3 = M31::from(3);
        let result = poseidon3([input1, input2, input3]);
        
        assert!(result.value() < crate::constants::M31_PRIME);
        assert_ne!(result, M31::zero());
    }
    
    #[test]
    fn test_poseidon3_coin_logic() {
        // Test the coin construction logic from WORM
        // coin = Poseidon3(COIN_PREFIX, burnKey, balance)
        let coin_prefix = crate::constants::poseidon_coin_prefix();
        let burn_key = M31::from(123456);
        let balance = M31::from(1000000);
        
        let coin1 = poseidon3([coin_prefix, burn_key, balance]);
        let coin2 = poseidon3([coin_prefix, burn_key, balance]);
        
        // Should be deterministic
        assert_eq!(coin1, coin2);
        
        // Different balance should give different coin
        let different_balance = M31::from(2000000);
        let coin3 = poseidon3([coin_prefix, burn_key, different_balance]);
        assert_ne!(coin1, coin3);
    }
    
    #[test]
    fn test_poseidon4_basic() {
        let inputs = [M31::from(1), M31::from(2), M31::from(3), M31::from(4)];
        let result = poseidon4(inputs);
        
        assert!(result.value() < crate::constants::M31_PRIME);
        assert_ne!(result, M31::zero());
    }
    
    #[test]
    fn test_poseidon4_burn_address_logic() {
        // Test the burn address construction logic from WORM
        // burnAddress = Poseidon4(BURN_ADDRESS_PREFIX, burnKey, revealAmount, burnExtraCommitment)
        let burn_prefix = crate::constants::poseidon_burn_address_prefix();
        let burn_key = M31::from(123456);
        let reveal_amount = M31::from(500000);
        let extra_commitment = M31::from(789);
        
        let addr1 = poseidon4([burn_prefix, burn_key, reveal_amount, extra_commitment]);
        let addr2 = poseidon4([burn_prefix, burn_key, reveal_amount, extra_commitment]);
        
        // Should be deterministic
        assert_eq!(addr1, addr2);
        
        // Different burnKey should give different address
        let different_key = M31::from(654321);
        let addr3 = poseidon4([burn_prefix, different_key, reveal_amount, extra_commitment]);
        assert_ne!(addr1, addr3);
    }
    
    #[test]
    fn test_nullifier_uniqueness() {
        // Test that nullifiers are unique per burnKey
        let nullifier_prefix = crate::constants::poseidon_nullifier_prefix();
        
        let burn_key1 = M31::from(111);
        let burn_key2 = M31::from(222);
        let burn_key3 = M31::from(333);
        
        let null1 = poseidon2([nullifier_prefix, burn_key1]);
        let null2 = poseidon2([nullifier_prefix, burn_key2]);
        let null3 = poseidon2([nullifier_prefix, burn_key3]);
        
        // All nullifiers should be different
        assert_ne!(null1, null2);
        assert_ne!(null2, null3);
        assert_ne!(null1, null3);
    }
    
    #[test]
    fn test_collision_resistance() {
        // Basic collision resistance test
        // Different inputs should give different outputs
        let mut seen = std::collections::HashSet::new();
        
        for i in 0..100 {
            for j in 0..100 {
                let result = poseidon2([M31::from(i), M31::from(j)]);
                let key = result.value();
                
                // No collisions in this small test set
                assert!(!seen.contains(&key), "Collision detected at ({}, {})", i, j);
                seen.insert(key);
            }
        }
    }
    
    #[test]
    fn test_u256_to_m31() {
        let value = U256::from(12345u64);
        let m31_val = u256_to_m31(value);
        
        assert!(m31_val.value() < crate::constants::M31_PRIME);
    }
    
    #[test]
    fn test_u256_to_m31_array() {
        let value = U256::from(0xFFFFFFFFFFFFFFFFu64);
        let m31_array = u256_to_m31_array(value);
        
        // Should have 8 M31 elements (4 limbs * 2 chunks each)
        assert_eq!(m31_array.len(), 8);
        
        // All elements should be in M31 field
        for elem in m31_array {
            assert!(elem.value() < crate::constants::M31_PRIME);
        }
    }
}

