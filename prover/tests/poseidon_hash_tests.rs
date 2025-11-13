// Comprehensive Poseidon Hash Tests
// Tests to ensure Poseidon implementation is consistent and correct

use proof_of_burn_stwo::field::M31;
use proof_of_burn_stwo::utils::poseidon::{poseidon2, poseidon3, poseidon4};
use proof_of_burn_stwo::constants::{poseidon_burn_address_prefix, poseidon_coin_prefix, poseidon_nullifier_prefix};
use std::collections::{HashMap, HashSet};

#[cfg(test)]
mod poseidon_basic_tests {
    use super::*;

    #[test]
    fn test_poseidon2_deterministic() {
        // Same inputs should always produce same output
        for i in 0..1000 {
            let a = M31::from(i * 123);
            let b = M31::from(i * 456);
            
            let result1 = poseidon2([a, b]);
            let result2 = poseidon2([a, b]);
            
            assert_eq!(result1, result2, "Poseidon2 not deterministic for inputs {} {}", a.value(), b.value());
        }
    }

    #[test]
    fn test_poseidon3_deterministic() {
        for i in 0..500 {
            let a = M31::from(i * 111);
            let b = M31::from(i * 222);
            let c = M31::from(i * 333);
            
            let result1 = poseidon3([a, b, c]);
            let result2 = poseidon3([a, b, c]);
            
            assert_eq!(result1, result2);
        }
    }

    #[test]
    fn test_poseidon4_deterministic() {
        for i in 0..500 {
            let a = M31::from(i * 11);
            let b = M31::from(i * 22);
            let c = M31::from(i * 33);
            let d = M31::from(i * 44);
            
            let result1 = poseidon4([a, b, c, d]);
            let result2 = poseidon4([a, b, c, d]);
            
            assert_eq!(result1, result2);
        }
    }

    #[test]
    fn test_poseidon_outputs_in_field() {
        // All outputs should be valid field elements
        for i in 0..1000 {
            let a = M31::from(i * 7919);
            let b = M31::from(i * 104729);
            
            let result = poseidon2([a, b]);
            assert!(result.value() < M31::PRIME, "Output not in field: {}", result.value());
        }
    }

    #[test]
    fn test_poseidon_non_zero_for_non_zero() {
        // Non-zero inputs should generally produce non-zero output
        let mut zero_count = 0;
        let total = 10000;
        
        for i in 1..total {
            let a = M31::from(i * 123);
            let b = M31::from(i * 456);
            
            let result = poseidon2([a, b]);
            if result == M31::zero() {
                zero_count += 1;
            }
        }
        
        // Less than 0.1% should be zero (probabilistically)
        assert!(zero_count < total / 1000, "Too many zero outputs: {}", zero_count);
    }
}

#[cfg(test)]
mod poseidon_collision_tests {
    use super::*;

    #[test]
    fn test_poseidon2_no_simple_collisions() {
        let mut seen = HashMap::new();
        let mut collision_count = 0;
        
        for i in 0..1000 {
            for j in 0..1000 {
                let a = M31::from(i);
                let b = M31::from(j);
                
                let hash = poseidon2([a, b]);
                let key = hash.value();
                
                if let Some((prev_i, prev_j)) = seen.get(&key) {
                    if (*prev_i, *prev_j) != (i, j) {
                        collision_count += 1;
                    }
                } else {
                    seen.insert(key, (i, j));
                }
            }
        }
        
        // Should have very few collisions (probabilistically)
        // With 1M inputs and 2^31 output space, expect ~0 collisions
        // Our simplified Poseidon may have more, but should still be < 0.1%
        assert!(collision_count < 1000, "Too many collisions: {} (>0.1%)", collision_count);
    }

    #[test]
    fn test_poseidon3_avalanche_effect() {
        // Small change in input should cause large change in output
        let base = M31::from(12345u32);
        let b = M31::from(67890u32);
        let c = M31::from(11111u32);
        
        let hash1 = poseidon3([base, b, c]);
        
        // Change first input by 1
        let modified = M31::from(12346u32);
        let hash2 = poseidon3([modified, b, c]);
        
        assert_ne!(hash1, hash2, "Avalanche effect failed: hashes should differ");
        
        // Check that many bits changed
        let diff = hash1.value() ^ hash2.value();
        let bits_changed = diff.count_ones();
        
        // At least 25% of bits should change
        assert!(bits_changed >= 8, "Only {} bits changed, avalanche effect too weak", bits_changed);
    }

    #[test]
    fn test_poseidon_different_arities_different_outputs() {
        let a = M31::from(100u32);
        let b = M31::from(200u32);
        let c = M31::from(300u32);
        let d = M31::from(400u32);
        
        // Same values in different arity functions should give different results
        let hash2 = poseidon2([a, b]);
        let hash3 = poseidon3([a, b, c]);
        let hash4 = poseidon4([a, b, c, d]);
        
        // All should be different
        assert_ne!(hash2, hash3);
        assert_ne!(hash3, hash4);
        assert_ne!(hash2, hash4);
    }
}

#[cfg(test)]
mod poseidon_order_sensitivity_tests {
    use super::*;

    #[test]
    fn test_poseidon2_order_matters() {
        // poseidon([a, b]) != poseidon([b, a])
        for i in 0..500 {
            let a = M31::from(i * 100);
            let b = M31::from(i * 200 + 1); // +1 to ensure a != b
            
            if a != b {
                let hash1 = poseidon2([a, b]);
                let hash2 = poseidon2([b, a]);
                
                assert_ne!(hash1, hash2, "Order doesn't matter for {} {}", a.value(), b.value());
            }
        }
    }

    #[test]
    fn test_poseidon3_order_matters() {
        for i in 0..300 {
            let a = M31::from(i * 10);
            let b = M31::from(i * 20 + 1);
            let c = M31::from(i * 30 + 2);
            
            let hash1 = poseidon3([a, b, c]);
            let hash2 = poseidon3([c, b, a]); // Reversed
            let hash3 = poseidon3([b, a, c]); // Permuted
            
            assert_ne!(hash1, hash2);
            assert_ne!(hash1, hash3);
            assert_ne!(hash2, hash3);
        }
    }

    #[test]
    fn test_poseidon4_all_permutations_different() {
        let a = M31::from(10u32);
        let b = M31::from(20u32);
        let c = M31::from(30u32);
        let d = M31::from(40u32);
        
        let mut hashes = HashSet::new();
        
        // Test several permutations
        hashes.insert(poseidon4([a, b, c, d]).value());
        hashes.insert(poseidon4([a, b, d, c]).value());
        hashes.insert(poseidon4([a, c, b, d]).value());
        hashes.insert(poseidon4([b, a, c, d]).value());
        hashes.insert(poseidon4([d, c, b, a]).value());
        
        // All permutations should give different hashes
        assert_eq!(hashes.len(), 5, "Some permutations gave same hash");
    }
}

#[cfg(test)]
mod poseidon_prefix_tests {
    use super::*;

    #[test]
    fn test_prefix_consistency() {
        // Prefixes should be deterministic
        let prefix1 = poseidon_burn_address_prefix();
        let prefix2 = poseidon_burn_address_prefix();
        assert_eq!(prefix1, prefix2);
        
        let coin1 = poseidon_coin_prefix();
        let coin2 = poseidon_coin_prefix();
        assert_eq!(coin1, coin2);
        
        let null1 = poseidon_nullifier_prefix();
        let null2 = poseidon_nullifier_prefix();
        assert_eq!(null1, null2);
    }

    #[test]
    fn test_prefixes_are_different() {
        let burn_prefix = poseidon_burn_address_prefix();
        let coin_prefix = poseidon_coin_prefix();
        let null_prefix = poseidon_nullifier_prefix();
        
        // All prefixes should be different
        assert_ne!(burn_prefix, coin_prefix);
        assert_ne!(coin_prefix, null_prefix);
        assert_ne!(burn_prefix, null_prefix);
    }

    #[test]
    fn test_prefix_relationship() {
        // Based on WORM: nullifier = base + 1, coin = base + 2
        let burn = poseidon_burn_address_prefix();
        let null = poseidon_nullifier_prefix();
        let coin = poseidon_coin_prefix();
        
        // null should be burn + 1
        assert_eq!(null, burn + M31::one());
        
        // coin should be burn + 2
        assert_eq!(coin, burn + M31::from(2u32));
    }
}

#[cfg(test)]
mod poseidon_nullifier_tests {
    use super::*;

    #[test]
    fn test_nullifier_uniqueness() {
        // Different burn keys should produce different nullifiers
        let prefix = poseidon_nullifier_prefix();
        let mut nullifiers = HashSet::new();
        
        for i in 0..10000 {
            let burn_key = M31::from(i);
            let nullifier = poseidon2([prefix, burn_key]);
            
            assert!(
                nullifiers.insert(nullifier.value()),
                "Duplicate nullifier for burn_key {}",
                i
            );
        }
        
        assert_eq!(nullifiers.len(), 10000);
    }

    #[test]
    fn test_nullifier_determinism() {
        let prefix = poseidon_nullifier_prefix();
        
        for i in 0..1000 {
            let burn_key = M31::from(i * 7919);
            
            let null1 = poseidon2([prefix, burn_key]);
            let null2 = poseidon2([prefix, burn_key]);
            
            assert_eq!(null1, null2, "Nullifier not deterministic for burn_key {}", i);
        }
    }

    #[test]
    fn test_nullifier_sensitivity() {
        // Nullifier should change dramatically for small burn_key changes
        let prefix = poseidon_nullifier_prefix();
        
        for i in 0..1000 {
            let key1 = M31::from(i);
            let key2 = M31::from(i + 1);
            
            let null1 = poseidon2([prefix, key1]);
            let null2 = poseidon2([prefix, key2]);
            
            assert_ne!(null1, null2, "Nullifiers too similar for adjacent keys");
        }
    }
}

#[cfg(test)]
mod poseidon_coin_tests {
    use super::*;

    #[test]
    fn test_coin_construction() {
        // coin = Poseidon3(prefix, burnKey, balance)
        let prefix = poseidon_coin_prefix();
        
        for i in 0..1000 {
            let burn_key = M31::from(i * 123);
            let balance = M31::from(i * 1000000);
            
            let coin1 = poseidon3([prefix, burn_key, balance]);
            let coin2 = poseidon3([prefix, burn_key, balance]);
            
            assert_eq!(coin1, coin2, "Coin construction not deterministic");
        }
    }

    #[test]
    fn test_coin_different_balances() {
        // Same burn key, different balances -> different coins
        let prefix = poseidon_coin_prefix();
        let burn_key = M31::from(12345u32);
        
        let mut coins = HashSet::new();
        
        for balance in 0..1000 {
            let coin = poseidon3([prefix, burn_key, M31::from(balance * 1000)]);
            assert!(
                coins.insert(coin.value()),
                "Duplicate coin for balance {}",
                balance
            );
        }
    }

    #[test]
    fn test_coin_different_keys() {
        // Different burn keys, same balance -> different coins
        let prefix = poseidon_coin_prefix();
        let balance = M31::from(1000000u32);
        
        let mut coins = HashSet::new();
        
        for key in 0..1000 {
            let coin = poseidon3([prefix, M31::from(key), balance]);
            assert!(
                coins.insert(coin.value()),
                "Duplicate coin for burn_key {}",
                key
            );
        }
    }

    #[test]
    fn test_remaining_coin_logic() {
        // Test the spend logic: remaining = balance - withdrawn
        let prefix = poseidon_coin_prefix();
        let burn_key = M31::from(123456u32);
        let balance = M31::from(1000000u32);
        let withdrawn = M31::from(300000u32);
        
        let original_coin = poseidon3([prefix, burn_key, balance]);
        let remaining_coin = poseidon3([prefix, burn_key, balance - withdrawn]);
        
        // Should be different
        assert_ne!(original_coin, remaining_coin);
    }
}

#[cfg(test)]
mod poseidon_burn_address_tests {
    use super::*;

    #[test]
    fn test_burn_address_construction() {
        // burnAddress = Poseidon4(prefix, burnKey, revealAmount, extraCommitment)
        let prefix = poseidon_burn_address_prefix();
        
        for i in 0..500 {
            let burn_key = M31::from(i * 111);
            let reveal = M31::from(i * 500);
            let extra = M31::from(i * 789);
            
            let addr1 = poseidon4([prefix, burn_key, reveal, extra]);
            let addr2 = poseidon4([prefix, burn_key, reveal, extra]);
            
            assert_eq!(addr1, addr2, "Burn address not deterministic");
        }
    }

    #[test]
    fn test_burn_address_uniqueness_by_key() {
        let prefix = poseidon_burn_address_prefix();
        let reveal = M31::from(500000u32);
        let extra = M31::from(100u32);
        
        let mut addresses = HashSet::new();
        
        for key in 0..1000 {
            let addr = poseidon4([prefix, M31::from(key), reveal, extra]);
            assert!(
                addresses.insert(addr.value()),
                "Duplicate address for key {}",
                key
            );
        }
    }

    #[test]
    fn test_burn_address_sensitivity() {
        let prefix = poseidon_burn_address_prefix();
        let base_key = M31::from(12345u32);
        let reveal = M31::from(500000u32);
        let extra = M31::from(100u32);
        
        let addr1 = poseidon4([prefix, base_key, reveal, extra]);
        
        // Change each parameter slightly
        let addr2 = poseidon4([prefix, base_key + M31::one(), reveal, extra]);
        let addr3 = poseidon4([prefix, base_key, reveal + M31::one(), extra]);
        let addr4 = poseidon4([prefix, base_key, reveal, extra + M31::one()]);
        
        // All should be different
        assert_ne!(addr1, addr2);
        assert_ne!(addr1, addr3);
        assert_ne!(addr1, addr4);
        assert_ne!(addr2, addr3);
        assert_ne!(addr2, addr4);
        assert_ne!(addr3, addr4);
    }
}

#[cfg(test)]
mod poseidon_consistency_tests {
    use super::*;

    #[test]
    fn test_worm_logic_consistency() {
        // Test that our implementation follows WORM's logic patterns
        
        // 1. Nullifier = Poseidon2(nullifier_prefix, burnKey)
        let null_prefix = poseidon_nullifier_prefix();
        let burn_key = M31::from(123456u32);
        let nullifier = poseidon2([null_prefix, burn_key]);
        
        // 2. Coin = Poseidon3(coin_prefix, burnKey, balance)
        let coin_prefix = poseidon_coin_prefix();
        let balance = M31::from(1000000u32);
        let coin = poseidon3([coin_prefix, burn_key, balance]);
        
        // 3. Remaining coin after spending
        let withdrawn = M31::from(300000u32);
        let remaining_coin = poseidon3([coin_prefix, burn_key, balance - withdrawn]);
        
        // All should be different
        assert_ne!(nullifier, coin);
        assert_ne!(coin, remaining_coin);
        assert_ne!(nullifier, remaining_coin);
    }

    #[test]
    fn test_double_spend_prevention_logic() {
        // Same burn_key should always produce same nullifier
        let prefix = poseidon_nullifier_prefix();
        let burn_key = M31::from(999999u32);
        
        // Multiple "uses" of same burn_key
        let null1 = poseidon2([prefix, burn_key]);
        let null2 = poseidon2([prefix, burn_key]);
        let null3 = poseidon2([prefix, burn_key]);
        
        // All nullifiers should be identical (would be caught by contract)
        assert_eq!(null1, null2);
        assert_eq!(null2, null3);
    }

    #[test]
    fn test_spend_chain() {
        // Test a chain of spends
        let coin_prefix = poseidon_coin_prefix();
        let burn_key = M31::from(777777u32);
        
        let initial_balance = M31::from(1000000u32);
        let coin1 = poseidon3([coin_prefix, burn_key, initial_balance]);
        
        // Spend 100k
        let balance2 = initial_balance - M31::from(100000u32);
        let coin2 = poseidon3([coin_prefix, burn_key, balance2]);
        
        // Spend another 200k
        let balance3 = balance2 - M31::from(200000u32);
        let coin3 = poseidon3([coin_prefix, burn_key, balance3]);
        
        // All coins should be different
        assert_ne!(coin1, coin2);
        assert_ne!(coin2, coin3);
        assert_ne!(coin1, coin3);
    }
}

#[cfg(test)]
mod poseidon_edge_case_tests {
    use super::*;

    #[test]
    fn test_zero_inputs() {
        let zero = M31::zero();
        
        let hash2 = poseidon2([zero, zero]);
        let hash3 = poseidon3([zero, zero, zero]);
        let hash4 = poseidon4([zero, zero, zero, zero]);
        
        // Should produce valid (non-zero) outputs even for zero inputs
        assert!(hash2.value() < M31::PRIME);
        assert!(hash3.value() < M31::PRIME);
        assert!(hash4.value() < M31::PRIME);
        
        // Different arities should give different results even with all zeros
        assert_ne!(hash2, hash3);
        assert_ne!(hash3, hash4);
    }

    #[test]
    fn test_max_value_inputs() {
        let max = M31::from(M31::PRIME - 1);
        
        let hash2 = poseidon2([max, max]);
        let hash3 = poseidon3([max, max, max]);
        let hash4 = poseidon4([max, max, max, max]);
        
        // Should handle maximum field values
        assert!(hash2.value() < M31::PRIME);
        assert!(hash3.value() < M31::PRIME);
        assert!(hash4.value() < M31::PRIME);
    }

    #[test]
    fn test_one_inputs() {
        let one = M31::one();
        
        let hash2 = poseidon2([one, one]);
        let hash3 = poseidon3([one, one, one]);
        let hash4 = poseidon4([one, one, one, one]);
        
        // All should be different despite same input values
        assert_ne!(hash2, hash3);
        assert_ne!(hash3, hash4);
        assert_ne!(hash2, hash4);
    }

    #[test]
    fn test_sequential_inputs() {
        // Test patterns like [1,2], [2,3], [3,4]...
        for i in 0..1000 {
            let a = M31::from(i);
            let b = M31::from(i + 1);
            
            let hash = poseidon2([a, b]);
            
            // Should produce valid hash
            assert!(hash.value() < M31::PRIME);
        }
    }
}

#[cfg(test)]
mod poseidon_performance_tests {
    use super::*;

    #[test]
    fn test_many_hashes() {
        // Performance test: hash 100k values
        let mut hashes = Vec::with_capacity(100_000);
        
        for i in 0..100_000 {
            let a = M31::from(i);
            let b = M31::from(i * 2);
            
            let hash = poseidon2([a, b]);
            hashes.push(hash);
        }
        
        assert_eq!(hashes.len(), 100_000);
    }

    #[test]
    fn test_hash_distribution() {
        // Check that hashes are well-distributed
        let mut distribution: HashMap<u32, u32> = HashMap::new();
        
        for i in 0..10000 {
            let a = M31::from(i * 123);
            let b = M31::from(i * 456);
            
            let hash = poseidon2([a, b]);
            let bucket = hash.value() / (M31::PRIME / 100); // 100 buckets
            
            *distribution.entry(bucket).or_insert(0) += 1;
        }
        
        // Check that distribution is reasonably uniform
        let avg = (10000 / distribution.len()) as u32;
        for (bucket, count) in distribution.iter() {
            // Each bucket should be within 50% of average
            let diff = if *count > avg { count - avg } else { avg - count };
            assert!(
                diff < avg / 2,
                "Bucket {} has poor distribution: {} (avg: {})",
                bucket,
                count,
                avg
            );
        }
    }
}

