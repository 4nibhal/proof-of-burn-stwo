// Boundary and Edge Case Tests
// Tests that verify behavior at boundaries and extreme values

use proof_of_burn_stwo::field::M31;
use proof_of_burn_stwo::utils::poseidon::{poseidon2, poseidon3, poseidon4};
use proof_of_burn_stwo::constants::{
    poseidon_burn_address_prefix, poseidon_coin_prefix, poseidon_nullifier_prefix,
    M31_PRIME,
};

#[cfg(test)]
mod field_boundary_tests {
    use super::*;

    #[test]
    fn test_zero_value() {
        let zero = M31::zero();
        assert_eq!(zero.value(), 0);
        
        // Hashing zero should work
        let hash = poseidon2([zero, zero]);
        assert!(hash.value() < M31_PRIME);
    }

    #[test]
    fn test_one_value() {
        let one = M31::one();
        assert_eq!(one.value(), 1);
        
        let hash = poseidon2([one, one]);
        assert!(hash.value() < M31_PRIME);
    }

    #[test]
    fn test_prime_minus_one() {
        let max = M31::from(M31_PRIME - 1);
        assert_eq!(max.value(), M31_PRIME - 1);
        
        // Adding 1 should wrap to 0
        let result = max + M31::one();
        assert_eq!(result, M31::zero());
    }

    #[test]
    fn test_exactly_prime() {
        let p = M31::from(M31_PRIME);
        assert_eq!(p, M31::zero());
    }

    #[test]
    fn test_double_prime() {
        let double_p = M31::from(M31_PRIME * 2);
        assert_eq!(double_p, M31::zero());
    }

    #[test]
    fn test_prime_plus_values() {
        for i in 0..1000u32 {
            let val = M31::from(M31_PRIME + i);
            assert_eq!(val.value(), i);
        }
    }
}

#[cfg(test)]
mod balance_boundary_tests {
    use super::*;

    #[test]
    fn test_zero_balance() {
        let burn_key = M31::from(12345u32);
        let coin_prefix = poseidon_coin_prefix();
        let zero_balance = M31::zero();
        
        let coin = poseidon3([coin_prefix, burn_key, zero_balance]);
        assert!(coin.value() < M31_PRIME);
    }

    #[test]
    fn test_one_wei_balance() {
        let burn_key = M31::from(12345u32);
        let coin_prefix = poseidon_coin_prefix();
        let one_wei = M31::one();
        
        let coin = poseidon3([coin_prefix, burn_key, one_wei]);
        assert!(coin.value() < M31_PRIME);
    }

    #[test]
    fn test_maximum_safe_balance() {
        // Maximum balance that fits in M31 without wrapping
        let burn_key = M31::from(12345u32);
        let coin_prefix = poseidon_coin_prefix();
        let max_balance = M31::from(M31_PRIME - 1);
        
        let coin = poseidon3([coin_prefix, burn_key, max_balance]);
        assert!(coin.value() < M31_PRIME);
    }

    #[test]
    fn test_balances_around_boundaries() {
        let burn_key = M31::from(99999u32);
        let coin_prefix = poseidon_coin_prefix();
        
        // Test powers of 10
        let boundaries = [
            1,
            10,
            100,
            1_000,
            10_000,
            100_000,
            1_000_000,
            10_000_000,
            100_000_000,
            1_000_000_000,
            2_000_000_000,
        ];
        
        for balance in boundaries {
            let balance_m31 = M31::from(balance);
            let coin = poseidon3([coin_prefix, burn_key, balance_m31]);
            assert!(coin.value() < M31_PRIME, "Failed for balance {}", balance);
        }
    }

    #[test]
    fn test_withdraw_exact_balance() {
        let burn_key = M31::from(55555u32);
        let coin_prefix = poseidon_coin_prefix();
        
        let balance = M31::from(1000000u32);
        let coin = poseidon3([coin_prefix, burn_key, balance]);
        
        // Withdraw exactly the balance
        let withdrawn = balance;
        let remaining = balance - withdrawn;
        assert_eq!(remaining, M31::zero());
        
        let new_coin = poseidon3([coin_prefix, burn_key, remaining]);
        assert_ne!(coin, new_coin);
    }

    #[test]
    fn test_withdraw_one_wei() {
        let burn_key = M31::from(77777u32);
        let coin_prefix = poseidon_coin_prefix();
        
        let balance = M31::from(1000000u32);
        let coin = poseidon3([coin_prefix, burn_key, balance]);
        
        // Withdraw just 1 wei
        let withdrawn = M31::one();
        let remaining = balance - withdrawn;
        
        let new_coin = poseidon3([coin_prefix, burn_key, remaining]);
        assert_ne!(coin, new_coin);
    }
}

#[cfg(test)]
mod reveal_amount_boundary_tests {
    use super::*;

    #[test]
    fn test_zero_reveal() {
        let burn_key = M31::from(11111u32);
        let balance = M31::from(1000000u32);
        let reveal = M31::zero();
        
        let remaining = balance - reveal;
        assert_eq!(remaining, balance);
        
        let coin = poseidon3([poseidon_coin_prefix(), burn_key, remaining]);
        assert!(coin.value() < M31_PRIME);
    }

    #[test]
    fn test_full_reveal() {
        let burn_key = M31::from(22222u32);
        let balance = M31::from(1000000u32);
        let reveal = balance;
        
        let remaining = balance - reveal;
        assert_eq!(remaining, M31::zero());
        
        let coin = poseidon3([poseidon_coin_prefix(), burn_key, remaining]);
        assert!(coin.value() < M31_PRIME);
    }

    #[test]
    fn test_reveal_boundary_values() {
        let burn_key = M31::from(33333u32);
        let coin_prefix = poseidon_coin_prefix();
        let balance = M31::from(1000000u32);
        
        // Test revealing different percentages
        let percentages = [0, 1, 10, 25, 50, 75, 90, 99, 100];
        
        for pct in percentages {
            let reveal = M31::from((balance.value() * pct) / 100);
            let remaining = balance - reveal;
            
            let coin = poseidon3([coin_prefix, burn_key, remaining]);
            assert!(coin.value() < M31_PRIME);
        }
    }
}

#[cfg(test)]
mod burn_key_boundary_tests {
    use super::*;

    #[test]
    fn test_zero_burn_key() {
        let burn_key = M31::zero();
        let nullifier_prefix = poseidon_nullifier_prefix();
        
        let nullifier = poseidon2([nullifier_prefix, burn_key]);
        assert!(nullifier.value() < M31_PRIME);
    }

    #[test]
    fn test_one_burn_key() {
        let burn_key = M31::one();
        let nullifier_prefix = poseidon_nullifier_prefix();
        
        let nullifier = poseidon2([nullifier_prefix, burn_key]);
        assert!(nullifier.value() < M31_PRIME);
    }

    #[test]
    fn test_max_burn_key() {
        let burn_key = M31::from(M31_PRIME - 1);
        let nullifier_prefix = poseidon_nullifier_prefix();
        
        let nullifier = poseidon2([nullifier_prefix, burn_key]);
        assert!(nullifier.value() < M31_PRIME);
    }

    #[test]
    fn test_sequential_burn_keys() {
        let nullifier_prefix = poseidon_nullifier_prefix();
        
        // Test keys 0 through 10000
        for i in 0..10000 {
            let burn_key = M31::from(i);
            let nullifier = poseidon2([nullifier_prefix, burn_key]);
            assert!(nullifier.value() < M31_PRIME);
        }
    }

    #[test]
    fn test_adjacent_burn_keys_different_nullifiers() {
        let nullifier_prefix = poseidon_nullifier_prefix();
        
        for i in 0..1000 {
            let key1 = M31::from(i);
            let key2 = M31::from(i + 1);
            
            let null1 = poseidon2([nullifier_prefix, key1]);
            let null2 = poseidon2([nullifier_prefix, key2]);
            
            assert_ne!(null1, null2, "Adjacent keys {} and {} gave same nullifier", i, i + 1);
        }
    }
}

#[cfg(test)]
mod commitment_boundary_tests {
    use super::*;

    #[test]
    fn test_zero_commitment() {
        let burn_key = M31::from(12345u32);
        let reveal = M31::from(100000u32);
        let extra = M31::zero();
        
        let address = poseidon4([poseidon_burn_address_prefix(), burn_key, reveal, extra]);
        assert!(address.value() < M31_PRIME);
    }

    #[test]
    fn test_max_commitment() {
        let burn_key = M31::from(12345u32);
        let reveal = M31::from(100000u32);
        let extra = M31::from(M31_PRIME - 1);
        
        let address = poseidon4([poseidon_burn_address_prefix(), burn_key, reveal, extra]);
        assert!(address.value() < M31_PRIME);
    }

    #[test]
    fn test_commitment_range() {
        let burn_key = M31::from(99999u32);
        let reveal = M31::from(500000u32);
        let burn_prefix = poseidon_burn_address_prefix();
        
        // Test various commitment values
        let commitments = [0, 1, 100, 10000, 1000000, 100000000, M31_PRIME - 1];
        
        for commit in commitments {
            let extra = M31::from(commit);
            let address = poseidon4([burn_prefix, burn_key, reveal, extra]);
            assert!(address.value() < M31_PRIME);
        }
    }
}

#[cfg(test)]
mod arithmetic_boundary_tests {
    use super::*;

    #[test]
    fn test_subtraction_underflow() {
        let small = M31::from(100u32);
        let large = M31::from(200u32);
        
        // small - large should wrap around
        let result = small - large;
        let expected = M31::from(M31_PRIME - 100);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_addition_overflow() {
        let large1 = M31::from(M31_PRIME - 100);
        let large2 = M31::from(200u32);
        
        // Should wrap around
        let result = large1 + large2;
        let expected = M31::from(100u32);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_multiplication_overflow() {
        let large1 = M31::from(M31_PRIME / 2);
        let large2 = M31::from(3u32);
        
        // Should stay in field
        let result = large1 * large2;
        assert!(result.value() < M31_PRIME);
    }

    #[test]
    fn test_repeated_addition_to_zero() {
        let mut sum = M31::zero();
        let max = M31::from(M31_PRIME - 1);
        
        // Adding P-1 and then 1 should wrap to 0
        sum = sum + max;
        sum = sum + M31::one();
        
        assert_eq!(sum, M31::zero());
        
        // Test with exact divisor: add M31_PRIME many times M31::one()
        let mut sum2 = M31::zero();
        for _ in 0..M31_PRIME {
            sum2 = sum2 + M31::one();
        }
        assert_eq!(sum2, M31::zero());
    }
}

#[cfg(test)]
mod hash_input_boundary_tests {
    use super::*;

    #[test]
    fn test_all_zero_inputs() {
        let zero = M31::zero();
        
        let hash2 = poseidon2([zero, zero]);
        let hash3 = poseidon3([zero, zero, zero]);
        let hash4 = poseidon4([zero, zero, zero, zero]);
        
        // Should all be valid
        assert!(hash2.value() < M31_PRIME);
        assert!(hash3.value() < M31_PRIME);
        assert!(hash4.value() < M31_PRIME);
        
        // Should all be different
        assert_ne!(hash2, hash3);
        assert_ne!(hash3, hash4);
    }

    #[test]
    fn test_all_max_inputs() {
        let max = M31::from(M31_PRIME - 1);
        
        let hash2 = poseidon2([max, max]);
        let hash3 = poseidon3([max, max, max]);
        let hash4 = poseidon4([max, max, max, max]);
        
        assert!(hash2.value() < M31_PRIME);
        assert!(hash3.value() < M31_PRIME);
        assert!(hash4.value() < M31_PRIME);
    }

    #[test]
    fn test_mixed_boundary_inputs() {
        let zero = M31::zero();
        let one = M31::one();
        let max = M31::from(M31_PRIME - 1);
        
        let hash = poseidon4([zero, one, max, one]);
        assert!(hash.value() < M31_PRIME);
    }

    #[test]
    fn test_alternating_pattern() {
        let zero = M31::zero();
        let max = M31::from(M31_PRIME - 1);
        
        let hash1 = poseidon4([zero, max, zero, max]);
        let hash2 = poseidon4([max, zero, max, zero]);
        
        assert_ne!(hash1, hash2);
    }
}

#[cfg(test)]
mod spend_boundary_tests {
    use super::*;

    #[test]
    fn test_spend_leaving_one_wei() {
        let burn_key = M31::from(12345u32);
        let coin_prefix = poseidon_coin_prefix();
        
        let balance = M31::from(1000000u32);
        let withdraw = M31::from(999999u32);
        
        let remaining = balance - withdraw;
        assert_eq!(remaining.value(), 1);
        
        let coin = poseidon3([coin_prefix, burn_key, remaining]);
        assert!(coin.value() < M31_PRIME);
    }

    #[test]
    fn test_spend_from_one_wei() {
        let burn_key = M31::from(54321u32);
        let coin_prefix = poseidon_coin_prefix();
        
        let balance = M31::one();
        let coin = poseidon3([coin_prefix, burn_key, balance]);
        
        // Spend the one wei
        let withdraw = M31::one();
        let remaining = balance - withdraw;
        assert_eq!(remaining, M31::zero());
        
        let new_coin = poseidon3([coin_prefix, burn_key, remaining]);
        assert_ne!(coin, new_coin);
    }

    #[test]
    fn test_many_small_spends() {
        let burn_key = M31::from(11111u32);
        let coin_prefix = poseidon_coin_prefix();
        
        let mut balance = M31::from(10000u32);
        let mut prev_coin = poseidon3([coin_prefix, burn_key, balance]);
        
        // Spend 1 wei at a time, 5000 times
        for _ in 0..5000 {
            balance = balance - M31::one();
            let new_coin = poseidon3([coin_prefix, burn_key, balance]);
            assert_ne!(new_coin, prev_coin);
            prev_coin = new_coin;
        }
        
        assert_eq!(balance.value(), 5000);
    }
}

#[cfg(test)]
mod extreme_value_tests {
    use super::*;

    #[test]
    fn test_2_power_30() {
        // 2^30 = 1073741824, which is less than M31_PRIME
        let val = M31::from(1u32 << 30);
        assert_eq!(val.value(), 1073741824);
        
        let hash = poseidon2([val, val]);
        assert!(hash.value() < M31_PRIME);
    }

    #[test]
    fn test_fibonacci_sequence() {
        let mut a = M31::one();
        let mut b = M31::one();
        
        // Generate Fibonacci numbers in M31 field
        for _ in 0..100 {
            let c = a + b;
            assert!(c.value() < M31_PRIME);
            a = b;
            b = c;
        }
    }

    #[test]
    fn test_geometric_progression() {
        let mut val = M31::one();
        let multiplier = M31::from(2u32);
        
        // Generate 2^i for i in 0..30
        for _ in 0..30 {
            assert!(val.value() < M31_PRIME);
            val = val * multiplier;
        }
    }
}

