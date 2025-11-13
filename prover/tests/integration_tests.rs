// Integration Tests
// End-to-end tests that verify complete workflows

use proof_of_burn_stwo::field::M31;
use proof_of_burn_stwo::utils::poseidon::{poseidon2, poseidon3, poseidon4, u256_to_m31};
use proof_of_burn_stwo::constants::{
    poseidon_burn_address_prefix, poseidon_coin_prefix, poseidon_nullifier_prefix,
};
use alloy_primitives::U256;

#[cfg(test)]
mod end_to_end_proof_of_burn_tests {
    use super::*;

    #[test]
    fn test_complete_proof_of_burn_flow() {
        // Simulate a complete proof-of-burn flow
        
        // Step 1: User generates burn key (secret)
        let burn_key = M31::from(123456789u32);
        
        // Step 2: Set parameters
        let intended_balance = U256::from(1_000_000_000u64); // 1 Gwei
        let reveal_amount = U256::from(200_000_000u64); // 200M wei revealed
        let extra_commitment = M31::from(100u32);
        
        // Step 3: Generate nullifier (for double-spend prevention)
        let nullifier_prefix = poseidon_nullifier_prefix();
        let nullifier = poseidon2([nullifier_prefix, burn_key]);
        
        // Step 4: Generate burn address
        let burn_prefix = poseidon_burn_address_prefix();
        let reveal_m31 = u256_to_m31(reveal_amount);
        let burn_address_hash = poseidon4([burn_prefix, burn_key, reveal_m31, extra_commitment]);
        
        // Step 5: Calculate remaining coin
        let coin_prefix = poseidon_coin_prefix();
        let intended_m31 = u256_to_m31(intended_balance);
        let remaining_balance = intended_m31 - reveal_m31;
        let remaining_coin = poseidon3([coin_prefix, burn_key, remaining_balance]);
        
        // Verify all components are valid
        assert!(nullifier.value() < M31::PRIME);
        assert!(burn_address_hash.value() < M31::PRIME);
        assert!(remaining_coin.value() < M31::PRIME);
        
        // Verify all components are unique
        assert_ne!(nullifier, remaining_coin);
        assert_ne!(burn_address_hash, remaining_coin);
        assert_ne!(nullifier, burn_address_hash);
        
        // Step 6: Verify nullifier prevents reuse
        let nullifier2 = poseidon2([nullifier_prefix, burn_key]);
        assert_eq!(nullifier, nullifier2, "Double-spend not detectable");
    }

    #[test]
    fn test_multiple_users_different_outputs() {
        // Multiple users with different burn keys should get different outputs
        let num_users = 100;
        let mut nullifiers = std::collections::HashSet::new();
        let mut coins = std::collections::HashSet::new();
        let mut addresses = std::collections::HashSet::new();
        
        let nullifier_prefix = poseidon_nullifier_prefix();
        let coin_prefix = poseidon_coin_prefix();
        let burn_prefix = poseidon_burn_address_prefix();
        
        for i in 0..num_users {
            let burn_key = M31::from(i * 12345);
            let balance = M31::from(1000000u32);
            let reveal = M31::from(200000u32);
            let extra = M31::from(100u32);
            
            let nullifier = poseidon2([nullifier_prefix, burn_key]);
            let coin = poseidon3([coin_prefix, burn_key, balance - reveal]);
            let address = poseidon4([burn_prefix, burn_key, reveal, extra]);
            
            // All should be unique per user
            assert!(nullifiers.insert(nullifier.value()));
            assert!(coins.insert(coin.value()));
            assert!(addresses.insert(address.value()));
        }
        
        assert_eq!(nullifiers.len(), num_users);
        assert_eq!(coins.len(), num_users);
        assert_eq!(addresses.len(), num_users);
    }

    #[test]
    fn test_burn_and_reveal_scenarios() {
        let burn_key = M31::from(999999u32);
        let coin_prefix = poseidon_coin_prefix();
        
        // Scenario 1: Burn 1M, reveal nothing
        let balance1 = M31::from(1000000u32);
        let reveal1 = M31::zero();
        let coin1 = poseidon3([coin_prefix, burn_key, balance1 - reveal1]);
        
        // Scenario 2: Burn 1M, reveal 500k
        let balance2 = M31::from(1000000u32);
        let reveal2 = M31::from(500000u32);
        let coin2 = poseidon3([coin_prefix, burn_key, balance2 - reveal2]);
        
        // Scenario 3: Burn 1M, reveal everything
        let balance3 = M31::from(1000000u32);
        let reveal3 = M31::from(1000000u32);
        let coin3 = poseidon3([coin_prefix, burn_key, balance3 - reveal3]);
        
        // All coins should be different
        assert_ne!(coin1, coin2);
        assert_ne!(coin2, coin3);
        assert_ne!(coin1, coin3);
    }
}

#[cfg(test)]
mod end_to_end_spend_tests {
    use super::*;

    #[test]
    fn test_complete_spend_flow() {
        // Simulate a complete spend flow
        
        // Step 1: User has an existing coin
        let burn_key = M31::from(555555u32);
        let coin_prefix = poseidon_coin_prefix();
        let balance = M31::from(800000u32);
        let original_coin = poseidon3([coin_prefix, burn_key, balance]);
        
        // Step 2: User wants to spend 300k
        let withdrawn = M31::from(300000u32);
        assert!(withdrawn.value() <= balance.value(), "Invalid withdrawal");
        
        // Step 3: Calculate remaining balance
        let remaining_balance = balance - withdrawn;
        assert_eq!(remaining_balance.value(), 500000);
        
        // Step 4: Generate new coin
        let remaining_coin = poseidon3([coin_prefix, burn_key, remaining_balance]);
        
        // Step 5: Verify coins are different
        assert_ne!(original_coin, remaining_coin);
        
        // Step 6: Verify both coins use same burn key (lineage)
        let test_coin1 = poseidon3([coin_prefix, burn_key, balance]);
        let test_coin2 = poseidon3([coin_prefix, burn_key, remaining_balance]);
        assert_eq!(test_coin1, original_coin);
        assert_eq!(test_coin2, remaining_coin);
    }

    #[test]
    fn test_multiple_sequential_spends() {
        // Test a chain of spends
        let burn_key = M31::from(777777u32);
        let coin_prefix = poseidon_coin_prefix();
        
        let mut current_balance = M31::from(1000000u32);
        let mut prev_coin = poseidon3([coin_prefix, burn_key, current_balance]);
        
        let spends = [100000, 200000, 150000, 250000, 50000];
        
        for spend in spends {
            // Spend amount
            current_balance = current_balance - M31::from(spend);
            
            // Generate new coin
            let new_coin = poseidon3([coin_prefix, burn_key, current_balance]);
            
            // Verify it's different from previous
            assert_ne!(new_coin, prev_coin);
            
            // Update for next iteration
            prev_coin = new_coin;
        }
        
        // Verify final balance
        let expected_final = 1000000 - 100000 - 200000 - 150000 - 250000 - 50000;
        assert_eq!(current_balance.value(), expected_final);
    }

    #[test]
    fn test_spend_to_zero_balance() {
        let burn_key = M31::from(333333u32);
        let coin_prefix = poseidon_coin_prefix();
        
        // Start with 100k
        let balance = M31::from(100000u32);
        let original_coin = poseidon3([coin_prefix, burn_key, balance]);
        
        // Spend everything
        let withdrawn = balance;
        let remaining = balance - withdrawn;
        assert_eq!(remaining, M31::zero());
        
        // Generate coin with zero balance
        let zero_coin = poseidon3([coin_prefix, burn_key, remaining]);
        
        // Should be valid but different from original
        assert_ne!(zero_coin, original_coin);
        assert!(zero_coin.value() < M31::PRIME);
    }
}

#[cfg(test)]
mod integrated_workflow_tests {
    use super::*;

    #[test]
    fn test_full_lifecycle_burn_to_multiple_spends() {
        // Complete lifecycle: burn -> reveal -> spend -> spend -> spend
        let burn_key = M31::from(111222333u32);
        
        // PHASE 1: Proof of Burn
        let nullifier_prefix = poseidon_nullifier_prefix();
        let coin_prefix = poseidon_coin_prefix();
        let burn_prefix = poseidon_burn_address_prefix();
        
        let intended_balance = M31::from(1000000u32);
        let reveal_amount = M31::from(200000u32); // Reveal 200k upfront
        let extra_commitment = M31::from(1u32);
        
        // Generate proof-of-burn outputs
        let nullifier = poseidon2([nullifier_prefix, burn_key]);
        let burn_address = poseidon4([burn_prefix, burn_key, reveal_amount, extra_commitment]);
        let initial_coin_balance = intended_balance - reveal_amount; // 800k
        let coin0 = poseidon3([coin_prefix, burn_key, initial_coin_balance]);
        
        // PHASE 2: First Spend (300k from 800k)
        let spend1 = M31::from(300000u32);
        let balance1 = initial_coin_balance - spend1; // 500k
        let coin1 = poseidon3([coin_prefix, burn_key, balance1]);
        
        // PHASE 3: Second Spend (200k from 500k)
        let spend2 = M31::from(200000u32);
        let balance2 = balance1 - spend2; // 300k
        let coin2 = poseidon3([coin_prefix, burn_key, balance2]);
        
        // PHASE 4: Third Spend (100k from 300k)
        let spend3 = M31::from(100000u32);
        let balance3 = balance2 - spend3; // 200k
        let coin3 = poseidon3([coin_prefix, burn_key, balance3]);
        
        // Verify nullifier is consistent (double-spend prevention)
        let nullifier_check = poseidon2([nullifier_prefix, burn_key]);
        assert_eq!(nullifier, nullifier_check);
        
        // Verify all coins are unique
        let coins = vec![coin0, coin1, coin2, coin3];
        for i in 0..coins.len() {
            for j in (i + 1)..coins.len() {
                assert_ne!(coins[i], coins[j], "Coins {} and {} are not unique", i, j);
            }
        }
        
        // Verify final balance
        assert_eq!(balance3.value(), 200000);
    }

    #[test]
    fn test_multiple_independent_burns() {
        // Multiple users burning independently
        let num_users = 50;
        let mut all_nullifiers = std::collections::HashSet::new();
        
        for i in 0..num_users {
            let burn_key = M31::from(i * 77777);
            let balance = M31::from((i + 1) * 100000);
            let reveal = M31::from(i * 10000);
            
            // Each user does proof-of-burn
            let nullifier = poseidon2([poseidon_nullifier_prefix(), burn_key]);
            let coin = poseidon3([poseidon_coin_prefix(), burn_key, balance - reveal]);
            
            // Nullifiers must be unique
            assert!(all_nullifiers.insert(nullifier.value()));
            
            // Each user can then spend
            let spend = M31::from(50000u32);
            let new_coin = poseidon3([poseidon_coin_prefix(), burn_key, balance - reveal - spend]);
            
            assert_ne!(coin, new_coin);
        }
    }

    #[test]
    fn test_revealing_different_amounts() {
        // Same burn key, different reveal amounts
        let burn_key = M31::from(444444u32);
        let balance = M31::from(1000000u32);
        
        let reveal_amounts = [0, 100000, 500000, 900000, 1000000];
        let mut coins = Vec::new();
        
        for reveal in reveal_amounts {
            let reveal_m31 = M31::from(reveal);
            let remaining = balance - reveal_m31;
            let coin = poseidon3([poseidon_coin_prefix(), burn_key, remaining]);
            coins.push(coin);
        }
        
        // All coins should be unique
        for i in 0..coins.len() {
            for j in (i + 1)..coins.len() {
                assert_ne!(coins[i], coins[j]);
            }
        }
    }
}

#[cfg(test)]
mod error_scenario_tests {
    use super::*;

    #[test]
    fn test_double_spend_detection() {
        // Attempt to use same burn key twice
        let burn_key = M31::from(666666u32);
        let nullifier_prefix = poseidon_nullifier_prefix();
        
        // First use
        let nullifier1 = poseidon2([nullifier_prefix, burn_key]);
        
        // Second use (should produce same nullifier, caught by contract)
        let nullifier2 = poseidon2([nullifier_prefix, burn_key]);
        
        assert_eq!(nullifier1, nullifier2, "Double spend not detectable!");
    }

    #[test]
    fn test_coin_reuse_detection() {
        // Attempting to spend same coin twice
        let burn_key = M31::from(888888u32);
        let coin_prefix = poseidon_coin_prefix();
        let balance = M31::from(500000u32);
        
        // Original coin
            let _coin = poseidon3([coin_prefix, burn_key, balance]);
        
        // "Spend" 100k twice from same original balance
        let spend = M31::from(100000u32);
        let coin_after_spend1 = poseidon3([coin_prefix, burn_key, balance - spend]);
        let coin_after_spend2 = poseidon3([coin_prefix, burn_key, balance - spend]);
        
        // These would be identical (caught by contract checking coin has been used)
        assert_eq!(coin_after_spend1, coin_after_spend2);
    }

    #[test]
    fn test_balance_overflow_protection() {
        // Test that we handle balances near field limit
        let burn_key = M31::from(123u32);
        let coin_prefix = poseidon_coin_prefix();
        
        // Balance near M31::PRIME
        let large_balance = M31::from(M31::PRIME - 1000);
        let coin = poseidon3([coin_prefix, burn_key, large_balance]);
        
        // Should still produce valid coin
        assert!(coin.value() < M31::PRIME);
        
        // Spending from it should work
        let spend = M31::from(500u32);
        let remaining = large_balance - spend;
        let new_coin = poseidon3([coin_prefix, burn_key, remaining]);
        
        assert!(new_coin.value() < M31::PRIME);
        assert_ne!(coin, new_coin);
    }
}

#[cfg(test)]
mod stress_tests {
    use super::*;

    #[test]
    fn test_many_users() {
        // Stress test with many users
        let num_users = 1000;
        let mut nullifiers = std::collections::HashSet::new();
        
        for i in 0..num_users {
            let burn_key = M31::from(i * 314159);
            let nullifier = poseidon2([poseidon_nullifier_prefix(), burn_key]);
            
            assert!(nullifiers.insert(nullifier.value()));
        }
        
        assert_eq!(nullifiers.len(), num_users);
    }

    #[test]
    fn test_many_spends_per_user() {
        // One user doing many spends
        let burn_key = M31::from(271828u32);
        let coin_prefix = poseidon_coin_prefix();
        
        let mut balance = M31::from(10000000u32);
        let mut prev_coin = poseidon3([coin_prefix, burn_key, balance]);
        
        for i in 1..100 {
            let spend = M31::from(i * 1000);
            balance = balance - spend;
            
            let new_coin = poseidon3([coin_prefix, burn_key, balance]);
            assert_ne!(new_coin, prev_coin);
            
            prev_coin = new_coin;
        }
    }

    #[test]
    fn test_concurrent_burns() {
        // Simulate concurrent burns from different users
        let scenarios: Vec<(u32, u32, u32)> = (0..500)
            .map(|i| (i * 1000, i * 500, i * 10))
            .collect();
        
        let mut nullifiers = std::collections::HashSet::new();
        let mut addresses = std::collections::HashSet::new();
        
        for (key, reveal, extra) in scenarios {
            let burn_key = M31::from(key);
            let reveal_m31 = M31::from(reveal);
            let extra_m31 = M31::from(extra);
            
            let nullifier = poseidon2([poseidon_nullifier_prefix(), burn_key]);
            let address = poseidon4([
                poseidon_burn_address_prefix(),
                burn_key,
                reveal_m31,
                extra_m31,
            ]);
            
            nullifiers.insert(nullifier.value());
            addresses.insert(address.value());
        }
        
        // All should be unique
        assert_eq!(nullifiers.len(), 500);
        assert_eq!(addresses.len(), 500);
    }
}
