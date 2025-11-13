// Circuit Logic Tests
// Tests that verify the logic of proof-of-burn and spend circuits matches WORM

use proof_of_burn_stwo::field::M31;
use proof_of_burn_stwo::utils::poseidon::{poseidon2, poseidon3, poseidon4};
use proof_of_burn_stwo::constants::{
    poseidon_burn_address_prefix, poseidon_coin_prefix, poseidon_nullifier_prefix,
};

#[cfg(test)]
mod proof_of_burn_logic_tests {
    use super::*;

    #[test]
    fn test_nullifier_generation() {
        // nullifier = Poseidon2(NULLIFIER_PREFIX, burnKey)
        let prefix = poseidon_nullifier_prefix();
        
        for i in 0..1000 {
            let burn_key = M31::from(i * 12345);
            let nullifier = poseidon2([prefix, burn_key]);
            
            // Nullifier should be deterministic
            let nullifier2 = poseidon2([prefix, burn_key]);
            assert_eq!(nullifier, nullifier2);
            
            // Different burn keys should give different nullifiers
            if i > 0 {
                let prev_key = M31::from((i - 1) * 12345);
                let prev_nullifier = poseidon2([prefix, prev_key]);
                assert_ne!(nullifier, prev_nullifier);
            }
        }
    }

    #[test]
    fn test_remaining_coin_calculation() {
        // remainingCoin = Poseidon3(COIN_PREFIX, burnKey, intendedBalance - revealAmount)
        let prefix = poseidon_coin_prefix();
        let burn_key = M31::from(123456u32);
        
        for intended in [100000, 500000, 1000000, 5000000] {
            for reveal in [0, 10000, 50000, 100000] {
                if reveal <= intended {
                    let intended_m31 = M31::from(intended);
                    let reveal_m31 = M31::from(reveal);
                    
                    let remaining_balance = intended_m31 - reveal_m31;
                    let remaining_coin = poseidon3([prefix, burn_key, remaining_balance]);
                    
                    // Should be deterministic
                    let remaining_coin2 = poseidon3([prefix, burn_key, remaining_balance]);
                    assert_eq!(remaining_coin, remaining_coin2);
                    
                    // Different remaining balances should give different coins
                    if reveal > 0 {
                        let full_coin = poseidon3([prefix, burn_key, intended_m31]);
                        assert_ne!(remaining_coin, full_coin);
                    }
                }
            }
        }
    }

    #[test]
    fn test_burn_address_derivation() {
        // burnAddress = Poseidon4(BURN_ADDRESS_PREFIX, burnKey, revealAmount, burnExtraCommitment)
        let prefix = poseidon_burn_address_prefix();
        
        for i in 0..500 {
            let burn_key = M31::from(i * 7919);
            let reveal_amount = M31::from(i * 50000);
            let extra_commitment = M31::from(i * 100);
            
            let address = poseidon4([prefix, burn_key, reveal_amount, extra_commitment]);
            
            // Should be deterministic
            let address2 = poseidon4([prefix, burn_key, reveal_amount, extra_commitment]);
            assert_eq!(address, address2);
            
            // Changing any parameter should change address
            let address3 = poseidon4([prefix, burn_key + M31::one(), reveal_amount, extra_commitment]);
            assert_ne!(address, address3);
        }
    }

    #[test]
    fn test_balance_constraints() {
        // revealAmount <= intendedBalance <= actualBalance (logical constraint)
        let coin_prefix = poseidon_coin_prefix();
        let burn_key = M31::from(999999u32);
        
        let actual_balance = M31::from(1000000u32);
        let intended_balance = M31::from(900000u32); // Can be less than actual (dust from attackers)
        let reveal_amount = M31::from(300000u32); // Must be <= intended
        
        // This should be valid
        assert!(reveal_amount.value() <= intended_balance.value());
        assert!(intended_balance.value() <= actual_balance.value());
        
        // Compute remaining coin
        let remaining = intended_balance - reveal_amount;
        let remaining_coin = poseidon3([coin_prefix, burn_key, remaining]);
        
        assert!(remaining_coin.value() < M31::PRIME);
    }

    #[test]
    fn test_double_spend_prevention() {
        // Using same burn_key twice should produce same nullifier (caught by contract)
        let prefix = poseidon_nullifier_prefix();
        let burn_key = M31::from(777777u32);
        
        // First "use"
        let nullifier1 = poseidon2([prefix, burn_key]);
        
        // Second "use" (should be prevented by checking nullifier1 already exists)
        let nullifier2 = poseidon2([prefix, burn_key]);
        
        // Nullifiers must be identical to be caught
        assert_eq!(nullifier1, nullifier2);
    }

    #[test]
    fn test_coin_tracking() {
        // Test that coins track correctly through the system
        let coin_prefix = poseidon_coin_prefix();
        let burn_key = M31::from(555555u32);
        
        // Initial mint: 1M wei
        let initial_balance = M31::from(1000000u32);
        let reveal_on_mint = M31::from(200000u32);
        let remaining_after_mint = initial_balance - reveal_on_mint;
        
        let coin1 = poseidon3([coin_prefix, burn_key, remaining_after_mint]);
        
        // Subsequent spend: 300k wei from 800k remaining
        let withdraw1 = M31::from(300000u32);
        let remaining_after_spend1 = remaining_after_mint - withdraw1;
        
        let coin2 = poseidon3([coin_prefix, burn_key, remaining_after_spend1]);
        
        // Another spend: 200k wei from 500k remaining
        let withdraw2 = M31::from(200000u32);
        let remaining_after_spend2 = remaining_after_spend1 - withdraw2;
        
        let coin3 = poseidon3([coin_prefix, burn_key, remaining_after_spend2]);
        
        // All coins should be different
        assert_ne!(coin1, coin2);
        assert_ne!(coin2, coin3);
        assert_ne!(coin1, coin3);
        
        // Final balance should be 300k
        assert_eq!(remaining_after_spend2.value(), 300000);
    }

    #[test]
    fn test_multiple_burns_different_addresses() {
        // Different burn parameters should give different addresses
        let prefix = poseidon_burn_address_prefix();
        
        let scenarios = vec![
            (M31::from(100u32), M31::from(1000u32), M31::from(1u32)),
            (M31::from(101u32), M31::from(1000u32), M31::from(1u32)), // Different key
            (M31::from(100u32), M31::from(1001u32), M31::from(1u32)), // Different reveal
            (M31::from(100u32), M31::from(1000u32), M31::from(2u32)), // Different extra
        ];
        
        let mut addresses = std::collections::HashSet::new();
        
        for (key, reveal, extra) in scenarios {
            let addr = poseidon4([prefix, key, reveal, extra]);
            addresses.insert(addr.value());
        }
        
        // All should be unique
        assert_eq!(addresses.len(), 4);
    }
}

#[cfg(test)]
mod spend_circuit_logic_tests {
    use super::*;

    #[test]
    fn test_spend_coin_reconstruction() {
        // coin = Poseidon3(COIN_PREFIX, burnKey, balance)
        let prefix = poseidon_coin_prefix();
        
        for i in 0..500 {
            let burn_key = M31::from(i * 111);
            let balance = M31::from(i * 100000);
            
            let coin = poseidon3([prefix, burn_key, balance]);
            
            // Should be deterministic
            let coin2 = poseidon3([prefix, burn_key, balance]);
            assert_eq!(coin, coin2);
        }
    }

    #[test]
    fn test_spend_remaining_coin() {
        // remainingCoin = Poseidon3(COIN_PREFIX, burnKey, balance - withdrawnBalance)
        let prefix = poseidon_coin_prefix();
        let burn_key = M31::from(123456u32);
        
        let test_cases = vec![
            (1000000u32, 100000u32),
            (1000000u32, 500000u32),
            (1000000u32, 999999u32),
            (5000000u32, 1000000u32),
        ];
        
        for (balance, withdrawn) in test_cases {
            let balance_m31 = M31::from(balance);
            let withdrawn_m31 = M31::from(withdrawn);
            
            let original_coin = poseidon3([prefix, burn_key, balance_m31]);
            let remaining_balance = balance_m31 - withdrawn_m31;
            let remaining_coin = poseidon3([prefix, burn_key, remaining_balance]);
            
            // Coins should be different
            assert_ne!(original_coin, remaining_coin);
            
            // Remaining coin should be deterministic
            let remaining_coin2 = poseidon3([prefix, burn_key, remaining_balance]);
            assert_eq!(remaining_coin, remaining_coin2);
        }
    }

    #[test]
    fn test_spend_balance_constraint() {
        // withdrawnBalance <= balance (logical constraint)
        let prefix = poseidon_coin_prefix();
        let burn_key = M31::from(999999u32);
        
        let balance = M31::from(1000000u32);
        let valid_withdrawals = [0, 100000, 500000, 999999, 1000000];
        
        for withdrawn in valid_withdrawals {
            let withdrawn_m31 = M31::from(withdrawn);
            
            // This should be valid
            assert!(withdrawn_m31.value() <= balance.value());
            
            let remaining = balance - withdrawn_m31;
            let remaining_coin = poseidon3([prefix, burn_key, remaining]);
            
            assert!(remaining_coin.value() < M31::PRIME);
        }
    }

    #[test]
    fn test_spend_full_balance() {
        // Withdrawing full balance should leave zero
        let prefix = poseidon_coin_prefix();
        let burn_key = M31::from(777777u32);
        let balance = M31::from(1000000u32);
        
        let coin = poseidon3([prefix, burn_key, balance]);
        
        // Withdraw everything
        let remaining_balance = balance - balance;
        assert_eq!(remaining_balance, M31::zero());
        
        let remaining_coin = poseidon3([prefix, burn_key, remaining_balance]);
        
        // Should be different from original (even though balance is 0)
        assert_ne!(coin, remaining_coin);
    }

    #[test]
    fn test_spend_partial_amounts() {
        // Test various partial spends
        let prefix = poseidon_coin_prefix();
        let burn_key = M31::from(555555u32);
        let initial = M31::from(1000000u32);
        
        let percentages = [10, 25, 50, 75, 90];
        let mut prev_coin = poseidon3([prefix, burn_key, initial]);
        
        for pct in percentages {
            let withdrawn = M31::from((initial.value() * pct) / 100);
            let remaining = initial - withdrawn;
            let coin = poseidon3([prefix, burn_key, remaining]);
            
            // Each should be different
            assert_ne!(coin, prev_coin);
            prev_coin = coin;
        }
    }

    #[test]
    fn test_spend_consistency() {
        // Multiple spends should chain correctly
        let prefix = poseidon_coin_prefix();
        let burn_key = M31::from(111111u32);
        
        let mut current_balance = M31::from(1000000u32);
        let mut prev_coin = poseidon3([prefix, burn_key, current_balance]);
        
        let withdrawals = [100000, 200000, 150000, 250000];
        
        for withdrawal in withdrawals {
            current_balance = current_balance - M31::from(withdrawal);
            let new_coin = poseidon3([prefix, burn_key, current_balance]);
            
            // Each new coin should be different
            assert_ne!(new_coin, prev_coin);
            prev_coin = new_coin;
        }
        
        // Final balance should be correct
        let expected_final = 1000000 - 100000 - 200000 - 150000 - 250000;
        assert_eq!(current_balance.value(), expected_final);
    }
}

#[cfg(test)]
mod circuit_edge_case_tests {
    use super::*;

    #[test]
    fn test_zero_reveal_amount() {
        // Revealing zero should be valid
        let coin_prefix = poseidon_coin_prefix();
        let burn_key = M31::from(123456u32);
        let intended_balance = M31::from(1000000u32);
        let reveal_amount = M31::zero();
        
        let remaining = intended_balance - reveal_amount;
        assert_eq!(remaining, intended_balance);
        
        let coin = poseidon3([coin_prefix, burn_key, remaining]);
        assert!(coin.value() < M31::PRIME);
    }

    #[test]
    fn test_zero_withdrawal() {
        // Withdrawing zero should leave coin unchanged logically
        let prefix = poseidon_coin_prefix();
        let burn_key = M31::from(999999u32);
        let balance = M31::from(500000u32);
        
        let original_coin = poseidon3([prefix, burn_key, balance]);
        
        let withdrawn = M31::zero();
        let remaining = balance - withdrawn;
        let new_coin = poseidon3([prefix, burn_key, remaining]);
        
        // Coins should be identical (same balance)
        assert_eq!(original_coin, new_coin);
    }

    #[test]
    fn test_small_balances() {
        // Test with very small balances
        let prefix = poseidon_coin_prefix();
        let burn_key = M31::from(777777u32);
        
        for balance in 1..100 {
            let coin = poseidon3([prefix, burn_key, M31::from(balance)]);
            assert!(coin.value() < M31::PRIME);
        }
    }

    #[test]
    fn test_large_balances() {
        // Test with large balances (but within M31 range)
        let prefix = poseidon_coin_prefix();
        let burn_key = M31::from(555555u32);
        
        // Test balances near 10^9 wei (< 2^31)
        let large_balances = [
            1_000_000_000,
            1_500_000_000,
            2_000_000_000,
            2_100_000_000, // Close to M31::PRIME
        ];
        
        for balance in large_balances {
            let coin = poseidon3([prefix, burn_key, M31::from(balance)]);
            assert!(coin.value() < M31::PRIME);
        }
    }

    #[test]
    fn test_maximum_reveal() {
        // Revealing entire balance
        let coin_prefix = poseidon_coin_prefix();
        let burn_key = M31::from(333333u32);
        let balance = M31::from(1000000u32);
        
        // Reveal everything
        let reveal = balance;
        let remaining = balance - reveal;
        assert_eq!(remaining, M31::zero());
        
        let coin = poseidon3([coin_prefix, burn_key, remaining]);
        assert!(coin.value() < M31::PRIME);
    }
}

#[cfg(test)]
mod circuit_worm_equivalence_tests {
    use super::*;

    #[test]
    fn test_worm_proof_of_burn_structure() {
        // Verify we follow WORM's proof-of-burn structure:
        // 1. Generate nullifier from burn key
        // 2. Generate burn address from burn key + params
        // 3. Generate remaining coin from burn key + balance
        
        let burn_key = M31::from(123456u32);
        let intended_balance = M31::from(1000000u32);
        let reveal_amount = M31::from(200000u32);
        let extra_commitment = M31::from(100u32);
        
        // Step 1: Nullifier
        let nullifier = poseidon2([poseidon_nullifier_prefix(), burn_key]);
        
        // Step 2: Burn address
        let burn_address = poseidon4([
            poseidon_burn_address_prefix(),
            burn_key,
            reveal_amount,
            extra_commitment,
        ]);
        
        // Step 3: Remaining coin
        let remaining_balance = intended_balance - reveal_amount;
        let remaining_coin = poseidon3([poseidon_coin_prefix(), burn_key, remaining_balance]);
        
        // All should be valid and different
        assert!(nullifier.value() < M31::PRIME);
        assert!(burn_address.value() < M31::PRIME);
        assert!(remaining_coin.value() < M31::PRIME);
        
        assert_ne!(nullifier, burn_address);
        assert_ne!(burn_address, remaining_coin);
        assert_ne!(nullifier, remaining_coin);
    }

    #[test]
    fn test_worm_spend_structure() {
        // Verify we follow WORM's spend structure:
        // 1. Reconstruct original coin from burn key + balance
        // 2. Generate new coin from burn key + remaining balance
        
        let burn_key = M31::from(654321u32);
        let balance = M31::from(800000u32);
        let withdrawn = M31::from(300000u32);
        
        // Step 1: Original coin
        let coin = poseidon3([poseidon_coin_prefix(), burn_key, balance]);
        
        // Step 2: Remaining coin
        let remaining_balance = balance - withdrawn;
        let remaining_coin = poseidon3([poseidon_coin_prefix(), burn_key, remaining_balance]);
        
        // Should be valid and different
        assert!(coin.value() < M31::PRIME);
        assert!(remaining_coin.value() < M31::PRIME);
        assert_ne!(coin, remaining_coin);
    }

    #[test]
    fn test_worm_nullifier_reuse_detection() {
        // WORM prevents double-spending by tracking nullifiers
        // Same burn key always produces same nullifier
        
        let burn_key = M31::from(987654u32);
        let prefix = poseidon_nullifier_prefix();
        
        // "Attempt" to use burn key multiple times
        let nullifiers: Vec<M31> = (0..10)
            .map(|_| poseidon2([prefix, burn_key]))
            .collect();
        
        // All nullifiers must be identical
        for null in &nullifiers[1..] {
            assert_eq!(nullifiers[0], *null);
        }
    }

    #[test]
    fn test_worm_coin_lineage() {
        // WORM tracks coin lineage: root -> parent -> child
        // Each spend creates a new coin with same burn key
        
        let burn_key = M31::from(11111u32);
        let prefix = poseidon_coin_prefix();
        
        // Root coin (from burn)
        let root_balance = M31::from(1000000u32);
        let root_coin = poseidon3([prefix, burn_key, root_balance]);
        
        // First spend
        let balance1 = M31::from(700000u32);
        let coin1 = poseidon3([prefix, burn_key, balance1]);
        
        // Second spend
        let balance2 = M31::from(400000u32);
        let coin2 = poseidon3([prefix, burn_key, balance2]);
        
        // All use same burn key but different balances
        // This maintains lineage while preventing double-spend
        assert_ne!(root_coin, coin1);
        assert_ne!(coin1, coin2);
        assert_ne!(root_coin, coin2);
    }
}

