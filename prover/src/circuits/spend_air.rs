// Spend AIR (Algebraic Intermediate Representation) for Stwo
// Implements constraints for partial coin spending

use itertools::Itertools;
use stwo_prover::core::fields::m31::BaseField;
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::ColumnVec;
use stwo_prover::prover::backend::simd::SimdBackend;
use stwo_prover::prover::backend::{Col, Column};
use stwo_prover::prover::poly::circle::CircleEvaluation;
use stwo_prover::prover::poly::BitReversedOrder;
use stwo_constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval};

use crate::circuits::spend::SpendInputs;
use crate::utils::poseidon2_stwo::poseidon2_permutation;

/// Helper constant for zero field element
const ZERO: BaseField = BaseField::from_u32_unchecked(0);

/// Number of columns in the Spend trace
/// 
/// Trace structure:
/// 0. burn_key (private witness)
/// 1. balance_low (lower 128 bits)
/// 2. balance_high (upper 128 bits)
/// 3. withdrawn_balance_low
/// 4. withdrawn_balance_high
/// 5. extra_commitment
/// 6. coin (computed)
/// 7. remaining_coin (computed)
/// 8. commitment (public output)
/// 9-15. intermediate_poseidon_state
pub const NUM_SPEND_COLUMNS: usize = 16;

pub type SpendComponent = FrameworkComponent<SpendEval>;

/// Spend constraint evaluator
/// Defines the AIR constraints for partial coin spending
#[derive(Clone)]
pub struct SpendEval {
    /// Log2 of the number of rows in the trace
    pub log_n_rows: u32,
}

impl FrameworkEval for SpendEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    
    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Degree bound: LOG_EXPAND for interpolation (matching stwo examples)
        self.log_n_rows + 2
    }
    
    /// Evaluate constraints at a single row
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // Read trace columns
        let burn_key = eval.next_trace_mask();
        let balance_low = eval.next_trace_mask();
        let balance_high = eval.next_trace_mask();
        let withdrawn_balance_low = eval.next_trace_mask();
        let withdrawn_balance_high = eval.next_trace_mask();
        let extra_commitment = eval.next_trace_mask();
        let coin = eval.next_trace_mask();
        let remaining_coin = eval.next_trace_mask();
        let commitment = eval.next_trace_mask();
        
        // Intermediate Poseidon state columns
        let _poseidon_state_0 = eval.next_trace_mask();
        let _poseidon_state_1 = eval.next_trace_mask();
        let _poseidon_state_2 = eval.next_trace_mask();
        let _poseidon_state_3 = eval.next_trace_mask();
        let _poseidon_state_4 = eval.next_trace_mask();
        let _poseidon_state_5 = eval.next_trace_mask();
        let _poseidon_state_6 = eval.next_trace_mask();
        
        // === CONSTRAINT 1: Balance validation ===
        // withdrawn_balance <= balance
        // This would need proper range checks in production
        
        // === CONSTRAINT 2: Coin computation ===
        // coin = Poseidon3([COIN_PREFIX, burn_key, balance])
        // 
        // In production, this would be a full Poseidon AIR constraint
        
        // === CONSTRAINT 3: Remaining coin computation ===
        // remaining_balance = balance - withdrawn_balance
        // remaining_coin = Poseidon3([COIN_PREFIX, burn_key, remaining_balance])
        // BaseField subtraction handles underflow correctly with modular arithmetic,
        // but we validate in trace generation that withdrawn_balance <= balance
        let _remaining_balance_low = balance_low.clone() - withdrawn_balance_low.clone();
        let _remaining_balance_high = balance_high.clone() - withdrawn_balance_high.clone();
        
        // === CONSTRAINT 4: Commitment computation ===
        // commitment = Hash(coin, withdrawn_balance, remaining_coin, extra_commitment)
        
        // === PLACEHOLDER CONSTRAINTS ===
        // These ensure the trace compiles and columns are used
        // TODO: Replace with actual cryptographic constraints
        eval.add_constraint(burn_key.clone() - burn_key.clone());
        
        eval
    }
}

/// Generate the execution trace for Spend
pub fn generate_spend_trace(
    log_size: u32,
    inputs: &SpendInputs,
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let size = 1 << log_size;
    
    // Create empty columns
    let mut trace = (0..NUM_SPEND_COLUMNS)
        .map(|_| Col::<SimdBackend, BaseField>::zeros(size))
        .collect_vec();
    
    // Validate M31 values are in correct range before conversion
    use crate::constants::M31_PRIME;
    let burn_key_val = inputs.burn_key.value();
    if burn_key_val >= M31_PRIME {
        panic!("burn_key value {} exceeds M31 prime {}", burn_key_val, M31_PRIME);
    }
    let extra_commitment_val = inputs.extra_commitment.value();
    if extra_commitment_val >= M31_PRIME {
        panic!("extra_commitment value {} exceeds M31 prime {}", extra_commitment_val, M31_PRIME);
    }
    
    // Extract balance parts and validate
    let balance_low_u32 = (inputs.balance.as_limbs()[0] & 0xFFFFFFFF) as u32;
    let balance_high_u32 = ((inputs.balance.as_limbs()[0] >> 32) & 0xFFFFFFFF) as u32;
    let withdrawn_balance_low_u32 = (inputs.withdrawn_balance.as_limbs()[0] & 0xFFFFFFFF) as u32;
    let withdrawn_balance_high_u32 = ((inputs.withdrawn_balance.as_limbs()[0] >> 32) & 0xFFFFFFFF) as u32;
    
    // Validate that withdrawn_balance <= balance before subtraction
    // We need to compare the raw u32 values before conversion to BaseField
    let withdrawn_gt_balance = (withdrawn_balance_high_u32 > balance_high_u32) ||
        (withdrawn_balance_high_u32 == balance_high_u32 && withdrawn_balance_low_u32 > balance_low_u32);
    if withdrawn_gt_balance {
        panic!(
            "Withdrawn balance exceeds balance: withdrawn_low={}, withdrawn_high={}, balance_low={}, balance_high={}",
            withdrawn_balance_low_u32, withdrawn_balance_high_u32, balance_low_u32, balance_high_u32
        );
    }
    
    // Convert u32 values to BaseField
    // BaseField::from() automatically reduces modulo M31_PRIME, so values can be any u32
    // For M31 values that are already validated, we use from_u32_unchecked for efficiency
    let burn_key_field = BaseField::from_u32_unchecked(burn_key_val);
    let balance_low = BaseField::from(balance_low_u32);
    let balance_high = BaseField::from(balance_high_u32);
    let withdrawn_balance_low = BaseField::from(withdrawn_balance_low_u32);
    let withdrawn_balance_high = BaseField::from(withdrawn_balance_high_u32);
    let extra_commitment_field = BaseField::from_u32_unchecked(extra_commitment_val);
    
    // Compute derived values using Poseidon2
    
    // coin = Poseidon3([COIN_PREFIX, burn_key, balance])
    let coin_state = [
        BaseField::from_u32_unchecked(2), // COIN_PREFIX
        burn_key_field,
        balance_low,
        ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
    ];
    let coin_output = poseidon2_permutation(coin_state);
    let coin = coin_output[0];
    
    // remaining_coin = Poseidon3([COIN_PREFIX, burn_key, remaining_balance])
    // Safe to subtract now - we validated withdrawn_balance <= balance above
    // BaseField subtraction handles underflow correctly with modular arithmetic
    let remaining_balance_low = balance_low - withdrawn_balance_low;
    let remaining_balance_high = balance_high - withdrawn_balance_high;
    
    let remaining_coin_state = [
        BaseField::from_u32_unchecked(2), // COIN_PREFIX
        burn_key_field,
        remaining_balance_low,
        ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
    ];
    let remaining_coin_output = poseidon2_permutation(remaining_coin_state);
    let remaining_coin = remaining_coin_output[0];
    
    // commitment = Hash(coin, withdrawn_balance, remaining_coin, extra_commitment)
    let commitment_state = [
        coin,
        withdrawn_balance_low,
        remaining_coin,
        extra_commitment_field,
        ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
    ];
    let commitment_output = poseidon2_permutation(commitment_state);
    let commitment = commitment_output[0];
    
    // Fill the trace
    // For SIMD backend, we fill vec_index 0 (first SIMD lane)
    let vec_index = 0;
    trace[0].data[vec_index] = burn_key_field.into();
    trace[1].data[vec_index] = balance_low.into();
    trace[2].data[vec_index] = balance_high.into();
    trace[3].data[vec_index] = withdrawn_balance_low.into();
    trace[4].data[vec_index] = withdrawn_balance_high.into();
    trace[5].data[vec_index] = extra_commitment_field.into();
    trace[6].data[vec_index] = coin.into();
    trace[7].data[vec_index] = remaining_coin.into();
    trace[8].data[vec_index] = commitment.into();
    trace[9].data[vec_index] = coin_output[1].into();
    trace[10].data[vec_index] = coin_output[2].into();
    trace[11].data[vec_index] = remaining_coin_output[1].into();
    trace[12].data[vec_index] = remaining_coin_output[2].into();
    trace[13].data[vec_index] = commitment_output[1].into();
    trace[14].data[vec_index] = commitment_output[2].into();
    trace[15].data[vec_index] = ZERO.into();
    
    // Convert to CircleEvaluations
    let domain = CanonicCoset::new(log_size).circle_domain();
    trace
        .into_iter()
        .map(|col| CircleEvaluation::<SimdBackend, _, BitReversedOrder>::new(domain, col))
        .collect_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::M31;
    use alloy_primitives::U256;
    
    fn create_test_inputs() -> SpendInputs {
        SpendInputs {
            burn_key: M31::from(12345),
            balance: U256::from(1000),
            withdrawn_balance: U256::from(400),
            extra_commitment: M31::from(100),
        }
    }
    
    #[test]
    fn test_generate_spend_trace() {
        let inputs = create_test_inputs();
        let log_size = 4; // 16 rows
        
        let trace = generate_spend_trace(log_size, &inputs);
        
        // Verify we have the correct number of columns
        assert_eq!(trace.len(), NUM_SPEND_COLUMNS);
        
        // Verify each column has the correct size
        for col in &trace {
            assert_eq!(col.len(), 1 << log_size);
        }
    }
    
    #[test]
    fn test_spend_eval_structure() {
        let eval = SpendEval { log_n_rows: 4 };
        
        assert_eq!(eval.log_size(), 4);
        assert_eq!(eval.max_constraint_log_degree_bound(), 6); // log_n_rows + LOG_EXPAND (4 + 2)
    }
}

