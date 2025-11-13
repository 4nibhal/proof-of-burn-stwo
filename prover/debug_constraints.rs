use proof_of_burn_stwo::circuits::proof_of_burn_air::*;
use proof_of_burn_stwo::circuits::ProofOfBurnInputs;
use proof_of_burn_stwo::M31;
use alloy_primitives::U256;
use stwo_constraint_framework::assert_constraints;

fn main() {
    let inputs = ProofOfBurnInputs {
        burn_key: M31::from(12345),
        actual_balance: U256::from(1000000000000000000u64),
        intended_balance: U256::from(1000000000000000000u64),
        reveal_amount: U256::from(500000000000000000u64),
        burn_extra_commitment: M31::from(100),
        layers: vec![vec![0u8; 100], vec![0u8; 80]],
        block_header: vec![0u8; 643],
        num_leaf_address_nibbles: 50,
        byte_security_relax: 0,
        proof_extra_commitment: M31::from(200),
    };
    
    let log_size = 4;
    let (trace, lookup_data) = generate_pob_trace(log_size, &inputs);
    
    println!("Trace columns: {}", trace.len());
    println!("Lookup data nullifier initial[0]: {:?}", lookup_data.nullifier_initial[0].data[0]);
    println!("Lookup data nullifier final[0]: {:?}", lookup_data.nullifier_final[0].data[0]);
    
    // Test constraints
    let result = assert_constraints(
        &ProofOfBurnEval {
            log_n_rows: log_size,
            nullifier_lookup: NullifierElements::dummy(),
            remaining_coin_lookup: RemainingCoinElements::dummy(),
            commitment_lookup: CommitmentElements::dummy(),
            claimed_sum: stwo_prover::core::fields::qm31::SecureField::from_u32_unchecked(0, 0, 0, 0),
        },
        &trace,
    );
    
    match result {
        Ok(_) => println!("All constraints satisfied!"),
        Err(e) => {
            println!("Constraints failed: {}", e);
            // Print more details about the trace values
            println!("Trace values (first few):");
            for (i, col) in trace.iter().enumerate() {
                println!("  Column {}: {:?}", i, col.data.iter().take(3).collect::<Vec<_>>());
            }
        }
    }
}
