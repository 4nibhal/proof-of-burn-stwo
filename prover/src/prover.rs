// Stwo Prover and Verifier for Proof of Burn circuits
// Implements the full Circle STARK proving protocol

use stwo_prover::core::air::Component;
use stwo_prover::core::channel::Blake2sChannel;
use stwo_prover::core::fields::m31::M31;
use stwo_prover::core::fields::qm31::SecureField;
use stwo_prover::core::fri::FriConfig;
use stwo_prover::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::proof::StarkProof;
use stwo_prover::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_prover::core::verifier::{verify, VerificationError};
use stwo_prover::prover::backend::simd::SimdBackend;
use stwo_prover::prover::poly::circle::PolyOps;
use stwo_prover::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::TraceLocationAllocator;

use crate::circuits::proof_of_burn::ProofOfBurnInputs;
use crate::circuits::proof_of_burn_air::{
    generate_pob_trace, gen_interaction_trace, ProofOfBurnComponent, ProofOfBurnEval,
    NullifierElements, RemainingCoinElements, CommitmentElements,
};
use crate::circuits::spend::SpendInputs;
use crate::circuits::spend_air::{generate_spend_trace, SpendComponent, SpendEval};

/// Log expansion factor for constraints
/// Used for interpolation degree bound in proofs
const LOG_EXPAND: u32 = 2;

/// Configuration for STARK proofs
#[derive(Clone)]
pub struct StarkConfig {
    /// Number of proof-of-work bits for security
    pub pow_bits: u32,
    
    /// FRI configuration
    pub fri_config: FriConfig,
}

impl Default for StarkConfig {
    fn default() -> Self {
        Self {
            pow_bits: 10, // ~1024 iterations required
            fri_config: FriConfig::new(
                2,  // log_last_layer_degree_bound (must be low enough to work with small traces)
                1,  // log_blowup_factor (2x blowup)
                64, // n_queries (security parameter)
            ),
        }
    }
}

impl From<StarkConfig> for PcsConfig {
    fn from(config: StarkConfig) -> Self {
        PcsConfig {
            pow_bits: config.pow_bits,
            fri_config: config.fri_config,
        }
    }
}

/// Prove a Proof of Burn statement using Circle STARKs
/// 
/// # Arguments
/// * `inputs` - The witness data for the proof
/// * `log_n_rows` - Log2 of the number of rows in the execution trace
/// * `config` - STARK configuration parameters
/// 
/// # Returns
/// * STARK proof and the component used for verification
pub fn prove_proof_of_burn(
    inputs: &ProofOfBurnInputs,
    log_n_rows: u32,
    config: StarkConfig,
) -> Result<(ProofOfBurnComponent, StarkProof<Blake2sMerkleHasher>), anyhow::Error> {
    // Validate log_n_rows
    const MIN_LOG_SIZE: u32 = 4; // Minimum 16 rows
    const MAX_LOG_SIZE: u32 = 20; // Maximum ~1M rows
    
    if log_n_rows < MIN_LOG_SIZE || log_n_rows > MAX_LOG_SIZE {
        anyhow::bail!(
            "log_n_rows must be between {} and {}, got {}",
            MIN_LOG_SIZE,
            MAX_LOG_SIZE,
            log_n_rows
        );
    }
    
    let pcs_config: PcsConfig = config.into();
    
    // === Phase 1: Precompute twiddles for FFT operations ===
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_n_rows + LOG_EXPAND + pcs_config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    
    // === Phase 2: Setup Fiat-Shamir channel ===
    let channel = &mut Blake2sChannel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<_, Blake2sMerkleChannel>::new(pcs_config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();
    
    // === Phase 3: Commit preprocessed trace (empty for PoB) ===
    let tree_builder = commitment_scheme.tree_builder();
    tree_builder.commit(channel);
    
    // === Phase 4: Generate and commit main execution trace ===
    let (trace, lookup_data) = generate_pob_trace(log_n_rows, inputs)
        .map_err(|e| anyhow::anyhow!("Trace generation failed: {}", e))?;
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(channel);
    
    // === Phase 5: Generate lookup elements (random challenges from verifier) ===
    let nullifier_lookup = NullifierElements::draw(channel);
    let remaining_coin_lookup = RemainingCoinElements::draw(channel);
    let commitment_lookup = CommitmentElements::draw(channel);
    
    // === Phase 6: Generate and commit interaction trace (logup for Poseidon2 verification) ===
    let (interaction_trace, claimed_sum) = gen_interaction_trace(
        log_n_rows,
        lookup_data,
        &nullifier_lookup,
        &remaining_coin_lookup,
        &commitment_lookup,
    );
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(interaction_trace);
    tree_builder.commit(channel);
    
    // === Phase 7: Create component with claimed sum and lookup elements ===
    let component = ProofOfBurnComponent::new(
        &mut TraceLocationAllocator::default(),
        ProofOfBurnEval {
            log_n_rows,
            nullifier_lookup,
            remaining_coin_lookup,
            commitment_lookup,
            claimed_sum,
        },
        claimed_sum,
    );
    
    // === Phase 8: Generate the STARK proof ===
    let stark_proof = prove(&[&component], channel, commitment_scheme)?;
    
    Ok((component, stark_proof))
}

/// Verify a Proof of Burn STARK proof
/// 
/// # Arguments
/// * `component` - The component used to generate the proof
/// * `proof` - The STARK proof to verify
/// 
/// # Returns
/// * Ok(()) if verification succeeds, Err otherwise
pub fn verify_proof_of_burn(
    component: &ProofOfBurnComponent,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<(), VerificationError> {
    // Setup verifier channel
    let channel = &mut Blake2sChannel::default();
    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(proof.config);
    
    // Replay the commitment phase
    // This must match the prover's commitment order exactly
    
    // Retrieve the expected column sizes in each commitment interaction, from the AIR
    let sizes = component.trace_log_degree_bounds();
    
    // Preprocessed trace (empty for us)
    commitment_scheme.commit(proof.commitments[0], &sizes[0], channel);
    
    // Main trace
    commitment_scheme.commit(proof.commitments[1], &sizes[1], channel);
    
    // Draw lookup elements (must match prover's order)
    let _nullifier_lookup = NullifierElements::draw(channel);
    let _remaining_coin_lookup = RemainingCoinElements::draw(channel);
    let _commitment_lookup = CommitmentElements::draw(channel);
    
    // Interaction trace
    commitment_scheme.commit(proof.commitments[2], &sizes[2], channel);
    
    // Verify the proof
    verify(&[component], channel, &mut commitment_scheme, proof)
}

/// Prove a Spend statement using Circle STARKs
pub fn prove_spend(
    inputs: &SpendInputs,
    log_n_rows: u32,
    config: StarkConfig,
) -> Result<(SpendComponent, StarkProof<Blake2sMerkleHasher>), anyhow::Error> {
    const MIN_LOG_SIZE: u32 = 4;
    const MAX_LOG_SIZE: u32 = 20;
    
    if log_n_rows < MIN_LOG_SIZE || log_n_rows > MAX_LOG_SIZE {
        anyhow::bail!(
            "log_n_rows must be between {} and {}, got {}",
            MIN_LOG_SIZE,
            MAX_LOG_SIZE,
            log_n_rows
        );
    }
    
    let pcs_config: PcsConfig = config.into();
    
    // === Phase 1: Precompute twiddles ===
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_n_rows + LOG_EXPAND + pcs_config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    
    // === Phase 2: Setup channel ===
    let channel = &mut Blake2sChannel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<_, Blake2sMerkleChannel>::new(pcs_config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();
    
    // === Phase 3: Commit preprocessed trace (empty) ===
    let tree_builder = commitment_scheme.tree_builder();
    tree_builder.commit(channel);
    
    // === Phase 4: Generate and commit main trace ===
    let trace = generate_spend_trace(log_n_rows, inputs);
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace);
    tree_builder.commit(channel);
    
    // === Phase 5: Create component AFTER commits ===
    let component = SpendComponent::new(
        &mut TraceLocationAllocator::default(),
        SpendEval { log_n_rows },
        SecureField::from_m31(M31::from_u32_unchecked(0), M31::from_u32_unchecked(0), M31::from_u32_unchecked(0), M31::from_u32_unchecked(0)),
    );
    
    // === Phase 6: Generate proof ===
    let stark_proof = prove(&[&component], channel, commitment_scheme)?;
    
    Ok((component, stark_proof))
}

/// Verify a Spend STARK proof
pub fn verify_spend(
    component: &SpendComponent,
    proof: StarkProof<Blake2sMerkleHasher>,
) -> Result<(), VerificationError> {
    let channel = &mut Blake2sChannel::default();
    let mut commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(proof.config);
    
    // Preprocessed trace (empty)
    commitment_scheme.commit(proof.commitments[0], &[], channel);
    
    // Main trace
    let trace_log_sizes = component.trace_log_degree_bounds();
    commitment_scheme.commit(proof.commitments[1], &trace_log_sizes[1], channel);
    
    // Verify
    verify(&[component], channel, &mut commitment_scheme, proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::M31;
    use alloy_primitives::U256;
    
    fn create_test_pob_inputs() -> ProofOfBurnInputs {
        ProofOfBurnInputs {
            burn_key: M31::from(12345),
            // Use smaller values that fit within M31 after conversion
            actual_balance: U256::from(1000000u64),  // 1M instead of 1e18
            intended_balance: U256::from(1000000u64),
            reveal_amount: U256::from(500000u64),     // 500K instead of 5e17
            burn_extra_commitment: M31::from(100),
            layers: vec![vec![0u8; 100]],
            block_header: vec![0u8; 643],
            num_leaf_address_nibbles: 50,
            byte_security_relax: 0,
            proof_extra_commitment: M31::from(200),
        }
    }
    
    fn create_test_spend_inputs() -> SpendInputs {
        SpendInputs {
            burn_key: M31::from(12345),
            balance: U256::from(1000),
            withdrawn_balance: U256::from(400),
            extra_commitment: M31::from(100),
        }
    }
    
    #[test]
    fn test_prove_and_verify_pob() {
        let inputs = create_test_pob_inputs();
        let log_n_rows = 6; // 64 rows - safe minimum for twiddles
        let config = StarkConfig::default();
        
        // Generate proof
        let (component, proof) = prove_proof_of_burn(&inputs, log_n_rows, config)
            .expect("Failed to generate proof");
        
        // Verify proof
        let result = verify_proof_of_burn(&component, proof);
        assert!(result.is_ok(), "Verification failed: {:?}", result);
    }
    
    #[test]
    fn test_prove_and_verify_spend() {
        let inputs = create_test_spend_inputs();
        let log_n_rows = 6; // 64 rows - safe minimum for twiddles
        let config = StarkConfig::default();
        
        // Generate proof
        let (component, proof) = prove_spend(&inputs, log_n_rows, config)
            .expect("Failed to generate proof");
        
        // Verify proof
        let result = verify_spend(&component, proof);
        assert!(result.is_ok(), "Verification failed: {:?}", result);
    }
    
    #[test]
    fn test_invalid_log_n_rows() {
        let inputs = create_test_pob_inputs();
        let config = StarkConfig::default();
        
        // Too small
        let result = prove_proof_of_burn(&inputs, 2, config.clone());
        assert!(result.is_err());
        
        // Too large
        let result = prove_proof_of_burn(&inputs, 25, config);
        assert!(result.is_err());
    }
}

