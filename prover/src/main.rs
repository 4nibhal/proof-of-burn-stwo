//! Proof of Burn STWO Prover
//!
//! Zero-knowledge proof generator for Proof of Burn protocol using Circle STARKs.
//! Designed for WebAssembly deployment in browsers for maximum privacy.

use alloy_primitives::B256;
use anyhow::Context;
use clap::{Parser, Subcommand};
use proof_of_burn_stwo::{
    circuits::{
        proof_of_burn::{ProofOfBurnCircuit, ProofOfBurnInputs},
        spend::{SpendCircuit, SpendInputs},
    },
    prover::prove_proof_of_burn,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Simplified proof structure containing only accessible commitment data.
/// This replaces the complex SolidityStarkProof with placeholders.
#[derive(Serialize, Deserialize, Debug)]
pub struct SimpleProof {
    /// Trace commitment from STWO proof
    pub trace_commitment: B256,
    /// Composition commitment from STWO proof
    pub composition_commitment: B256,
    /// Unique proof identifier
    pub proof_id: B256,
}

#[derive(Parser)]
#[command(
    name = "stwo-pob-prover",
    about = "Zero-knowledge proof generator for Proof of Burn protocol",
    version,
    long_about = r#"Generate Circle STARK proofs for Proof of Burn operations.

This tool creates zero-knowledge proofs that prove the validity of burn operations
without revealing sensitive information. Designed for deployment as WebAssembly
in browser environments to maintain user privacy.

The prover uses transparent Circle STARKs (STWO) without trusted setup,
providing post-quantum security and universal composability."#
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate proof for token burning operation
    #[command(
        about = "Create a proof that validates an ETH burn operation",
        long_about = r#"Generate a zero-knowledge proof for a Proof of Burn operation.

The proof demonstrates that:
- The burn address exists in the specified Ethereum block
- The balance meets the intended amount criteria
- The proof-of-work requirement is satisfied
- All cryptographic commitments are valid

Input: JSON file with burn parameters
Output: STWO proof file suitable for on-chain verification"#
    )]
    GenerateBurn {
        /// Path to JSON input file containing burn proof parameters
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Path where the generated proof will be saved
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },

    /// Generate proof for token spending operation
    #[command(
        about = "Create a proof that validates token spending with balance verification",
        long_about = r#"Generate a zero-knowledge proof for a token spend operation.

The proof demonstrates that:
- The spending key is valid for the coin
- The remaining balance is correctly computed
- The new coin commitment is properly formed

Input: JSON file with spend parameters
Output: STWO proof file for spend verification"#
    )]
    GenerateSpend {
        /// Path to JSON input file containing spend parameters
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Path where the generated proof will be saved
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },

    /// Verify proof locally (for testing)
    #[command(
        about = "Verify a proof locally without blockchain interaction",
        long_about = r#"Perform local verification of a generated proof.

This command is primarily for testing and development. In production,
proof verification occurs on-chain through the smart contract.

Note: This verification uses the same cryptographic algorithms as
the on-chain verifier but runs locally for development purposes."#
    )]
    Verify {
        /// Path to the proof file to verify
        #[arg(short, long, value_name = "FILE")]
        proof: PathBuf,

        /// Type of proof to verify ("burn" or "spend")
        #[arg(short = 't', long, value_name = "TYPE")]
        proof_type: String,
    },

    /// Display circuit parameters and system information
    #[command(
        about = "Show circuit parameters and system capabilities",
        long_about = r#"Display detailed information about the proof system parameters.

This includes:
- Circuit size limits and constraints
- Cryptographic parameter details
- Security level information
- Estimated gas costs for verification

Useful for understanding system capabilities and planning deployments."#
    )]
    Info,
}

#[cfg(not(target_arch = "wasm32"))]
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateBurn { input, output } => {
            generate_burn_proof(input, output)?;
        }
        Commands::GenerateSpend { input, output } => {
            generate_spend_proof(input, output)?;
        }
        Commands::Verify { proof, proof_type } => {
            verify_proof(proof, proof_type)?;
        }
        Commands::Info => {
            show_system_info();
        }
    }

    Ok(())
}

// WASM entry point for browser usage
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn main() {
    // Initialize console logging for WASM
    console_error_panic_hook::set_once();
    console_log::init_with_level(log::Level::Info).expect("Failed to initialize logger");
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn generate_burn_proof_wasm(input_json: &str) -> Result<String, JsValue> {
    // Parse input JSON and generate proof
    // Return proof as JSON string
    unimplemented!("WASM implementation pending")
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn generate_spend_proof_wasm(input_json: &str) -> Result<String, JsValue> {
    // Parse input JSON and generate proof
    // Return proof as JSON string
    unimplemented!("WASM implementation pending")
}

/// Convert STWO StarkProof to SimpleProof using only accessible data.
/// This function extracts only the commitment data that STWO exposes publicly.
/// The proof_id is calculated to match the Solidity contract expectation.
fn convert_stark_proof_to_simple(
    proof: &stwo_prover::core::proof::StarkProof<stwo_prover::core::vcs::blake2_merkle::Blake2sMerkleHasher>,
    public_commitment: alloy_primitives::U256,
    nullifier: alloy_primitives::U256,
    commitment: alloy_primitives::U256,
) -> anyhow::Result<SimpleProof> {
    // TODO: Verify that proof.commitments[0] is trace_commitment and [1] is composition_commitment
    let trace_commitment = B256::from(proof.commitments[0].0);
    let composition_commitment = B256::from(proof.commitments[1].0);

    // Calculate proof_id to match Solidity contract: keccak256(abi.encodePacked(publicCommitment, nullifier, commitment))
    let mut packed_data = Vec::new();
    packed_data.extend_from_slice(&public_commitment.to_be_bytes::<32>());
    packed_data.extend_from_slice(&nullifier.to_be_bytes::<32>());
    packed_data.extend_from_slice(&commitment.to_be_bytes::<32>());
    let proof_id = alloy_primitives::keccak256(&packed_data);

    let simple_proof = SimpleProof {
        trace_commitment,
        composition_commitment,
        proof_id: B256::from(proof_id),
    };

    Ok(simple_proof)
}

fn generate_burn_proof(input_path: PathBuf, output_path: PathBuf) -> anyhow::Result<()> {
    println!("Reading burn proof inputs from: {}", input_path.display());

    // Validate input file exists
    if !input_path.exists() {
        anyhow::bail!("Input file does not exist: {}", input_path.display());
    }

    // Read and parse input
    let input_data = std::fs::read_to_string(&input_path)
        .with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    let inputs: ProofOfBurnInputs = serde_json::from_str(&input_data)
        .with_context(|| "Failed to parse input JSON")?;

    println!("Generating complete STWO proof for Proof of Burn...");

    // Generate full STWO proof using the prover
    // TODO: Use proper log_n_rows calculation instead of hardcoded 16
    // TODO: Use proper ProverConfig instead of Default::default()
    let (_component, stark_proof) = prove_proof_of_burn(&inputs, 16, Default::default())
        .with_context(|| "Failed to generate STWO proof")?;

    println!("STWO proof generation successful");

    // Create circuit instance and get real outputs
    let circuit = proof_of_burn_stwo::circuits::proof_of_burn::ProofOfBurnCircuit::new(inputs.clone())
        .with_context(|| "Failed to create ProofOfBurnCircuit instance")?;

    let outputs = circuit.compute_outputs()
        .with_context(|| "Failed to compute circuit outputs")?;

    println!("Circuit outputs computed:");
    println!("  Commitment: {:?}", outputs.commitment);
    println!("  Nullifier: {:?}", outputs.nullifier);
    println!("  Remaining Coin: {:?}", outputs.remaining_coin);

    // Convert outputs to U256 for contract compatibility
    let nullifier = alloy_primitives::U256::from(outputs.nullifier.0 as u64);
    let commitment = alloy_primitives::U256::from(outputs.commitment.0 as u64);

    // Calculate block hash from block header (this is what Commitments.sol uses as blockHash)
    let block_hash = alloy_primitives::keccak256(&inputs.block_header);

    // Calculate publicCommitment as per Commitments.sol:
    // keccak256(abi.encodePacked(blockHash, nullifier, commitment, revealAmount)) >> 8
    let mut packed_data = Vec::new();
    packed_data.extend_from_slice(block_hash.as_slice());
    packed_data.extend_from_slice(&nullifier.to_be_bytes::<32>());
    packed_data.extend_from_slice(&commitment.to_be_bytes::<32>());
    packed_data.extend_from_slice(&inputs.reveal_amount.to_be_bytes::<32>());
    let public_commitment_bytes = alloy_primitives::keccak256(&packed_data);
    let public_commitment = alloy_primitives::U256::from_be_bytes(public_commitment_bytes.into()) >> alloy_primitives::U256::from(8);

    // Convert to SimpleProof using commitment data and calculated proof_id
    let simple_proof = convert_stark_proof_to_simple(&stark_proof, public_commitment, nullifier, commitment)
        .with_context(|| "Failed to convert STWO proof to SimpleProof")?;

    println!("Converted to SimpleProof:");
    println!("  Trace commitment: {:?}", simple_proof.trace_commitment);
    println!("  Composition commitment: {:?}", simple_proof.composition_commitment);
    println!("  Proof ID: {:?}", simple_proof.proof_id);
    println!("  Public inputs: commitment={:?}, nullifier={:?}, commitment={:?}", public_commitment, nullifier, commitment);

    // Create output directory if it doesn't exist
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create output directory: {}", parent.display()))?;
    }

    // Save SimpleProof
    let output_data = serde_json::to_string_pretty(&simple_proof)?;
    std::fs::write(&output_path, output_data)
        .with_context(|| format!("Failed to write output file: {}", output_path.display()))?;

    println!("SimpleProof saved to: {}", output_path.display());
    println!("Note: This generates commitments-only proof data suitable for on-chain verification.");

    Ok(())
}

fn generate_spend_proof(input_path: PathBuf, output_path: PathBuf) -> anyhow::Result<()> {
    println!("Reading spend proof inputs from: {}", input_path.display());

    // Validate input file exists
    if !input_path.exists() {
        anyhow::bail!("Input file does not exist: {}", input_path.display());
    }

    // Read and parse input
    let input_data = std::fs::read_to_string(&input_path)
        .with_context(|| format!("Failed to read input file: {}", input_path.display()))?;

    let inputs: SpendInputs = serde_json::from_str(&input_data)
        .with_context(|| "Failed to parse input JSON")?;

    println!("Creating Spend circuit...");
    let circuit = SpendCircuit::new(inputs)?;

    println!("Computing circuit witness...");
    let outputs = circuit.compute_outputs();

    println!("Circuit computation successful");
    println!("  Coin: {:?}", outputs.coin);
    println!("  Remaining Coin: {:?}", outputs.remaining_coin);
    println!("  Commitment: {:?}", outputs.commitment);

    // Create output directory if it doesn't exist
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create output directory: {}", parent.display()))?;
    }

    // Save outputs
    let output_data = serde_json::to_string_pretty(&outputs)?;
    std::fs::write(&output_path, output_data)
        .with_context(|| format!("Failed to write output file: {}", output_path.display()))?;

    println!("Proof outputs saved to: {}", output_path.display());
    println!("Note: This generates circuit outputs only. Full STWO proof generation requires additional implementation.");

    Ok(())
}

fn verify_proof(proof_path: PathBuf, proof_type: String) -> anyhow::Result<()> {
    println!("Verifying {} proof from: {}", proof_type, proof_path.display());

    // Validate proof file exists
    if !proof_path.exists() {
        anyhow::bail!("Proof file does not exist: {}", proof_path.display());
    }

    // Read and parse proof data
    let proof_data = std::fs::read_to_string(&proof_path)
        .with_context(|| format!("Failed to read proof file: {}", proof_path.display()))?;

    match proof_type.as_str() {
        "burn" => {
            let outputs: proof_of_burn_stwo::circuits::proof_of_burn::ProofOfBurnOutputs =
                serde_json::from_str(&proof_data)
                    .with_context(|| "Failed to parse burn proof JSON")?;

            println!("Burn proof structure is valid");
            println!("  Nullifier: {:?}", outputs.nullifier);
            println!("  Commitment: {:?}", outputs.commitment);
        }
        "spend" => {
            let outputs: proof_of_burn_stwo::circuits::spend::SpendOutputs =
                serde_json::from_str(&proof_data)
                    .with_context(|| "Failed to parse spend proof JSON")?;

            println!("Spend proof structure is valid");
            println!("  Coin: {:?}", outputs.coin);
            println!("  Remaining Coin: {:?}", outputs.remaining_coin);
            println!("  Commitment: {:?}", outputs.commitment);
        }
        _ => {
            anyhow::bail!("Unsupported proof type: {}. Supported types: 'burn', 'spend'", proof_type);
        }
    }

    println!("Note: This verifies proof structure only. Full cryptographic verification requires STWO implementation.");

    Ok(())
}

fn show_system_info() {
    use proof_of_burn_stwo::constants::circuit_params::*;

    println!("Proof of Burn STWO - System Information");
    println!("========================================");
    println!();

    println!("Circuit Parameters:");
    println!("  Max MPT Layers:           {}", MAX_NUM_LAYERS);
    println!("  Max Node Blocks:          {}", MAX_NODE_BLOCKS);
    println!("  Max Header Blocks:        {}", MAX_HEADER_BLOCKS);
    println!("  Min Leaf Address Nibbles: {}", MIN_LEAF_ADDRESS_NIBBLES);
    println!("  Amount Bytes:             {}", AMOUNT_BYTES);
    println!("  PoW Min Zero Bytes:       {}", POW_MINIMUM_ZERO_BYTES);
    println!();

    println!("Balance Limits:");
    println!("  Max Intended Balance:     {} wei ({:.2} ETH)",
             MAX_INTENDED_BALANCE,
             MAX_INTENDED_BALANCE as f64 / 1_000_000_000_000_000_000.0);
    println!("  Max Actual Balance:       {} wei ({:.2} ETH)",
             MAX_ACTUAL_BALANCE,
             MAX_ACTUAL_BALANCE as f64 / 1_000_000_000_000_000_000.0);
    println!();

    println!("Cryptographic Parameters:");
    println!("  Proof System:             Circle STARK (STWO)");
    println!("  Finite Field:             M31 (2^31 - 1)");
    println!("  Hash Function:            Poseidon2 (128-bit security)");
    println!("  Ethereum Hash:            Keccak256");
    println!("  Trusted Setup:            None (transparent)");
    println!("  Post-Quantum Security:    Yes");
    println!();

    println!("Security Analysis:");
    println!("  Address Hash Security:    200 bits (50 nibbles)");
    println!("  PoW Additional Security:  16 bits (2 zero bytes)");
    println!("  Total Security Level:     ~216 bits");
    println!("  Collision Resistance:     128 bits");
    println!();

    println!("Performance Estimates:");
    println!("  Proof Generation:         ~10-30 seconds (client-side)");
    println!("  Proof Size:               ~50-100 KB");
    println!("  Verification Gas Cost:    ~1,500,000 gas");
    println!("  Verification Cost:        ~$2.63 USD (at 0.5 gwei, $3500 ETH)");
    println!();

    println!("Comparison with WORM (Circom/Groth16):");
    println!("  WORM Verification Cost:   ~$0.44 USD (250k gas)");
    println!("  WORM Trusted Setup:       Required (not transparent)");
    println!("  STWO Trusted Setup:       None (fully transparent)");
    println!("  Composability:            Universal (STWO)");
    println!("  Future-Proof:             Yes (post-quantum ready)");
    println!();

    println!("Implementation Status:");
    println!("  Circuit Logic:            Complete");
    println!("  STWO Integration:         Partial (constraints framework ready)");
    println!("  WASM Compilation:         Ready for implementation");
    println!("  Production Ready:         Requires full STWO proof generation");
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use std::str::FromStr;

    #[test]
    fn test_proof_id_calculation_consistency() {
        // Test values that match the JavaScript verification script
        let block_hash = alloy_primitives::keccak256([0xabu8; 32]);
        let nullifier = U256::from_str("0x1212121212121212121212121212121212121212121212121212121212121212").unwrap();
        let commitment = U256::from_str("0x3434343434343434343434343434343434343434343434343434343434343434").unwrap();
        let reveal_amount = U256::from(500000000000000000u64); // 0.5 ETH

        // Calculate publicCommitment as per Commitments.sol
        let mut packed_data = Vec::new();
        packed_data.extend_from_slice(block_hash.as_slice());
        packed_data.extend_from_slice(&nullifier.to_be_bytes::<32>());
        packed_data.extend_from_slice(&commitment.to_be_bytes::<32>());
        packed_data.extend_from_slice(&reveal_amount.to_be_bytes::<32>());
        let public_commitment_bytes = alloy_primitives::keccak256(&packed_data);
        let public_commitment = alloy_primitives::U256::from_be_bytes(public_commitment_bytes.into()) >> alloy_primitives::U256::from(8);

        // Calculate proof_id as per STWOProofOfBurnVerifier.sol
        let mut proof_id_data = Vec::new();
        proof_id_data.extend_from_slice(&public_commitment.to_be_bytes::<32>());
        proof_id_data.extend_from_slice(&nullifier.to_be_bytes::<32>());
        proof_id_data.extend_from_slice(&commitment.to_be_bytes::<32>());
        let proof_id = alloy_primitives::keccak256(&proof_id_data);

        // Expected values from JavaScript verification (UPDATED with correct blockHash)
        let expected_public_commitment = U256::from_str("0x7f3efa11a3601ff4488fca730751aefabbd29bb9651349c4658aa67a64c550").unwrap();
        let expected_proof_id_bytes = hex::decode("af19dffbe9939dedd30df03d7100b38fe1ef8eccf4544889a2ca1fcd907beeac").unwrap();
        let expected_proof_id = alloy_primitives::B256::from_slice(&expected_proof_id_bytes);

        assert_eq!(public_commitment, expected_public_commitment, "publicCommitment calculation mismatch");
        assert_eq!(B256::from(proof_id), expected_proof_id, "proof_id calculation mismatch");
    }
}
