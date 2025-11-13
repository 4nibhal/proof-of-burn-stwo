// Proof of Burn with Stwo (Circle STARKs)
// Fork of WORM protocol replacing Groth16 with transparent STARK proofs

pub mod field;
pub mod constants;
pub mod utils;
pub mod circuits;
pub mod prover;

// Re-export commonly used types
pub use field::M31;
pub use constants::*;

// Re-export prover functions
pub use prover::{
    prove_proof_of_burn, verify_proof_of_burn,
    prove_spend, verify_spend,
    StarkConfig,
};

