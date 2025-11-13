// Circuit implementations

pub mod proof_of_burn;
pub mod spend;

// AIR (Algebraic Intermediate Representation) implementations for Stwo
pub mod proof_of_burn_air;
pub mod spend_air;

// Re-export main types
pub use proof_of_burn::{ProofOfBurnCircuit, ProofOfBurnInputs, ProofOfBurnOutputs, ProofOfBurnError};
pub use spend::{SpendCircuit, SpendInputs, SpendOutputs, SpendError};
pub use proof_of_burn_air::{
    ProofOfBurnComponent, ProofOfBurnEval, LookupData, NullifierElements, RemainingCoinElements,
    CommitmentElements, generate_pob_trace, gen_interaction_trace,
};
pub use spend_air::{SpendComponent, SpendEval, generate_spend_trace};

