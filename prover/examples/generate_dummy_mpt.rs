// Generate dummy MPT proof layers for testing
use proof_of_burn_stwo::circuits::proof_of_burn::ProofOfBurnInputs;
use proof_of_burn_stwo::utils::rlp::{Account, MptLeaf};
use proof_of_burn_stwo::utils::keccak::keccak256;
use proof_of_burn_stwo::utils::burn_address::compute_burn_address_hash;
use proof_of_burn_stwo::field::M31;
use alloy_primitives::U256;

fn main() {
    // Create inputs matching the JSON
    let burn_key = M31::from(12345);
    let reveal_amount = U256::from_str_radix("100000000000000000", 10).unwrap(); // 0.1 ETH
    let burn_extra_commitment = M31::from(67890);
    let actual_balance = U256::from_str_radix("1000000000000000000", 10).unwrap();

    // Compute burn address hash
    let address_hash = compute_burn_address_hash(burn_key, reveal_amount, burn_extra_commitment);
    
    // Create account
    let account = Account::new_burn_account(actual_balance);
    let account_rlp = account.encode_to_vec();
    
    // Create leaf with address nibbles (50 nibbles = 25 bytes)
    let address_nibbles = vec![0u8; 50]; // Dummy nibbles
    let leaf = MptLeaf::new_account_leaf(&address_nibbles, &account);
    let layer1 = leaf.encode_to_vec();
    
    // Calculate hash of layer1
    let layer1_hash = keccak256(&layer1);
    
    // Create layer0 that contains layer1_hash
    // For a branch node, we'll embed the hash
    let mut layer0 = vec![0u8; 100];
    // Embed hash at the beginning (simplified MPT branch node)
    layer0[0..32].copy_from_slice(&layer1_hash);
    
    // Calculate hash of layer0
    let layer0_hash = keccak256(&layer0);
    
    // Create block header with state_root at offset 91
    let mut block_header = vec![0u8; 643];
    block_header[91..91+32].copy_from_slice(&layer0_hash);
    
    println!("Layer0 hash (state_root): {:?}", layer0_hash);
    println!("Layer1 hash: {:?}", layer1_hash);
    println!("Layer0 length: {}", layer0.len());
    println!("Layer1 length: {}", layer1.len());
    println!("Account RLP length: {}", account_rlp.len());
    
    // Output JSON format
    println!("\nJSON layers:");
    println!("  \"layers\": [");
    print!("    [");
    for (i, byte) in layer0.iter().enumerate() {
        if i > 0 { print!(", "); }
        if i % 20 == 0 && i > 0 { print!("\n     "); }
        print!("{}", byte);
    }
    println!("],");
    print!("    [");
    for (i, byte) in layer1.iter().enumerate() {
        if i > 0 { print!(", "); }
        if i % 20 == 0 && i > 0 { print!("\n     "); }
        print!("{}", byte);
    }
    println!("]");
    println!("  ],");
    print!("  \"block_header\": [");
    for (i, byte) in block_header.iter().enumerate() {
        if i > 0 { print!(", "); }
        if i % 20 == 0 && i > 0 { print!("\n    "); }
        print!("{}", byte);
    }
    println!("]");
}

