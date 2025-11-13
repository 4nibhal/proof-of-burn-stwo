// RLP encoding utilities for Ethereum data structures
// Reference: proof-of-burn/circuits/utils/rlp/

use alloy_primitives::U256;
use alloy_rlp::{Encodable, BufMut};

/// Ethereum account state
/// RLP encoding: [nonce, balance, storage_root, code_hash]
#[derive(Debug, Clone)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

impl Encodable for Account {
    fn encode(&self, out: &mut dyn BufMut) {
        // Calculate total length first
        let payload_length = self.nonce.length() + 
                           self.balance.length() + 
                           self.storage_root.as_slice().length() + 
                           self.code_hash.as_slice().length();
        
        // Encode list header
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(out);
        
        // Encode fields
        self.nonce.encode(out);
        self.balance.encode(out);
        self.storage_root.as_slice().encode(out);
        self.code_hash.as_slice().encode(out);
    }
    
    fn length(&self) -> usize {
        let payload_length = self.nonce.length() + 
                           self.balance.length() + 
                           self.storage_root.as_slice().length() + 
                           self.code_hash.as_slice().length();
        
        payload_length + alloy_rlp::length_of_length(payload_length)
    }
}

impl Account {
    /// Create a new account with given balance
    /// Uses empty storage root and code hash for burn addresses
    pub fn new_burn_account(balance: U256) -> Self {
        Self {
            nonce: 0,
            balance,
            storage_root: crate::constants::circuit_params::EMPTY_STORAGE_ROOT,
            code_hash: crate::constants::circuit_params::EMPTY_CODE_HASH,
        }
    }
    
    /// Encode account to RLP bytes
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

/// MPT leaf node structure
/// RLP encoding: [key_nibbles, account_rlp]
#[derive(Debug, Clone)]
pub struct MptLeaf {
    pub key_nibbles: Vec<u8>,
    pub value: Vec<u8>,
}

impl MptLeaf {
    /// Create MPT leaf for an account
    pub fn new_account_leaf(address_hash_nibbles: &[u8], account: &Account) -> Self {
        Self {
            key_nibbles: address_hash_nibbles.to_vec(),
            value: account.encode_to_vec(),
        }
    }
    
    /// Encode MPT leaf to RLP
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        
        // MPT leaf encoding: [0x20 + nibbles, value]
        // The 0x20 prefix indicates this is a leaf node
        let mut key_with_prefix = vec![0x20];
        key_with_prefix.extend_from_slice(&self.key_nibbles);
        
        // Calculate payload length
        let payload_length = key_with_prefix.as_slice().length() + self.value.as_slice().length();
        
        // Encode list header
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(&mut buf);
        
        // Encode elements
        key_with_prefix.as_slice().encode(&mut buf);
        self.value.as_slice().encode(&mut buf);
        
        buf
    }
}

/// Convert address hash (32 bytes) to nibbles (64 nibbles, 4 bits each)
pub fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        nibbles.push(byte >> 4);        // High nibble
        nibbles.push(byte & 0x0F);      // Low nibble
    }
    nibbles
}

/// Convert nibbles back to bytes
pub fn nibbles_to_bytes(nibbles: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(nibbles.len() / 2);
    for chunk in nibbles.chunks(2) {
        if chunk.len() == 2 {
            bytes.push((chunk[0] << 4) | chunk[1]);
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_account_encoding() {
        let account = Account::new_burn_account(U256::from(1000000000000000000u64)); // 1 ETH
        let encoded = account.encode_to_vec();
        
        // Should be valid RLP
        assert!(!encoded.is_empty());
    }
    
    #[test]
    fn test_bytes_to_nibbles() {
        let bytes = vec![0xAB, 0xCD];
        let nibbles = bytes_to_nibbles(&bytes);
        
        assert_eq!(nibbles, vec![0x0A, 0x0B, 0x0C, 0x0D]);
    }
    
    #[test]
    fn test_nibbles_to_bytes() {
        let nibbles = vec![0x0A, 0x0B, 0x0C, 0x0D];
        let bytes = nibbles_to_bytes(&nibbles);
        
        assert_eq!(bytes, vec![0xAB, 0xCD]);
    }
    
    #[test]
    fn test_nibbles_roundtrip() {
        let original = vec![0x12, 0x34, 0x56, 0x78];
        let nibbles = bytes_to_nibbles(&original);
        let recovered = nibbles_to_bytes(&nibbles);
        
        assert_eq!(original, recovered);
    }
    
    #[test]
    fn test_mpt_leaf_encoding() {
        let address_hash = [0u8; 32];
        let nibbles = bytes_to_nibbles(&address_hash);
        let account = Account::new_burn_account(U256::from(1000000000000000000u64));
        
        let leaf = MptLeaf::new_account_leaf(&nibbles, &account);
        let encoded = leaf.encode_to_vec();
        
        assert!(!encoded.is_empty());
    }
}
