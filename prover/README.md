# Proof of Burn Stwo Prover

Rust implementation of Proof of Burn circuits using Circle STARKs (stwo) - no trusted setup required.

## 📖 Overview

This prover differs from the WORM focus in key ways:

### WORM Protocol
- **Goal**: Privacy-preserving proof of ETH burn
- **Method**: Groth16 zkSNARKs with trusted setup
- **Trade-off**: Small proofs (128 bytes) but requires ceremony
- **Use Case**: Optimized for gas costs and proof size

### Proof-of-Burn-Stwo
- **Goal**: Trustless proof of ETH burn
- **Method**: Circle STARKs with M31 field - NO trusted setup
- **Trade-off**: Larger proofs (~100-200 KB) but fully transparent
- **Use Case**: Maximum transparency and security

## 🎯 Why No Trusted Setup Matters

### The Trusted Setup Problem

Groth16 (used by WORM) requires a "ceremony" where:
1. Multiple parties generate secret parameters
2. If ANY party keeps their secret, they can forge proofs
3. You must trust the ceremony was executed correctly
4. These "toxic waste" parameters could exist forever

### The Stwo Solution

Circle STARKs are **transparent**:
- No secrets, no ceremony, no trust assumptions
- Security comes purely from mathematics
- Anyone can verify the proving system is sound
- Post-quantum secure (resistant to quantum computers)

This is **critical for a truly cypherpunk protocol**.

## 🔧 Circuit Parameters

All parameters match the original Circom circuits:

```rust
Max MPT Layers:           16      // Ethereum state trie depth
Max Node Blocks:          4       // MPT node size (532 bytes max)
Max Header Blocks:        8       // Block header (643 bytes avg)
Min Leaf Address Nibbles: 50      // 200-bit security level
Amount Bytes:             31      // 248-bit amounts (no overflow)
PoW Min Zero Bytes:       2       // 16-bit additional security
Max Intended Balance:     10 ETH  // Per burn limit
Max Actual Balance:       100 ETH // Including dust attacks
```

### Why These Limits?

**Max Intended Balance (10 ETH)**:
- Reduces incentive for address-hash collision attacks
- Attacker would need to spend more than 10 ETH worth of compute to fake a burn

**Max Actual Balance (100 ETH)**:
- Allows burn address to receive "dust" (small amounts sent by attackers)
- Intended balance must be ≤ actual balance
- Prevents dust attacks from blocking legitimate burns

**Min Leaf Address Nibbles (50)**:
- 50 nibbles = 200 bits of security
- Can be relaxed by doing more PoW (byte_security_relax parameter)
- Trade-off: deeper trie proof vs. more PoW computation

**PoW Zero Bytes (2)**:
- Burn key must hash to value with 2 leading zero bytes
- Adds 16 bits of security = 2^16 = 65,536 attempts
- Makes address collision attacks ~65,000x harder

## 🏛️ Architecture

### Module Structure

```
src/
├── constants.rs           # Circuit parameters & Poseidon prefixes
├── utils/                # Cryptographic utilities
│   ├── poseidon.rs       # Poseidon hash over M31 field
│   ├── keccak.rs         # Keccak256 (Ethereum compatibility)
│   ├── rlp.rs            # RLP encoding for Ethereum data
│   ├── mpt.rs            # Merkle-Patricia-Trie verification
│   ├── pow.rs            # Proof-of-Work checker
│   └── burn_address.rs   # Burn address computation
├── circuits/             # Circuit implementations
│   ├── spend.rs          # Spend circuit (simpler)
│   └── proof_of_burn.rs  # Main proof of burn circuit
└── main.rs               # CLI interface
```

### Data Flow

```
User Burns ETH → Ethereum Block → MPT Proof
                       ↓
              [Prover Inputs]
                       ↓
    ┌──────────────────────────────────┐
    │   Proof of Burn Circuit          │
    │  - Validate balances              │
    │  - Compute nullifier (prevent 2x) │
    │  - Verify MPT proof               │
    │  - Check PoW requirement          │
    │  - Compute commitment             │
    └──────────────────────────────────┘
                       ↓
              [Public Outputs]
         - Nullifier (unique)
         - Commitment (binds all data)
         - Remaining Coin (encrypted)
                       ↓
              Submit to Contract
```

## 🚀 Usage

### CLI Commands

#### 1. Show Circuit Info
```bash
cargo run --release -- info
```

Displays:
- Circuit parameters
- Balance limits
- Cryptographic primitives
- Estimated gas costs
- Comparison with WORM

#### 2. Generate Spend Proof

Create a spend proof to partially withdraw from an encrypted coin:

```bash
# Create input file
cat > spend_input.json << EOF
{
  "burn_key": 12345,
  "balance": "1000000000000000000",
  "withdrawn_balance": "300000000000000000",
  "extra_commitment": 100
}
EOF

# Generate proof
cargo run --release -- prove-spend \
  -i spend_input.json \
  -o spend_output.json
```

#### 3. Generate Burn Proof

Create a proof that ETH was burned (requires actual Ethereum data):

```bash
# Create input file (this requires real MPT proof data)
cat > burn_input.json << EOF
{
  "burn_key": 12345,
  "actual_balance": "1000000000000000000",
  "intended_balance": "1000000000000000000",
  "reveal_amount": "500000000000000000",
  "burn_extra_commitment": 100,
  "layers": [...],  // MPT proof layers
  "block_header": "0x...",  // Block header bytes
  "num_leaf_address_nibbles": 50,
  "byte_security_relax": 0,
  "proof_extra_commitment": 200
}
EOF

# Generate proof
cargo run --release -- prove-burn \
  -i burn_input.json \
  -o burn_output.json
```

#### 4. Verify Proof

```bash
# Verify spend proof
cargo run --release -- verify \
  -p spend_output.json \
  -t spend

# Verify burn proof
cargo run --release -- verify \
  -p burn_output.json \
  -t burn
```

## 🧪 Testing

### Run All Tests
```bash
cargo test
```

### Run Specific Test Suite
```bash
# Spend circuit tests only
cargo test spend

# Proof of burn tests only
cargo test pob

# Integration tests
cargo test integration
```

### Test Coverage

The test suite includes:

**Spend Circuit**:
- ✓ Valid withdrawals
- ✓ Full withdrawals
- ✓ Insufficient balance (should fail)
- ✓ Zero withdrawal edge case
- ✓ Deterministic proof generation

**Proof of Burn Circuit**:
- ✓ Valid burn with all constraints
- ✓ Balance limit violations (should fail)
- ✓ Invalid reveal amounts (should fail)
- ✓ MPT proof validation
- ✓ PoW requirement checking
- ✓ Dust attack scenarios

**Integration**:
- ✓ Burn → Spend workflow
- ✓ Minimum/maximum valid amounts
- ✓ Edge cases

## ⚡ Performance

### Proof Generation (Estimated)

With Phase 2 full stwo integration:

| Circuit | Constraints | Prover Time | Proof Size |
|---------|-------------|-------------|------------|
| Spend | ~1K | ~5 seconds | ~50 KB |
| Burn | ~100K | ~30 seconds | ~150 KB |

*Note*: Times on modern laptop (8 cores, 16GB RAM)

### Verification Cost

On Ethereum mainnet:
- **Gas Cost**: ~1,500,000 gas
- **Cost at 0.5 gwei**: $2.63 USD
- **Cost at 5 gwei**: $26.25 USD
- **Cost at 50 gwei**: $262.50 USD

**Optimization Strategy**:
- Deploy on L2 (Arbitrum/Base) for $2-5 per verification
- Batch multiple verifications together
- Use for high-value burns where transparency justifies cost

## 🔬 Technical Deep Dive

### M31 Field (2^31 - 1)

Circle STARKs use M31 because:
- **CPU-friendly**: 32-bit operations are native to modern CPUs
- **Fast arithmetic**: ~100x faster than BN254 field operations
- **SIMD support**: Can process 8 elements in parallel with AVX2
- **Small field**: Reduces memory usage and cache misses

### Poseidon Hash over M31

```rust
// Poseidon with M31 is optimized for speed
poseidon3([prefix, burn_key, balance])
// → ~1 microsecond on modern CPU
// vs. BN254: ~100 microseconds

// This speed difference compounds:
// Burn circuit has ~1000 Poseidon calls
// → 10x faster overall proving time
```

### Why Proofs Are Larger

STARKs are **transparent** but require:
- Multiple FRI layers (proximity tests)
- Merkle paths for commitments
- Query responses for soundness

Trade-off equation:
```
Size ↑ (~200 KB vs 128 bytes)
Transparency ↑ (NO trusted setup)
Prover Time ↓ (10-30s vs 1-2min)
Gas Cost ↑ (~1.5M vs 250K)
```

**Verdict**: For trustless cypherpunk protocols, transparency wins.

## 🐛 Debugging

### Enable Verbose Output
```bash
RUST_LOG=debug cargo run -- prove-spend -i input.json -o output.json
```

### Common Issues

**1. "Insufficient balance"**
```
Error: balance < withdrawn_balance
Fix: Check your balance values are in wei (not ETH)
```

**2. "Amount too large"**
```
Error: Amount exceeds 31 bytes (248 bits)
Fix: Max amount is ~100 ETH, use smaller values
```

**3. "MPT verification failed"**
```
Error: Invalid Merkle-Patricia-Trie proof
Fix: Ensure your MPT proof data matches the state root
```

## 📦 Dependencies

Key external crates:
- `stwo-prover`: Circle STARK prover (StarkWare)
- `alloy-primitives`: Ethereum types and utilities
- `sha3`: Keccak256 implementation
- `serde/serde_json`: Serialization

## 🔮 Future Work

### Phase 2: Full Stwo Integration
- [ ] Implement actual Circle FFT proof generation
- [ ] Optimize Poseidon for M31 field
- [ ] Benchmark and profile performance
- [ ] Reduce proof size where possible

### Phase 3: Advanced Features
- [ ] Parallel proof generation
- [ ] GPU acceleration for FFT
- [ ] Proof aggregation (combine multiple burns)
- [ ] Recursive proofs for scalability

## 📚 References

- [Stwo Repository](https://github.com/starkware-libs/stwo)
- [Circle STARKs Paper](https://eprint.iacr.org/2024/278)
- [WORM Protocol](https://github.com/worm-privacy)
- [FRI Protocol](https://eccc.weizmann.ac.il/report/2017/134/)

---

**Current Status**: Phase 1 complete - Circuit translation and structure done. Phase 2 (full stwo integration) is next.

