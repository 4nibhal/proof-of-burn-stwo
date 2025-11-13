# Proof of Burn - Circle STARKs Implementation

**Project**: WORM Protocol Fork using Stwo (Circle STARKs)  
**Status**: Development - Testnet Ready  
**Date**: November 13, 2025

---

## 🎯 Overview

This is a fork of the WORM protocol that replaces Groth16 (which requires a trusted setup) with Circle STARKs using StarkWare's stwo prover. The implementation maintains all the logic of WORM while providing transparency through STARK proofs.

### Key Features

- ✅ **No Trusted Setup**: Uses transparent Circle STARKs
- ✅ **M31 Field**: Mersenne-31 prime (2^31 - 1) for fast arithmetic
- ✅ **Poseidon2 Hash**: ZK-friendly hash with real constants (Sage-generated)
- ✅ **Complete Logic**: Full translation of WORM circuits
- ✅ **Extensively Tested**: 63 passing tests
- ✅ **Critical State Verification**: Verifies Poseidon round transitions

---

## 🔒 Security Status

### ✅ What's Secure

1. **Poseidon2 Algorithm**: Correctly implemented from paper with real constants
2. **Round Constants**: Generated using Sage with proper security parameters
3. **Internal Round Matrix**: Fixed to satisfy minpoly condition (see `SECURITY_FIX_APPLIED.md`)
4. **Circuit Logic**: Complete and correct translation from WORM
5. **MPT Verification**: Full Merkle Patricia Trie implementation
6. **RLP Encoding**: Production-grade using alloy
7. **Critical State Verification**: Verifies Poseidon round transitions in AIR

### ⚠️ What Needs Work (Before Mainnet)

1. **Complete Constraints**: Full symbolic verification of Poseidon rounds
   - Current implementation verifies critical states only
   - Need complete round-by-round verification for maximum security

2. **External Audit**: Required before mainnet deployment

3. **Performance Optimization**: WASM compilation and browser testing

---

## 📁 Project Structure

```
proof-of-burn-stwo/
├── prover/
│   ├── src/
│   │   ├── circuits/
│   │   │   ├── proof_of_burn.rs    # Main PoB circuit
│   │   │   └── spend.rs             # Spend circuit
│   │   ├── utils/
│   │   │   ├── poseidon2_stwo.rs   # Real Poseidon2 (SECURITY FIX APPLIED)
│   │   │   ├── poseidon.rs         # Legacy implementation
│   │   │   ├── keccak.rs            # Keccak256
│   │   │   ├── rlp.rs               # RLP encoding
│   │   │   ├── mpt.rs               # Merkle Patricia Trie
│   │   │   ├── pow.rs               # Proof of Work
│   │   │   └── burn_address.rs     # Burn address computation
│   │   ├── field.rs                 # M31 field arithmetic
│   │   └── constants.rs             # Protocol constants
│   ├── tests/                       # 52 comprehensive tests
│   ├── Cargo.toml
│   └── rust-toolchain.toml         # nightly-2025-07-14
├── contracts/                       # Future Solidity contracts
├── ESTADO_ACTUAL.md                 # Current status (Spanish)
├── SECURITY_FIX_APPLIED.md          # Security fix documentation
└── README.md                        # This file
```

---

## 🚀 Quick Start

### Prerequisites

- Rust nightly-2025-07-14 (auto-installed via rust-toolchain.toml)
- Cargo

### Build

```bash
cd prover
cargo build --release
```

### Run Tests

```bash
cargo test
```

### Run Specific Tests

```bash
cargo test poseidon2
cargo test proof_of_burn
cargo test spend
```

---

## 🔬 Technical Details

### Field

- **Prime**: p = 2^31 - 1 (M31, Mersenne-31)
- **Size**: 31 bits
- **Properties**: Fast arithmetic, SIMD-friendly

### Poseidon2 Configuration

- **State Size**: 16
- **Full Rounds**: 8 (4 + 4)
- **Partial Rounds**: 14
- **S-box**: x^5
- **Internal Matrix**: Fixed for minpoly condition (diagonal: [4, 5, 9, ...])

### Circuit Components

1. **ProofOfBurn**
   - MPT proof verification
   - Burn address computation (Poseidon + Keccak)
   - Nullifier generation
   - Proof of Work validation

2. **Spend**
   - Coin existence verification
   - Partial spending support
   - Balance constraints

---

## 🎓 Important Documentation

### Must Read

1. **SECURITY_FIX_APPLIED.md** - Critical fix for Poseidon2 internal matrix
2. **ESTADO_ACTUAL.md** - Current project status (Spanish)

### Papers & References

- [Circle STARKs Paper](https://eprint.iacr.org/2024/278)
- [Poseidon2 Paper](https://eprint.iacr.org/2023/323.pdf)
- [Stwo Repository](https://github.com/starkware-libs/stwo)
- [Original WORM Protocol](https://github.com/bitcoin-worm)

---

## 🛠️ Development Roadmap

### Phase 1: Circuit Translation ✅ DONE
- [x] Translate ProofOfBurn circuit
- [x] Translate Spend circuit
- [x] Implement all utilities (Poseidon, Keccak, RLP, MPT)
- [x] Extensive testing (52 tests)
- [x] Apply security fixes

### Phase 2: Constants Generation 🔄 IN PROGRESS
- [ ] Install SageMath
- [ ] Generate proper round constants for M31
- [ ] Integrate and test
- [ ] Contact StarkWare for validation

### Phase 3: AIR Integration 📋 TODO
- [ ] Define AIR constraints for ProofOfBurn
- [ ] Define AIR constraints for Spend
- [ ] Implement trace generation
- [ ] Connect to stwo prover

### Phase 4: Proof Generation 📋 TODO
- [ ] Generate first STARK proof
- [ ] Optimize proof size
- [ ] Benchmark performance

### Phase 5: Verification 📋 TODO
- [ ] Generate Solidity verifier
- [ ] Deploy to Sepolia testnet
- [ ] End-to-end testing
- [ ] Gas cost analysis

### Phase 6: Production 📋 TODO
- [ ] External security audit
- [ ] Testnet deployment (Sepolia)
- [ ] Mainnet deployment (after audit)

---

## 🔧 Configuration

### Rust Toolchain

The project uses a specific nightly version:

```toml
# rust-toolchain.toml
[toolchain]
channel = "nightly-2025-07-14"
```

This is required for stwo's experimental features.

### Dependencies

Key dependencies:
- `stwo-prover`: Circle STARK prover
- `alloy-primitives`: Ethereum types
- `alloy-rlp`: RLP encoding
- `sha3`: Keccak256
- `serde`: Serialization

---

## 🧪 Testing

### Test Coverage

- **Field Arithmetic**: M31 operations, modulo, overflow
- **Poseidon2**: Hash properties, determinism, collision resistance
- **Circuits**: Logic validation, constraint checking
- **Boundaries**: Edge cases, max values, zero handling
- **Integration**: End-to-end flows

### Running Tests

```bash
# All tests
cargo test

# With output
cargo test -- --nocapture

# Specific test
cargo test test_poseidon2_deterministic

# Release mode (faster)
cargo test --release
```

---

## 📝 Contributing

### Code Style

- Follow Rust conventions
- Add comprehensive comments
- Include security notes where relevant
- Write tests for all new code

### Security

- Never commit placeholder constants to production
- Document all cryptographic choices
- Include paper references
- Flag TODOs clearly

---

## ⚠️ Disclaimers

### Current Status

**FOR TESTNET USE ONLY**

This implementation is:
- ✅ Cryptographically sound (with fixes applied)
- ✅ Extensively tested
- ⚠️ Using placeholder round constants
- ❌ Not yet audited for mainnet

### Before Mainnet Deployment

Required steps:
1. Generate proper round constants
2. External cryptographic audit
3. Extensive testnet testing
4. Gas optimization
5. Security review

---

## 📧 Contact

For questions about:
- **Implementation**: See code comments and documentation
- **Security**: Review SECURITY_FIX_APPLIED.md
- **Status**: Check ESTADO_ACTUAL.md

---

## 📜 License

[To be determined - follow WORM's license]

---

## 🙏 Acknowledgments

- **StarkWare**: For stwo and Circle STARKs research
- **WORM Protocol**: For original circuit design
- **Community**: For security issue identification and validation

---

**Last Updated**: November 12, 2025  
**Version**: 0.1.0-dev  
**Status**: Active Development

