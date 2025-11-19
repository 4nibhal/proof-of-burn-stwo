# Proof of Burn - Circle STARKs

Fork of WORM protocol using Circle STARKs instead of Groth16. No trusted setup required.

## Overview

This project replaces the trusted setup requirement of the original WORM protocol with transparent Circle STARKs using StarkWare's stwo prover.

## Project Structure

```
proof-of-burn-stwo/
├── prover/                 # Rust prover implementation
│   ├── src/
│   │   ├── circuits/       # Proof of Burn and Spend circuits
│   │   ├── utils/          # Cryptographic utilities
│   │   └── field.rs        # M31 field arithmetic
│   └── Cargo.toml
└── README.md
```

## Installation

```bash
cd prover
cargo build --release
```

## Usage

### Run Tests

```bash
cargo test
```

### Generate Proof

```bash
./target/release/pob-prover generate-burn --input input.json --output proof.json
```

## References

- [Circle STARKs Paper](https://eprint.iacr.org/2024/278)
- [Stwo Repository](https://github.com/starkware-libs/stwo)
- [Original WORM Protocol](https://github.com/worm-privacy)

