# Proof of Burn Prover

Rust implementation of Proof of Burn circuits using Circle STARKs.

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test
```

## Usage

```bash
# Generate burn proof
./target/release/pob-prover generate-burn --input input.json --output proof.json

```


