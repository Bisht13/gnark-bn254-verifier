# Plonk Verifier

This Rust library enables the verification of PLONK proofs in `Bn254` curve generated with the `gnark` library, utilizing serialization from [plonk-bn254-serializer](https://github.com/Bisht13/plonk-bn254-serializer).

## Usage

To use this library, add it as a dependency in your `Cargo.toml`:
```toml
[dependencies]
plonk-verifier = { git = "https://github.com/Bisht13/plonk-verifier.git", branch = "main" }
```

Then, you can verify a proof by calling the `verify` function:
```rs
use ark_bn254::Fr;
use plonk_verifier::verify;

fn main() {

    let proof = vec![0u8; 1000];
    let vk = vec![0u8; 1000];

    if verify(&proof, &vk, &[Fr::from(1u8), Fr::from(7u8)]) {
        println!("Proof is valid");
    } else {
        println!("Proof is invalid");
    }
}

```

## Features

- Verification of PLONK proofs generated using `gnark`.
- Easy integration into Rust projects.