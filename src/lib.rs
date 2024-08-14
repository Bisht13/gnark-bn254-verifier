use ark_bn254::Fr;

use converter::{
    load_groth16_proof_from_bytes, load_groth16_verifying_key_from_bytes,
    load_plonk_proof_from_bytes, load_plonk_verifying_key_from_bytes,
};
use verify::{verify_groth16, verify_plonk};

mod constants;
mod converter;
mod element;
mod hash_to_field;
mod kzg;
mod prove;
mod transcript;
mod verify;

pub enum ProvingSystem {
    Plonk,
    Groth16,
}

pub fn verify(
    proof: &[u8],
    vk: &[u8],
    public_inputs: &[Fr],
    proving_system: ProvingSystem,
) -> bool {
    match proving_system {
        ProvingSystem::Plonk => {
            let proof = load_plonk_proof_from_bytes(proof).unwrap();
            let vk = load_plonk_verifying_key_from_bytes(vk).unwrap();

            match verify_plonk(&vk, &proof, public_inputs) {
                Ok(result) => result,
                Err(e) => {
                    println!("Error: {:?}", e);
                    false
                }
            }
        }
        ProvingSystem::Groth16 => {
            let proof = load_groth16_proof_from_bytes(proof).unwrap();
            let vk = load_groth16_verifying_key_from_bytes(vk).unwrap();

            match verify_groth16(&vk, &proof, public_inputs) {
                Ok(result) => result,
                Err(e) => {
                    println!("Error: {:?}", e);
                    false
                }
            }
        }
    }
}
