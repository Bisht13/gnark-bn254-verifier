use ark_bn254::Fr;

use converter::{load_proof_from_bytes, load_verifying_key};
use verify::verify_plonk;

mod constants;
mod converter;
mod element;
mod hash_to_field;
mod kzg;
mod prove;
mod transcript;
mod verify;

pub fn verify(proof: &[u8], vk: &[u8], public_inputs: &[Fr]) -> bool {
    let proof = load_proof_from_bytes(proof).unwrap();
    let vk = load_verifying_key(vk).unwrap();

    match verify_plonk(&vk, &proof, public_inputs) {
        Ok(result) => result,
        Err(e) => {
            println!("Error: {:?}", e);
            false
        }
    }
}
