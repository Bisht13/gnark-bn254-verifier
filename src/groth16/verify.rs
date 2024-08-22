use anyhow::Result;
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_groth16::{Groth16, Proof as ArkGroth16Proof, VerifyingKey as ArkGroth16VerifyingKey};
use ark_snark::SNARK;

use super::Groth16Proof;

#[allow(dead_code)]
pub(crate) struct Groth16G1 {
    pub(crate) alpha: G1Affine,
    pub(crate) beta: G1Affine,
    pub(crate) delta: G1Affine,
    pub(crate) k: Vec<G1Affine>,
}

#[derive(Debug)]
pub(crate) struct Groth16G2 {
    pub(crate) beta: G2Affine,
    pub(crate) delta: G2Affine,
    pub(crate) gamma: G2Affine,
}

#[allow(dead_code)]
pub(crate) struct PedersenVerifyingKey {
    pub(crate) g: G2Affine,
    pub(crate) g_root_sigma_neg: G2Affine,
}

#[allow(dead_code)]
pub(crate) struct Groth16VerifyingKey {
    pub(crate) g1: Groth16G1,
    pub(crate) g2: Groth16G2,
    pub(crate) commitment_key: PedersenVerifyingKey,
    pub(crate) public_and_commitment_committed: Vec<Vec<u32>>,
}

pub fn verify_groth16(
    vk: &Groth16VerifyingKey,
    proof: &Groth16Proof,
    public_inputs: &[Fr],
) -> Result<bool> {
    let proof: ArkGroth16Proof<Bn254> = ArkGroth16Proof {
        a: proof.ar,
        b: proof.bs,
        c: proof.krs,
    };
    let vk: ArkGroth16VerifyingKey<Bn254> = ArkGroth16VerifyingKey {
        alpha_g1: vk.g1.alpha,
        beta_g2: vk.g2.beta,
        gamma_g2: vk.g2.gamma,
        delta_g2: vk.g2.delta,
        gamma_abc_g1: vk.g1.k.clone(),
    };

    let pvk = Groth16::<Bn254>::process_vk(&vk)?;

    Ok(Groth16::<Bn254>::verify_with_processed_vk(
        &pvk,
        public_inputs,
        &proof,
    )?)
}
