use ark_bn254::{G1Affine, G2Affine};

use crate::kzg::{BatchOpeningProof, Digest, OpeningProof};

#[derive(Debug)]
pub(crate) struct PlonkProof {
    pub(crate) lro: [Digest; 3],
    pub(crate) z: Digest,
    pub(crate) h: [Digest; 3],
    pub(crate) bsb22_commitments: Vec<Digest>,
    pub(crate) batched_proof: BatchOpeningProof,
    pub(crate) z_shifted_opening: OpeningProof,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct Groth16Proof {
    pub(crate) ar: G1Affine,
    pub(crate) krs: G1Affine,
    pub(crate) bs: G2Affine,
    pub(crate) commitments: Vec<G1Affine>,
    pub(crate) commitment_pok: G1Affine,
}
