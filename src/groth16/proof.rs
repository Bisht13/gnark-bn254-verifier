use ark_bn254::{G1Affine, G2Affine};

#[derive(Debug)]
pub(crate) struct Groth16Proof {
    pub(crate) ar: G1Affine,
    pub(crate) krs: G1Affine,
    pub(crate) bs: G2Affine,
    pub(crate) commitments: Vec<G1Affine>,
    pub(crate) commitment_pok: G1Affine,
}
