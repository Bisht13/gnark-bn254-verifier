use anyhow::{anyhow, Error, Result};
use rand::rngs::OsRng;
use substrate_bn::{pairing_batch, AffineG1, Fr, G1, G2};

use crate::{
    constants::{ERR_INVALID_NUMBER_OF_DIGESTS, ERR_PAIRING_CHECK_FAILED, GAMMA},
    transcript::Transcript,
};

use super::{converter::g1_to_bytes, element::PlonkFr};

pub(crate) type Digest = AffineG1;

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct E2 {
    pub(crate) a0: Fr,
    pub(crate) a1: Fr,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct LineEvaluationAff {
    pub(crate) r0: E2,
    pub(crate) r1: E2,
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct KZGVerifyingKey {
    pub(crate) g2: [G2; 2], // [G₂, [α]G₂]
    pub(crate) g1: G1,
    // Precomputed pairing lines corresponding to G₂, [α]G₂
    pub(crate) lines: [[[LineEvaluationAff; 66]; 2]; 2],
}

#[derive(Clone, Debug)]
pub(crate) struct BatchOpeningProof {
    pub(crate) h: AffineG1,
    pub(crate) claimed_values: Vec<Fr>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OpeningProof {
    pub(crate) h: AffineG1,
    pub(crate) claimed_value: Fr,
}

fn derive_gamma(
    point: &Fr,
    digests: Vec<Digest>,
    claimed_values: Vec<Fr>,
    data_transcript: Option<Vec<u8>>,
) -> Result<Fr> {
    let mut transcript = Transcript::new(Some([GAMMA.to_string()].to_vec()))?;
    transcript.bind(GAMMA, &point.into_u256().to_bytes_be().map_err(Error::msg)?)?;

    for digest in digests.iter() {
        transcript.bind(GAMMA, &g1_to_bytes(digest)?)?;
    }

    for claimed_value in claimed_values.iter() {
        transcript.bind(
            GAMMA,
            &claimed_value
                .into_u256()
                .to_bytes_be()
                .map_err(Error::msg)?,
        )?;
    }

    if let Some(data_transcript) = data_transcript {
        transcript.bind(GAMMA, &data_transcript)?;
    }

    let gamma_byte = transcript.compute_challenge(GAMMA)?;
    let x = PlonkFr::set_bytes(&gamma_byte.as_slice())?.into_fr()?;

    Ok(x)
}

fn fold(di: Vec<Digest>, fai: Vec<Fr>, ci: Vec<Fr>) -> Result<(G1, Fr)> {
    let nb_digests = di.len();

    let mut folded_evaluations = Fr::zero();

    for i in 0..nb_digests {
        folded_evaluations += fai[i] * ci[i];
    }

    let folded_digests = G1::msm(&di, &ci);

    Ok((folded_digests, folded_evaluations))
}

pub(crate) fn fold_proof(
    digests: Vec<Digest>,
    batch_opening_proof: &BatchOpeningProof,
    point: &Fr,
    data_transcript: Option<Vec<u8>>,
) -> Result<(OpeningProof, G1)> {
    let nb_digests = digests.len();

    if nb_digests != batch_opening_proof.claimed_values.len() {
        return Err(anyhow!(ERR_INVALID_NUMBER_OF_DIGESTS));
    }

    let gamma = derive_gamma(
        point,
        digests.clone(),
        batch_opening_proof.claimed_values.clone(),
        data_transcript,
    )?;

    let mut gammai = vec![Fr::zero(); nb_digests];
    gammai[0] = Fr::one();
    if nb_digests > 1 {
        gammai[1] = gamma;
    }
    for i in 2..nb_digests {
        gammai[i] = gammai[i - 1] * gamma;
    }

    let (folded_digests, folded_evaluations) =
        fold(digests, batch_opening_proof.claimed_values.clone(), gammai)?;

    let open_proof = OpeningProof {
        h: batch_opening_proof.h,
        claimed_value: folded_evaluations,
    };

    Ok((open_proof, folded_digests))
}

// fn verify(
//     commitment: &Digest,
//     proof: &OpeningProof,
//     point: &Fr,
//     vk: &PlonkVerifyingKey,
// ) -> Result<bool, &'static str> {
//     let mut total_g1 = G1Projective::zero();
//     let point_neg = -point;
//     let cm_int = proof.claimed_value.into_repr();
//     let point_int = point_neg.into_repr();

//     // Perform joint scalar multiplication
//     let scalars = vec![cm_int, point_int];
//     let bases = vec![vk.g1.into_projective(), proof.h.into_projective()];
//     total_g1 = G1Projective::msm_unchecked(&bases, &scalars);

//     // [f(a) - a*H(α)]G1 + [-f(α)]G1 = [f(a) - f(α) - a*H(α)]G1
//     let commitment_jac = commitment.0.into_projective();
//     total_g1 -= commitment_jac;

//     // Convert total_g1 to affine
//     let total_g1_aff = total_g1.into_affine();

//     // Perform the pairing check
//     let check = Bn254::product_of_pairings(&[
//         (total_g1_aff.prepare(), vk.lines[0].clone()),
//         (proof.h.prepare(), vk.lines[1].clone()),
//     ]);

//     // Check if the result is 1 (pairing check passed)
//     if check.is_one() {
//         Ok(())
//     } else {
//         Err("Verification failed".into())
//     }
// }

pub(crate) fn batch_verify_multi_points(
    digests: Vec<Digest>,
    proofs: Vec<OpeningProof>,
    points: Vec<Fr>,
    vk: &KZGVerifyingKey,
) -> Result<()> {
    let nb_digests = digests.len();
    let nb_proofs = proofs.len();
    let nb_points = points.len();

    if nb_digests != nb_proofs {
        return Err(anyhow!(ERR_INVALID_NUMBER_OF_DIGESTS));
    }

    if nb_digests != nb_points {
        return Err(anyhow!(ERR_INVALID_NUMBER_OF_DIGESTS));
    }

    if nb_digests == 1 {
        todo!();
    }

    let mut rng = OsRng;
    let mut random_numbers = Vec::with_capacity(nb_digests);
    random_numbers.push(Fr::one());
    for _ in 1..nb_digests {
        random_numbers.push(Fr::random(&mut rng));
    }

    let mut quotients = Vec::with_capacity(nb_proofs);
    for i in 0..random_numbers.len() {
        quotients.push(proofs[i].h.into());
    }

    let mut folded_quotients = G1::msm(&quotients, &random_numbers);

    let mut evals = Vec::with_capacity(nb_digests);
    for i in 0..nb_digests {
        evals.push(proofs[i].claimed_value);
    }

    let (mut folded_digests, folded_evals) = fold(digests, evals, random_numbers.clone())?;
    let folded_evals_commit = vk.g1 * folded_evals;
    folded_digests = folded_digests - folded_evals_commit;

    for i in 0..random_numbers.len() {
        random_numbers[i] = random_numbers[i] * points[i];
    }

    let folded_points_quotients = G1::msm(&quotients, &random_numbers);

    folded_digests = folded_digests + folded_points_quotients;
    folded_quotients = -folded_quotients;

    // Pairing check
    let pairing_result = pairing_batch(&[(folded_digests, vk.g2[0]), (folded_quotients, vk.g2[1])]);

    if !pairing_result.is_zero() {
        return Err(anyhow!(ERR_PAIRING_CHECK_FAILED));
    }

    Ok(())
}
