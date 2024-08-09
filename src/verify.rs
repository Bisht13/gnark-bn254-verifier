use std::hash::Hasher;

use anyhow::{anyhow, Result};
use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{batch_inversion, BigInteger, Field, One, PrimeField, Zero};

use crate::{
    constants::{
        ALPHA, BETA, ERR_BSB22_COMMITMENT_MISMATCH, ERR_INVALID_POINT, ERR_INVALID_WITNESS,
        ERR_INVERSE_NOT_FOUND, ERR_OPENING_POLY_MISMATCH, GAMMA, ZETA,
    },
    converter::g1_to_bytes,
    element::PlonkFr,
    kzg::{self, is_in_subgroup},
    prove,
    transcript::Transcript,
};

#[derive(Debug)]
pub(crate) struct VerifyingKey {
    pub(crate) size: usize,
    pub(crate) size_inv: Fr,
    pub(crate) generator: Fr,
    pub(crate) nb_public_variables: usize,

    pub(crate) kzg: kzg::VerifyingKey,

    pub(crate) coset_shift: Fr,

    pub(crate) s: [kzg::Digest; 3],

    pub(crate) ql: kzg::Digest,
    pub(crate) qr: kzg::Digest,
    pub(crate) qm: kzg::Digest,
    pub(crate) qo: kzg::Digest,
    pub(crate) qk: kzg::Digest,
    pub(crate) qcp: Vec<kzg::Digest>,

    pub(crate) commitment_constraint_indexes: Vec<usize>,
}

pub(crate) fn verify_plonk(
    vk: &VerifyingKey,
    proof: &prove::Proof,
    public_inputs: &[Fr],
) -> Result<bool> {
    if proof.bsb22_commitments.len() != vk.qcp.len() {
        return Err(anyhow::anyhow!(ERR_BSB22_COMMITMENT_MISMATCH));
    }

    if public_inputs.len() != vk.nb_public_variables {
        return Err(anyhow::anyhow!(ERR_INVALID_WITNESS));
    }

    for lro in proof.lro.iter() {
        if !is_in_subgroup(lro)? {
            return Err(anyhow::anyhow!(ERR_INVALID_POINT));
        }
    }

    if !is_in_subgroup(&proof.z)? {
        return Err(anyhow::anyhow!(ERR_INVALID_POINT));
    }

    for h in proof.h.iter() {
        if !is_in_subgroup(h)? {
            return Err(anyhow::anyhow!(ERR_INVALID_POINT));
        }
    }

    for bsb22_commitment in proof.bsb22_commitments.iter() {
        if !is_in_subgroup(bsb22_commitment)? {
            return Err(anyhow::anyhow!(ERR_INVALID_POINT));
        }
    }

    if !is_in_subgroup(&proof.batched_proof.h)? {
        return Err(anyhow::anyhow!(ERR_INVALID_POINT));
    }

    if !is_in_subgroup(&proof.z_shifted_opening.h)? {
        return Err(anyhow::anyhow!(ERR_INVALID_POINT));
    }

    let mut fs = Transcript::new(Some(
        [
            GAMMA.to_string(),
            BETA.to_string(),
            ALPHA.to_string(),
            ZETA.to_string(),
        ]
        .to_vec(),
    ))?;

    bind_public_data(&mut fs, GAMMA, vk, public_inputs)?;

    let gamma = derive_randomness(
        &mut fs,
        GAMMA,
        Some([proof.lro[0], proof.lro[1], proof.lro[2]].to_vec()),
    )?;

    let beta = derive_randomness(&mut fs, BETA, None)?;

    let mut alpha_deps: Vec<G1Affine> = proof.bsb22_commitments.iter().cloned().collect();
    alpha_deps.push(proof.z);
    let alpha = derive_randomness(&mut fs, ALPHA, Some(alpha_deps))?;

    let zeta = derive_randomness(
        &mut fs,
        ZETA,
        Some([proof.h[0], proof.h[1], proof.h[2]].to_vec()),
    )?;

    let one = Fr::one();
    let zeta_power_m = zeta.pow(&[vk.size as u64]);
    let zh_zeta = zeta_power_m - &one; // ζⁿ-1
    let mut lagrange_one = (zeta - &one).inverse().expect(ERR_INVERSE_NOT_FOUND); // 1/(ζ-1)
    lagrange_one *= &zh_zeta; // (ζ^n-1)/(ζ-1)
    lagrange_one *= &vk.size_inv; // 1/n * (ζ^n-1)/(ζ-1)

    let mut pi = Fr::zero();
    let mut accw = Fr::one();
    let mut dens = Vec::with_capacity(public_inputs.len());

    for _ in 0..public_inputs.len() {
        let mut temp = zeta;
        temp -= &accw;
        dens.push(temp);
        accw *= &vk.generator;
    }

    let inv_dens = batch_invert(&dens)?;

    accw = Fr::one();
    let mut xi_li;
    for (i, public_input) in public_inputs.iter().enumerate() {
        xi_li = zh_zeta;
        xi_li *= &inv_dens[i];
        xi_li *= &vk.size_inv;
        xi_li *= &accw;
        xi_li *= public_input; // Pi[i]*(ωⁱ/n)(ζ^n-1)/(ζ-ω^i)
        accw *= &vk.generator;
        pi += &xi_li;
    }

    let mut hash_to_field = crate::hash_to_field::WrappedHashToField::new(b"BSB22-Plonk")?;
    for i in 0..vk.commitment_constraint_indexes.len() {
        // Hash the commitment
        hash_to_field.write(&g1_to_bytes(&proof.bsb22_commitments[i])?);
        let hash_bts = hash_to_field.sum()?;
        hash_to_field.reset();
        let hashed_cmt = Fr::from_be_bytes_mod_order(&hash_bts);

        // Computing Lᵢ(ζ) where i=CommitmentIndex
        let w_pow_i = vk
            .generator
            .pow(&[(vk.nb_public_variables + vk.commitment_constraint_indexes[i]) as u64]);
        let mut den = zeta;
        den -= &w_pow_i; // ζ-wⁱ
        let mut lagrange = zh_zeta;
        lagrange *= &w_pow_i; // wⁱ(ζⁿ-1)
        lagrange /= &den; // wⁱ(ζⁿ-1)/(ζ-wⁱ)
        lagrange *= &vk.size_inv; // wⁱ/n (ζⁿ-1)/(ζ-wⁱ)

        xi_li = lagrange;
        xi_li *= &hashed_cmt;
        pi += &xi_li;
    }

    let l = proof.batched_proof.claimed_values[1];
    let r = proof.batched_proof.claimed_values[2];
    let o = proof.batched_proof.claimed_values[3];
    let s1 = proof.batched_proof.claimed_values[4];
    let s2 = proof.batched_proof.claimed_values[5];

    // Z(ωζ)
    let zu = proof.z_shifted_opening.claimed_value;

    // α²*L₁(ζ)
    let alpha_square_lagrange_one = {
        let mut tmp = lagrange_one;
        tmp *= &alpha;
        tmp *= &alpha;
        tmp
    };

    // (l(ζ)+β*s1(ζ)+γ)
    let mut tmp = beta;
    tmp *= &s1;
    tmp += &gamma;
    tmp += &l;
    let mut const_lin = tmp;

    // (r(ζ)+β*s2(ζ)+γ)
    tmp = beta;
    tmp *= &s2;
    tmp += &gamma;
    tmp += &r;

    // (l(ζ)+β*s1(ζ)+γ)(r(ζ)+β*s2(ζ)+γ)
    const_lin *= &tmp;

    // (o(ζ)+γ)
    tmp = o;
    tmp += &gamma;

    // α(l(ζ)+β*s1(ζ)+γ)(r(ζ)+β*s2(ζ)+γ)(o(ζ)+γ)*z(ωζ)
    const_lin *= &tmp;
    const_lin *= &alpha;
    const_lin *= &zu;

    // PI(ζ) - α²*L₁(ζ) + α(l(ζ)+β*s1(ζ)+γ)(r(ζ)+β*s2(ζ)+γ)(o(ζ)+γ)*z(ωζ)
    const_lin -= &alpha_square_lagrange_one;
    const_lin += &pi;

    // -[PI(ζ) - α²*L₁(ζ) + α(l(ζ)+β*s1(ζ)+γ)(r(ζ)+β*s2(ζ)+γ)(o(ζ)+γ)*z(ωζ)]
    const_lin = -const_lin;

    let opening_lin_pol = proof.batched_proof.claimed_values[0];
    if const_lin != opening_lin_pol {
        return Err(anyhow::anyhow!(ERR_OPENING_POLY_MISMATCH));
    }

    let _s1 = Fr::zero();
    let _s2 = Fr::zero();

    let mut _s1 = beta * s1 + l + gamma; // (l(ζ)+β*s1(ζ)+γ)
    let tmp = beta * s2 + r + gamma; // (r(ζ)+β*s2(ζ)+γ)
    _s1 = _s1 * tmp * beta * alpha * zu; // α*(l(ζ)+β*s1(ζ)+γ)*(r(ζ)+β*s2(ζ)+γ)*β*Z(ωζ)
    let mut _s2 = beta * zeta + gamma + l; // (l(ζ)+β*ζ+γ)
    let mut tmp = beta * vk.coset_shift * zeta + gamma + r; // (r(ζ)+β*u*ζ+γ)
    _s2 *= tmp; // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)
    tmp = beta * vk.coset_shift * vk.coset_shift * zeta + gamma + o; // (o(ζ)+β*u²*ζ+γ)
    _s2 *= tmp; // (l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
    _s2 *= alpha; // α*(l(ζ)+β*ζ+γ)*(r(ζ)+β*u*ζ+γ)*(o(ζ)+β*u²*ζ+γ)
    _s2 = -_s2; // Negate the result

    let coeff_z = alpha_square_lagrange_one + _s2;
    let rl = l * r;

    let n_plus_two = vk.size as u64 + 2;
    let mut zeta_n_plus_two_zh = zeta.pow([n_plus_two]);
    let mut zeta_n_plus_two_square_zh = zeta_n_plus_two_zh * zeta_n_plus_two_zh; // ζ²⁽ⁿ⁺²⁾
    zeta_n_plus_two_zh *= zh_zeta; // ζⁿ⁺²*(ζⁿ-1)
    zeta_n_plus_two_zh = -zeta_n_plus_two_zh; // -ζⁿ⁺²*(ζⁿ-1)
    zeta_n_plus_two_square_zh *= zh_zeta; // ζ²⁽ⁿ⁺²⁾*(ζⁿ-1)
    zeta_n_plus_two_square_zh = -zeta_n_plus_two_square_zh; // -ζ²⁽ⁿ⁺²⁾*(ζⁿ-1)
    let zh = -zh_zeta; // -(ζⁿ-1)

    let mut points = Vec::new();
    points.extend_from_slice(&proof.bsb22_commitments);
    points.push(vk.ql);
    points.push(vk.qr);
    points.push(vk.qm);
    points.push(vk.qo);
    points.push(vk.qk);
    points.push(vk.s[2]);
    points.push(proof.z);
    points.push(proof.h[0]);
    points.push(proof.h[1]);
    points.push(proof.h[2]);

    let qc = proof.batched_proof.claimed_values[6..].to_vec();

    let mut scalars = Vec::new();
    scalars.extend_from_slice(&qc);
    scalars.push(l);
    scalars.push(r);
    scalars.push(rl);
    scalars.push(o);
    scalars.push(one);
    scalars.push(_s1);
    scalars.push(coeff_z);
    scalars.push(zh);
    scalars.push(zeta_n_plus_two_zh);
    scalars.push(zeta_n_plus_two_square_zh);

    // Perform the multi-scalar multiplication
    let linearized_polynomial_digest = G1Projective::msm(&points, &scalars)
        .map_err(|e| anyhow!(e))?
        .into_affine();

    let mut digests_to_fold = vec![G1Affine::default(); vk.qcp.len() + 6];
    digests_to_fold[6..].copy_from_slice(&vk.qcp);
    digests_to_fold[0] = linearized_polynomial_digest;
    digests_to_fold[1] = proof.lro[0];
    digests_to_fold[2] = proof.lro[1];
    digests_to_fold[3] = proof.lro[2];
    digests_to_fold[4] = vk.s[0];
    digests_to_fold[5] = vk.s[1];

    let (folded_proof, folded_digest) = kzg::fold_proof(
        digests_to_fold,
        &proof.batched_proof,
        &zeta,
        Some(zu.into_bigint().to_bytes_be()),
    )?;

    let shifted_zeta = zeta * vk.generator;
    kzg::batch_verify_multi_points(
        [folded_digest, proof.z].to_vec(),
        [folded_proof, proof.z_shifted_opening].to_vec(),
        [zeta, shifted_zeta].to_vec(),
        &vk.kzg,
    )?;

    Ok(true)
}

fn bind_public_data(
    transcript: &mut Transcript,
    challenge: &str,
    vk: &VerifyingKey,
    public_inputs: &[Fr],
) -> Result<()> {
    transcript.bind(challenge, &g1_to_bytes(&vk.s[0])?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.s[1])?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.s[2])?)?;

    transcript.bind(challenge, &g1_to_bytes(&vk.ql)?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.qr)?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.qm)?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.qo)?)?;
    transcript.bind(challenge, &g1_to_bytes(&vk.qk)?)?;

    for qcp in vk.qcp.iter() {
        transcript.bind(challenge, &g1_to_bytes(qcp)?)?;
    }

    for public_input in public_inputs.iter() {
        transcript.bind(challenge, &public_input.into_bigint().to_bytes_be())?;
    }

    Ok(())
}

fn derive_randomness(
    transcript: &mut Transcript,
    challenge: &str,
    points: Option<Vec<G1Affine>>,
) -> Result<Fr> {
    if let Some(points) = points {
        for point in points {
            let buf = g1_to_bytes(&point)?;
            transcript.bind(challenge, &buf)?;
        }
    }

    let b = transcript.compute_challenge(challenge)?;
    let x = PlonkFr::set_bytes(&b.as_slice())?.into_fr()?;
    Ok(x)
}

fn batch_invert(elements: &[Fr]) -> Result<Vec<Fr>> {
    let mut elements = elements.to_vec();
    batch_inversion(&mut elements);
    Ok(elements)
}
