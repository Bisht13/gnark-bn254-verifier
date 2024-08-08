use anyhow::{anyhow, Error, Result};
use ark_bn254::{Fq, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, SerializationError};
use num_traits::Zero;
use std::{
    cmp::{Ord, Ordering},
    ops::Neg,
};

use crate::{
    constants::{
        ERR_FAILED_TO_GET_X, ERR_FAILED_TO_GET_Y, ERR_INVALID_GNARK_X_LENGTH,
        ERR_UNEXPECTED_GNARK_FLAG,
    },
    kzg::{self, BatchOpeningProof, LineEvaluationAff, OpeningProof, E2},
    prove::Proof,
    verify::VerifyingKey,
};

const GNARK_MASK: u8 = 0b11 << 6;
const GNARK_COMPRESSED_POSTIVE: u8 = 0b10 << 6;
const GNARK_COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
const GNARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

const ARK_MASK: u8 = 0b11 << 6;
const ARK_COMPRESSED_POSTIVE: u8 = 0b00 << 6;
const ARK_COMPRESSED_NEGATIVE: u8 = 0b10 << 6;
const ARK_COMPRESSED_INFINITY: u8 = 0b01 << 6;

fn gnark_flag_to_ark_flag(msb: u8) -> Result<u8> {
    let gnark_flag = msb & GNARK_MASK;

    let ark_flag = match gnark_flag {
        GNARK_COMPRESSED_POSTIVE => ARK_COMPRESSED_POSTIVE,
        GNARK_COMPRESSED_NEGATIVE => ARK_COMPRESSED_NEGATIVE,
        GNARK_COMPRESSED_INFINITY => ARK_COMPRESSED_INFINITY,
        _ => {
            let err_msg = format!("{}: {}", ERR_UNEXPECTED_GNARK_FLAG, gnark_flag);
            return Err(anyhow!(err_msg));
        }
    };

    Ok(msb & !ARK_MASK | ark_flag)
}

/// Convert big-endian gnark compressed x bytes to litte-endian ark compressed x for g1 and g2 point
fn ganrk_commpressed_x_to_ark_commpressed_x(x: &Vec<u8>) -> Result<Vec<u8>> {
    if x.len() != 32 && x.len() != 64 {
        let err_msg = format!("{}: {}", ERR_INVALID_GNARK_X_LENGTH, x.len());
        return Err(anyhow!(err_msg));
    }
    let mut x_copy = x.clone();

    let msb = gnark_flag_to_ark_flag(x_copy[0])?;
    x_copy[0] = msb;

    x_copy.reverse();
    Ok(x_copy)
}

fn gnark_compressed_x_to_g1_point(buf: &[u8]) -> Result<G1Affine> {
    if buf.len() != 32 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let m_data = buf[0] & GNARK_MASK;
    if m_data == GNARK_COMPRESSED_INFINITY {
        if !is_zeroed(buf[0] & !GNARK_MASK, &buf[1..32])? {
            return Err(anyhow!(SerializationError::InvalidData));
        }
        Ok(G1Affine::identity())
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !GNARK_MASK;

        let x = Fq::from_be_bytes_mod_order(&x_bytes.to_vec());
        let (y, neg_y) = G1Affine::get_ys_from_x_unchecked(x)
            .ok_or(SerializationError::InvalidData)
            .map_err(Error::msg)?;

        let mut final_y = y;
        if y.cmp(&neg_y) == Ordering::Greater {
            if m_data == GNARK_COMPRESSED_POSTIVE {
                final_y = y.neg();
            }
        } else {
            if m_data == GNARK_COMPRESSED_NEGATIVE {
                final_y = y.neg();
            }
        }

        let p = G1Affine::new_unchecked(x, final_y);
        if !p.is_on_curve() {
            return Err(anyhow!(SerializationError::InvalidData));
        }
        Ok(p)
    }
}

fn is_zeroed(first_byte: u8, buf: &[u8]) -> Result<bool> {
    if first_byte != 0 {
        return Ok(false);
    }
    for &b in buf {
        if b != 0 {
            return Ok(false);
        }
    }

    Ok(true)
}

fn gnark_compressed_x_to_g2_point(buf: &[u8]) -> Result<G2Affine> {
    if buf.len() != 64 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let bytes = ganrk_commpressed_x_to_ark_commpressed_x(&buf.to_vec())?;
    let p = G2Affine::deserialize_compressed::<&[u8]>(&bytes).map_err(Error::msg)?;
    Ok(p)
}

pub(crate) fn load_verifying_key(path: &str) -> Result<VerifyingKey> {
    let buffer = std::fs::read(path)?;

    let size = u64::from_be_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]) as usize;
    let size_inv = Fr::from_be_bytes_mod_order(&buffer[8..40]);
    let generator = Fr::from_be_bytes_mod_order(&buffer[40..72]);
    let nb_public_variables = u64::from_be_bytes([
        buffer[72], buffer[73], buffer[74], buffer[75], buffer[76], buffer[77], buffer[78],
        buffer[79],
    ]) as usize;

    let g2_0 = gnark_compressed_x_to_g2_point(&buffer[80..144])?;
    let g2_1 = gnark_compressed_x_to_g2_point(&buffer[144..208])?;

    let g1 = gnark_compressed_x_to_g1_point(&buffer[208..240])?;

    let mut lines = [[[LineEvaluationAff {
        r0: E2 {
            a0: Fr::zero(),
            a1: Fr::zero(),
        },
        r1: E2 {
            a0: Fr::zero(),
            a1: Fr::zero(),
        },
    }; 66]; 2]; 2];
    let mut offset = 240;
    for i in 0..2 {
        for j in 0..2 {
            for k in 0..66 {
                let r0_a0 = Fr::from_be_bytes_mod_order(&buffer[offset..offset + 32]);
                let r0_a1 = Fr::from_be_bytes_mod_order(&buffer[offset + 32..offset + 64]);
                let r1_a0 = Fr::from_be_bytes_mod_order(&buffer[offset + 64..offset + 96]);
                let r1_a1 = Fr::from_be_bytes_mod_order(&buffer[offset + 96..offset + 128]);
                lines[i][j][k] = LineEvaluationAff {
                    r0: E2 {
                        a0: r0_a0,
                        a1: r0_a1,
                    },
                    r1: E2 {
                        a0: r1_a0,
                        a1: r1_a1,
                    },
                };
                offset += 128;
            }
        }
    }

    let coset_shift = Fr::from_be_bytes_mod_order(&buffer[offset..offset + 32]);
    offset += 32;

    let s = [
        gnark_compressed_x_to_g1_point(&buffer[offset..offset + 32])?,
        gnark_compressed_x_to_g1_point(&buffer[offset + 32..offset + 64])?,
        gnark_compressed_x_to_g1_point(&buffer[offset + 64..offset + 96])?,
    ];
    offset += 96;

    let ql = gnark_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
    let qr = gnark_compressed_x_to_g1_point(&buffer[offset + 32..offset + 64])?;
    let qm = gnark_compressed_x_to_g1_point(&buffer[offset + 64..offset + 96])?;
    let qo = gnark_compressed_x_to_g1_point(&buffer[offset + 96..offset + 128])?;
    let qk = gnark_compressed_x_to_g1_point(&buffer[offset + 128..offset + 160])?;
    offset += 160;

    let num_qcp = u16::from_be_bytes([buffer[offset], buffer[offset + 1]]);
    let mut qcp = Vec::new();
    offset += 2;
    for _ in 0..num_qcp {
        let point = gnark_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
        qcp.push(point);
        offset += 32;
    }

    let num_commitment_constraint_indexes =
        u16::from_be_bytes([buffer[offset], buffer[offset + 1]]);
    let mut commitment_constraint_indexes = Vec::new();
    offset += 2;
    for _ in 0..num_commitment_constraint_indexes {
        let index = u64::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
            buffer[offset + 4],
            buffer[offset + 5],
            buffer[offset + 6],
            buffer[offset + 7],
        ]) as usize;
        commitment_constraint_indexes.push(index);
        offset += 8;
    }

    Ok(VerifyingKey {
        size,
        size_inv,
        generator,
        nb_public_variables,
        kzg: kzg::VerifyingKey {
            g2: [g2_0, g2_1],
            g1,
            lines,
        },
        coset_shift,
        s,
        ql,
        qr,
        qm,
        qo,
        qk,
        qcp,
        commitment_constraint_indexes,
    })
}

pub(crate) fn load_proof(path: &str) -> Result<Proof> {
    let buffer = std::fs::read(path)?;

    let lro0 = gnark_compressed_x_to_g1_point(&buffer[..32])?;
    let lro1 = gnark_compressed_x_to_g1_point(&buffer[32..64])?;
    let lro2 = gnark_compressed_x_to_g1_point(&buffer[64..96])?;

    let z = gnark_compressed_x_to_g1_point(&buffer[96..128])?;

    let h0 = gnark_compressed_x_to_g1_point(&buffer[128..160])?;
    let h1 = gnark_compressed_x_to_g1_point(&buffer[160..192])?;
    let h2 = gnark_compressed_x_to_g1_point(&buffer[192..224])?;

    let num_bsb22_commitments = u16::from_be_bytes([buffer[224], buffer[225]]);
    let mut bsb22_commitments = Vec::new();
    let mut offset = 226;
    for _ in 0..num_bsb22_commitments {
        let commitment = gnark_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
        bsb22_commitments.push(commitment);
        offset += 32;
    }

    let batched_proof_h = gnark_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;

    let num_claimed_values = u16::from_be_bytes([buffer[offset + 32], buffer[offset + 33]]);
    let mut claimed_values = Vec::new();
    offset += 34;
    for _ in 0..num_claimed_values {
        let value = Fr::from_be_bytes_mod_order(&buffer[offset..offset + 32]);
        claimed_values.push(value);
        offset += 32;
    }

    let z_shifted_opening_h = gnark_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
    let z_shifted_opening_value = Fr::from_be_bytes_mod_order(&buffer[offset + 32..offset + 64]);

    Ok(Proof {
        lro: [lro0, lro1, lro2],
        z,
        h: [h0, h1, h2],
        bsb22_commitments,
        batched_proof: BatchOpeningProof {
            h: batched_proof_h,
            claimed_values,
        },
        z_shifted_opening: OpeningProof {
            h: z_shifted_opening_h,
            claimed_value: z_shifted_opening_value,
        },
    })
}

pub(crate) fn g1_to_bytes(g1: &G1Affine) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    let value_x = g1
        .x()
        .expect(ERR_FAILED_TO_GET_X)
        .into_bigint()
        .to_bytes_be();
    let value_y = g1
        .y()
        .expect(ERR_FAILED_TO_GET_Y)
        .into_bigint()
        .to_bytes_be();
    bytes.extend_from_slice(&value_x);
    bytes.extend_from_slice(&value_y);
    Ok(bytes)
}
