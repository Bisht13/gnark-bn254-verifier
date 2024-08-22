use anyhow::{anyhow, Error, Result};
use ark_serialize::SerializationError;
use std::cmp::Ordering;
use substrate_bn::{AffineG1, Fq, Fr, G2};

use crate::{
    constants::{
        GNARK_COMPRESSED_INFINITY, GNARK_COMPRESSED_NEGATIVE, GNARK_COMPRESSED_POSTIVE, GNARK_MASK,
    },
    converter::{gnark_commpressed_x_to_ark_commpressed_x, is_zeroed},
};

use super::{
    kzg::{self, BatchOpeningProof, LineEvaluationAff, OpeningProof, E2},
    verify::PlonkVerifyingKey,
    PlonkProof,
};

fn gnark_compressed_x_to_g1_point(buf: &[u8]) -> Result<AffineG1> {
    if buf.len() != 32 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let m_data = buf[0] & GNARK_MASK;
    if m_data == GNARK_COMPRESSED_INFINITY {
        if !is_zeroed(buf[0] & !GNARK_MASK, &buf[1..32])? {
            return Err(anyhow!(SerializationError::InvalidData));
        }
        Ok(AffineG1::identity())
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !GNARK_MASK;

        let x = Fq::from_slice(&x_bytes.to_vec()).map_err(Error::msg)?;
        let (y, neg_y) = AffineG1::get_ys_from_x_unchecked(x)
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

        let p = AffineG1::new(x, final_y).map_err(Error::msg)?;

        Ok(p)
    }
}

fn gnark_compressed_x_to_g2_point(buf: &[u8]) -> Result<G2> {
    if buf.len() != 64 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let bytes = gnark_commpressed_x_to_ark_commpressed_x(&buf.to_vec())?;
    let p = G2::from_compressed(&bytes).map_err(Error::msg)?;
    Ok(p)
}

pub fn gnark_uncompressed_bytes_to_g1_point(buf: &[u8]) -> Result<AffineG1> {
    if buf.len() != 64 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let (x_bytes, y_bytes) = buf.split_at(32);

    let x = Fq::from_slice(&x_bytes.to_vec()).map_err(Error::msg)?;
    let y = Fq::from_slice(&y_bytes.to_vec()).map_err(Error::msg)?;
    let p = AffineG1::new(x, y).map_err(Error::msg)?;

    Ok(p)
}

pub(crate) fn load_plonk_verifying_key_from_bytes(buffer: &[u8]) -> Result<PlonkVerifyingKey> {
    let size = u64::from_be_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]) as usize;
    let size_inv = Fr::from_slice(&buffer[8..40]).map_err(Error::msg)?;
    let generator = Fr::from_slice(&buffer[40..72]).map_err(|err| anyhow!("{err:?}"))?;
    let nb_public_variables = u64::from_be_bytes([
        buffer[72], buffer[73], buffer[74], buffer[75], buffer[76], buffer[77], buffer[78],
        buffer[79],
    ]) as usize;
    let coset_shift = Fr::from_slice(&buffer[80..112]).map_err(|err| anyhow!("{err:?}"))?;

    let s0 = gnark_compressed_x_to_g1_point(&buffer[112..144])?;
    let s1 = gnark_compressed_x_to_g1_point(&buffer[144..176])?;
    let s2 = gnark_compressed_x_to_g1_point(&buffer[176..208])?;

    let ql = gnark_compressed_x_to_g1_point(&buffer[208..240])?;
    let qr = gnark_compressed_x_to_g1_point(&buffer[240..272])?;
    let qm = gnark_compressed_x_to_g1_point(&buffer[272..304])?;
    let qo = gnark_compressed_x_to_g1_point(&buffer[304..336])?;
    let qk = gnark_compressed_x_to_g1_point(&buffer[336..368])?;

    let num_qcp = u32::from_be_bytes([buffer[368], buffer[369], buffer[370], buffer[371]]);
    let mut qcp = Vec::new();
    let mut offset = 372;
    for _ in 0..num_qcp {
        let point = gnark_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
        qcp.push(point);
        offset += 32;
    }

    let g1 = gnark_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
    let g2_0 = gnark_compressed_x_to_g2_point(&buffer[offset + 32..offset + 96])?;
    let g2_1 = gnark_compressed_x_to_g2_point(&buffer[offset + 96..offset + 160])?;

    // Skip 33788 bytes
    offset += 160 + 33788;

    let num_commitment_constraint_indexes = u64::from_be_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ]) as usize;
    let mut commitment_constraint_indexes = Vec::new();
    offset += 8;
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

    Ok(PlonkVerifyingKey {
        size,
        size_inv,
        generator,
        nb_public_variables,
        kzg: kzg::KZGVerifyingKey {
            g2: [g2_0, g2_1],
            g1,
            lines: [[[LineEvaluationAff {
                r0: E2 {
                    a0: Fr::zero(),
                    a1: Fr::zero(),
                },
                r1: E2 {
                    a0: Fr::zero(),
                    a1: Fr::zero(),
                },
            }; 66]; 2]; 2],
        },
        coset_shift,
        s: [s0, s1, s2],
        ql,
        qr,
        qm,
        qo,
        qk,
        qcp,
        commitment_constraint_indexes,
    })
}

pub(crate) fn load_plonk_proof_from_bytes(buffer: &[u8]) -> Result<PlonkProof> {
    let lro0 = gnark_uncompressed_bytes_to_g1_point(&buffer[..64])?;
    let lro1 = gnark_uncompressed_bytes_to_g1_point(&buffer[64..128])?;
    let lro2 = gnark_uncompressed_bytes_to_g1_point(&buffer[128..192])?;

    let z = gnark_uncompressed_bytes_to_g1_point(&buffer[192..256])?;

    let h0 = gnark_uncompressed_bytes_to_g1_point(&buffer[256..320])?;
    let h1 = gnark_uncompressed_bytes_to_g1_point(&buffer[320..384])?;
    let h2 = gnark_uncompressed_bytes_to_g1_point(&buffer[384..448])?;

    let batched_proof_h = gnark_uncompressed_bytes_to_g1_point(&buffer[448..512])?;

    let num_claimed_values =
        u32::from_be_bytes([buffer[512], buffer[513], buffer[514], buffer[515]]) as usize;

    let mut claimed_values = Vec::new();
    let mut offset = 516;
    for _ in 0..num_claimed_values {
        let value = Fr::from_slice(&buffer[offset..offset + 32]).map_err(Error::msg)?;
        claimed_values.push(value);
        offset += 32;
    }

    let z_shifted_opening_h = gnark_uncompressed_bytes_to_g1_point(&buffer[offset..offset + 64])?;
    let z_shifted_opening_value =
        Fr::from_slice(&buffer[offset + 64..offset + 96]).map_err(Error::msg)?;

    let num_bsb22_commitments = u32::from_be_bytes([
        buffer[offset + 96],
        buffer[offset + 97],
        buffer[offset + 98],
        buffer[offset + 99],
    ]) as usize;
    let mut bsb22_commitments = Vec::new();
    offset += 100;
    for _ in 0..num_bsb22_commitments {
        let commitment = gnark_uncompressed_bytes_to_g1_point(&buffer[offset..offset + 64])?;
        bsb22_commitments.push(commitment);
        offset += 64;
    }

    Ok(PlonkProof {
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

pub(crate) fn g1_to_bytes(g1: &AffineG1) -> Result<Vec<u8>> {
    let mut bytes = vec![];
    g1.x()
        .to_big_endian(&mut bytes)
        .map_err(|err| anyhow!("{err:?}"))?;
    g1.y()
        .to_big_endian(&mut bytes)
        .map_err(|err| anyhow!("{err:?}"))?;
    Ok(bytes)
}
