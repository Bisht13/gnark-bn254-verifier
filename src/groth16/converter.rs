use anyhow::{anyhow, Error, Result};
use ark_bn254::{Fq, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, SerializationError};
use std::{
    cmp::{Ord, Ordering},
    ops::Neg,
};

use crate::{
    constants::{
        GNARK_COMPRESSED_INFINITY, GNARK_COMPRESSED_NEGATIVE, GNARK_COMPRESSED_POSTIVE, GNARK_MASK,
    },
    converter::{gnark_commpressed_x_to_ark_commpressed_x, is_zeroed},
};

use super::{
    verify::{Groth16G1, Groth16G2, Groth16VerifyingKey, PedersenVerifyingKey},
    Groth16Proof,
};

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

fn gnark_compressed_x_to_g2_point(buf: &[u8]) -> Result<G2Affine> {
    if buf.len() != 64 {
        return Err(anyhow!(SerializationError::InvalidData));
    };

    let bytes = gnark_commpressed_x_to_ark_commpressed_x(&buf.to_vec())?;
    let p = G2Affine::deserialize_compressed::<&[u8]>(&bytes).map_err(Error::msg)?;
    Ok(p)
}

pub(crate) fn load_groth16_proof_from_bytes(buffer: &[u8]) -> Result<Groth16Proof> {
    let ar = gnark_compressed_x_to_g1_point(&buffer[..32])?;
    let bs = gnark_compressed_x_to_g2_point(&buffer[32..96])?;
    let krs = gnark_compressed_x_to_g1_point(&buffer[96..128])?;

    Ok(Groth16Proof {
        ar,
        bs,
        krs,
        commitments: Vec::new(),
        commitment_pok: G1Affine::identity(),
    })
}

pub(crate) fn load_groth16_verifying_key_from_bytes(buffer: &[u8]) -> Result<Groth16VerifyingKey> {
    let g1_alpha = gnark_compressed_x_to_g1_point(&buffer[..32])?;
    let g1_beta = gnark_compressed_x_to_g1_point(&buffer[32..64])?;
    let g2_beta = gnark_compressed_x_to_g2_point(&buffer[64..128])?;
    let g2_gamma = gnark_compressed_x_to_g2_point(&buffer[128..192])?;
    let g1_delta = gnark_compressed_x_to_g1_point(&buffer[192..224])?;
    let g2_delta = gnark_compressed_x_to_g2_point(&buffer[224..288])?;

    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut k = Vec::new();
    let mut offset = 292;
    for _ in 0..num_k {
        let point = gnark_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
        k.push(point);
        offset += 32;
    }

    let num_of_array_of_public_and_commitment_committed = u32::from_be_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;
    for _ in 0..num_of_array_of_public_and_commitment_committed {
        let num = u32::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]);
        offset += 4;
        for _ in 0..num {
            offset += 4;
        }
    }

    let commitment_key_g = gnark_compressed_x_to_g2_point(&buffer[offset..offset + 64])?;
    let commitment_key_g_root_sigma_neg =
        gnark_compressed_x_to_g2_point(&buffer[offset + 64..offset + 128])?;

    Ok(Groth16VerifyingKey {
        g1: Groth16G1 {
            alpha: g1_alpha,
            beta: g1_beta,
            delta: g1_delta,
            k,
        },
        g2: Groth16G2 {
            beta: g2_beta,
            gamma: g2_gamma,
            delta: g2_delta,
        },
        commitment_key: PedersenVerifyingKey {
            g: commitment_key_g,
            g_root_sigma_neg: commitment_key_g_root_sigma_neg,
        },
        public_and_commitment_committed: vec![vec![0u32; 0]],
    })
}
