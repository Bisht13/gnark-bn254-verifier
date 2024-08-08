use anyhow::{Ok, Result};
use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, Zero};
use lazy_static::lazy_static;
use num_bigint::{BigInt, Sign};
use num_traits::Num;
use std::cmp::Ordering;

use crate::constants::ERR_FAILED_TO_GET_FR_FROM_RANDOM_BYTES;

#[derive(Clone, Debug)]
pub(crate) struct PlonkFr(Fr);

lazy_static! {
    static ref MODULUS: BigInt = BigInt::from_str_radix(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10
    )
    .unwrap();
}

impl PlonkFr {
    pub(crate) fn set_bytes(bytes: &[u8]) -> Result<Self> {
        let biguint_bytes = BigInt::from_bytes_be(Sign::Plus, bytes);

        let cmp = biguint_bytes.cmp(&MODULUS);
        if cmp == Ordering::Equal {
            return Ok(PlonkFr(Fr::zero()));
        } else if cmp != Ordering::Greater && bytes.cmp(&[0u8; 32][..]) != Ordering::Less {
            return Ok(PlonkFr(Fr::from_be_bytes_mod_order(bytes)));
        }

        // Mod the bytes with MODULUS
        let biguint_bytes = BigInt::from_bytes_be(Sign::Plus, bytes);
        let biguint_mod = biguint_bytes % &*MODULUS;
        let (_, bytes_le) = biguint_mod.to_bytes_le();
        let e = Fr::from_random_bytes(&bytes_le).expect(ERR_FAILED_TO_GET_FR_FROM_RANDOM_BYTES);

        Ok(PlonkFr(e))
    }

    pub(crate) fn into_fr(self) -> Result<Fr> {
        Ok(self.0)
    }
}
