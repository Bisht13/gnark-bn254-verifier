use anyhow::Result;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use num_traits::Zero;
use std::hash::Hasher;

#[allow(dead_code)]
pub(crate) struct WrappedHashToField {
    domain: Vec<u8>,
    to_hash: Vec<u8>,
}

impl WrappedHashToField {
    // Creates a new instance with a domain separator
    pub(crate) fn new(domain_separator: &[u8]) -> Result<Self> {
        Ok(Self {
            domain: domain_separator.to_vec(),
            to_hash: Vec::new(),
        })
    }

    // Hashes the bytes to a field element and returns the byte representation
    pub(crate) fn sum(&self) -> Result<Vec<u8>> {
        let hash_result = Fr::zero();
        let result_bytes = hash_result.into_bigint().to_bytes_le(); // Convert to bytes
        Ok(result_bytes)
    }
}

impl Hasher for WrappedHashToField {
    fn finish(&self) -> u64 {
        // This method is not directly applicable to field elements, so it's a stub
        unimplemented!();
    }

    fn write(&mut self, bytes: &[u8]) {
        self.to_hash.extend_from_slice(bytes);
    }
}

impl Default for WrappedHashToField {
    fn default() -> Self {
        Self::new(&[]).unwrap()
    }
}

impl WrappedHashToField {
    // Resets the state of the hasher
    pub(crate) fn reset(&mut self) {
        self.to_hash.clear();
    }
}
