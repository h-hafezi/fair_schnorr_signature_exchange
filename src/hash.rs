use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_ff::{PrimeField};

pub struct Hash256;

impl Hash256 {
    /// Hash bytes element and convert the result into a new field element
    pub fn hash_bytes<F: PrimeField>(bytes: &[u8]) -> F {
        let hash_bytes = Sha256::evaluate(&(), bytes).unwrap();
        F::from_le_bytes_mod_order(&hash_bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::hash::Hash256;
    use ark_bn254::Fr;

    #[test]
    fn test_hash() {
        println!("{}", Hash256::hash_bytes::<Fr>(&[0u8, 0u8, 0u8, 0u8]));
    }
}