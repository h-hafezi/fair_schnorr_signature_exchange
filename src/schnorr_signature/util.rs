use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{PrimeField};

pub fn group_element_into_bytes<G1>(g: &Projective<G1>) -> Vec<u8>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    vec![0u8, 1u8, 2u8, 3u8]
}