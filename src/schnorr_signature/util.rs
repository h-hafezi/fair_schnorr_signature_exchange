use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{BigInteger, PrimeField};

pub fn group_element_into_bytes<G1>(g: &Projective<G1>) -> Vec<u8>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
    G1::BaseField: PrimeField,
{
    let mut res = g.into_affine().x().unwrap().into_bigint().to_bytes_le();
    res.extend(g.into_affine().y().unwrap().into_bigint().to_bytes_le());
    res
}