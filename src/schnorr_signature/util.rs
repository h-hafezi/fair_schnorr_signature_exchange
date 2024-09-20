use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};

pub fn group_element_into_bytes<E: Pairing>(g: E::G1) -> Vec<u8>
where
    <<E as Pairing>::G1Affine as AffineRepr>::BaseField: PrimeField,
{
    let mut res = g.into_affine().x().unwrap().into_bigint().to_bytes_le();
    res.extend(g.into_affine().y().unwrap().into_bigint().to_bytes_le());
    res
}