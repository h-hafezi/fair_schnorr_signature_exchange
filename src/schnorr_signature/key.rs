use std::ops::Mul;

use ark_ec::Group;
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::Rng;

#[derive(Clone, Debug, Default)]
pub struct SecretKey<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub sk: G1::ScalarField,
}

#[derive(Clone, Debug, Default)]
pub struct PublicKey<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub pk: Projective<G1>,
}

pub fn generate_key_pair<G1, R>(rng: &mut R) -> (SecretKey<G1>, PublicKey<G1>)
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
    R: Rng,
{
    let sk = G1::ScalarField::rand(rng);
    (
        SecretKey { sk },
        PublicKey { pk: Projective::generator().mul(sk) }
    )
}
