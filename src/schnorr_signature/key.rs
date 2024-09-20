use std::ops::Mul;
use ark_ec::Group;
use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use rand::Rng;

#[derive(Clone, Debug, Default)]
pub struct SecretKey<E: Pairing> {
    pub sk: E::ScalarField,
}

#[derive(Clone, Debug, Default)]
pub struct PublicKey<E: Pairing> {
    pub pk: E::G1,
}

pub fn generate_key_pair<E: Pairing, R: Rng>(rng: &mut R) -> (SecretKey<E>, PublicKey<E>) {
    let sk = E::ScalarField::rand(rng);
    (
        SecretKey { sk },
        PublicKey { pk: E::G1::generator().mul(sk) }
    )
}
