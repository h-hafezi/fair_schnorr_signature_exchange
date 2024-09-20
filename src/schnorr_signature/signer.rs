use std::ops::Mul;

use ark_ec::{Group};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::Rng;

use crate::hash::Hash256;
use crate::schnorr_signature::key::SecretKey;
use crate::schnorr_signature::signature::Signature;
use crate::schnorr_signature::util::group_element_into_bytes;

pub struct Signer<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub sk: SecretKey<G1>,
    pub g: Projective<G1>,
}

impl<G1> Signer<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub fn new(sk: SecretKey<G1>) -> Signer<G1> {
        Signer {
            sk,
            g: Projective::generator(),
        }
    }
}

impl<G1> Signer<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub(crate) fn get_generator(&self) -> Projective<G1> {
        self.g.clone()
    }

    pub(crate) fn get_secret_key(&self) -> SecretKey<G1> {
        self.sk.clone()
    }

    pub(crate) fn sign<R: Rng>(&self, message: &Vec<u8>, rng: &mut R) -> Signature<G1> {
        // Random nonce
        let r = G1::ScalarField::rand(rng);
        // R = g^r
        let r_g = self.get_generator().mul(r);

        let c: G1::ScalarField = {
            let mut bytes = group_element_into_bytes::<G1>(&r_g);
            bytes.extend(message);
            Hash256::hash_bytes(&bytes)
        };

        // Compute s = r - e * sk
        let s = r + c * self.sk.sk;

        Signature { s, r_g }
    }
}