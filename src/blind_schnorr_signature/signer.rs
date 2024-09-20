use std::ops::Mul;

use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::Rng;

use crate::blind_schnorr_signature::verifier::BSVerifierFirstRoundMessage;
use crate::schnorr_signature::key::SecretKey;
use crate::schnorr_signature::signer::Signer;

pub struct BSSigner<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub sk: SecretKey<G1>,
    pub g: Projective<G1>,
}

pub struct BSSignerSecretRandomness<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub r: G1::ScalarField,
}

pub struct BSSignerFirstRoundMessage<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub r_g: Projective<G1>,
}

pub struct BSSignerSecondRoundMessage<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub s: G1::ScalarField,
}


impl<G1> BSSigner<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub fn new(signer: &Signer<G1>) -> Self {
        BSSigner {
            sk: signer.get_secret_key(),
            g: signer.get_generator(),
        }
    }

    pub fn first_round<R: Rng>(&self, rng: &mut R) -> (BSSignerSecretRandomness<G1>, BSSignerFirstRoundMessage<G1>) {
        let r = G1::ScalarField::rand(rng);
        let r_g = self.g.mul(r);

        // return the tuple of (r, g^r)
        (BSSignerSecretRandomness { r }, BSSignerFirstRoundMessage { r_g })
    }

    pub fn second_round(&self, secret_randomness: &BSSignerSecretRandomness<G1>, m1: &BSVerifierFirstRoundMessage<G1>) -> BSSignerSecondRoundMessage<G1> {
        BSSignerSecondRoundMessage { s: secret_randomness.r + self.sk.sk * m1.c }
    }
}

