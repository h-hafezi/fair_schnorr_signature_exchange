use std::ops::Mul;

use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use rand::Rng;

use crate::blind_schnorr_signature::verifier::BSVerifierFirstRoundMessage;
use crate::schnorr_signature::key::SecretKey;
use crate::schnorr_signature::signer::Signer;

pub struct BSSigner<E: Pairing> {
    pub sk: SecretKey<E>,
    pub g: E::G1,
}

pub struct BSSignerSecretRandomness<E: Pairing> {
    pub r: E::ScalarField,
}

pub struct BSSignerFirstRoundMessage<E: Pairing> {
    pub r_g: E::G1,
}

pub struct BSSignerSecondRoundMessage<E: Pairing> {
    pub s: E::ScalarField,
}


impl<E: Pairing> BSSigner<E> {
    pub fn new(signer: &Signer<E>) -> Self {
        BSSigner {
            sk: signer.get_secret_key(),
            g: signer.get_generator(),
        }
    }

    pub fn first_round<R: Rng>(&self, rng: &mut R) -> (BSSignerSecretRandomness<E>, BSSignerFirstRoundMessage<E>) {
        let r = E::ScalarField::rand(rng);
        let r_g = self.g.mul(r);

        // return the tuple of (r, g^r)
        (BSSignerSecretRandomness { r }, BSSignerFirstRoundMessage { r_g })
    }

    pub fn second_round(&self, secret_randomness: &BSSignerSecretRandomness<E>, m1: &BSVerifierFirstRoundMessage<E>) -> BSSignerSecondRoundMessage<E> {
        BSSignerSecondRoundMessage { s: secret_randomness.r + self.sk.sk * m1.c }
    }
}

