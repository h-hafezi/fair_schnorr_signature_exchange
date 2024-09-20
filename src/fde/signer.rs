/*use std::ops::Mul;

use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use rand::Rng;

use crate::fde::verifier::FDEVerifierFirstRoundMessage;
use crate::schnorr_signature::key::SecretKey;
use crate::schnorr_signature::signer::Signer;

pub struct FDESigner<E: Pairing> {
    pub sk: SecretKey<E>,
    pub g: E::G1,
    pub n: usize,
}

pub struct FDESignerSecretRandomness<E: Pairing> {
    pub r: Vec<E::ScalarField>,
}

pub struct FDESignerFirstRoundMessage<E: Pairing> {
    pub r_g: Vec<E::G1>,
}

pub struct FDESignerSecondRoundMessage<E: Pairing> {
    pub com_k: E::G1,
    pub alpha: Vec<E::ScalarField>,
    pub com: Vec<E::G1>,
}

impl<E: Pairing> FDESigner<E> {
    pub fn new(signer: Signer<E>, n: usize) -> FDESigner<E> {
        FDESigner {
            sk: signer.get_secret_key(),
            g: signer.get_generator(),
            n,
        }
    }

    pub fn first_round<R: Rng>(&self, rng: &mut R) -> (FDESignerSecretRandomness<E>, FDESignerFirstRoundMessage<E>) {
        let mut r = Vec::new();
        let mut r_g = Vec::new();

        for i in 0..self.n {
            let r_i = E::ScalarField::rand(rng);
            r.push(r_i);
            r_g.push(self.g.mul(r_i));
        }

        // return the tuple of (r, g^r)
        (FDESignerSecretRandomness { r }, FDESignerFirstRoundMessage { r_g })
    }

    pub fn second_round<R: Rng>(&self, secret_randomness: FDESignerSecretRandomness<E>, m1: FDEVerifierFirstRoundMessage<E>, rng: &mut R) {
        let k = E::ScalarField::rand(rng);
        let g_k = self.g.mul(k);
    }
}