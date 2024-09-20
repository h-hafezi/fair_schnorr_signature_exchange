use std::ops::Mul;

use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use rand::Rng;

use crate::fde::verifier::FDEVerifierFirstRoundMessage;
use crate::schnorr_signature::key::SecretKey;
use crate::schnorr_signature::signer::Signer;

#[derive(Clone, Debug, Default)]
pub struct FDESigner<E: Pairing> {
    pub sk: SecretKey<E>,
    pub g: E::G1,
    pub n: usize,
}

#[derive(Clone, Debug, Default)]
pub struct FDESignerSecretRandomness<E: Pairing> {
    pub r: Vec<E::ScalarField>,
}

#[derive(Clone, Debug, Default)]
pub struct FDESignerFirstRoundMessage<E: Pairing> {
    pub r_g: Vec<E::G1>,
}

#[derive(Clone, Debug, Default)]
pub struct FDESignerSecondRoundMessage<E: Pairing> {
    pub com_k: E::G1,
    pub alpha: Vec<E::ScalarField>,
    pub com: Vec<E::G1>,
}

impl<E: Pairing> FDESigner<E> {
    pub fn new(signer: &Signer<E>, n: usize) -> FDESigner<E> {
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

    pub fn second_round<R: Rng>(&self, secret_randomness: FDESignerSecretRandomness<E>, m1: FDEVerifierFirstRoundMessage<E>, rng: &mut R) -> FDESignerSecondRoundMessage<E> {
        let k = E::ScalarField::rand(rng);
        let com_k: E::G1 = self.g.mul(k);

        let vec_s = {
            let mut temp = Vec::new();
            for i in 0..secret_randomness.r.len() {
                let val: E::ScalarField = secret_randomness.r[i] + m1.c[i] * self.sk.sk;
                temp.push(val);
            }
            temp
        };

        let vec_g_s = {
            let mut temp: Vec<E::G1> = Vec::new();
            for s in vec_s.clone() {
                temp.push(self.g.mul(s));
            }
            temp
        };

        let alpha = {
            let mut temp = Vec::new();
            for s in vec_s.clone() {
                let val: E::ScalarField = (s + k) / E::ScalarField::from(2u8);
                temp.push(val);
            }
            temp
        };

        FDESignerSecondRoundMessage {
            com_k,
            alpha,
            com: vec_g_s,
        }
    }
}