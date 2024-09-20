use std::ops::Mul;

use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::Rng;

use crate::fde::verifier::FDEVerifierFirstRoundMessage;
use crate::schnorr_signature::key::SecretKey;
use crate::schnorr_signature::signer::Signer;

#[derive(Clone, Debug, Default)]
pub struct FDESigner<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub sk: SecretKey<G1>,
    pub g: Projective<G1>,
    pub n: usize,
}

#[derive(Clone, Debug, Default)]
pub struct FDESignerSecretRandomness<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub r: Vec<G1::ScalarField>,
}

#[derive(Clone, Debug, Default)]
pub struct FDESignerFirstRoundMessage<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub r_g: Vec<Projective<G1>>,
}

#[derive(Clone, Debug, Default)]
pub struct FDESignerSecondRoundMessage<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub com_k: Projective<G1>,
    pub alpha: Vec<G1::ScalarField>,
    pub com: Vec<Projective<G1>>,
}

impl<G1> FDESigner<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub fn new(signer: &Signer<G1>, n: usize) -> FDESigner<G1> {
        FDESigner {
            sk: signer.get_secret_key(),
            g: signer.get_generator(),
            n,
        }
    }

    pub fn first_round<R: Rng>(&self, rng: &mut R) -> (FDESignerSecretRandomness<G1>, FDESignerFirstRoundMessage<G1>) {
        let mut r = Vec::new();
        let mut r_g = Vec::new();

        for _ in 0..self.n {
            let r_i = G1::ScalarField::rand(rng);
            r.push(r_i);
            r_g.push(self.g.mul(r_i));
        }

        // return the tuple of (r, g^r)
        (FDESignerSecretRandomness { r }, FDESignerFirstRoundMessage { r_g })
    }

    pub fn second_round<R: Rng>(&self,
                                secret_randomness: FDESignerSecretRandomness<G1>,
                                m1: FDEVerifierFirstRoundMessage<G1>,
                                rng: &mut R,
    ) -> FDESignerSecondRoundMessage<G1> {
        let k = G1::ScalarField::rand(rng);
        let com_k: Projective<G1> = self.g.mul(k);

        let vec_s = {
            let mut temp = Vec::new();
            for i in 0..secret_randomness.r.len() {
                let val: G1::ScalarField = secret_randomness.r[i] + m1.c[i] * self.sk.sk;
                temp.push(val);
            }
            temp
        };

        let vec_g_s = {
            let mut temp: Vec<Projective<G1>> = Vec::new();
            for s in vec_s.clone() {
                temp.push(self.g.mul(s));
            }
            temp
        };

        let alpha = {
            let mut temp = Vec::new();
            for s in vec_s.clone() {
                let val: G1::ScalarField = (s + k) / G1::ScalarField::from(2u8);
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
