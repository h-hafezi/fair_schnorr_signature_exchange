use std::ops::Mul;

use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::Rng;
use rayon::iter::ParallelIterator;
use rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator};

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
        // Sequential random generation (since rng is not thread-safe)
        let r: Vec<G1::ScalarField> = (0..self.n).map(|_| G1::ScalarField::rand(rng)).collect();

        // Parallel scalar multiplication using rayon
        let r_g: Vec<Projective<G1>> = r.par_iter().map(|r_i| self.g.mul(*r_i)).collect();

        // Return the tuple of (r, g^r)
        (FDESignerSecretRandomness { r }, FDESignerFirstRoundMessage { r_g })
    }

    pub fn second_round<R: Rng>(&self,
                                secret_randomness: &FDESignerSecretRandomness<G1>,
                                m1: &FDEVerifierFirstRoundMessage<G1>,
                                rng: &mut R,
    ) -> FDESignerSecondRoundMessage<G1> {
        // Random generation is kept sequential
        let k = G1::ScalarField::rand(rng);
        let com_k: Projective<G1> = self.g.mul(k);

        // Parallelize vec_s computation
        let vec_s: Vec<G1::ScalarField> = (0..secret_randomness.r.len())
            .into_par_iter()
            .map(|i| secret_randomness.r[i] + m1.c[i] * self.sk.sk)
            .collect();

        // Parallelize vec_g_s computation (g^s)
        let vec_g_s: Vec<Projective<G1>> = vec_s
            .par_iter()
            .map(|s| self.g.mul(*s))
            .collect();

        // Parallelize alpha computation ((s + k) / 2)
        let alpha: Vec<G1::ScalarField> = vec_s
            .par_iter()
            .map(|s| (*s + k) / G1::ScalarField::from(2u8))
            .collect();

        // Return the second round message
        FDESignerSecondRoundMessage {
            com_k,
            alpha,
            com: vec_g_s,
        }
    }
}
