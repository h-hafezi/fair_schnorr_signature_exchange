use std::ops::Mul;

use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::Rng;
use rayon::iter::ParallelIterator;
use rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator};

use crate::blind_fse::verifier::BFDEVerifierFirstRoundMessage;
use crate::schnorr_signature::key::SecretKey;
use crate::schnorr_signature::signer::Signer;

#[derive(Clone, Debug, Default)]
pub struct BFDESigner<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub sk: SecretKey<G1>,
    pub g: Projective<G1>,
    pub n: usize,
}

#[derive(Clone, Debug, Default)]
pub struct BFDESignerSecretRandomness<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub r0: Vec<G1::ScalarField>,
    pub r1: Vec<G1::ScalarField>,
}

#[derive(Clone, Debug, Default)]
pub struct BFDESignerFirstRoundMessage<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub r0_g: Vec<Projective<G1>>,
    pub r1_g: Vec<Projective<G1>>,
}

#[derive(Clone, Debug, Default)]
pub struct BFDESignerSecondRoundMessage<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub com_k: Projective<G1>,
    pub alpha: Vec<G1::ScalarField>,
    pub com: Vec<Projective<G1>>,
    pub b: bool,
}

impl<G1> BFDESigner<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub fn new(signer: &Signer<G1>, n: usize) -> BFDESigner<G1> {
        BFDESigner {
            sk: signer.get_secret_key(),
            g: signer.get_generator(),
            n,
        }
    }

    pub fn first_round<R: Rng>(&self, rng: &mut R) -> (BFDESignerSecretRandomness<G1>, BFDESignerFirstRoundMessage<G1>) {
        // Sequential random generation (since rng is not thread-safe)
        let r0: Vec<G1::ScalarField> = (0..self.n).map(|_| G1::ScalarField::rand(rng)).collect();
        let r1: Vec<G1::ScalarField> = (0..self.n).map(|_| G1::ScalarField::rand(rng)).collect();

        // Parallel scalar multiplication using rayon
        let r0_g: Vec<Projective<G1>> = r0.par_iter().map(|r_i| self.g.mul(*r_i)).collect();
        let r1_g: Vec<Projective<G1>> = r1.par_iter().map(|r_i| self.g.mul(*r_i)).collect();

        // Return the tuple of (r, g^r)
        (BFDESignerSecretRandomness { r0, r1 }, BFDESignerFirstRoundMessage { r0_g, r1_g })
    }

    pub fn second_round<R: Rng>(&self,
                                secret_randomness: &BFDESignerSecretRandomness<G1>,
                                m1: &BFDEVerifierFirstRoundMessage<G1>,
                                rng: &mut R,
    ) -> BFDESignerSecondRoundMessage<G1> {
        let b = bool::rand(rng);

        // Random generation is kept sequential
        let k = G1::ScalarField::rand(rng);
        let com_k: Projective<G1> = self.g.mul(k);

        let (r, c) = {
            if b == true {
                (&secret_randomness.r1, &m1.c1)
            } else {
                (&secret_randomness.r0, &m1.c0)
            }
        };

        // Parallelize vec_s computation
        let vec_s: Vec<G1::ScalarField> = (0..r.len())
            .into_par_iter()
            .map(|i| r[i] + c[i] * self.sk.sk)
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
        BFDESignerSecondRoundMessage {
            com_k,
            alpha,
            com: vec_g_s,
            b,
        }
    }
}
