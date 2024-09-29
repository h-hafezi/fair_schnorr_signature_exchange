use std::ops::Add;
use std::ops::Mul;

use ark_ec::{CurveConfig, Group};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::Rng;
use rayon::iter::ParallelIterator;
use rayon::prelude::IntoParallelIterator;

use crate::fde::signer::{FDESignerFirstRoundMessage, FDESignerSecondRoundMessage};
use crate::hash::Hash256;
use crate::schnorr_signature::key::PublicKey;
use crate::schnorr_signature::util::group_element_into_bytes;
use crate::schnorr_signature::verifier::Verifier;

#[derive(Clone, Debug, Default)]
pub struct FDEVerifier<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub pk: PublicKey<G1>,
    pub g: Projective<G1>,
    pub n: usize,
}

#[derive(Clone, Debug, Default)]
pub struct FDEVerifierSecretRandomness<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub alpha_0: G1::ScalarField,
    pub beta_0: G1::ScalarField,
    pub alpha_1: G1::ScalarField,
    pub beta_1: G1::ScalarField,
}

#[derive(Clone, Debug, Default)]
pub struct FDEVerifierFirstRoundMessage<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub c0: Vec<G1::ScalarField>,
    pub c1: Vec<G1::ScalarField>,
}

impl<G1> FDEVerifier<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub fn new(verifier: &Verifier<G1>, n: usize) -> FDEVerifier<G1> {
        FDEVerifier {
            pk: verifier.pk.clone(),
            g: verifier.get_generator(),
            n,
        }
    }

    pub fn first_round<R: Rng>(&self,
                               m1: &FDESignerFirstRoundMessage<G1>,
                               message: &Vec<Vec<u8>>,
                               rng: &mut R,
    ) -> (FDEVerifierSecretRandomness<G1>, FDEVerifierFirstRoundMessage<G1>)
    where
        <G1 as CurveConfig>::BaseField: PrimeField,
    {
        let alpha_0 = G1::ScalarField::rand(rng);
        let beta_0 = G1::ScalarField::rand(rng);
        let alpha_1 = G1::ScalarField::rand(rng);
        let beta_1 = G1::ScalarField::rand(rng);

        // Parallelized the computation of vec_c using rayon's par_iter
        let vec_c0: Vec<G1::ScalarField> = (0..self.n).into_par_iter().map(|i| {
            // R' = R * g^{alpha} * pk^{beta}
            let r_g_prime: Projective<G1> = {
                let mut temp = self.g.mul(alpha_0);
                temp = temp.add(self.pk.pk.mul(beta_0));
                temp = temp.add(m1.r0_g[i]);
                temp
            };

            let c_prime: G1::ScalarField = {
                let mut bytes = group_element_into_bytes::<G1>(&r_g_prime);
                bytes.extend(message[i].clone());
                Hash256::hash_bytes(bytes.as_slice())
            };

            let c = c_prime + beta_0;
            c
        }).collect();

        // Parallelized the computation of vec_c using rayon's par_iter
        let vec_c1: Vec<G1::ScalarField> = (0..self.n).into_par_iter().map(|i| {
            // R' = R * g^{alpha} * pk^{beta}
            let r_g_prime: Projective<G1> = {
                let mut temp = self.g.mul(alpha_1);
                temp = temp.add(self.pk.pk.mul(beta_1));
                temp = temp.add(m1.r1_g[i]);
                temp
            };

            let c_prime: G1::ScalarField = {
                let mut bytes = group_element_into_bytes::<G1>(&r_g_prime);
                bytes.extend(message[i].clone());
                Hash256::hash_bytes(bytes.as_slice())
            };

            let c = c_prime + beta_1;
            c
        }).collect();


        (FDEVerifierSecretRandomness { alpha_0, beta_0, alpha_1, beta_1 }, FDEVerifierFirstRoundMessage { c0: vec_c0, c1: vec_c1 })
    }

    pub fn second_round(&self,
                        m1: &FDESignerFirstRoundMessage<G1>,
                        m2: &FDEVerifierFirstRoundMessage<G1>,
                        m3: &FDESignerSecondRoundMessage<G1>,
    ) -> bool
    {
        let (r_g, c) = {
            if m3.b == true {
                (&m1.r1_g, &m2.c1)
            } else {
                (&m1.r0_g, &m2.c0)
            }
        };

        // compute a vector of boolean and add them
        let res: bool = (0..self.n).into_par_iter().map(|i| {
            // com_i = R_i * pk^c_i
            let temp = r_g[i].add(self.pk.pk.mul(c[i]));
            let first_check = m3.com[i] == temp;

            // g^a_i = (com_k * com_i)^{1/2}
            let lhs: Projective<G1> = {
                let temp = self.g.mul(m3.alpha[i]);
                temp.double()
            };
            let rhs: Projective<G1> = m3.com_k.add(m3.com[i]);
            let second_check = lhs == rhs;

            // Return the result of both checks
            first_check && second_check
        }).reduce(|| true, |acc, x| acc && x);

        res
    }
}

