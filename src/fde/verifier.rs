/*use std::ops::Mul;
use ark_ec::AffineRepr;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::Rng;
use crate::hash::Hash256;
use crate::schnorr_signature::key::PublicKey;
use crate::schnorr_signature::util::group_element_into_bytes;
use crate::schnorr_signature::verifier::Verifier;
use std::ops::Add;

pub struct FDEVerifier<E: Pairing> {
    pub pk: PublicKey<E>,
    pub g: E::G1,
    pub n: usize,
}

pub struct FDEVerifierSecretRandomness<E: Pairing> {
    pub alpha: E::ScalarField,
    pub beta: E::ScalarField,
}

pub struct FDEVerifierFirstRoundMessage<E: Pairing> {
    pub c: Vec<E::ScalarField>,
}

impl<E: Pairing> FDEVerifier<E> {
    pub fn new(verifier: &Verifier<E>, n: usize) -> FDEVerifier<E> {
        FDEVerifier {
            pk: verifier.get_public_key(),
            g: verifier.get_generator(),
            n,
        }
    }

    pub fn first_round<R: Rng>(&self,
                               m1: &FDESignerFirstRoundMessage<E>,
                               message: Vec<Vec<u8>>,
                               rng: &mut R,
    ) -> (FDEVerifier<E>, FDEVerifierFirstRoundMessage<E>)
    where
        <<E as Pairing>::G1Affine as AffineRepr>::BaseField: PrimeField,
    {
        let alpha = E::ScalarField::rand(rng);
        let beta = E::ScalarField::rand(rng);

        let mut vec_c = Vec::new();
        for i in 0..self.n {
            // R' = R * g^{alpha} * pk^{beta}
            let r_g_prime: E::G1 = {
                let mut temp = self.g.mul(alpha);
                temp = temp.add(self.pk.pk.mul(beta));
                temp = temp.add(m1[i].r_g);
                temp
            };

            let c_prime: E::ScalarField = {
                let mut bytes = group_element_into_bytes::<E>(r_g_prime);
                bytes.extend(message[i].clone());
                Hash256::hash_bytes(bytes.as_slice())
            };

            let c = c_prime + beta;

            vec_c.push(c);
        }

        (FDEVerifierSecretRandomness { alpha, beta }, FDEVerifierFirstRoundMessage { c: vec_c })
    }
}
 */
