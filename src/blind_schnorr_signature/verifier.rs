use std::ops::{Add, Mul};

use ark_ec::{AffineRepr, CurveGroup};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_std::UniformRand;
use rand::Rng;

use crate::blind_schnorr_signature::signer::{BSSignerFirstRoundMessage, BSSignerSecondRoundMessage};
use crate::hash::Hash256;
use crate::schnorr_signature::key::PublicKey;
use crate::schnorr_signature::signature::Signature;
use crate::schnorr_signature::util::group_element_into_bytes;
use crate::schnorr_signature::verifier::Verifier;

pub struct BSVerifier<E: Pairing> {
    pub pk: PublicKey<E>,
    pub g: E::G1,
}

pub struct BSVerifierSecretRandomness<E: Pairing> {
    pub alpha: E::ScalarField,
    pub beta: E::ScalarField,
}

pub struct BSVerifierFirstRoundMessage<E: Pairing> {
    pub c: E::ScalarField,
}

impl<E: Pairing> BSVerifier<E> {
    pub fn new(verifier: &Verifier<E>) -> Self {
        BSVerifier {
            pk: verifier.get_public_key(),
            g: verifier.get_generator(),
        }
    }

    pub fn first_round<R: Rng>(&self,
                               m1: &BSSignerFirstRoundMessage<E>,
                               message: Vec<u8>,
                               rng: &mut R,
    ) -> (BSVerifierSecretRandomness<E>, BSVerifierFirstRoundMessage<E>)
    where
        <<E as Pairing>::G1Affine as AffineRepr>::BaseField: PrimeField,
    {
        let alpha = E::ScalarField::rand(rng);
        let beta = E::ScalarField::rand(rng);

        // R' = R * g^{alpha} * pk^{beta}
        let r_g_prime: E::G1 = {
            let mut temp = self.g.mul(alpha);
            temp = temp.add(self.pk.pk.mul(beta));
            temp = temp.add(m1.r_g);
            temp
        };

        let c_prime: E::ScalarField = {
            let mut bytes = group_element_into_bytes::<E>(r_g_prime);
            bytes.extend(message);
            Hash256::hash_bytes(bytes.as_slice())
        };

        let c = c_prime + beta;

        (BSVerifierSecretRandomness { alpha, beta }, BSVerifierFirstRoundMessage { c })
    }

    pub fn second_round(&self,
                        secret_randomness: &BSVerifierSecretRandomness<E>,
                        m1: &BSSignerFirstRoundMessage<E>,
                        m2: &BSVerifierFirstRoundMessage<E>,
                        m3: &BSSignerSecondRoundMessage<E>,
    ) -> Signature<E> {
        assert!(self.g.mul(m3.s) == m1.r_g.add(self.pk.pk.mul(m2.c)));

        let s_prime = m3.s + secret_randomness.alpha;

        // R' = R * g^{alpha} * pk^{beta}
        let r_g_prime: E::G1 = {
            let mut temp = self.g.mul(secret_randomness.alpha);
            temp = temp.add(self.pk.pk.mul(secret_randomness.beta));
            temp = temp.add(m1.r_g);
            temp
        };

        Signature {
            r_g: r_g_prime,
            s: s_prime,
        }
    }
}


