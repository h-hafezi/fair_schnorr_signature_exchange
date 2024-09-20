use std::ops::{Add, Mul};

use ark_ec::CurveConfig;
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::Rng;

use crate::blind_schnorr_signature::signer::{BSSignerFirstRoundMessage, BSSignerSecondRoundMessage};
use crate::hash::Hash256;
use crate::schnorr_signature::key::PublicKey;
use crate::schnorr_signature::signature::Signature;
use crate::schnorr_signature::util::group_element_into_bytes;
use crate::schnorr_signature::verifier::Verifier;

pub struct BSVerifier<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub pk: PublicKey<G1>,
    pub g: Projective<G1>,
}

pub struct BSVerifierSecretRandomness<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub alpha: G1::ScalarField,
    pub beta: G1::ScalarField,
}

pub struct BSVerifierFirstRoundMessage<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub c: G1::ScalarField,
}

impl<G1> BSVerifier<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub fn new(verifier: &Verifier<G1>) -> Self {
        BSVerifier {
            pk: verifier.pk.clone(),
            g: verifier.get_generator(),
        }
    }

    pub fn first_round<R: Rng>(&self,
                               m1: &BSSignerFirstRoundMessage<G1>,
                               message: Vec<u8>,
                               rng: &mut R,
    ) -> (BSVerifierSecretRandomness<G1>, BSVerifierFirstRoundMessage<G1>)
    where
        <G1 as CurveConfig>::BaseField: PrimeField,
    {
        let alpha = G1::ScalarField::rand(rng);
        let beta = G1::ScalarField::rand(rng);

        // R' = R * g^{alpha} * pk^{beta}
        let r_g_prime: Projective<G1> = {
            let mut temp: Projective<G1> = self.g.mul(alpha);
            temp = temp.add(self.pk.pk.mul(beta));
            temp = temp.add(m1.r_g);
            temp
        };

        let c_prime: G1::ScalarField = {
            let mut bytes = group_element_into_bytes::<G1>(&r_g_prime);
            bytes.extend(message);
            Hash256::hash_bytes(bytes.as_slice())
        };

        let c = c_prime + beta;

        (BSVerifierSecretRandomness { alpha, beta }, BSVerifierFirstRoundMessage { c })
    }

    pub fn second_round(&self,
                        secret_randomness: &BSVerifierSecretRandomness<G1>,
                        m1: &BSSignerFirstRoundMessage<G1>,
                        m2: &BSVerifierFirstRoundMessage<G1>,
                        m3: &BSSignerSecondRoundMessage<G1>,
    ) -> Signature<G1> {
        assert_eq!(self.g.mul(m3.s), m1.r_g.add(self.pk.pk.mul(m2.c)));

        let s_prime = m3.s + secret_randomness.alpha;

        // R' = R * g^{alpha} * pk^{beta}
        let r_g_prime: Projective<G1> = {
            let mut temp: Projective<G1> = self.g.mul(secret_randomness.alpha);
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

