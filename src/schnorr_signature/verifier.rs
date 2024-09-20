use std::ops::Mul;

use ark_ec::{Group};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;

use crate::hash::Hash256;
use crate::schnorr_signature::key::PublicKey;
use crate::schnorr_signature::signature::Signature;
use crate::schnorr_signature::util::group_element_into_bytes;

pub struct Verifier<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub pk: PublicKey<G1>,
    pub g: Projective<G1>,
}

impl<G1> Verifier<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub fn new(pk: PublicKey<G1>) -> Verifier<G1> {
        Verifier {
            pk,
            g: Projective::generator(),
        }
    }
}

impl<G1> Verifier<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub fn get_generator(&self) -> Projective<G1> {
        self.g.clone()
    }

    pub fn get_public_key(&self) -> PublicKey<G1> {
        self.pk.clone()
    }

    pub fn verify(&self, message: &Vec<u8>, signature: Signature<G1>) -> bool {
        // Serialize R', the message, and the public key
        let c: G1::ScalarField = {
            let mut bytes = group_element_into_bytes::<G1>(&signature.r_g);
            bytes.extend(message);
            Hash256::hash_bytes(&bytes)
        };

        // Check if the recomputed e' matches the provided e
        self.g.clone().mul(signature.s) == {
            signature.r_g + self.pk.pk.clone().mul(c)
        }
    }
}
