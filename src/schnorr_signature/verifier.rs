use std::ops::Mul;

use ark_ec::{AffineRepr, Group};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

use crate::hash::Hash256;
use crate::schnorr_signature::key::PublicKey;
use crate::schnorr_signature::signature::Signature;
use crate::schnorr_signature::util::group_element_into_bytes;

pub struct Verifier<E: Pairing> {
    pub pk: PublicKey<E>,
    pub g: E::G1,
}

impl<E: Pairing> Verifier<E> {
    pub fn new(pk: PublicKey<E>) -> Verifier<E> {
        Verifier {
            pk,
            g: E::G1::generator(),
        }
    }
}

impl<E: Pairing> Verifier<E> {
    pub fn get_generator(&self) -> E::G1 {
        self.g
    }

    pub fn get_public_key(&self) -> PublicKey<E> {
        self.pk.clone()
    }

    pub fn verify(&self, message: &Vec<u8>, signature: Signature<E>) -> bool
    where
        <<E as Pairing>::G1Affine as AffineRepr>::BaseField: PrimeField,
    {
        // Serialize R', the message, and the public key
        let c: E::ScalarField = {
            let mut bytes = group_element_into_bytes::<E>(signature.r_g);
            bytes.extend(message);
            Hash256::hash_bytes(&bytes)
        };

        // Check if the recomputed e' matches the provided e
        self.g.mul(signature.s) == {
            signature.r_g + self.pk.pk.mul(c)
        }
    }
}
