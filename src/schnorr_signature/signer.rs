use ark_ff::PrimeField;
use std::ops::Mul;

use ark_ec::{AffineRepr, Group};
use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use rand::Rng;
use crate::hash::Hash256;
use crate::schnorr_signature::key::SecretKey;
use crate::schnorr_signature::signature::Signature;
use crate::schnorr_signature::util::group_element_into_bytes;

pub struct Signer<E: Pairing> {
    pub sk: SecretKey<E>,
    pub g: E::G1,
}

impl<E: Pairing> Signer<E> {
    pub fn new(sk: SecretKey<E>) -> Signer<E> {
        Signer {
            sk,
            g: E::G1::generator(),
        }
    }
}

impl<E: Pairing> Signer<E> {
    pub(crate) fn get_generator(&self) -> E::G1 {
        self.g
    }

    pub(crate) fn get_secret_key(&self) -> SecretKey<E> {
        self.sk.clone()
    }

    pub(crate) fn sign<R: Rng>(&self, message: &Vec<u8>, rng: &mut R) -> Signature<E> where <<E as Pairing>::G1Affine as AffineRepr>::BaseField: PrimeField {
        // Random nonce
        let r = E::ScalarField::rand(rng);
        // R = g^r
        let r_g = self.g.mul(r);

        let c: E::ScalarField = {
            let mut bytes = group_element_into_bytes::<E>(r_g);
            bytes.extend(message);
            Hash256::hash_bytes(&bytes)
        };

        // Compute s = r - e * sk
        let s = r + c * self.sk.sk;

        Signature { s, r_g }
    }
}