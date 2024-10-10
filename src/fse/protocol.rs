use std::marker::PhantomData;
use std::ops::{Add, Mul};

use ark_ec::{CurveConfig, Group};
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;
use ark_std::UniformRand;
use rand::Rng;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator};
use rayon::iter::ParallelIterator;

use crate::hash::Hash256;
use crate::schnorr_signature::key::{generate_key_pair, PublicKey, SecretKey};
use crate::schnorr_signature::signature::Signature;
use crate::schnorr_signature::util::group_element_into_bytes;

pub struct FSE<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    phantom: PhantomData<G1>,
}

impl<G1> FSE<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    pub fn gen_key<R: Rng>(rng: &mut R) -> (SecretKey<G1>, PublicKey<G1>) {
        generate_key_pair(rng)
    }

    pub fn sign<R: Rng>(sk: &SecretKey<G1>, message: &Vec<Vec<u8>>, rng: &mut R) -> (Vec<G1::ScalarField>, Vec<Projective<G1>>, Projective<G1>, G1::ScalarField)
    where
        <G1 as CurveConfig>::BaseField: PrimeField,
    {
        let n = message.len();

        let r: Vec<G1::ScalarField> = (0..n).map(|_| G1::ScalarField::rand(rng)).collect();
        let r_g: Vec<Projective<G1>> = r.par_iter().map(|r_i| Projective::generator().mul(*r_i)).collect();

        let k = G1::ScalarField::rand(rng);
        let g_k = Projective::generator().mul(k);

        // Parallelized the computation of vec_c using rayon's par_iter
        let vec_alpha: Vec<G1::ScalarField> = (0..n).into_par_iter().map(|i| {
            let c_i: G1::ScalarField = {
                let mut bytes = group_element_into_bytes::<G1>(&r_g[i]);
                bytes.extend(message[i].clone());
                Hash256::hash_bytes(bytes.as_slice())
            };

            let s_i = r[i] + c_i * sk.sk;
            let alpha_i = (s_i + k) / G1::ScalarField::from(2u8);

            alpha_i
        }).collect();

        (vec_alpha, r_g, g_k, k)
    }

    pub fn verify(pk: &PublicKey<G1>, message: &Vec<Vec<u8>>, alpha: &Vec<G1::ScalarField>, r_g: &Vec<Projective<G1>>, com_k: &Projective<G1>)
    where
        <G1 as CurveConfig>::BaseField: PrimeField,
    {
        let n = message.len();

        // Parallelized the computation of vec_c using rayon's par_iter
        let vec_c: Vec<G1::ScalarField> = (0..n).into_par_iter().map(|i| {
            let c_i: G1::ScalarField = {
                let mut bytes = group_element_into_bytes::<G1>(&r_g[i]);
                bytes.extend(message[i].clone());
                Hash256::hash_bytes(bytes.as_slice())
            };
            c_i
        }).collect();

        for i in 0..n {
            let com_i = r_g[i].add(pk.pk.mul(vec_c[i]));
            assert_eq!(
                Projective::generator().mul(G1::ScalarField::from(2u128) * alpha[i]),
                com_k.add(com_i)
            );
        }
    }

    pub fn recover(alpha: &Vec<G1::ScalarField>, r_g: &Vec<Projective<G1>>, k: G1::ScalarField) -> Vec<Signature<G1>> {
        let signatures: Vec<Signature<G1>> = {
            let mut res = Vec::new();
            for i in 0..alpha.len() {
                let s_i = G1::ScalarField::from(2u128) * alpha[i] - k;
                res.push(Signature {
                    r_g: r_g[i],
                    s: s_i,
                });
            }
            res
        };

        signatures
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::g1::Config;
    use rand::thread_rng;

    use crate::fse::protocol::FSE;
    use crate::schnorr_signature::key::{PublicKey, SecretKey};
    use crate::schnorr_signature::verifier::Verifier;

    #[test]
    fn test() {
        let message = {
            let mut temp = Vec::new();
            temp.push([0u8, 1u8, 2u8, 3u8].to_vec());
            temp.push([0u8, 1u8, 2u8, 3u8].to_vec());
            temp
        };
        let (sk, pk): (SecretKey<Config>, PublicKey<Config>) = FSE::gen_key(&mut thread_rng());

        let (vec_alpha, r_g, g_k, k) = FSE::sign(&sk, &message, &mut thread_rng());
        FSE::verify(&pk, &message, &vec_alpha, &r_g, &g_k);

        let signatures = FSE::recover(&vec_alpha, &r_g, k);

        for (i, sig) in signatures.iter().enumerate() {
            let verifier = Verifier::new(pk.clone());
            assert!(verifier.verify(&message[i], sig));
        }
    }
}
