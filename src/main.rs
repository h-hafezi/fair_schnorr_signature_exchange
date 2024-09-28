pub mod hash;
pub mod schnorr_signature;
pub mod blind_schnorr_signature;
pub mod fde;

use std::mem;

fn main() {
    println!("BLS group element size: {} bytes", mem::size_of::<ark_bls12_381::g1::G1Affine>());
    println!("BLS scalar field element size: {} bytes", mem::size_of::<ark_bls12_381::Fr>());
}
