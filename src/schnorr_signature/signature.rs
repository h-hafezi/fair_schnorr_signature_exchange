use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::PrimeField;

/// Signature structure
pub struct Signature<G1>
where
    G1: SWCurveConfig + Clone,
    G1::ScalarField: PrimeField,
{
    /// R = g^r
    pub r_g: Projective<G1>,

    /// s = r + H(R, m) * sk
    pub s: G1::ScalarField,
}
